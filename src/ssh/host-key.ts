import { HOST_CERTIFICATE_ALGORITHMS } from './algorithms';
import { base64UrlEncodeUnsigned } from './crypto';
import { concat, encodeString } from './utils';

const MAX_HOST_KEY_BYTES = 64 * 1024;
const MAX_SIGNATURE_BYTES = 16 * 1024;
const MAX_CERT_FIELD_BYTES = 16 * 1024;
const MAX_CERT_ENTRIES = 256;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Lengths are checked before slicing or advancing, including nested certificate fields. */
class HostKeyReader {
  offset = 0;

  constructor(readonly data: Uint8Array, limit = MAX_HOST_KEY_BYTES) {
    if (data.length > limit) throw new Error('SSH host key field exceeds size limit');
  }

  private require(length: number): void {
    if (length > this.data.length - this.offset) throw new Error('Truncated SSH host key field');
  }

  uint32(): number {
    this.require(4);
    const value = new DataView(
      this.data.buffer, this.data.byteOffset + this.offset, 4
    ).getUint32(0);
    this.offset += 4;
    return value;
  }

  uint64(): bigint {
    return (BigInt(this.uint32()) << 32n) | BigInt(this.uint32());
  }

  string(limit = MAX_CERT_FIELD_BYTES): Uint8Array {
    const length = this.uint32();
    if (length > limit) throw new Error('SSH host key field exceeds size limit');
    this.require(length);
    const value = this.data.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  name(): string {
    const value = decoder.decode(this.string(128));
    if (!/^[\x21-\x7e]+$/.test(value)) throw new Error('Invalid SSH algorithm or option name');
    return value;
  }

  positiveMPInt(limit: number): Uint8Array {
    const value = this.string(limit);
    if (!value.length || (value[0] & 0x80) || (value.length === 1 && value[0] === 0) ||
        (value.length > 1 && value[0] === 0 && !(value[1] & 0x80))) {
      throw new Error('Invalid positive SSH mpint');
    }
    return value;
  }

  end(): void {
    if (this.offset !== this.data.length) throw new Error('Trailing SSH host key data');
  }
}

const EC_CURVES = {
  'ecdsa-sha2-nistp256': { curve: 'nistp256', namedCurve: 'P-256', hash: 'SHA-256', bytes: 32 },
  'ecdsa-sha2-nistp384': { curve: 'nistp384', namedCurve: 'P-384', hash: 'SHA-384', bytes: 48 },
  'ecdsa-sha2-nistp521': { curve: 'nistp521', namedCurve: 'P-521', hash: 'SHA-512', bytes: 66 },
} as const;

type ECKeyType = keyof typeof EC_CURVES;
type RawPublicKey =
  | { type: 'ssh-ed25519'; key: Uint8Array }
  | { type: 'ssh-rsa'; e: Uint8Array; n: Uint8Array }
  | { type: ECKeyType; point: Uint8Array };

function parseRawPublicKey(blob: Uint8Array): RawPublicKey {
  const reader = new HostKeyReader(blob);
  const type = reader.name();
  let key: RawPublicKey;
  if (type === 'ssh-ed25519') {
    const raw = reader.string(32);
    if (raw.length !== 32) throw new Error('Invalid Ed25519 public key length');
    key = { type, key: raw };
  } else if (type === 'ssh-rsa') {
    key = { type, e: reader.positiveMPInt(9), n: reader.positiveMPInt(1025) };
  } else if (Object.hasOwn(EC_CURVES, type)) {
    const ecType = type as ECKeyType;
    const curve = EC_CURVES[ecType];
    if (reader.name() !== curve.curve) throw new Error('ECDSA curve does not match key type');
    const point = reader.string(1 + 2 * curve.bytes);
    if (point.length !== 1 + 2 * curve.bytes || point[0] !== 4) {
      throw new Error('Invalid ECDSA public point');
    }
    key = { type: ecType, point };
  } else {
    // Certificate CA keys must themselves be raw keys, never nested certificates.
    throw new Error(`Unsupported SSH public key algorithm: ${type}`);
  }
  reader.end();
  return key;
}

function parseSignature(blob: Uint8Array): { type: string; signature: Uint8Array } {
  const reader = new HostKeyReader(blob, MAX_SIGNATURE_BYTES);
  const type = reader.name();
  const signature = reader.string(MAX_SIGNATURE_BYTES);
  reader.end();
  return { type, signature };
}

/** Bind both the key blob and signature algorithm to the actual KEXINIT selection. */
export function assertHostKeyAlgorithm(
  algorithm: string,
  hostKeyBlob: Uint8Array,
  signatureBlob: Uint8Array
): void {
  const reader = new HostKeyReader(hostKeyBlob);
  const keyType = reader.name();
  const signatureType = parseSignature(signatureBlob).type;
  const certificate = Object.hasOwn(HOST_CERTIFICATE_ALGORITHMS, algorithm)
    ? HOST_CERTIFICATE_ALGORITHMS[algorithm] : undefined;
  const expectedKeyType = certificate?.keyType ?? (
    algorithm === 'rsa-sha2-256' || algorithm === 'rsa-sha2-512' ? 'ssh-rsa' : algorithm
  );
  const expectedSignatureType = certificate?.signatureType ?? algorithm;
  if (keyType !== expectedKeyType || signatureType !== expectedSignatureType) {
    throw new Error('SSH host key or signature does not match the negotiated algorithm');
  }
}

/** Verify a raw SSH key's signature; certificate integrity is separate from CA trust. */
export async function verifySSHSignature(
  publicKeyBlob: Uint8Array,
  signatureBlob: Uint8Array,
  data: Uint8Array,
  allowRsaSha1 = true
): Promise<boolean> {
  const key = parseRawPublicKey(publicKeyBlob);
  const { type, signature } = parseSignature(signatureBlob);
  if (key.type === 'ssh-ed25519') {
    if (type !== key.type || signature.length !== 64) return false;
    const publicKey = await crypto.subtle.importKey('raw', key.key, 'Ed25519', false, ['verify']);
    return crypto.subtle.verify('Ed25519', publicKey, signature, data);
  }
  if (key.type === 'ssh-rsa') {
    const hash = type === 'rsa-sha2-512' ? 'SHA-512'
      : type === 'rsa-sha2-256' ? 'SHA-256'
      : type === 'ssh-rsa' && allowRsaSha1 ? 'SHA-1' : null;
    if (!hash || signature.length > 1024) return false;
    const publicKey = await crypto.subtle.importKey(
      'jwk', { kty: 'RSA', e: base64UrlEncodeUnsigned(key.e), n: base64UrlEncodeUnsigned(key.n) },
      { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']
    );
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, data);
  }
  if (type !== key.type) return false;
  const curve = EC_CURVES[key.type];
  const reader = new HostKeyReader(signature, 2 * (curve.bytes + 5));
  const r = reader.positiveMPInt(curve.bytes + 1);
  const s = reader.positiveMPInt(curve.bytes + 1);
  reader.end();
  const rawSignature = new Uint8Array(2 * curve.bytes);
  for (const [index, value] of [r, s].entries()) {
    const unsigned = value[0] === 0 ? value.subarray(1) : value;
    if (unsigned.length > curve.bytes) return false;
    rawSignature.set(unsigned, (index + 1) * curve.bytes - unsigned.length);
  }
  const publicKey = await crypto.subtle.importKey(
    'raw', key.point, { name: 'ECDSA', namedCurve: curve.namedCurve }, false, ['verify']
  );
  return crypto.subtle.verify({ name: 'ECDSA', hash: curve.hash }, publicKey, rawSignature, data);
}

export interface PresentedHostKey {
  /** Original wire type, including the certificate suffix when present. */
  keyType: string;
  /** Canonical raw public-key blob, used for KEX verification and stable TOFU fingerprints. */
  publicKeyBlob: Uint8Array;
  certificate: boolean;
}

function validatePrincipals(data: Uint8Array): void {
  const reader = new HostKeyReader(data, MAX_CERT_FIELD_BYTES);
  let count = 0;
  while (reader.offset < data.length) {
    if (++count > MAX_CERT_ENTRIES) throw new Error('Too many SSH certificate principals');
    const principal = decoder.decode(reader.string(1024));
    if (!principal || Array.from(principal).some((c) => c.charCodeAt(0) < 32 || c === '\x7f')) {
      throw new Error('Invalid SSH certificate principal');
    }
  }
}

function validateExtensions(data: Uint8Array): void {
  const reader = new HostKeyReader(data, MAX_CERT_FIELD_BYTES);
  let previous = '';
  let count = 0;
  while (reader.offset < data.length) {
    if (++count > MAX_CERT_ENTRIES) throw new Error('Too many SSH certificate extensions');
    const name = reader.name();
    if (name <= previous) throw new Error('Unsorted or duplicate SSH certificate extension');
    previous = name;
    reader.string(); // Unknown non-critical extensions may be ignored, but never parsed unboundedly.
  }
}

/**
 * OpenSSH host certificate carrier with raw-key TOFU, NOT automatic trust of its embedded CA.
 * We additionally reject invalid lifetimes/types/critical options even in TOFU mode. Principals
 * are structurally checked, not used as CA-authorized identities (there is no trusted CA store).
 * The caller MUST keep the original certificate blob in the KEX exchange hash.
 */
export async function parsePresentedHostKey(
  blob: Uint8Array,
  now = Date.now()
): Promise<PresentedHostKey> {
  const reader = new HostKeyReader(blob);
  const keyType = reader.name();
  const certificate = Object.values(HOST_CERTIFICATE_ALGORITHMS)
    .find((entry) => entry.keyType === keyType);
  if (!certificate) {
    parseRawPublicKey(blob);
    return { keyType, publicKeyBlob: blob, certificate: false };
  }

  reader.string(1024); // nonce
  const subjectStart = reader.offset;
  const rawType = certificate.signatureType.startsWith('rsa-') ? 'ssh-rsa' : certificate.signatureType;
  if (rawType === 'ssh-ed25519') {
    if (reader.string(32).length !== 32) throw new Error('Invalid certificate Ed25519 key length');
  } else if (rawType === 'ssh-rsa') {
    reader.positiveMPInt(9); // exponent
    reader.positiveMPInt(1025); // modulus
  } else {
    reader.name(); // curve, checked against the key type below
    reader.string(133); // uncompressed NIST public point
  }
  const publicKeyBlob = concat(encodeString(rawType), blob.subarray(subjectStart, reader.offset));
  parseRawPublicKey(publicKeyBlob);
  reader.uint64(); // serial
  if (reader.uint32() !== 2) throw new Error('Expected an SSH host certificate');
  reader.string(4096); // key ID is untrusted metadata; do not log or use it for identity.
  validatePrincipals(reader.string());
  const validAfter = reader.uint64();
  const validBefore = reader.uint64();
  const timestamp = BigInt(Math.floor(now / 1000));
  if (validBefore <= validAfter || timestamp < validAfter || timestamp >= validBefore) {
    throw new Error('SSH host certificate is expired or not yet valid');
  }
  if (reader.string().length) throw new Error('Unsupported SSH host certificate critical options');
  validateExtensions(reader.string());
  reader.string(); // reserved
  const caPublicKey = reader.string();
  const signedEnd = reader.offset;
  const caSignature = reader.string(MAX_SIGNATURE_BYTES);
  reader.end();
  // CA-key signature integrity does not authorize or trust that CA. No SHA-1 CA signatures.
  if (!await verifySSHSignature(caPublicKey, caSignature, blob.subarray(0, signedEnd), false)) {
    throw new Error('Invalid SSH host certificate signature');
  }
  return {
    keyType,
    publicKeyBlob,
    certificate: true,
  };
}

export async function fingerprintHostKey(publicKeyBlob: Uint8Array): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKeyBlob));
  return `SHA256:${btoa(String.fromCharCode(...hash)).replace(/=+$/, '')}`;
}
