/// <reference path="./bcrypt-pbkdf.d.ts" />
import { pbkdf } from 'bcrypt-pbkdf';
import { decodeOid, integerBytes, parseDer, sequenceChildren, TAG_OCTET_STRING, type DerNode } from '../../src/ssh/der';
import { concat, encodeString, encodeUint32 } from '../../src/ssh/utils';

const MAX_KEY_BYTES = 64 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
export class PrivateKeyUnlockError extends Error {
  constructor(readonly reason: 'invalid' | 'unsupported' | 'budget' | 'password') { super(reason); }
}
const fail = (reason: PrivateKeyUnlockError['reason']): never => { throw new PrivateKeyUnlockError(reason); };

class KeyReader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) { if (bytes.length > MAX_KEY_BYTES) fail('budget'); }
  uint32(): number {
    if (this.bytes.length - this.offset < 4) fail('invalid');
    const n = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4).getUint32(0);
    this.offset += 4;
    return n;
  }
  string(limit = MAX_KEY_BYTES): Uint8Array {
    const n = this.uint32();
    if (n > limit || n > this.bytes.length - this.offset) fail('invalid');
    const result = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return result;
  }
  name(): string { return decoder.decode(this.string(128)); }
  end(): void { if (this.offset !== this.bytes.length) fail('invalid'); }
}

function decodePem(text: string): { label: string; bytes: Uint8Array } {
  if (text.length > 128 * 1024) fail('budget');
  const trimmed = text.trim();
  const header = trimmed.match(/^-----BEGIN ([A-Z0-9 ]{1,64})-----/);
  const label = header?.[1];
  if (!header || !label) throw new PrivateKeyUnlockError('invalid');
  const footer = `-----END ${label}-----`;
  if (!trimmed.endsWith(footer)) fail('invalid');
  // Split framing before stripping whitespace; avoid overlapping unbounded regex quantifiers.
  const body = trimmed.slice(header[0].length, -footer.length).replace(/\s/g, '');
  if (!body || !/^[A-Za-z0-9+/]*={0,2}$/.test(body)) fail('invalid');
  const bytes = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  if (bytes.length > MAX_KEY_BYTES) fail('budget');
  return { label, bytes };
}
function pem(label: string, bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `-----BEGIN ${label}-----\n${btoa(binary).match(/.{1,64}/g)!.join('\n')}\n-----END ${label}-----`;
}

function opensshEnvelope(bytes: Uint8Array) {
  const magic = encoder.encode('openssh-key-v1\0');
  if (!magic.every((byte, i) => bytes[i] === byte)) fail('invalid');
  const reader = new KeyReader(bytes);
  reader.offset = magic.length;
  const cipher = reader.name();
  const kdf = reader.name();
  const options = reader.string(1024);
  if (reader.uint32() !== 1) fail('unsupported');
  const publicKey = reader.string();
  const encrypted = reader.string();
  reader.end();
  return { magic, cipher, kdf, options, publicKey, encrypted };
}

/** Only classification; no passphrase or decrypted material is retained here. */
export function isEncryptedPrivateKey(text: string): boolean {
  if (text.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----') || /Proc-Type:\s*4\s*,\s*ENCRYPTED/i.test(text)) return true;
  if (!text.includes('-----BEGIN OPENSSH PRIVATE KEY-----')) return false;
  return opensshEnvelope(decodePem(text).bytes).cipher !== 'none';
}

function validateOpenSSHPlaintext(bytes: Uint8Array, blockSize: number): void {
  const reader = new KeyReader(bytes);
  const check1 = reader.uint32();
  const check2 = reader.uint32();
  if (check1 !== check2) fail('password');
  const type = reader.name();
  const fields = type === 'ssh-ed25519' ? 2 : type === 'ssh-rsa' ? 6
    : /^ecdsa-sha2-nistp(256|384|521)$/.test(type) ? 3 : fail('unsupported');
  for (let i = 0; i < fields; i++) reader.string();
  reader.string(); // comment
  const padding = bytes.subarray(reader.offset);
  if (padding.length >= blockSize || !padding.every((value, i) => value === i + 1)) fail('password');
}

async function unlockOpenSSH(bytes: Uint8Array, password: Uint8Array): Promise<string> {
  const envelope = opensshEnvelope(bytes);
  const sizes: Record<string, number> = { 'aes128-ctr': 16, 'aes192-ctr': 24, 'aes256-ctr': 32 };
  if (envelope.kdf !== 'bcrypt' || !Object.hasOwn(sizes, envelope.cipher)) fail('unsupported');
  const options = new KeyReader(envelope.options);
  const salt = options.string(64);
  const rounds = options.uint32();
  options.end();
  // bcrypt is synchronous JavaScript. Bound adversarial KDF work before executing it.
  if (salt.length < 8 || rounds < 1 || rounds > 64) fail('budget');
  if (!envelope.encrypted.length || envelope.encrypted.length % 16) fail('invalid');
  const keyLength = sizes[envelope.cipher];
  const material = new Uint8Array(keyLength + 16);
  let plaintext: Uint8Array | undefined;
  try {
    if (pbkdf(password, password.length, salt, salt.length, material, material.length, rounds) !== 0) fail('password');
    const key = await crypto.subtle.importKey('raw', material.subarray(0, keyLength), 'AES-CTR', false, ['decrypt']);
    plaintext = new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-CTR', counter: material.subarray(keyLength), length: 128,
    }, key, envelope.encrypted));
    validateOpenSSHPlaintext(plaintext, 16);
    return pem('OPENSSH PRIVATE KEY', concat(envelope.magic,
      encodeString('none'), encodeString('none'), encodeString(new Uint8Array(0)),
      encodeUint32(1), encodeString(envelope.publicKey), encodeString(plaintext)));
  } finally {
    material.fill(0);
    plaintext?.fill(0);
  }
}

function octets(node: DerNode): Uint8Array {
  if (node.tag !== TAG_OCTET_STRING) fail('invalid');
  return node.value;
}
function positiveInt(node: DerNode): number {
  if (node.tag !== 2 || !node.value.length || (node.value[0] & 0x80)) fail('invalid');
  const bytes = integerBytes(node, 'encrypted private key');
  if (bytes.length > 4) fail('budget');
  return bytes.reduce((n, byte) => n * 256 + byte, 0);
}
// Restrict nesting/node count before the shared DER parser allocates its node tree.
function boundDer(bytes: Uint8Array, depth = 0, budget = { nodes: 0 }): void {
  if (depth > 12) fail('budget');
  for (let offset = 0; offset < bytes.length;) {
    if (++budget.nodes > 128 || bytes.length - offset < 2) fail('budget');
    const tag = bytes[offset++];
    let length = bytes[offset++];
    if (length & 128) {
      const count = length & 127;
      if (!count || count > 4 || count > bytes.length - offset) fail('invalid');
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
    }
    if (length > bytes.length - offset) fail('invalid');
    if (tag & 32) boundDer(bytes.subarray(offset, offset + length), depth + 1, budget);
    offset += length;
  }
}

async function unlockPkcs8(bytes: Uint8Array, password: Uint8Array): Promise<string> {
  boundDer(bytes);
  const children = (node: DerNode, count: number) => {
    const value = sequenceChildren(node, 'encrypted private key');
    if (value.length !== count) fail('invalid');
    return value;
  };
  const [algorithm, encrypted] = children(parseDer(bytes), 2);
  const [pbesOid, parameters] = children(algorithm, 2);
  if (decodeOid(pbesOid, 'PBES2') !== '1.2.840.113549.1.5.13') fail('unsupported');
  const [kdf, encryption] = children(parameters, 2);
  const [kdfOid, kdfParameters] = children(kdf, 2);
  if (decodeOid(kdfOid, 'PBKDF2') !== '1.2.840.113549.1.5.12') fail('unsupported');
  const kdfFields = sequenceChildren(kdfParameters, 'PBKDF2');
  if (kdfFields.length < 2 || kdfFields.length > 4) fail('invalid');
  const salt = octets(kdfFields[0]);
  const iterations = positiveInt(kdfFields[1]);
  if (salt.length < 8 || salt.length > 64 || iterations < 1 || iterations > 1_000_000) fail('budget');
  const [cipherOid, ivNode] = children(encryption, 2);
  const keyLengths: Record<string, number> = {
    '2.16.840.1.101.3.4.1.2': 16, '2.16.840.1.101.3.4.1.22': 24, '2.16.840.1.101.3.4.1.42': 32,
  };
  const oid = decodeOid(cipherOid, 'AES-CBC');
  if (!Object.hasOwn(keyLengths, oid)) fail('unsupported');
  const keyLength = keyLengths[oid];
  let index = 2;
  if (kdfFields[index]?.tag === 2 && positiveInt(kdfFields[index++]) !== keyLength) fail('invalid');
  let hash = 'SHA-1';
  if (index < kdfFields.length) {
    const prf = sequenceChildren(kdfFields[index++], 'PBKDF2 PRF');
    if (prf.length < 1 || prf.length > 2 || (prf[1] && (prf[1].tag !== 5 || prf[1].value.length))) fail('invalid');
    const hashes: Record<string, string> = { '1.2.840.113549.2.7': 'SHA-1',
      '1.2.840.113549.2.9': 'SHA-256', '1.2.840.113549.2.10': 'SHA-384', '1.2.840.113549.2.11': 'SHA-512' };
    hash = hashes[decodeOid(prf[0], 'PRF')];
    if (!hash) fail('unsupported');
  }
  if (index !== kdfFields.length) fail('invalid');
  const iv = octets(ivNode);
  const ciphertext = octets(encrypted);
  if (iv.length !== 16 || !ciphertext.length || ciphertext.length % 16) fail('invalid');
  const base = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash }, base,
    { name: 'AES-CBC', length: keyLength * 8 }, false, ['decrypt']);
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ciphertext));
    boundDer(plaintext);
    sequenceChildren(parseDer(plaintext), 'PKCS8');
    return pem('PRIVATE KEY', plaintext);
  } finally { plaintext?.fill(0); }
}

/** Browser-only KDF/decryption; never pass a key passphrase to the Worker or persistence. */
export async function unlockPrivateKey(text: string, passphrase: string): Promise<string> {
  const password = encoder.encode(passphrase);
  try {
    if (password.length > 1024) fail('budget');
    if (/Proc-Type:\s*4\s*,\s*ENCRYPTED/i.test(text)) fail('unsupported');
    const { label, bytes } = decodePem(text);
    if (label === 'OPENSSH PRIVATE KEY') return await unlockOpenSSH(bytes, password);
    if (label === 'ENCRYPTED PRIVATE KEY') return await unlockPkcs8(bytes, password);
    return fail('unsupported');
  } catch (error) {
    if (error instanceof PrivateKeyUnlockError) throw error;
    throw new PrivateKeyUnlockError('password');
  } finally { password.fill(0); }
}
