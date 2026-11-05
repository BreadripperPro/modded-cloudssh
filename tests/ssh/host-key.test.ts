import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ED25519_HOST_CERTIFICATE_ALGORITHM } from '../../src/ssh/algorithms';
import {
  assertHostKeyAlgorithm,
  fingerprintHostKey,
  parsePresentedHostKey,
  verifySSHSignature,
} from '../../src/ssh/host-key';
import { KEXInitBuilder, negotiate, parseKEXInit } from '../../src/ssh/kex';
import { concat, encodeString, encodeUint32 } from '../../src/ssh/utils';
import { certificateKeys, createHostCertificate, createSigningKey } from './host-certificate-fixture';

const CERT = ED25519_HOST_CERTIFICATE_ALGORITHM;
const data = new TextEncoder().encode('SSH exchange hash test');

describe('SSH host-key negotiation and signature binding', () => {
  it('advertises the implemented Ed25519 certificate type, preserving raw-key preference', () => {
    const offer = parseKEXInit(KEXInitBuilder.build()).hostKeyAlgorithms;
    expect(offer[0]).toBe('ssh-ed25519');
    expect(negotiate(offer, [CERT], 'host key algorithm')).toBe(CERT);
    expect(() => negotiate(offer, ['ssh-dss'], 'host key algorithm'))
      .toThrow('No common host key algorithm');
  });

  it('bounds and sanitizes untrusted algorithm proposals in errors', () => {
    let message = '';
    try { negotiate(['ssh-ed25519'], ['\x1b[31m' + 'x'.repeat(100_000)], 'host key algorithm'); }
    catch (error) { message = (error as Error).message; }
    expect(message).not.toContain('\x1b');
    expect(message.length).toBeLessThan(400);
  });

  it.each([
    'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-rsa',
  ])('verifies %s without allowing an unrelated signature algorithm', async (algorithm) => {
    const key = await createSigningKey(algorithm);
    const signature = await key.sign(data);
    assertHostKeyAlgorithm(algorithm, key.blob, signature);
    expect(await parsePresentedHostKey(key.blob)).toMatchObject({ certificate: false });
    expect(await verifySSHSignature(key.blob, signature, data)).toBe(true);
    expect(await verifySSHSignature(key.blob, signature, new Uint8Array([0]))).toBe(false);
    expect(() => assertHostKeyAlgorithm('different-algorithm', key.blob, signature)).toThrow();
    expect(() => assertHostKeyAlgorithm(algorithm, key.blob,
      concat(encodeString('different-algorithm'), encodeString(new Uint8Array(64))))).toThrow();
    expect(() => assertHostKeyAlgorithm(algorithm, key.blob, concat(signature, new Uint8Array(1))))
      .toThrow('Trailing');
  });

  it('does not accept RSA-SHA256 when RSA-SHA512 was selected', async () => {
    const key = await createSigningKey('rsa-sha2-256');
    expect(() => assertHostKeyAlgorithm('rsa-sha2-512', key.blob, key.blob)).toThrow();
    expect(() => assertHostKeyAlgorithm('rsa-sha2-512', key.blob,
      concat(encodeString('rsa-sha2-256'), encodeString(new Uint8Array(256))))).toThrow();
  });
});

describe('OpenSSH host certificates with raw-key TOFU', () => {
  it.each(['rsa-sha2-256', 'rsa-sha2-512', 'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'])('verifies a %s certificate subject', async (algorithm) => {
    const { ca } = await certificateKeys();
    const host = await createSigningKey(algorithm);
    const cert = await createHostCertificate({}, { host, ca });
    const offer = parseKEXInit(KEXInitBuilder.build()).hostKeyAlgorithms;
    const selected = `${algorithm}-cert-v01@openssh.com`;
    expect(negotiate(offer, [selected], 'host key algorithm')).toBe(selected);
    const parsed = await parsePresentedHostKey(cert.blob);
    expect(parsed.publicKeyBlob).toEqual(host.blob);
    const signature = await host.sign(data);
    assertHostKeyAlgorithm(selected, cert.blob, signature);
    expect(await verifySSHSignature(parsed.publicKeyBlob, signature, data)).toBe(true);
    expect(await verifySSHSignature(parsed.publicKeyBlob, await ca.sign(data), data)).toBe(false);
    if (algorithm.startsWith('rsa-')) {
      expect(() => assertHostKeyAlgorithm('ssh-rsa-cert-v01@openssh.com', cert.blob, signature)).toThrow();
      const wrongHash = algorithm === 'rsa-sha2-256' ? 'rsa-sha2-512' : 'rsa-sha2-256';
      expect(() => assertHostKeyAlgorithm(`${wrongHash}-cert-v01@openssh.com`, cert.blob, signature)).toThrow();
    }
    const renewed = await createHostCertificate({ serial: 2n }, { host, ca });
    expect(await fingerprintHostKey((await parsePresentedHostKey(renewed.blob)).publicKeyBlob))
      .toBe(await fingerprintHostKey(parsed.publicKeyBlob));
    const tampered = cert.blob.slice();
    tampered[tampered.length - 1] ^= 1;
    await expect(parsePresentedHostKey(tampered)).rejects.toThrow();
  });
  it('checks the CA signature and verifies KEX using the subject key, not the CA', async () => {
    const { blob, host, ca } = await createHostCertificate();
    const parsed = await parsePresentedHostKey(blob);
    expect(parsed).toEqual({ keyType: CERT, certificate: true, publicKeyBlob: host.blob });
    const signature = await host.sign(data);
    assertHostKeyAlgorithm(CERT, blob, signature);
    expect(await verifySSHSignature(parsed.publicKeyBlob, signature, data)).toBe(true);
    expect(await verifySSHSignature(parsed.publicKeyBlob, await ca.sign(data), data)).toBe(false);
  });

  it('keeps fingerprints stable across certificate renewal and identical to the raw key', async () => {
    const first = await createHostCertificate();
    const renewed = await createHostCertificate({
      nonce: new Uint8Array(16).fill(3), serial: 999n, keyId: 'renewed',
      validAfter: 100n, principals: encodeString('different-alias.example.com'),
    });
    expect(first.blob).not.toEqual(renewed.blob);
    const a = await parsePresentedHostKey(first.blob);
    const b = await parsePresentedHostKey(renewed.blob);
    expect(await fingerprintHostKey(a.publicKeyBlob)).toBe(await fingerprintHostKey(b.publicKeyBlob));
    expect(await fingerprintHostKey(a.publicKeyBlob)).toBe(await fingerprintHostKey(first.host.blob));
    expect(await fingerprintHostKey(first.blob)).not.toBe(await fingerprintHostKey(a.publicKeyBlob));
  });

  it('accepts a real ssh-keygen host certificate and matches its OpenSSH raw fingerprint', async () => {
    const line = readFileSync(join(__dirname, 'fixtures/id_ed25519_host-cert.pub'), 'utf8').trim();
    const blob = new Uint8Array(Buffer.from(line.split(/\s+/)[1], 'base64'));
    const parsed = await parsePresentedHostKey(blob, Date.UTC(2027, 0, 1));
    expect(parsed.keyType).toBe(CERT);
    expect(await fingerprintHostKey(parsed.publicKeyBlob)).toBe(
      'SHA256:op2SSHjuVjU6fJLh8xqcnB77BhHwfYCmTThjvDb0RcI'
    );
  });

  it.each(['rsa-sha2-256', 'rsa-sha2-512', 'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'])('accepts a %s CA for an Ed25519 subject', async (algorithm) => {
    const { host } = await certificateKeys();
    const ca = await createSigningKey(algorithm);
    const cert = await createHostCertificate({}, { host, ca });
    expect((await parsePresentedHostKey(cert.blob)).publicKeyBlob).toEqual(host.blob);
  });

  it.each(['id_rsa_2048', 'id_ecdsa_256', 'id_ecdsa_384', 'id_ecdsa_521'])(
    'accepts the real ssh-keygen certificate for %s', async (name) => {
      const decode = (file: string) => new Uint8Array(Buffer.from(
        readFileSync(join(__dirname, `fixtures/${file}.pub`), 'utf8').trim().split(/\s+/)[1], 'base64'
      ));
      const parsed = await parsePresentedHostKey(decode(`${name}_host-cert`), Date.UTC(2027, 0, 1));
      expect(parsed.publicKeyBlob).toEqual(decode(name));
    }
  );

  it('rejects legacy RSA/SHA-1 certificate signatures without disabling raw RSA compatibility', async () => {
    const { host } = await certificateKeys();
    const ca = await createSigningKey('ssh-rsa');
    const cert = await createHostCertificate({}, { host, ca });
    await expect(parsePresentedHostKey(cert.blob)).rejects.toThrow('certificate signature');
  });

  it('rejects a certificate signed by a key other than its declared CA', async () => {
    const material = await certificateKeys();
    const unrelated = await createSigningKey();
    const cert = await createHostCertificate({ caPublicKey: unrelated.blob }, material);
    await expect(parsePresentedHostKey(cert.blob)).rejects.toThrow('certificate signature');
  });

  it('rejects tampered certificate fields or signatures', async () => {
    const { blob } = await createHostCertificate();
    const badSignature = blob.slice();
    badSignature[badSignature.length - 1] ^= 1;
    await expect(parsePresentedHostKey(badSignature)).rejects.toThrow('certificate signature');
    const badNonce = blob.slice();
    badNonce[encodeString(CERT).length + 4] ^= 1;
    await expect(parsePresentedHostKey(badNonce)).rejects.toThrow('certificate signature');
  });

  it.each([
    { type: 1 }, { publicKey: new Uint8Array(31) }, { nonce: new Uint8Array(1025) },
    { criticalOptions: concat(encodeString('unknown-critical'), encodeString('')) },
    { validAfter: 100n, validBefore: 99n }, { validBefore: 1n },
    { validAfter: 0xfffffffffffffffen },
    { principals: encodeUint32(0xffffffff) },
    { principals: encodeString(new Uint8Array([0xc0, 0xaf])) },
    { principals: concat(...Array.from({ length: 257 }, () => encodeString('host'))) },
    { extensions: concat(encodeString('z'), encodeString(''), encodeString('a'), encodeString('')) },
    { extensions: concat(encodeString('a'), encodeString(''), encodeString('a'), encodeString('')) },
  ])('rejects invalid certificate structure or policy %#', async (options) => {
    const { blob } = await createHostCertificate(options);
    await expect(parsePresentedHostKey(blob)).rejects.toThrow();
  });

  it('checks lifetime boundaries using uint64 without losing integer precision', async () => {
    const { blob } = await createHostCertificate({ validAfter: 100n, validBefore: 200n });
    await expect(parsePresentedHostKey(blob, 99_000)).rejects.toThrow();
    await expect(parsePresentedHostKey(blob, 100_000)).resolves.toMatchObject({ certificate: true });
    await expect(parsePresentedHostKey(blob, 200_000)).rejects.toThrow();
  });

  it('allows unknown non-critical extensions, opaque reserved bytes, and empty principals', async () => {
    const { blob } = await createHostCertificate({
      principals: new Uint8Array(0), reserved: new Uint8Array([0, 1, 255]),
      extensions: concat(encodeString('custom@example.com'), encodeString(new Uint8Array([255]))),
    });
    await expect(parsePresentedHostKey(blob)).resolves.toMatchObject({ certificate: true });
  });

  it('rejects nested CA certificates', async () => {
    const nested = await createHostCertificate();
    const { blob } = await createHostCertificate({ caPublicKey: nested.blob });
    await expect(parsePresentedHostKey(blob)).rejects.toThrow('Unsupported SSH public key');
  });

  it('rejects every truncation, trailing bytes, and oversized outer or nested lengths', async () => {
    const { blob } = await createHostCertificate();
    for (let i = 0; i < blob.length; i++) {
      await expect(parsePresentedHostKey(blob.subarray(0, i)), `truncation ${i}`).rejects.toThrow();
    }
    await expect(parsePresentedHostKey(concat(blob, new Uint8Array(1)))).rejects.toThrow('Trailing');
    await expect(parsePresentedHostKey(new Uint8Array(64 * 1024 + 1))).rejects.toThrow('size limit');
    const badLength = blob.slice();
    badLength.set(encodeUint32(0xffffffff), encodeString(CERT).length);
    await expect(parsePresentedHostKey(badLength)).rejects.toThrow('size limit');
  });

  it('rejects malformed raw public keys as well as malformed signature envelopes', async () => {
    const { host } = await certificateKeys();
    await expect(parsePresentedHostKey(concat(host.blob, new Uint8Array(1)))).rejects.toThrow('Trailing');
    await expect(parsePresentedHostKey(concat(encodeString('ssh-ed25519'), encodeString(new Uint8Array(31)))))
      .rejects.toThrow('length');
    await expect(verifySSHSignature(host.blob,
      concat(encodeString('ssh-ed25519'), encodeUint32(0xffffffff)), data)).rejects.toThrow();
  });
});
