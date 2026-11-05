import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { isEncryptedPrivateKey, unlockPrivateKey } from '../frontend/src/private-key-unlock';
import { SSHAuth } from '../src/ssh/auth';
import { encodeUint32 } from '../src/ssh/utils';

const fixture = (name: string) => readFileSync(new URL(`./ssh/fixtures/${name}`, import.meta.url), 'utf8');
const passphrase = 'cloudssh-fixture-passphrase'; // Public protocol fixture, never a real credential.
const cases = [
  ['id_ed25519_encrypted', 'id_ed25519'],
  ['id_rsa_2048_encrypted', 'id_rsa_2048'],
  ['id_ecdsa_256_encrypted', 'id_ecdsa_256'],
  ['id_rsa_pkcs8_aes128_encrypted.pem', 'id_rsa_2048'],
  ['id_rsa_pkcs8_aes192_encrypted.pem', 'id_rsa_2048'],
  ['id_rsa_pkcs8_aes256_encrypted.pem', 'id_rsa_2048'],
];

describe('browser-only encrypted private key import', () => {
  it('retains the bcrypt license in standalone HTML source as well as repository documentation', () => {
    const html = readFileSync(new URL('../frontend/index.html', import.meta.url), 'utf8');
    const license = readFileSync(new URL('../docs/licenses/bcrypt-pbkdf.txt', import.meta.url), 'utf8');
    for (const line of license.split('\n').map((value) => value.trim()).filter(Boolean)) {
      expect(html).toContain(line);
    }
  });
  it.each(cases)('unlocks native ssh-keygen/openssl fixture %s and signs correctly', async (encrypted, original) => {
    const input = fixture(encrypted);
    expect(isEncryptedPrivateKey(input)).toBe(true);
    expect(isEncryptedPrivateKey(fixture(original))).toBe(false);
    const unlocked = await unlockPrivateKey(input, passphrase);
    expect(isEncryptedPrivateKey(unlocked)).toBe(false);
    expect(unlocked).not.toContain(passphrase);
    const sessionId = new Uint8Array(32).fill(7);
    const actual = await SSHAuth.buildPublicKeyAuthRequest('test-user', unlocked, sessionId);
    const expected = await SSHAuth.buildPublicKeyAuthRequest('test-user', fixture(original), sessionId);
    // ECDSA signatures are randomized; compare the key/request body, not the signature itself.
    const readKey = (bytes: Uint8Array) => {
      let offset = 1;
      const read = () => {
        const length = new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0);
        offset += 4;
        const value = bytes.subarray(offset, offset + length);
        offset += length;
        return value;
      };
      read(); read(); read(); offset++; read();
      return read();
    };
    expect(readKey(actual)).toEqual(readKey(expected));
  });

  it.each(cases)('rejects a wrong passphrase for %s without echoing it', async (encrypted) => {
    await expect(unlockPrivateKey(fixture(encrypted), 'wrong-secret')).rejects.toThrow('password');
  });

  it('rejects adversarial bcrypt rounds before doing unbounded KDF work', async () => {
    const text = fixture('id_ed25519_encrypted');
    const bytes = new Uint8Array(Buffer.from(text.replace(/-----[^\n]+-----/g, '').replace(/\s/g, ''), 'base64'));
    let offset = 15;
    const skip = () => { const n = new DataView(bytes.buffer).getUint32(offset); offset += n + 4; };
    skip(); skip();
    offset += 4; // kdf options string header
    skip(); // salt
    bytes.set(encodeUint32(0xffffffff), offset);
    const pem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.from(bytes).toString('base64')}\n-----END OPENSSH PRIVATE KEY-----`;
    await expect(unlockPrivateKey(pem, passphrase)).rejects.toThrow('budget');
  });

  it('rejects oversized input, deep DER, malformed envelopes and unsupported ciphers', async () => {
    await expect(unlockPrivateKey('x'.repeat(128 * 1024 + 1), passphrase)).rejects.toThrow('budget');
    await expect(unlockPrivateKey('not a key', passphrase)).rejects.toThrow('invalid');
    await expect(unlockPrivateKey(`-----BEGIN ENCRYPTED PRIVATE KEY-----\n${' '.repeat(100_000)}\n-----END ENCRYPTED PRIVATE KEY-----`, passphrase)).rejects.toThrow('invalid');
    await expect(unlockPrivateKey(fixture('id_ed25519'), passphrase)).rejects.toThrow('unsupported');
    let nested = new Uint8Array([4, 0]);
    for (let i = 0; i < 20; i++) nested = new Uint8Array([0x30, nested.length, ...nested]);
    await expect(unlockPrivateKey(`-----BEGIN ENCRYPTED PRIVATE KEY-----\n${Buffer.from(nested).toString('base64')}\n-----END ENCRYPTED PRIVATE KEY-----`, passphrase)).rejects.toThrow('budget');
    await expect(unlockPrivateKey('Proc-Type: 4,ENCRYPTED', passphrase)).rejects.toThrow('unsupported');
    const altered = fixture('id_ed25519_encrypted').replace('-----END', '-----BAD');
    await expect(unlockPrivateKey(altered, passphrase)).rejects.toThrow();
  });
});
