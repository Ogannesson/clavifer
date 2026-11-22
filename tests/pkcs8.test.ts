import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { jwtKey } from '../packages/core/jwt';
import { base64Bytes, children, element, encodeElement, privateKeyPem, whole } from '../packages/core/pem';
import { decryptKey, encryptedKey, UnsupportedKeyEncryption, type EncryptedKey } from '../packages/core/pkcs8';

// Throwaway test keys made by scripts/fixtures-keys.mjs: the encrypted ones are copies of p256-pkcs8.pem
// (rsa-defaults.pem of rsa-pkcs8.pem) under this passphrase unless named otherwise.
const passphrase = 'fixture-passphrase';
const wrong = 'The passphrase is wrong or the encrypted key is damaged.';
const pem = (name: string) => readFileSync(new URL(`./fixtures/keys/${name}`, import.meta.url), 'utf8');
const der = (value: string) => base64Bytes(privateKeyPem(value)!.body);
const read = (name: string) => encryptedKey(pem(`encrypted/${name}`)) as EncryptedKey;
const seq = (...parts: Uint8Array[]) => encodeElement(0x30, ...parts);
const oid = (hex: string) => encodeElement(0x06, Buffer.from(hex, 'hex'));
const armor = (bytes: Uint8Array) =>
  `-----BEGIN ENCRYPTED PRIVATE KEY-----\n${Buffer.from(bytes).toString('base64')}\n-----END ENCRYPTED PRIVATE KEY-----`;
/** An EncryptedPrivateKeyInfo built by hand: PBES2, PBKDF2 with hmacWithSHA256 and 2048 iterations,
 * aes-256-cbc with the given IV. */
const handMade = (iv: Uint8Array) =>
  armor(
    seq(
      seq(
        oid('2a864886f70d01050d'),
        seq(
          seq(
            oid('2a864886f70d01050c'),
            seq(
              encodeElement(0x04, new Uint8Array(8)),
              Uint8Array.of(0x02, 0x02, 0x08, 0x00),
              seq(oid('2a864886f70d0209'), Uint8Array.of(0x05, 0x00)),
            ),
          ),
          seq(oid('60864801650304012a'), encodeElement(0x04, iv)),
        ),
      ),
      encodeElement(0x04, new Uint8Array(32)),
    ),
  );

describe('decryptKey', () => {
  it.each([
    ['sha1', 'SHA-1'],
    ['sha256', 'SHA-256'],
    ['sha384', 'SHA-384'],
    ['sha512', 'SHA-512'],
  ])('decrypts PBKDF2 with hmacWith%s and both AES key sizes', async (prf, hash) => {
    for (const bits of [128, 256]) {
      const key = read(`pbkdf2-${prf}-aes-${bits}-cbc.pem`);
      expect(key).toMatchObject({ hash, bits, iterations: 2048 });
      const plain = await decryptKey(key, passphrase);
      expect(plain).toMatch(/^-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+/=]{1,64}\n)+-----END PRIVATE KEY-----\n$/);
      expect(der(plain)).toEqual(der(pem('p256-pkcs8.pem')));
    }
  });
  it('reads hmacWithSHA1 from a PRF field that is left out', () => {
    // OpenSSL omits the PRF when it is the default; the OID 1.2.840.113549.2.7 appears nowhere.
    const bytes = Buffer.from(der(pem('encrypted/pbkdf2-sha1-aes-256-cbc.pem'))).toString('hex');
    expect(bytes).not.toContain('2a864886f70d0207');
    expect(bytes).toContain('2a864886f70d01050c'); // PBKDF2
    expect(read('pbkdf2-sha1-aes-256-cbc.pem').hash).toBe('SHA-1');
  });
  it("decrypts OpenSSL's defaults on an RSA key into a key the signer reads", async () => {
    const key = read('rsa-defaults.pem');
    expect(key).toMatchObject({ hash: 'SHA-256', bits: 256, iterations: 2048 });
    const plain = await decryptKey(key, passphrase);
    expect(der(plain)).toEqual(der(pem('rsa-pkcs8.pem')));
    await expect(jwtKey('RS256', plain, 'private_key')).resolves.toBeDefined();
  });
  it('decrypts a million iterations', async () => {
    const key = read('iter-1000000.pem');
    expect(key.iterations).toBe(1_000_000);
    expect(der(await decryptKey(key, passphrase))).toEqual(der(pem('p256-pkcs8.pem')));
  });
  it('takes the passphrase as its UTF-8 bytes, without normalizing it', async () => {
    const key = read('unicode-passphrase.pem');
    const composed = 'päss密码🔑';
    expect(der(await decryptKey(key, composed))).toEqual(der(pem('p256-pkcs8.pem')));
    expect(composed.normalize('NFD')).not.toBe(composed);
    await expect(decryptKey(key, composed.normalize('NFD'))).rejects.toThrow(wrong);
  });
  it('decrypts a version 1 OneAsymmetricKey, which carries the public key too', async () => {
    // RFC 5958 version 1 with the [1] publicKey, built from the Ed25519 test key and encrypted here.
    const [, algorithm, privateKey] = children(whole(der(pem('ed25519-pkcs8.pem'))).content);
    const pub = createPublicKey(pem('ed25519-pkcs8.pem')).export({ type: 'spki', format: 'der' }).subarray(12);
    const v1 = seq(
      Uint8Array.of(0x02, 0x01, 0x01),
      encodeElement(0x30, algorithm.content),
      encodeElement(0x04, privateKey.content),
      encodeElement(0x81, Uint8Array.of(0), pub),
    );
    const salt = new Uint8Array(8);
    const iv = new Uint8Array(16);
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode('pw'), 'PBKDF2', false, ['deriveKey']);
    const aes = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 2048, hash: 'SHA-256' },
      base,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt'],
    );
    const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aes, v1));
    const plain = await decryptKey({ salt, iterations: 2048, hash: 'SHA-256', bits: 256, iv, data }, 'pw');
    expect(der(plain)).toEqual(v1);
    await expect(jwtKey('EdDSA', plain, 'private_key')).resolves.toBeDefined();
  });
  it('says the passphrase is wrong or the file damaged, also when a wrong one passes the padding check', async () => {
    const key = read('pbkdf2-sha256-aes-128-cbc.pem');
    // About one wrong passphrase in 256 decrypts to valid padding, which only the PrivateKeyInfo check
    // catches; for the fixture as generated, wrong-62, -302, -502 and -555 do.
    const results = await Promise.all(
      Array.from({ length: 600 }, (_, i) => decryptKey(key, `wrong-${i}`).catch((e: Error & { code: string }) => e)),
    );
    for (const error of results) expect(error).toMatchObject({ code: 'key_decryption_failed', message: wrong });
    const damaged = { ...key, data: key.data.map((b, i) => (i === 20 ? b ^ 1 : b)) };
    await expect(decryptKey(damaged, passphrase)).rejects.toMatchObject({ code: 'key_decryption_failed' });
  });
});

describe('encryptedKey', () => {
  it.each([
    ['des-ede3-cbc.pem', 'des-ede3-cbc'],
    ['aes-192-cbc.pem', 'aes-192-cbc'],
    ['scrypt.pem', 'scrypt'],
    ['hmac-sha224.pem', 'hmacWithSHA224'],
    ['pbes1.pem', 'PBES1 pbeWithMD5AndDES-CBC'],
    ['pkcs12-pbe.pem', 'PKCS#12 pbeWithSHA1And3-KeyTripleDES-CBC'],
  ])('names the algorithm of %s and the command that converts it', (file, algorithm) => {
    const error = (() => {
      try {
        encryptedKey(pem(`encrypted/${file}`));
      } catch (e) {
        return e;
      }
    })() as UnsupportedKeyEncryption;
    expect(error).toBeInstanceOf(UnsupportedKeyEncryption);
    expect(error).toMatchObject({
      code: 'unsupported_key_encryption',
      algorithm,
      command: 'openssl pkcs8 -topk8 -in in.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 -out out.pem',
    });
    expect(error.message).toContain(algorithm);
    expect(error.message).toContain(error.command);
  });
  it('names traditional PEM encryption and the command that removes it', () => {
    expect(() => encryptedKey(pem('encrypted/traditional.pem'))).toThrow(
      expect.objectContaining({
        code: 'unsupported_key_encryption',
        algorithm: 'traditional PEM encryption (DEK-Info AES-256-CBC)',
        command: 'openssl pkey -in in.pem -out out.pem',
      }),
    );
  });
  it.each(['p256-pkcs8.pem', 'p256-sec1.pem', 'rsa-pkcs1.pem', 'ed25519-pkcs8.pem'])(
    'returns null for the unencrypted %s',
    (file) => {
      expect(encryptedKey(pem(file))).toBeNull();
    },
  );
  it('returns null for a value that is no PEM private key', () => {
    expect(encryptedKey('synthetic-token')).toBeNull();
    expect(encryptedKey('{"kty":"EC"}')).toBeNull();
  });
  it('reads a PEM whose line breaks were lost', async () => {
    const key = encryptedKey(pem('encrypted/pbkdf2-sha512-aes-256-cbc.pem').replace(/\r?\n/g, ''))!;
    expect(der(await decryptKey(key, passphrase))).toEqual(der(pem('p256-pkcs8.pem')));
  });
  it.each([
    ['a body that is not base64', '*'],
    ['a body that is not DER', 'AAAA'],
    ['a truncated body', pem('encrypted/pbkdf2-sha256-aes-256-cbc.pem').split(/\r?\n/)[1]],
  ])('calls %s damaged', (_name, body) => {
    expect(() =>
      encryptedKey(`-----BEGIN ENCRYPTED PRIVATE KEY-----\n${body}\n-----END ENCRYPTED PRIVATE KEY-----`),
    ).toThrow(expect.objectContaining({ code: 'key_decryption_failed' }));
  });
  it('calls an IV that is not one AES block damaged before asking for the passphrase', () => {
    expect(encryptedKey(handMade(new Uint8Array(16)))).toMatchObject({ iterations: 2048, bits: 256 });
    expect(() => encryptedKey(handMade(new Uint8Array(8)))).toThrow(
      expect.objectContaining({ code: 'key_decryption_failed' }),
    );
  });
  it('only ever returns a key or throws one of its two faults on mutated input', () => {
    const original = der(pem('encrypted/pbkdf2-sha256-aes-256-cbc.pem'));
    let seed = 7;
    const rand = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31);
    for (let i = 0; i < 5000; i++) {
      const copy = original.slice(0, rand() % 3 === 0 ? rand() % original.length : original.length);
      for (let j = rand() % 4; j >= 0; j--) if (copy.length) copy[rand() % copy.length] = rand() & 0xff;
      try {
        expect(encryptedKey(armor(copy))).not.toBeNull();
      } catch (e) {
        expect((e as { code?: string }).code).toMatch(/^(key_decryption_failed|unsupported_key_encryption)$/);
      }
    }
  });
});

describe('DER', () => {
  it.each([0, 1, 127, 128, 255, 256, 65535, 65536, 16_777_216])(
    'encodes a length of %i with the fewest length bytes and reads it back',
    (n) => {
      const out = encodeElement(0x04, new Uint8Array(n));
      expect(out.length - n).toBe(n < 0x80 ? 2 : 2 + Math.ceil(Math.log2(n + 1) / 8));
      const e = whole(out);
      expect([e.tag, e.content.length]).toEqual([0x04, n]);
    },
  );
  it('refuses lengths it cannot read without reading past the end', () => {
    for (const bytes of [
      [0x30],
      [0x30, 0x81],
      [0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
      [0x30, 0x85, 0, 0, 0, 0, 1],
      [0x30, 0x80, 0, 0],
      [0x30, 0x05, 0x02],
    ])
      expect(() => element(Uint8Array.from(bytes))).toThrow(RangeError);
    expect(() => children(Uint8Array.of(0x02, 0x01, 0x00, 0x02))).toThrow(RangeError);
  });
});
