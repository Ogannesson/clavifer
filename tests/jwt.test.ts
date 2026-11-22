import {
  constants,
  createHmac,
  createPrivateKey,
  createPublicKey,
  verify as nodeVerify,
  type KeyObject,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { build, type Rollup } from 'vite';
import { JWT_ALGS, jwtKey, sign, signJwt, type Jwt, type JwtAlg } from '../packages/core/jwt';

// Every key here is a throwaway test key made by scripts/fixtures-keys.mjs.
const pem = (name: string) => readFileSync(new URL(`./fixtures/keys/${name}`, import.meta.url), 'utf8');
const hmacKey = 'synthetic-hmac-key-for-tests';
// The key each algorithm signs with in the round trips below; the RSA and P-256 keys come in more
// than one format.
const cases: [JwtAlg, string][] = [
  ...(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'] as const).flatMap((alg): [JwtAlg, string][] => [
    [alg, 'rsa-pkcs1.pem'],
    [alg, 'rsa-pkcs8.pem'],
  ]),
  ['ES256', 'p256-sec1.pem'],
  ['ES256', 'p256-pkcs8.pem'],
  ['ES384', 'p384-sec1.pem'],
  ['ES512', 'p521-sec1.pem'],
  ['EdDSA', 'ed25519-pkcs8.pem'],
  ['Ed25519', 'ed25519-pkcs8.pem'],
  ['HS256', ''],
  ['HS384', ''],
  ['HS512', ''],
];
const config = (alg: JwtAlg): Jwt => ({
  alg,
  keyField: 'key',
  ...(alg.startsWith('HS') && { keyEncoding: 'utf8' as const }),
  header: { typ: 'JWT', kid: { $field: 'kid' } },
  claims: { iss: { $field: 'email' }, aud: 'https://token.example.com' },
  lifetime: 300,
});
const fields = (key: string) => ({ key, kid: 'key-1', email: 'robot@example.com' });
const fieldsFor = (alg: JwtAlg, file: string) => fields(alg.startsWith('HS') ? hmacKey : pem(file));
const jwkOf = (file: string) => JSON.stringify(createPrivateKey(pem(file)).export({ format: 'jwk' }));
// Every asymmetric algorithm with every key, as a PEM and as a JWK: a key signs only the algorithms of
// its own kind (and curve), and every other pairing is refused the same way.
const kinds: Record<string, JwtAlg[]> = {
  'rsa-pkcs1.pem': ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
  'rsa-pkcs8.pem': ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
  'p256-sec1.pem': ['ES256'],
  'p256-pkcs8.pem': ['ES256'],
  'p384-sec1.pem': ['ES384'],
  'p521-sec1.pem': ['ES512'],
  'ed25519-pkcs8.pem': ['EdDSA', 'Ed25519'],
};
const matrix = JWT_ALGS.filter((alg) => !alg.startsWith('HS')).flatMap((alg) =>
  Object.keys(kinds).flatMap((file) => [[alg, file, 'PEM'] as const, [alg, file, 'JWK'] as const]),
);
const matrixValue = (file: string, form: 'PEM' | 'JWK') => (form === 'PEM' ? pem(file) : jwkOf(file));

/** Verifies with node:crypto rather than WebCrypto, so the check does not share the signer's code. */
function verifies(alg: JwtAlg, key: KeyObject | string, token: string) {
  const [header, payload, signature] = token.split('.');
  const data = Buffer.from(`${header}.${payload}`);
  const sig = Buffer.from(signature, 'base64url');
  const hash = `sha${alg.slice(2)}`;
  if (typeof key === 'string') return createHmac(hash, key).update(data).digest().equals(sig);
  if (alg === 'EdDSA' || alg === 'Ed25519') return nodeVerify(null, data, key, sig);
  if (alg.startsWith('PS'))
    return nodeVerify(
      hash,
      data,
      { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
      sig,
    );
  if (alg.startsWith('ES')) return nodeVerify(hash, data, { key, dsaEncoding: 'ieee-p1363' }, sig);
  return nodeVerify(hash, data, key, sig);
}
const verifyKey = (alg: JwtAlg, file: string) => (alg.startsWith('HS') ? hmacKey : createPublicKey(pem(file)));
const parts = (token: string) =>
  token
    .split('.')
    .slice(0, 2)
    .map((p) => JSON.parse(Buffer.from(p, 'base64url').toString()));

describe('signJwt', () => {
  it('covers the whole algorithm table', () => {
    expect(new Set(cases.map(([alg]) => alg))).toEqual(new Set(JWT_ALGS));
  });
  it.each(cases)('signs %s with %s and the public key verifies it', async (alg, file) => {
    const now = 1_800_000_000_500;
    const token = await signJwt(config(alg), fieldsFor(alg, file), now);
    expect(verifies(alg, verifyKey(alg, file), token)).toBe(true);
    expect(parts(token)).toEqual([
      { typ: 'JWT', kid: 'key-1', alg },
      { iss: 'robot@example.com', aud: 'https://token.example.com', iat: 1_800_000_000, exp: 1_800_000_300 },
    ]);
  });
  it('carries any JSON as a claim and resolves only a whole {"$field"} value', async () => {
    const jwt: Jwt = {
      ...config('HS256'),
      claims: {
        video: { roomJoin: true, room: 'synthetic', grants: [1, null] },
        scope: ['a', 'b'],
        sub: { $field: 'email' },
        literal: { $field: 'email', other: 1 },
        nested: [{ $field: 'email' }],
      },
    };
    const [, claims] = parts(await signJwt(jwt, fieldsFor('HS256', ''), 0));
    expect(claims).toEqual({
      video: { roomJoin: true, room: 'synthetic', grants: [1, null] },
      scope: ['a', 'b'],
      sub: 'robot@example.com',
      literal: { $field: 'email', other: 1 },
      nested: [{ $field: 'email' }],
      iat: 0,
      exp: 300,
    });
  });
  it('adds a fresh jti on every call only when asked to', async () => {
    const fields = fieldsFor('HS256', '');
    expect(parts(await signJwt(config('HS256'), fields))[1]).not.toHaveProperty('jti');
    const [a, b] = await Promise.all([1, 2].map(() => signJwt({ ...config('HS256'), jti: true }, fields)));
    expect(parts(a)[1].jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(parts(a)[1].jti).not.toBe(parts(b)[1].jti);
  });
  it('sets alg, iat and exp itself', async () => {
    const jwt = {
      ...config('HS256'),
      header: { alg: 'none' },
      claims: { iat: 1, exp: 2 },
    } as unknown as Jwt;
    const [header, claims] = parts(await signJwt(jwt, fieldsFor('HS256', ''), 10_000));
    expect(header.alg).toBe('HS256');
    expect(claims).toEqual({ iat: 10, exp: 310 });
  });
});

describe('RFC 7515 appendix A', () => {
  const payload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
  it('A.1 HS256 with the key in base64url', async () => {
    const key = await jwtKey(
      'HS256',
      'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
      'k',
      'base64url',
    );
    expect(await sign('HS256', key, `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.${payload}`)).toBe(
      'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    );
  });
  it('A.2 RS256 with a JWK', async () => {
    const jwk = {
      kty: 'RSA',
      n:
        'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs' +
        'D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV' +
        'MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
      e: 'AQAB',
      d:
        'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0' +
        'BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT' +
        'CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
      p:
        '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG' +
        'BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
      q:
        'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA' +
        '-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
      dp:
        'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb' +
        '34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
      dq:
        'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky' +
        'NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
      qi:
        'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU' +
        'W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
    };
    const key = await jwtKey('RS256', JSON.stringify(jwk), 'key');
    expect(await sign('RS256', key, `eyJhbGciOiJSUzI1NiJ9.${payload}`)).toBe(
      'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZ' +
        'cAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-e' +
        'OkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw',
    );
  });
  it('A.3 ES256 with a JWK: the vector and a new signature both verify', async () => {
    const pub = {
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    };
    const key = await jwtKey(
      'ES256',
      JSON.stringify({ ...pub, d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI' }),
      'key',
    );
    const input = `eyJhbGciOiJFUzI1NiJ9.${payload}`;
    const publicKey = createPublicKey({ key: pub, format: 'jwk' });
    const vector = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
    expect(verifies('ES256', publicKey, `${input}.${vector}`)).toBe(true);
    expect(verifies('ES256', publicKey, `${input}.${await sign('ES256', key, input)}`)).toBe(true);
  });
});

describe('jwtKey', () => {
  const input = 'header.payload';
  it('reads PKCS#1 as the same key as its PKCS#8 form', async () => {
    const [pkcs1, pkcs8] = await Promise.all(
      ['rsa-pkcs1.pem', 'rsa-pkcs8.pem'].map(async (f) => sign('RS256', await jwtKey('RS256', pem(f), 'key'), input)),
    );
    expect(pkcs1).toBe(pkcs8);
  });
  it('reads SEC1 after an EC PARAMETERS block as the same key as its PKCS#8 form', async () => {
    expect(pem('p256-sec1.pem')).toContain('-----BEGIN EC PARAMETERS-----');
    const publicKey = createPublicKey(pem('p256-pkcs8.pem'));
    const signature = await sign('ES256', await jwtKey('ES256', pem('p256-sec1.pem'), 'key'), input);
    expect(verifies('ES256', publicKey, `${input}.${signature}`)).toBe(true);
  });
  it.each([
    ['without line breaks', (v: string) => v.replace(/\r?\n/g, '')],
    ['with spaces for line breaks', (v: string) => v.replace(/\r?\n/g, ' ')],
    ['with CRLF line breaks', (v: string) => v.replace(/\r?\n/g, '\r\n')],
    ['inside other text', (v: string) => `Bag Attributes\n${v}\ntrailing text`],
  ])('reads a PEM %s', async (_name, change) => {
    for (const [alg, file] of [
      ['RS256', 'rsa-pkcs1.pem'],
      ['ES256', 'p256-sec1.pem'],
      ['EdDSA', 'ed25519-pkcs8.pem'],
    ] as const) {
      const signature = await sign(alg, await jwtKey(alg, change(pem(file)), 'key'), input);
      expect(verifies(alg, createPublicKey(pem(file)), `${input}.${signature}`)).toBe(true);
    }
  });
  it.each([
    ['PS256', 'rsa-pkcs8.pem'],
    ['ES384', 'p384-sec1.pem'],
    ['Ed25519', 'ed25519-pkcs8.pem'],
  ] as const)('reads %s keys as a JWK', async (alg, file) => {
    const jwk = JSON.stringify(createPrivateKey(pem(file)).export({ format: 'jwk' }));
    const signature = await sign(alg, await jwtKey(alg, jwk, 'key'), input);
    expect(verifies(alg, createPublicKey(pem(file)), `${input}.${signature}`)).toBe(true);
  });
  it('decodes an HS key in each of the four encodings to the same bytes', async () => {
    const bytes = Buffer.from('synthetic key bytes \x00\xff with every value', 'latin1');
    const encoded = {
      utf8: 'synthetic key bytes',
      base64: bytes.toString('base64'),
      base64url: bytes.toString('base64url'),
      hex: bytes.toString('hex').toUpperCase(),
    };
    const signatures = await Promise.all(
      (['base64', 'base64url', 'hex'] as const).map(async (e) =>
        sign('HS256', await jwtKey('HS256', encoded[e], 'key', e), input),
      ),
    );
    expect(new Set(signatures).size).toBe(1);
    expect(signatures[0]).toBe(createHmac('sha256', bytes).update(input).digest('base64url'));
    expect(await sign('HS512', await jwtKey('HS512', encoded.utf8, 'key', 'utf8'), input)).toBe(
      createHmac('sha512', encoded.utf8).update(input).digest('base64url'),
    );
    // Padding is optional in both base64 spellings.
    const unpadded = await jwtKey('HS256', bytes.toString('base64').replace(/=+$/, ''), 'key', 'base64');
    expect(await sign('HS256', unpadded, input)).toBe(signatures[0]);
  });
  it.each([
    ['base64', 'not*base64'],
    ['base64', 'AAAAA'],
    ['base64', 'a-b_'],
    ['base64url', 'a+b/'],
    ['hex', 'abc'],
    ['hex', 'zz'],
  ] as const)('refuses an HS key that is not valid %s: %s', async (encoding, value) => {
    await expect(jwtKey('HS256', value, 'hmac_secret', encoding)).rejects.toThrow(
      `The key in field "hmac_secret" is not valid ${encoding}.`,
    );
  });
  it.each(['utf8', 'base64', 'base64url', 'hex'] as const)('refuses an empty HS key in %s', async (encoding) => {
    await expect(jwtKey('HS256', '', 'hmac_secret', encoding)).rejects.toThrow(
      'The key in field "hmac_secret" is empty.',
    );
  });

  const body = (file: string) => pem(file).split(/\r?\n/)[1];
  it.each([
    ['an encrypted PKCS#8 key', 'RS256', pem('encrypted/rsa-defaults.pem'), 'is encrypted'],
    ['a traditionally encrypted key', 'ES256', pem('encrypted/traditional.pem'), 'is encrypted'],
    [
      'a PEM body that is not base64',
      'RS256',
      '-----BEGIN PRIVATE KEY-----\n*\n-----END PRIVATE KEY-----',
      'is a PEM whose body is not base64',
    ],
    ['an RSA key for ES256', 'ES256', pem('rsa-pkcs1.pem'), 'is not a private key for ES256'],
    ['a P-256 key for ES384', 'ES384', pem('p256-sec1.pem'), 'is not a private key for ES384'],
    ['a P-521 key for ES256', 'ES256', pem('p521-sec1.pem'), 'is not a private key for ES256'],
    ['an EC key for PS256', 'PS256', pem('p256-pkcs8.pem'), 'is not a private key for PS256'],
    ['an Ed25519 key for RS256', 'RS256', pem('ed25519-pkcs8.pem'), 'is not a private key for RS256'],
    ['an RSA key for EdDSA', 'EdDSA', pem('rsa-pkcs8.pem'), 'is not a private key for EdDSA'],
    [
      'an RSA JWK for ES256',
      'ES256',
      JSON.stringify(createPrivateKey(pem('rsa-pkcs8.pem')).export({ format: 'jwk' })),
      'is not a private key for ES256',
    ],
    [
      'a public JWK',
      'ES256',
      JSON.stringify(createPublicKey(pem('p256-pkcs8.pem')).export({ format: 'jwk' })),
      'is not a private key for ES256',
    ],
    ['a broken JWK', 'RS256', '{"kty":', 'starts with "{" but is not JSON'],
    [
      'a public key PEM',
      'RS256',
      createPublicKey(pem('rsa-pkcs8.pem')).export({ type: 'spki', format: 'pem' }) as string,
      'is neither a PEM private key nor a JSON Web Key',
    ],
    [
      'an OpenSSH key',
      'EdDSA',
      `-----BEGIN OPENSSH PRIVATE KEY-----\n${body('ed25519-pkcs8.pem')}\n-----END OPENSSH PRIVATE KEY-----`,
      'is a PEM "OPENSSH PRIVATE KEY"',
    ],
    [
      'a truncated key',
      'RS256',
      `-----BEGIN PRIVATE KEY-----\n${body('rsa-pkcs8.pem')}\n-----END PRIVATE KEY-----`,
      'is not a private key for RS256',
    ],
    [
      'a SEC1 key without its curve',
      'ES256',
      // ECPrivateKey { version 1, privateKey } with the optional parameters left out.
      `-----BEGIN EC PRIVATE KEY-----\n${Buffer.concat([Buffer.from('30250201010420', 'hex'), Buffer.alloc(32, 1)]).toString('base64')}\n-----END EC PRIVATE KEY-----`,
      'is an EC PRIVATE KEY that names no curve',
    ],
  ] as const)('refuses %s and names only the field and the reason', async (_name, alg, value, reason) => {
    const error = await jwtKey(alg, value, 'private_key').catch((e: Error & { code: string }) => e);
    expect(error).toMatchObject({ code: 'invalid_key_credential', status: 400 });
    expect((error as Error).message).toMatch(
      new RegExp(`^The key in field "private_key" ${reason.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`),
    );
    // Nothing read from the value appears in the message.
    for (const chunk of value.replace(/-----[A-Z ]+-----/g, '').match(/[A-Za-z0-9+/]{12}/g) ?? [])
      expect((error as Error).message).not.toContain(chunk);
  });
  it.each([
    ['PS256', 'rsa-pkcs8.pem'],
    ['ES384', 'p384-sec1.pem'],
    ['EdDSA', 'ed25519-pkcs8.pem'],
  ] as const)('refuses the public JWK of a %s key', async (alg, file) => {
    const jwk = JSON.stringify(createPublicKey(pem(file)).export({ format: 'jwk' }));
    await expect(jwtKey(alg, jwk, 'key')).rejects.toMatchObject({ code: 'invalid_key_credential' });
  });
  it.each(matrix)('%s with %s as a %s', async (alg, file, form) => {
    const result = await signJwt(config(alg), fields(matrixValue(file, form))).then(
      (token) => ({ token }),
      (e: Error & { code: string }) => ({ code: e.code, message: e.message }),
    );
    if (kinds[file].includes(alg))
      expect(verifies(alg, createPublicKey(pem(file)), (result as { token: string }).token)).toBe(true);
    else
      expect(result).toEqual({
        code: 'invalid_key_credential',
        message: `The key in field "key" is not a private key for ${alg}.`,
      });
  });
});

// The algorithm table becomes part of the frozen snapshot format, and the Worker signs in workerd, not
// Node: every algorithm and key format is signed there once, by the same module bundled, and verified here.
describe('in workerd', () => {
  let mf: Miniflare;
  const signInWorkerd = async (jwt: Jwt, fields: Record<string, string>) => {
    const response = await mf.dispatchFetch('https://worker.example/', {
      method: 'POST',
      body: JSON.stringify({ jwt, fields }),
    });
    return (await response.json()) as { token?: string; code?: string; message?: string };
  };
  beforeAll(async () => {
    // One output per format, as a list.
    const [bundle] = (await build({
      configFile: false,
      logLevel: 'silent',
      build: {
        write: false,
        minify: false,
        lib: {
          entry: fileURLToPath(new URL('../packages/core/jwt.ts', import.meta.url)),
          formats: ['es'],
          fileName: 'jwt',
        },
      },
    })) as Rollup.RollupOutput[];
    mf = new Miniflare(
      convertV4MiniflareOptions({
        modules: [
          {
            type: 'ESModule',
            path: 'worker.js',
            contents: `import { signJwt } from './jwt.js';
export default {
  async fetch(request) {
    if (request.method === 'GET') return new Response(navigator.userAgent);
    const { jwt, fields } = await request.json();
    try {
      return Response.json({ token: await signJwt(jwt, fields) });
    } catch (e) {
      return Response.json({ code: e.code, message: e.message });
    }
  },
};`,
          },
          { type: 'ESModule', path: 'jwt.js', contents: bundle.output[0].code },
        ],
        compatibilityDate: '2026-09-11',
        compatibilityFlags: ['nodejs_compat'],
        log: new Log(LogLevel.ERROR),
      }),
    );
  });
  afterAll(() => mf?.dispose());
  it('runs in workerd', async () => {
    expect(await (await mf.dispatchFetch('https://worker.example/')).text()).toBe('Cloudflare-Workers');
  });
  it.each(cases)('signs %s with %s', async (alg, file) => {
    const result = await signInWorkerd(config(alg), fieldsFor(alg, file));
    expect(result.code).toBeUndefined();
    expect(verifies(alg, verifyKey(alg, file), result.token!)).toBe(true);
    expect(parts(result.token!)[0]).toEqual({ typ: 'JWT', kid: 'key-1', alg });
  });
  it('signs with a JWK and each HS key encoding', async () => {
    const jwk = JSON.stringify(createPrivateKey(pem('p521-sec1.pem')).export({ format: 'jwk' }));
    const fromJwk = await signInWorkerd(config('ES512'), fields(jwk));
    expect(verifies('ES512', createPublicKey(pem('p521-sec1.pem')), fromJwk.token!)).toBe(true);
    const bytes = Buffer.from(hmacKey);
    for (const [keyEncoding, key] of [
      ['base64', bytes.toString('base64')],
      ['base64url', bytes.toString('base64url')],
      ['hex', bytes.toString('hex')],
    ] as const) {
      const result = await signInWorkerd({ ...config('HS384'), keyEncoding }, fields(key));
      expect(verifies('HS384', hmacKey, result.token!)).toBe(true);
    }
  });
  // workerd imports some mismatched keys that Node refuses (an RSA or EC key as Ed25519), so the whole
  // matrix runs here too.
  it.each(matrix)('%s with %s as a %s', async (alg, file, form) => {
    const result = await signInWorkerd(config(alg), fields(matrixValue(file, form)));
    if (kinds[file].includes(alg)) expect(verifies(alg, createPublicKey(pem(file)), result.token!)).toBe(true);
    else
      expect(result).toEqual({
        code: 'invalid_key_credential',
        message: `The key in field "key" is not a private key for ${alg}.`,
      });
  });
});
