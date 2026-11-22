import { encode } from './crypto';
import { Fault } from './errors';
import { base64Bytes, children, encodeElement, hex, privateKeyPem, whole, type Element } from './pem';

// What signing a JWS takes from WebCrypto for each algorithm. One dictionary serves both importKey and
// sign, which ignore the members they do not read. EdDSA is RFC 8037's name for what RFC 9864 calls
// Ed25519; both sign with an Ed25519 key.
const algorithms = {
  RS256: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  RS384: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  RS512: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  PS256: { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 },
  PS384: { name: 'RSA-PSS', hash: 'SHA-384', saltLength: 48 },
  PS512: { name: 'RSA-PSS', hash: 'SHA-512', saltLength: 64 },
  ES256: { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' },
  ES384: { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' },
  ES512: { name: 'ECDSA', namedCurve: 'P-521', hash: 'SHA-512' },
  EdDSA: { name: 'Ed25519' },
  Ed25519: { name: 'Ed25519' },
  HS256: { name: 'HMAC', hash: 'SHA-256' },
  HS384: { name: 'HMAC', hash: 'SHA-384' },
  HS512: { name: 'HMAC', hash: 'SHA-512' },
};
// The algorithm object identifier that a PrivateKeyInfo for each kind of key carries, as the hex of its
// content: rsaEncryption, id-ecPublicKey and id-Ed25519. An EC key on another curve than alg's is
// refused by importKey itself.
const keyAlgorithms: Record<string, string> = {
  'RSASSA-PKCS1-v1_5': '2a864886f70d010101',
  'RSA-PSS': '2a864886f70d010101',
  ECDSA: '2a8648ce3d0201',
  Ed25519: '2b6570',
};
export type JwtAlg = keyof typeof algorithms;
export const JWT_ALGS = Object.keys(algorithms) as [JwtAlg, ...JwtAlg[]];
export const KEY_ENCODINGS = ['utf8', 'base64', 'base64url', 'hex'] as const;
export type KeyEncoding = (typeof KEY_ENCODINGS)[number];

/** A value taken from the field of that name in the connection's secret. */
export type Ref = { $field: string };
export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
/** How to sign a JWT, as a connection stores it. The schema that validates it lives with the
 * connection's auth: keyEncoding is required for HS* and absent otherwise, header has no alg, claims
 * have no iat, exp or jti, and lifetime is 10 to 3600 seconds. */
export type Jwt = {
  alg: JwtAlg;
  keyField: string;
  keyEncoding?: KeyEncoding;
  header?: Record<string, string | Ref>;
  claims: Record<string, Json | Ref>;
  lifetime: number;
  jti?: boolean;
};

export const isRef = (value: unknown): value is Ref =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).length === 1 &&
  typeof (value as Ref).$field === 'string';
// The message names the field and the reason, never anything read from the value.
const invalid = (field: string, reason: string) =>
  new Fault('invalid_key_credential', 400, `The key in field "${field}" ${reason}.`);

const utf8 = new TextEncoder();
const decoders: Record<KeyEncoding, (value: string) => Uint8Array | undefined> = {
  utf8: (value) => utf8.encode(value),
  base64: (value) => (/^[A-Za-z0-9+/]*={0,2}$/.test(value) ? base64Bytes(value) : undefined),
  base64url: (value) =>
    /^[A-Za-z0-9_-]*={0,2}$/.test(value) ? base64Bytes(value.replace(/-/g, '+').replace(/_/g, '/')) : undefined,
  hex: (value) =>
    /^(?:[0-9a-fA-F]{2})*$/.test(value) ? Uint8Array.from(value.match(/../g) ?? [], (b) => parseInt(b, 16)) : undefined,
};
function secretBytes(encoding: KeyEncoding, value: string, field: string) {
  let bytes: Uint8Array | undefined;
  try {
    bytes = decoders[encoding](value);
  } catch {}
  if (!bytes) throw invalid(field, `is not valid ${encoding}`);
  if (bytes.length === 0) throw invalid(field, 'is empty');
  return bytes;
}

// rsaEncryption with its NULL parameters (RFC 3279), and id-ecPublicKey, whose parameters are the curve.
const RSA_ENCRYPTION = Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00);
const EC_PUBLIC_KEY = Uint8Array.of(0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01);
/** PrivateKeyInfo (RFC 5958) around a key in its algorithm's own format; algorithm is the content of
 * the AlgorithmIdentifier. */
const privateKeyInfo = (key: Uint8Array, ...algorithm: Uint8Array[]) =>
  encodeElement(0x30, Uint8Array.of(0x02, 0x01, 0x00), encodeElement(0x30, ...algorithm), encodeElement(0x04, key));
/** The DER PKCS#8 of a PEM private key. PKCS#1 (RSA PRIVATE KEY) and SEC1 (EC PRIVATE KEY) are wrapped
 * here rather than handed to importKey, whose pkcs8 format only takes PrivateKeyInfo (workerd happens
 * to accept the other two, Node does not, and neither is documented). */
function pkcs8(value: string, field: string) {
  const pem = privateKeyPem(value);
  if (!pem) throw invalid(field, 'is neither a PEM private key nor a JSON Web Key');
  // PKCS#8 encryption, or RFC 1421 encryption of a traditional key.
  if (pem.label === 'ENCRYPTED PRIVATE KEY' || /Proc-Type:\s*4,ENCRYPTED/.test(pem.body))
    throw invalid(field, 'is encrypted: load it in the console, which decrypts it with its passphrase');
  let der: Uint8Array;
  try {
    der = base64Bytes(pem.body);
  } catch {
    throw invalid(field, 'is a PEM whose body is not base64');
  }
  if (pem.label === 'PRIVATE KEY') return der;
  if (pem.label === 'RSA PRIVATE KEY') return privateKeyInfo(der, RSA_ENCRYPTION);
  if (pem.label === 'EC PRIVATE KEY') {
    // ECPrivateKey (RFC 5915): the curve is the [0] parameters, which PKCS#8 moves to the algorithm.
    let curve: Element | undefined;
    try {
      curve = children(whole(der).content).find((e) => e.tag === 0xa0);
    } catch {}
    if (!curve) throw invalid(field, 'is an EC PRIVATE KEY that names no curve');
    return privateKeyInfo(der, EC_PUBLIC_KEY, curve.content);
  }
  throw invalid(field, `is a PEM "${pem.label}", which is not a format this service reads`);
}

/** The signing key for alg from a secret field's value: for HS* the key bytes in keyEncoding, otherwise
 * a JSON Web Key (a value starting with "{") or a PEM private key in PKCS#8, PKCS#1 or SEC1. */
export async function jwtKey(alg: JwtAlg, value: string, field: string, keyEncoding?: KeyEncoding) {
  const algorithm = algorithms[alg];
  if (algorithm.name === 'HMAC') {
    const bytes = secretBytes(keyEncoding as KeyEncoding, value, field);
    return crypto.subtle.importKey('raw', bytes as unknown as ArrayBuffer, algorithm, false, ['sign']);
  }
  let jwk: JsonWebKey | undefined;
  if (value.startsWith('{')) {
    try {
      jwk = JSON.parse(value);
    } catch {
      throw invalid(field, 'starts with "{" but is not JSON');
    }
  }
  const der = jwk ? undefined : pkcs8(value, field);
  try {
    // workerd imports an RSA or EC PrivateKeyInfo as Ed25519 and fails only when it signs, so the key's
    // own algorithm must be the one alg signs with before the import is trusted.
    if (der) {
      const [, privateKeyAlgorithm] = children(whole(der).content);
      const [oid] = children(privateKeyAlgorithm.content);
      if (hex(oid.content) !== keyAlgorithms[algorithm.name]) throw new RangeError(alg);
    }
    return await (jwk
      ? crypto.subtle.importKey('jwk', jwk, algorithm, false, ['sign'])
      : crypto.subtle.importKey('pkcs8', der as unknown as ArrayBuffer, algorithm, false, ['sign']));
  } catch {
    throw invalid(field, `is not a private key for ${alg}`);
  }
}
/** The base64url JWS signature of input. */
export async function sign(alg: JwtAlg, key: CryptoKey, input: string) {
  return encode(new Uint8Array(await crypto.subtle.sign(algorithms[alg], key, utf8.encode(input))));
}
/** A JWS compact JWT signed now. fields are the values of the connection's secret, which hold every
 * field the configuration refers to. alg, iat, exp and jti are set here and override the configuration. */
export async function signJwt(jwt: Jwt, fields: Record<string, string>, now = Date.now()) {
  const key = await jwtKey(jwt.alg, fields[jwt.keyField], jwt.keyField, jwt.keyEncoding);
  const resolve = <T>(entries: Record<string, T | Ref>) =>
    Object.fromEntries(Object.entries(entries).map(([name, v]) => [name, isRef(v) ? fields[v.$field] : v]));
  const iat = Math.floor(now / 1000);
  const header = { ...resolve(jwt.header ?? {}), alg: jwt.alg };
  const claims = {
    ...resolve(jwt.claims),
    iat,
    exp: iat + jwt.lifetime,
    ...(jwt.jti && { jti: crypto.randomUUID() }),
  };
  const input = `${encode(utf8.encode(JSON.stringify(header)))}.${encode(utf8.encode(JSON.stringify(claims)))}`;
  return `${input}.${await sign(jwt.alg, key, input)}`;
}
