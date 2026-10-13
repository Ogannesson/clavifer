import { assert } from './errors';

const utf8 = new TextEncoder();
export const encode = (data: Uint8Array) => Buffer.from(data).toString('base64url');
export const decode = (data: string) => new Uint8Array(Buffer.from(data, 'base64url'));
export async function digest(value: string) {
  return encode(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(value))));
}
export async function equalHash(value: string, expected: string) {
  const actual = await digest(value);
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}
async function aes(key: Uint8Array) {
  assert(key.length === 32, 'invalid_encryption_key', 503);
  return crypto.subtle.importKey('raw', key as unknown as ArrayBuffer, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function seal(key: Uint8Array, value: string | Uint8Array, context: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = typeof value === 'string' ? utf8.encode(value) : value;
  const out = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as ArrayBuffer,
      additionalData: utf8.encode(context) as unknown as ArrayBuffer,
    },
    await aes(key),
    data as unknown as ArrayBuffer,
  );
  return `${encode(iv)}.${encode(new Uint8Array(out))}`;
}
export async function open(key: Uint8Array, value: string, context: string) {
  const [iv, data, extra] = value.split('.');
  assert(iv && data && !extra, 'invalid_ciphertext', 503);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: decode(iv) as unknown as ArrayBuffer,
        additionalData: utf8.encode(context) as unknown as ArrayBuffer,
      },
      await aes(key),
      decode(data) as unknown as ArrayBuffer,
    ),
  );
}
export type Envelope = { format: 1; kekId: string; wrappedDek: string; ciphertext: string };
export type SecretIdentity = { ownerId: string; secretId: string; version: number };
const aad = (id: SecretIdentity) => JSON.stringify(['agent-credentials', 1, id.ownerId, id.secretId, id.version]);
export async function encryptSecret(
  keys: Record<string, string>,
  active: string,
  id: SecretIdentity,
  values: Record<string, string>,
): Promise<Envelope> {
  assert(keys[active], 'encryption_key_missing', 503);
  const dek = crypto.getRandomValues(new Uint8Array(32));
  try {
    return {
      format: 1,
      kekId: active,
      wrappedDek: await seal(decode(keys[active]), dek, `dek:${aad(id)}:${active}`),
      ciphertext: await seal(dek, JSON.stringify(values), aad(id)),
    };
  } finally {
    dek.fill(0);
  }
}
export async function decryptSecret(
  keys: Record<string, string>,
  id: SecretIdentity,
  envelope: Envelope,
): Promise<Record<string, string>> {
  assert(envelope.format === 1 && keys[envelope.kekId], 'encryption_key_missing', 503);
  const dek = await open(decode(keys[envelope.kekId]), envelope.wrappedDek, `dek:${aad(id)}:${envelope.kekId}`);
  try {
    return JSON.parse(new TextDecoder().decode(await open(dek, envelope.ciphertext, aad(id))));
  } finally {
    dek.fill(0);
  }
}
