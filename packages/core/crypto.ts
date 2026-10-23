import { assert } from './errors';

const utf8 = new TextEncoder();
export const encode = (data: Uint8Array) => Buffer.from(data).toString('base64url');
export const decode = (data: string) => new Uint8Array(Buffer.from(data, 'base64url'));
export async function digest(value: string) {
  return encode(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(value))));
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
/** One entry of the ROOT_KEY ring. The id is also the version of the Better Auth secret derived from
 * the key, which the library reads with parseInt and compares as a string, so it must be canonical. */
export type RootKey = { id: string; key: Uint8Array };
/** Parses ROOT_KEY: comma-separated `<id>:<32 bytes in base64url>`, the first entry current. The
 * Worker and the deployment use this one parser; anything else in the value is refused. */
export function parseRootKeys(value: string): RootKey[] {
  const ring = value.split(',').map((entry) => {
    assert(/^(0|[1-9][0-9]{0,8}):[A-Za-z0-9_-]{43}$/.test(entry), 'invalid_root_key', 503);
    const [id, key] = entry.split(':');
    const bytes = decode(key);
    // 43 characters always decode to 32 bytes; only the canonical spelling of them is accepted.
    assert(encode(bytes) === key, 'invalid_root_key', 503);
    return { id, key: bytes };
  });
  assert(new Set(ring.map((k) => k.id)).size === ring.length, 'invalid_root_key', 503);
  return ring;
}
const labels = {
  kek: 'clavifer/v1/kek',
  'better-auth': 'clavifer/v1/better-auth',
  fingerprint: 'clavifer/v1/fingerprint',
};
/** HKDF-SHA256 with an empty salt (the root key is already 32 uniformly random bytes), 32 bytes per use. */
export async function deriveKey(root: Uint8Array, use: keyof typeof labels) {
  const ikm = await crypto.subtle.importKey('raw', root as unknown as ArrayBuffer, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0) as unknown as ArrayBuffer,
        info: utf8.encode(labels[use]) as unknown as ArrayBuffer,
      },
      ikm,
      256,
    ),
  );
}
/** The fingerprint of every key in the ring, which the database records when the Owner is created. Not a secret. */
export async function rootKeyFingerprints(ring: RootKey[]) {
  const entries = await Promise.all(
    ring.map(async ({ id, key }) => [
      id,
      Buffer.from((await deriveKey(key, 'fingerprint')).slice(0, 16)).toString('hex'),
    ]),
  );
  return Object.fromEntries(entries) as Record<string, string>;
}
export type Envelope = { format: 1; kekId: string; wrappedDek: string; ciphertext: string };
export type SecretIdentity = { ownerId: string; secretId: string; version: number };
const secretAad = (id: SecretIdentity) => JSON.stringify(['clavifer', 1, id.ownerId, id.secretId, id.version]);
// The archive identity has four elements where a secret version has five, so neither envelope opens as the other.
const archiveAad = (ownerId: string) => JSON.stringify(['clavifer', 1, ownerId, 'archive-identity']);
/** Encrypts with the current root key; kekId records its id. */
async function sealEnvelope(ring: RootKey[], aad: string, plaintext: string): Promise<Envelope> {
  const { id: kekId, key } = ring[0];
  const dek = crypto.getRandomValues(new Uint8Array(32));
  try {
    return {
      format: 1,
      kekId,
      wrappedDek: await seal(await deriveKey(key, 'kek'), dek, `dek:${aad}:${kekId}`),
      ciphertext: await seal(dek, plaintext, aad),
    };
  } finally {
    dek.fill(0);
  }
}
async function openEnvelope(ring: RootKey[], aad: string, envelope: Envelope) {
  const root = ring.find((k) => k.id === envelope.kekId);
  assert(envelope.format === 1 && root, 'encryption_key_missing', 503);
  const dek = await open(await deriveKey(root.key, 'kek'), envelope.wrappedDek, `dek:${aad}:${envelope.kekId}`);
  try {
    return new TextDecoder().decode(await open(dek, envelope.ciphertext, aad));
  } finally {
    dek.fill(0);
  }
}
export const encryptSecret = (ring: RootKey[], id: SecretIdentity, values: Record<string, string>) =>
  sealEnvelope(ring, secretAad(id), JSON.stringify(values));
export const decryptSecret = async (
  ring: RootKey[],
  id: SecretIdentity,
  envelope: Envelope,
): Promise<Record<string, string>> => JSON.parse(await openEnvelope(ring, secretAad(id), envelope));
/** The archive identity (an age identity) of the Owner's cold data, in the envelope of a secret. */
export const encryptArchiveIdentity = (ring: RootKey[], ownerId: string, identity: string) =>
  sealEnvelope(ring, archiveAad(ownerId), identity);
export const decryptArchiveIdentity = (ring: RootKey[], ownerId: string, envelope: Envelope) =>
  openEnvelope(ring, archiveAad(ownerId), envelope);
