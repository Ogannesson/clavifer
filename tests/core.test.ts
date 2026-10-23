import { describe, expect, it } from 'vitest';
import {
  decryptArchiveIdentity,
  decryptSecret,
  deriveKey,
  encryptArchiveIdentity,
  encryptSecret,
  open,
  parseRootKeys,
  rootKeyFingerprints,
} from '../packages/core/crypto';
import { checkPath, targetUrl } from '../packages/core/proxy';

const encoded = (byte: string) => Buffer.from(byte.repeat(32)).toString('base64url');

describe('root key', () => {
  // IKM = bytes 0..31; the same values come out of workerd (private probe hkdf-workerd-probe.mjs).
  const ikm = new Uint8Array(32).map((_, i) => i);
  it.each([
    ['kek', 'f5d54355567ba1345785f39a7ee29d5f4773d4087881fd99033e9599a8b8ac4e'],
    ['better-auth', '2d5ff906d35f0281ea07d5acd1af35cbd564869cdc3b025995fe9a5a90f7c508'],
    ['fingerprint', '22c02d3b76f1c470c7a5f1819a2373e0d3d042fe1192e1084bca8677f730ff51'],
  ] as const)('derives the fixed %s vector', async (use, hex) => {
    expect(Buffer.from(await deriveKey(ikm, use)).toString('hex')).toBe(hex);
  });
  it('fingerprints each key of the ring with the first 16 bytes', async () => {
    const ring = parseRootKeys(`7:${Buffer.from(ikm).toString('base64url')},0:${encoded('z')}`);
    const fingerprints = await rootKeyFingerprints(ring);
    expect(Object.keys(fingerprints).sort()).toEqual(['0', '7']);
    expect(fingerprints['7']).toBe('22c02d3b76f1c470c7a5f1819a2373e0');
  });
  it('parses a ring, current key first', () => {
    const ring = parseRootKeys(`2:${encoded('n')},1:${encoded('o')},999999999:${encoded('x')}`);
    expect(ring.map((k) => k.id)).toEqual(['2', '1', '999999999']);
    expect(Buffer.from(ring[1].key).toString()).toBe('o'.repeat(32));
  });
  it.each([
    ['an empty value', ''],
    ['a non-canonical id', `01:${encoded('a')}`],
    ['an id past nine digits', `1234567890:${encoded('a')}`],
    ['a negative id', `-1:${encoded('a')}`],
    ['a short key', `1:${Buffer.from('a'.repeat(31)).toString('base64url')}`],
    ['a long key', `1:${Buffer.from('a'.repeat(33)).toString('base64url')}`],
    ['padding', `1:${Buffer.from('a'.repeat(32)).toString('base64')}`],
    ['a non-canonical last character', `1:${encoded('a').slice(0, 42)}F`],
    ['a duplicate id', `1:${encoded('a')},1:${encoded('b')}`],
    ['an empty entry', `1:${encoded('a')},`],
    ['spaces', ` 1:${encoded('a')}`],
  ])('refuses %s', (_name, value) => {
    expect(() => parseRootKeys(value)).toThrow('invalid_root_key');
  });
});

describe('secret envelopes', () => {
  const ring = parseRootKeys(`1:${encoded('a')}`);
  const identity = { ownerId: 'owner', secretId: 'secret', version: 1 };
  it('round trips and binds ciphertext to identity', async () => {
    const envelope = await encryptSecret(ring, identity, { token: 'value' });
    expect(envelope.kekId).toBe('1');
    await expect(decryptSecret(ring, identity, envelope)).resolves.toEqual({ token: 'value' });
    await expect(decryptSecret(ring, { ...identity, ownerId: 'other' }, envelope)).rejects.toThrow();
  });
  it('binds the clavifer additional data and wraps with the derived key of the named root key', async () => {
    const envelope = await encryptSecret(ring, identity, { token: 'value' });
    const aad = JSON.stringify(['clavifer', 1, 'owner', 'secret', 1]);
    const dek = await open(await deriveKey(ring[0].key, 'kek'), envelope.wrappedDek, `dek:${aad}:1`);
    expect(JSON.parse(new TextDecoder().decode(await open(dek, envelope.ciphertext, aad)))).toEqual({ token: 'value' });
  });
  it('decrypts under an older key of the ring and encrypts under the current one', async () => {
    const envelope = await encryptSecret(ring, identity, { token: 'value' });
    const rotated = parseRootKeys(`2:${encoded('b')},1:${encoded('a')}`);
    await expect(decryptSecret(rotated, identity, envelope)).resolves.toEqual({ token: 'value' });
    expect((await encryptSecret(rotated, identity, { token: 'value' })).kekId).toBe('2');
    await expect(decryptSecret(parseRootKeys(`2:${encoded('b')}`), identity, envelope)).rejects.toThrow(
      'encryption_key_missing',
    );
  });
  it('wraps the archive identity under its own four-element additional data', async () => {
    const envelope = await encryptArchiveIdentity(ring, 'owner', 'AGE-SECRET-KEY-PQ-1SYNTHETIC');
    await expect(decryptArchiveIdentity(ring, 'owner', envelope)).resolves.toBe('AGE-SECRET-KEY-PQ-1SYNTHETIC');
    await expect(decryptArchiveIdentity(ring, 'other', envelope)).rejects.toThrow();
    const aad = JSON.stringify(['clavifer', 1, 'owner', 'archive-identity']);
    const dek = await open(await deriveKey(ring[0].key, 'kek'), envelope.wrappedDek, `dek:${aad}:1`);
    expect(new TextDecoder().decode(await open(dek, envelope.ciphertext, aad))).toBe('AGE-SECRET-KEY-PQ-1SYNTHETIC');
    // Neither envelope opens as the other, whatever the secret is called.
    await expect(
      decryptSecret(ring, { ownerId: 'owner', secretId: 'archive-identity', version: 1 }, envelope),
    ).rejects.toThrow();
    const secret = await encryptSecret(ring, identity, { token: 'value' });
    await expect(decryptArchiveIdentity(ring, 'owner', secret)).rejects.toThrow();
  });
});

describe('proxy boundaries', () => {
  it('matches path prefixes by segment', () => {
    expect(checkPath('/v1/items', ['/v1'])).toBe(true);
    expect(checkPath('/v10/items', ['/v1'])).toBe(false);
    expect(() => targetUrl('http://example.com', '/x')).toThrow('origin_must_be_https');
    expect(() => targetUrl('http://localhost:8787/api', '/x', true)).toThrow('origin_must_not_contain_path');
  });
});
