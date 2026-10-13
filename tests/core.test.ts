import { describe, expect, it } from 'vitest';
import { decryptSecret, encryptSecret } from '../packages/core/crypto';
import { checkPath, targetUrl } from '../packages/core/proxy';

describe('secret envelopes', () => {
  const key = Buffer.from('a'.repeat(32)).toString('base64url');
  it('round trips and binds ciphertext to identity', async () => {
    const envelope = await encryptSecret(
      { v1: key },
      'v1',
      { ownerId: 'owner', secretId: 'secret', version: 1 },
      { token: 'value' },
    );
    await expect(
      decryptSecret({ v1: key }, { ownerId: 'owner', secretId: 'secret', version: 1 }, envelope),
    ).resolves.toEqual({ token: 'value' });
    await expect(
      decryptSecret({ v1: key }, { ownerId: 'other', secretId: 'secret', version: 1 }, envelope),
    ).rejects.toThrow();
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
