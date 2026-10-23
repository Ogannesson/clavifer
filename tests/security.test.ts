import { afterAll, beforeAll, describe, it, expect } from 'vitest';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { applyMigrations } from '../scripts/migrations.mjs';
import worker from '../apps/worker/src/index';
import { checkPath, targetUrl, upstreamHeaders } from '../packages/core/proxy';
import { parseRootKeys, rootKeyFingerprints } from '../packages/core/crypto';
import { type Bindings, boundedBytes } from '../apps/worker/src/context';
import { grantInput, connectionInput } from '../apps/worker/src/vault';

describe('proxy attack boundaries', () => {
  it.each([
    '/v1/../admin',
    '/v1/%2e%2e/admin',
    '/v1/%252e%252e/admin',
    '//other.example/x',
    '/v1\\admin',
    '/v1/%2fadmin',
    '/v1?x=1',
    '/v1/#x',
    '/v1/%00',
    '/v1/%',
  ])('rejects ambiguous path %s', (path) => expect(() => checkPath(path, ['/v1'])).toThrow());
  it.each([
    'https://127.0.0.1',
    'https://[::1]',
    'https://169.254.169.254',
    'https://internal',
    'https://service.local',
    'https://user:pass@example.com',
    'https://example.com/?key=x',
  ])('rejects unsafe origin %s', (origin) => expect(() => targetUrl(origin, '/')).toThrow());
  it('allows canonical prefix only', () => {
    expect(checkPath('/v1/items', ['/v1'])).toBe(true);
    expect(checkPath('/v11', ['/v1'])).toBe(false);
    expect(targetUrl('https://api.example.com', '/v1/items').href).toBe('https://api.example.com/v1/items');
  });
  it('drops credentials and routing headers supplied by caller', () => {
    const h = upstreamHeaders({
      Authorization: 'Bearer test',
      Cookie: 'x=test',
      Host: 'other.example',
      'X-Forwarded-Host': 'other.example',
      'Content-Length': '100',
      'X-Request-ID': 'internal',
      Accept: 'application/json',
    });
    expect([...h.keys()]).toEqual(['accept']);
  });
  it('enforces read bound while streaming, cancelling upstream', async () => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        c.enqueue(new Uint8Array(800));
      },
      cancel() {
        cancelled = true;
      },
    });
    await expect(boundedBytes(stream, 1024)).rejects.toThrow('body_too_large');
    expect(cancelled).toBe(true);
  });
  it('does not conflate invoke and secret-read grants', () => {
    expect(
      grantInput.safeParse({ resourceType: 'connection', resourceId: 'test', permission: 'secret:read' }).success,
    ).toBe(false);
  });
  it('rejects forbidden injected headers', () => {
    expect(
      connectionInput.safeParse({
        name: 'test',
        origin: 'https://api.example.com',
        paths: ['/'],
        auth: { type: 'header', secretId: 'test', field: 'token', name: 'Host' },
      }).success,
    ).toBe(false);
  });
});

// Tokens signed by a key the server trusts, so only the claim under test decides the answer.
describe('access token claims', () => {
  const origin = 'http://localhost:8787';
  let mf: Miniflare, env: Bindings, key: CryptoKey;
  const part = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const visit = async (claims: object) => {
    const input = `${part({ alg: 'ES256', kid: 'key' })}.${part({
      iss: `${origin}/api/auth`,
      aud: `${origin}/v1`,
      sub: 'owner',
      azp: 'client',
      scope: 'metadata:list',
      exp: Math.floor(Date.now() / 1000) + 600,
      ...claims,
    })}`;
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(input));
    const response = await worker.fetch(
      new Request(origin + '/v1/secrets', {
        headers: { authorization: `Bearer ${input}.${Buffer.from(signature).toString('base64url')}` },
      }),
      env,
      { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext,
    );
    return { status: response.status, error: ((await response.json()) as { error?: string }).error };
  };

  beforeAll(async () => {
    mf = new Miniflare(
      convertV4MiniflareOptions({
        modules: true,
        script: 'export default {fetch:()=>new Response("unused")}',
        compatibilityDate: '2026-09-11',
        compatibilityFlags: ['nodejs_compat'],
        log: new Log(LogLevel.ERROR),
        d1Databases: ['DB'],
      }),
    );
    const db = await mf.getD1Database('DB');
    await applyMigrations(db);
    const rootKey = `1:${Buffer.from('t'.repeat(32)).toString('base64url')}`;
    env = { DB: db, APP_ORIGIN: origin, ROOT_KEY: rootKey } as unknown as Bindings;
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    key = pair.privateKey;
    await db.batch([
      db.prepare("INSERT INTO system_state (key,value,updated_at) VALUES ('owner_user_id','owner',?)").bind(Date.now()),
      db
        .prepare("INSERT INTO system_state (key,value,updated_at) VALUES ('root_key_fingerprints',?,?)")
        .bind(JSON.stringify(await rootKeyFingerprints(parseRootKeys(rootKey))), Date.now()),
      db.prepare(
        `INSERT INTO "oauthClient" (id,clientId,userId,name,redirectUris) VALUES ('client','client','owner','Installation','[]')`,
      ),
      db
        .prepare(`INSERT INTO jwks (id,publicKey,privateKey,createdAt,alg) VALUES ('key',?,'unused',?,'ES256')`)
        .bind(JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey)), Date.now()),
    ]);
  });
  afterAll(() => mf.dispose());

  it('opens /v1 to a token for this audience from this issuer', async () => {
    expect(await visit({})).toEqual({ status: 200, error: undefined });
  });
  it.each([
    ['another resource of this origin', { aud: 'http://localhost:8787/mcp' }],
    ['the same path on another origin', { aud: 'https://other.example/v1' }],
    ['no audience', { aud: undefined }],
    ['this origin without the issuer path', { iss: 'http://localhost:8787' }],
    ['another issuer', { iss: 'https://other.example/api/auth' }],
    ['no issuer', { iss: undefined }],
  ])('refuses a token for %s', async (_name, claims) => {
    expect(await visit(claims)).toEqual({ status: 401, error: 'invalid_token' });
  });
});
