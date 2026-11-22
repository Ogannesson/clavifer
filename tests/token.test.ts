import { createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { applyMigrations } from '../scripts/migrations.mjs';
import { issueSql, newToken } from '../scripts/bootstrap-token.mjs';
import worker from '../apps/worker/src/index';
import { z } from 'zod';
import {
  accessRequest,
  accessStatus,
  authInput,
  boundSecret,
  invoke,
  invokeInput,
  requestInput,
} from '../apps/worker/src/vault';
import { takeLock, writeRefreshToken } from '../apps/worker/src/token';
import { type Bindings, type Principal, issuesHint, withContext } from '../apps/worker/src/context';

// Real D1 and the Owner's real routes; the token endpoint and the upstream are a stubbed fetch, told
// apart by host. Every field value is random and spelled so no part of it reads as an error code, so
// a test can look for any of them in what an Agent or the audit table sees.
const origin = 'http://localhost:8787';
const tokenUrl = 'https://auth.example/oauth/token';
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const rsaKey = await readFile(new URL('./fixtures/keys/rsa-pkcs8.pem', import.meta.url), 'utf8');
let mf: Miniflare,
  env: Bindings,
  cookie = '',
  owner = '',
  agent: Principal;

type Sent = { url: string; headers: Headers; body: string };
const sent: { token: Sent[]; upstream: Sent[] } = { token: [], upstream: [] };
let issuedCount = 0;
// The token endpoint: a fresh access token (and with rotate a fresh refresh token) for every request.
const granted = (extra: object = {}) => {
  const n = ++issuedCount;
  return Response.json({ access_token: `AT-${n}`, token_type: 'Bearer', expires_in: 3600, ...extra });
};
let tokenEndpoint: (request: Sent) => Response | Promise<Response> = () => granted();
let upstreamStatus = 200;
// How long the upstream takes, minding the abort signal the call carries.
let upstreamDelay = 0;
const stub = vi.fn(async (input: string | URL, init?: RequestInit) => {
  const request = { url: String(input), headers: new Headers(init?.headers), body: String(init?.body ?? '') };
  if (new URL(request.url).host === 'auth.example') {
    sent.token.push(request);
    return tokenEndpoint(request);
  }
  sent.upstream.push(request);
  await new Promise((resolve) => setTimeout(resolve, upstreamDelay));
  init?.signal?.throwIfAborted();
  return new Response('ok', { status: upstreamStatus });
});

async function call(path: string, method = 'GET', body?: unknown) {
  const response = await worker.fetch(
    new Request(origin + path, {
      method,
      headers: {
        'cf-connecting-ip': '127.0.0.1',
        origin,
        cookie,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    }),
    env,
    context,
  );
  const text = await response.text();
  return { status: response.status, body: text ? (JSON.parse(text) as Record<string, any>) : {} };
}

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
  env = {
    DB: db,
    APP_ORIGIN: origin,
    ALLOW_LOCAL_HTTP: 'true',
    ROOT_KEY: `1:${Buffer.from('t'.repeat(32)).toString('base64url')}`,
  } as unknown as Bindings;
  const { token, binds } = newToken();
  await db
    .prepare(issueSql)
    .bind(...binds)
    .run();
  const setup = await worker.fetch(
    new Request(origin + '/api/setup/owner', {
      method: 'POST',
      headers: {
        origin,
        'cf-connecting-ip': '127.0.0.1',
        'content-type': 'application/json',
        'x-bootstrap-token': token,
      },
      body: JSON.stringify({
        name: 'Owner',
        email: 'owner@example.com',
        password: 'synthetic-password-for-tokens',
        backupRecipient: await identityToRecipient(await generateIdentity()),
      }),
    }),
    env,
    context,
  );
  expect(setup.status).toBe(201);
  cookie = setup.headers
    .getSetCookie()
    .map((value) => value.split(';')[0])
    .join('; ');
  owner = (await db.prepare("SELECT value FROM system_state WHERE key='owner_user_id'").first<{ value: string }>())!
    .value;
  agent = { userId: owner, clientId: 'client', scopes: ['connection:invoke', 'access:request'] };
  await db
    .prepare('INSERT INTO "oauthClient" (id,clientId,userId,name,redirectUris) VALUES (?,?,?,?,?)')
    .bind('client', 'client', owner, 'Installation', '[]')
    .run();
  vi.stubGlobal('fetch', stub);
});
afterAll(async () => {
  vi.unstubAllGlobals();
  await mf.dispose();
});
beforeEach(() => {
  sent.token = [];
  sent.upstream = [];
  tokenEndpoint = () => granted();
  upstreamStatus = 200;
  upstreamDelay = 0;
});

let serial = 0;
const value = () => `V-${crypto.randomUUID().toUpperCase()}`;
const secretValues: string[] = [];
async function secret(values: Record<string, string>) {
  secretValues.push(...Object.values(values));
  const result = await call('/admin/secrets', 'POST', { name: `Credential ${++serial}`, values });
  expect(result.status).toBe(201);
  return result.body.id as string;
}
const policy = { paths: ['/v1'], methods: ['GET', 'POST'], free: ['GET /v1/*'], approval: ['POST /v1/pay'] };
const connect = (auth: object, id?: string) =>
  call(id ? `/admin/connections/${id}` : '/admin/connections', id ? 'PUT' : 'POST', {
    name: `Connection ${++serial}`,
    origin: 'https://api.example',
    ...policy,
    auth,
  });
async function connection(auth: object) {
  const result = await connect(auth);
  expect(result).toMatchObject({ status: 200 });
  return result.body.id as string;
}
const send = (connection: string, path = '/v1/items', extra: object = {}) =>
  invoke(env, agent, invokeInput.parse({ connection, path, ...extra }));
const failure = (connection: string, path = '/v1/items', extra: object = {}) =>
  send(connection, path, extra).then(
    () => {
      throw new Error('expected a refusal');
    },
    (e: { code: string; status: number; message: string }) => e,
  );
const lastAuthorization = () => sent.upstream[sent.upstream.length - 1].headers.get('authorization');
const rows = async <T>(sql: string, ...args: unknown[]) =>
  (
    await env.DB.prepare(sql)
      .bind(...args)
      .all<T>()
  ).results;
const cacheRows = (sid: string) =>
  rows<{ recipe: string; version: number; envelope_json: string; expires_at: number; created_at: number }>(
    'SELECT * FROM token_cache WHERE secret_id=? ORDER BY created_at',
    sid,
  );
const version = async (sid: string) =>
  (await env.DB.prepare('SELECT current_version FROM secrets WHERE id=?')
    .bind(sid)
    .first<{ current_version: number }>())!.current_version;
const exchangeResults = async (sid: string) =>
  (
    await rows<{ client_id: string; result: string }>(
      "SELECT client_id,result FROM audit_events WHERE action='token:exchange' AND resource_id=? ORDER BY created_at,rowid",
      sid,
    )
  ).map((r) => `${r.client_id}:${r.result}`);

const clientSecret = () =>
  secret({ client_id: value(), client_secret: value(), account: value() }).then((sid) => ({
    sid,
    auth: {
      type: 'oauth-client',
      secretId: sid,
      client: { method: 'basic', id: { $field: 'client_id' }, secretField: 'client_secret' },
      tokenUrl,
      scope: 'read',
    },
  }));
const refreshSecret = () =>
  secret({ client_secret: value(), refresh_token: value() }).then((sid) => ({
    sid,
    auth: (scope: string) => ({
      type: 'oauth-refresh',
      secretId: sid,
      refreshField: 'refresh_token',
      client: { method: 'post', id: 'app', secretField: 'client_secret' },
      tokenUrl,
      scope,
    }),
  }));
// A rotating endpoint: every refresh token works once and comes back replaced.
const rotating = () => {
  const used = new Set<string>();
  return (request: Sent) => {
    const old = new URLSearchParams(request.body).get('refresh_token')!;
    if (used.has(old)) return Response.json({ error: 'invalid_grant' }, { status: 400 });
    used.add(old);
    return granted({ refresh_token: `RT-${crypto.randomUUID()}` });
  };
};

describe('the auth schema', () => {
  const jwt = { alg: 'RS256', keyField: 'key', claims: { aud: 'x' }, lifetime: 60 };
  const parse = (auth: object) => authInput.safeParse({ type: 'jwt', secretId: 's', ...auth });
  it('refuses what signing sets itself and keeps keyEncoding to HMAC', () => {
    expect(parse({ jwt }).success).toBe(true);
    expect(parse({ jwt: { ...jwt, header: { alg: 'none' } } }).success).toBe(false);
    for (const claim of ['iat', 'exp', 'jti'])
      expect(parse({ jwt: { ...jwt, claims: { [claim]: 1 } } }).success).toBe(false);
    expect(parse({ jwt: { ...jwt, lifetime: 9 } }).success).toBe(false);
    expect(parse({ jwt: { ...jwt, lifetime: 3601 } }).success).toBe(false);
    expect(parse({ jwt: { ...jwt, keyEncoding: 'hex' } }).success).toBe(false);
    expect(parse({ jwt: { ...jwt, alg: 'HS256' } }).success).toBe(false);
    expect(parse({ jwt: { ...jwt, alg: 'HS256', keyEncoding: 'hex' } }).success).toBe(true);
    expect(parse({ jwt: { ...jwt, extra: 1 } }).success).toBe(false);
  });

  it('takes any JSON as a claim and reads {"$field"} only as a field', () => {
    expect(parse({ jwt: { ...jwt, claims: { video: { room: 'a', grants: [1, true, null] } } } }).success).toBe(true);
    expect(parse({ jwt: { ...jwt, claims: { iss: { $field: 'email' } } } }).success).toBe(true);
    expect(parse({ jwt: { ...jwt, claims: { iss: { $field: 'email', more: 1 } } } }).success).toBe(false);
    expect(parse({ jwt: { ...jwt, claims: { iss: { $field: 'not a field' } } } }).success).toBe(false);
  });

  it('takes a claim at most 32 levels deep, so its recipe can always be read', async () => {
    const nested = (depth: number) => JSON.parse('['.repeat(depth) + ']'.repeat(depth));
    expect(parse({ jwt: { ...jwt, claims: { deep: nested(32) } } }).success).toBe(true);
    expect(parse({ jwt: { ...jwt, claims: { deep: nested(33) } } }).success).toBe(false);
    // 6000 levels fit a draft many times over and would overflow the stack of recipe().
    const draft = requestInput.safeParse({
      requested: {
        setup: {
          secret: { name: 'x', fields: ['key'] },
          connections: [
            {
              name: 'x',
              origin: 'https://api.example',
              paths: ['/'],
              auth: { type: 'oauth-jwt', jwt: { ...jwt, claims: { deep: nested(6000) } }, tokenUrl },
              tests: [{ method: 'GET', path: '/', expect: 'grant_required' }],
            },
          ],
        },
      },
    });
    expect(issuesHint(draft.error!)).toContain('a claim nests at most 32 levels deep');
  });

  it('leaves only the values of JWT claims open in the schema MCP publishes', () => {
    const schema = z.toJSONSchema(requestInput, { io: 'input', unrepresentable: 'any' });
    const open: string[] = [];
    const walk = (node: unknown, path: string) => {
      if (Array.isArray(node)) return node.forEach((n, i) => walk(n, `${path}[${i}]`));
      if (!node || typeof node !== 'object') return;
      if (Object.keys(node).length === 0) open.push(path);
      for (const [k, v] of Object.entries(node)) walk(v, `${path}.${k}`);
    };
    walk(schema, '$');
    expect(open.length).toBeGreaterThan(0);
    for (const p of open) expect(p).toMatch(/claims\.additionalProperties/);
  });

  it('keeps the parameters the service writes out of params', () => {
    const client = { method: 'post', id: 'a', secretField: 'b' };
    const auth = (extra: object) =>
      authInput.safeParse({ type: 'oauth-client', secretId: 's', client, tokenUrl, ...extra });
    expect(auth({ params: { audience: 'x', account_id: 'y' } }).success).toBe(true);
    for (const name of ['grant_type', 'client_secret', 'scope', 'assertion'])
      expect(auth({ params: { [name]: 'x' } }).success).toBe(false);
    expect(auth({ client: { method: 'none' } }).success).toBe(false);
    const authorize = (params: object) =>
      authInput.safeParse({
        type: 'oauth-refresh',
        secretId: 's',
        refreshField: 'r',
        client,
        tokenUrl,
        authorize: { url: 'https://auth.example/authorize', params },
      });
    expect(authorize({ access_type: 'offline' }).success).toBe(true);
    for (const name of ['state', 'redirect_uri', 'code_challenge', 'response_type'])
      expect(authorize({ [name]: 'x' }).success).toBe(false);
  });
});

describe('saving a connection', () => {
  it('checks the token endpoint like an origin and names it', async () => {
    const { auth } = await clientSecret();
    for (const [url, error] of [
      ['https://auth.example/token?x=1', 'endpoint_must_not_contain_query'],
      ['http://auth.example/token', 'origin_must_be_https'],
      ['https://localhost.internal/token', 'public_origin_required'],
    ])
      expect(await connect({ ...auth, tokenUrl: url })).toMatchObject({
        status: 400,
        body: { error, hint: 'auth.tokenUrl' },
      });
    expect(sent.token).toHaveLength(0);
  });

  it('refuses a configuration whose test fails, telling the Owner what the endpoint said', async () => {
    const { sid, auth } = await clientSecret();
    const connections = (await rows('SELECT id FROM connections')).length;
    tokenEndpoint = () =>
      Response.json({ error: 'invalid_client', error_description: 'Client authentication failed' }, { status: 401 });
    const refused = await connect(auth);
    expect(refused).toMatchObject({
      status: 502,
      body: {
        error: 'token_exchange_failed',
        token_endpoint: {
          host: 'auth.example',
          status: 401,
          error: 'invalid_client',
          error_description: 'Client authentication failed',
        },
      },
    });
    expect(refused.body.hint).toContain('auth.example');
    tokenEndpoint = () => Response.json({ access_token: 'AT-without-expiry' });
    expect(await connect(auth)).toMatchObject({
      status: 400,
      body: { error: 'ttl_required', token_endpoint: { host: 'auth.example' } },
    });
    expect((await rows('SELECT id FROM connections')).length).toBe(connections);
    expect(await cacheRows(sid)).toEqual([]);
    expect(await exchangeResults(sid)).toEqual(['owner:invalid_client', 'owner:no_expiry']);
    // With a ttl the same answer is saved and cached for that long.
    const before = Date.now();
    await connection({ ...auth, ttl: 120 });
    const [row] = await cacheRows(sid);
    expect(row.version).toBe(1);
    expect(row.expires_at).toBeGreaterThanOrEqual(before + 120000);
    expect(row.expires_at).toBeLessThanOrEqual(Date.now() + 120000);
    expect(row.envelope_json).not.toContain('AT-without-expiry');
  });

  it('signs a JWT once and refuses a key that does not fit', async () => {
    const sid = await secret({ key: value() });
    const auth = { type: 'jwt', secretId: sid, jwt: { alg: 'RS256', keyField: 'key', claims: {}, lifetime: 60 } };
    expect(await connect(auth)).toMatchObject({ status: 400, body: { error: 'invalid_key_credential' } });
    const named = { ...auth, jwt: { ...auth.jwt, claims: { iss: { $field: 'missing' } } } };
    expect(await connect(named)).toMatchObject({ status: 404, body: { error: 'secret_field_not_found' } });
  });

  it('tries a refresh token on the normal path, so a rotated one is stored before the connection', async () => {
    tokenEndpoint = rotating();
    const { sid, auth } = await refreshSecret();
    const { values } = await boundSecret(env, owner, sid);
    const saved = await connect(auth('graph'));
    expect(saved.status).toBe(200);
    expect(await version(sid)).toBe(2);
    const rotated = await boundSecret(env, owner, sid);
    expect(rotated.values).toEqual({ ...values, refresh_token: expect.not.stringMatching(values.refresh_token) });
    // A save that fails after its test (the name is taken) keeps the token the test rotated.
    const again = await call('/admin/connections', 'POST', {
      name: (await env.DB.prepare('SELECT name FROM connections WHERE id=?').bind(saved.body.id).first<{
        name: string;
      }>())!.name,
      origin: 'https://api.example',
      ...policy,
      auth: auth('graph'),
    });
    expect(again.status).toBe(409);
    expect(await version(sid)).toBe(3);
    expect(
      await rows("SELECT client_id FROM audit_events WHERE action='secret:rotate' AND resource_id=?", sid),
    ).toEqual([{ client_id: 'system' }, { client_id: 'system' }]);
  });
});

describe('exchanging a token', () => {
  it('caches a token per recipe, shared by connections configured alike, and encrypted', async () => {
    const { sid, auth } = await clientSecret();
    const a = await connection(auth);
    const b = await connection({ ...auth, header: 'X-Token' });
    expect(sent.token).toHaveLength(2);
    const token = `AT-${issuedCount}`;
    sent.token = [];
    await send(a);
    await send(b);
    await send(a);
    expect(sent.token).toHaveLength(0);
    expect(sent.upstream.map((r) => r.headers.get('authorization') ?? r.headers.get('x-token'))).toEqual([
      `Bearer ${token}`,
      `Bearer ${token}`,
      `Bearer ${token}`,
    ]);
    const rowsNow = await cacheRows(sid);
    expect(rowsNow).toHaveLength(1);
    expect(rowsNow[0].envelope_json).not.toContain(token);
    // Another scope is another recipe.
    const c = await connection({ ...auth, scope: 'write' });
    await send(c);
    expect(await cacheRows(sid)).toHaveLength(2);
  });

  it('uses a cached token only while more than a minute is left', async () => {
    const { sid, auth } = await clientSecret();
    const cid = await connection(auth);
    sent.token = [];
    await env.DB.prepare('UPDATE token_cache SET expires_at=? WHERE secret_id=?')
      .bind(Date.now() + 61000, sid)
      .run();
    await send(cid);
    expect(sent.token).toHaveLength(0);
    await env.DB.prepare('UPDATE token_cache SET expires_at=? WHERE secret_id=?')
      .bind(Date.now() + 59000, sid)
      .run();
    await send(cid);
    expect(sent.token).toHaveLength(1);
    expect(lastAuthorization()).toBe(`Bearer AT-${issuedCount}`);
  });

  it('reads expires_in as a number or a decimal string, else the ttl, else refuses', async () => {
    const { sid, auth } = await clientSecret();
    const cid = await connection({ ...auth, ttl: 300 });
    const expiry = async (answer: object) => {
      await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
      tokenEndpoint = () => Response.json({ access_token: 'AT-x', ...answer });
      const before = Date.now();
      await send(cid);
      return (await cacheRows(sid))[0].expires_at - before;
    };
    for (const [answer, lasts] of [
      [{ expires_in: '7200' }, 7200000],
      [{ expires_in: 900 }, 900000],
      [{}, 300000],
    ] as const) {
      const took = await expiry(answer);
      expect(took).toBeGreaterThanOrEqual(lasts);
      expect(took).toBeLessThan(lasts + 10000);
    }
    // Without a ttl an answer without expires_in is refused at run time and nothing is cached.
    tokenEndpoint = () => granted();
    const plain = await connection(auth);
    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    tokenEndpoint = () => Response.json({ access_token: 'AT-y' });
    expect(await failure(plain)).toMatchObject({
      code: 'token_exchange_failed',
      status: 502,
      message: expect.stringContaining('expires_in'),
    });
    expect(await cacheRows(sid)).toEqual([]);
    expect((await exchangeResults(sid)).at(-1)).toBe('client:no_expiry');
  });

  it('sends a form or JSON body with the grant, extra parameters and client authentication', async () => {
    const sid = await secret({ client_id: 'id:with space', client_secret: 'sécret&=', account: value() });
    const cid = await connection({
      type: 'oauth-client',
      secretId: sid,
      client: { method: 'basic', id: { $field: 'client_id' }, secretField: 'client_secret' },
      grantType: 'account_credentials',
      params: { account_id: 'acct-1' },
      tokenUrl,
      header: 'X-Shopify-Access-Token',
      scheme: '',
    });
    const [form] = sent.token;
    expect(form.headers.get('content-type')).toBe('application/x-www-form-urlencoded');
    expect(form.headers.get('accept')).toBe('application/json');
    // RFC 6749 §2.3.1: both halves form-encoded before Basic.
    expect(Buffer.from(form.headers.get('authorization')!.slice(6), 'base64').toString()).toBe(
      'id%3Awith+space:s%C3%A9cret%26%3D',
    );
    expect(Object.fromEntries(new URLSearchParams(form.body))).toEqual({
      grant_type: 'account_credentials',
      account_id: 'acct-1',
    });
    await env.DB.prepare('DELETE FROM token_cache').run();
    await send(cid);
    const upstream = sent.upstream[0].headers;
    expect(upstream.get('x-shopify-access-token')).toBe(`AT-${issuedCount}`);
    expect(upstream.get('authorization')).toBeNull();

    sent.token = [];
    await connection({
      type: 'oauth-client',
      secretId: sid,
      client: { method: 'post', id: 'fixed-id', secretField: 'client_secret' },
      bodyFormat: 'json',
      scope: 'a b',
      tokenUrl,
    });
    const [json] = sent.token;
    expect(json.headers.get('content-type')).toBe('application/json');
    expect(json.headers.get('authorization')).toBeNull();
    expect(JSON.parse(json.body)).toEqual({
      grant_type: 'client_credentials',
      scope: 'a b',
      client_id: 'fixed-id',
      client_secret: 'sécret&=',
    });
  });

  it('signs a JWT bearer assertion and a client assertion', async () => {
    const sid = await secret({ key: rsaKey, email: 'svc@example.com' });
    const jwt = { alg: 'RS256', keyField: 'key', claims: { iss: { $field: 'email' }, aud: tokenUrl }, lifetime: 3600 };
    await connection({ type: 'oauth-jwt', secretId: sid, jwt, tokenUrl });
    const body = new URLSearchParams(sent.token[0].body);
    expect(body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
    const claims = JSON.parse(Buffer.from(body.get('assertion')!.split('.')[1], 'base64url').toString());
    expect(claims).toMatchObject({ iss: 'svc@example.com', aud: tokenUrl, exp: claims.iat + 3600 });
    expect(claims.jti).toBeUndefined();
    await connection({ type: 'oauth-client', secretId: sid, client: { method: 'jwt', id: 'app', jwt }, tokenUrl });
    const client = new URLSearchParams(sent.token[1].body);
    expect(client.get('client_assertion_type')).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    expect(client.get('client_id')).toBe('app');
    // A client assertion is used once, so it always has a jti.
    expect(JSON.parse(Buffer.from(client.get('client_assertion')!.split('.')[1], 'base64url').toString()).jti).toEqual(
      expect.any(String),
    );
  });

  it('signs a jwt credential anew for every request and caches nothing', async () => {
    const key = value();
    const sid = await secret({ key, kid: value() });
    const cid = await connection({
      type: 'jwt',
      secretId: sid,
      jwt: {
        alg: 'HS256',
        keyField: 'key',
        keyEncoding: 'utf8',
        header: { kid: { $field: 'kid' } },
        claims: { aud: '/admin/' },
        lifetime: 300,
        jti: true,
      },
      scheme: 'Ghost',
    });
    expect(sent.token).toHaveLength(0);
    await send(cid);
    await send(cid);
    const tokens = sent.upstream.map((r) => r.headers.get('authorization')!.replace(/^Ghost /, ''));
    expect(new Set(tokens).size).toBe(2);
    for (const token of tokens) {
      const [header, claims, signature] = token.split('.');
      expect(createHmac('sha256', key).update(`${header}.${claims}`).digest('base64url')).toBe(signature);
    }
    expect(await cacheRows(sid)).toEqual([]);
  });

  it('exchanges once for concurrent requests and lets another take over from a holder that failed', async () => {
    const { sid, auth } = await clientSecret();
    const cid = await connection(auth);
    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    sent.token = [];
    let open!: () => void;
    const gate = new Promise<void>((resolve) => (open = resolve));
    tokenEndpoint = async () => {
      await gate;
      return granted();
    };
    const both = Promise.all([send(cid), send(cid)]);
    await vi.waitFor(() => expect(sent.token).toHaveLength(1));
    await new Promise((resolve) => setTimeout(resolve, 600));
    open();
    await both;
    expect(sent.token).toHaveLength(1);
    expect(sent.upstream.map((r) => r.headers.get('authorization'))).toEqual([
      `Bearer AT-${issuedCount}`,
      `Bearer AT-${issuedCount}`,
    ]);

    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    sent.token = [];
    let fail!: () => void;
    const failing = new Promise<void>((resolve) => (fail = resolve));
    tokenEndpoint = async () => {
      if (sent.token.length === 1) {
        await failing;
        return new Response('busy', { status: 503 });
      }
      return granted();
    };
    const first = failure(cid);
    await vi.waitFor(() => expect(sent.token).toHaveLength(1));
    const second = send(cid);
    await new Promise((resolve) => setTimeout(resolve, 300));
    fail();
    expect(await first).toMatchObject({ code: 'token_unavailable', status: 503 });
    expect((await second).status).toBe(200);
    expect(sent.token).toHaveLength(2);
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
  });

  // An approved write to the connection's approval rule, ready to run once.
  const approved = async (cid: string) => {
    const pay = { method: 'POST', path: '/v1/pay', body: '{}' };
    const { id: rid } = await accessRequest(
      env,
      agent,
      { requested: { invocation: { connection: cid, ...pay } } },
      origin,
    );
    await env.DB.prepare("UPDATE access_requests SET status='approved',expires_at=? WHERE id=?")
      .bind(Date.now() + 600000, rid)
      .run();
    return { rid, pay };
  };

  it('gives up waiting for a lock at its own time limit, keeping the approval', async () => {
    const { sid, auth } = await clientSecret();
    const cid = await connection(auth);
    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    const { rid, pay } = await approved(cid);
    sent.token = [];
    // A lock someone else holds that outlasts the request.
    await env.DB.prepare('INSERT INTO token_locks (secret_id,holder,until) VALUES (?,?,?)')
      .bind(sid, 'other', Date.now() + 1e12)
      .run();
    const spy = vi.spyOn(Date, 'now');
    const start = Date.now();
    let calls = 0;
    // Each read of the clock moves it on a second, so the 20 second limit passes quickly.
    spy.mockImplementation(() => start + 1000 * calls++);
    try {
      expect(await failure(cid, pay.path, pay)).toMatchObject({ code: 'token_unavailable' });
    } finally {
      spy.mockRestore();
      await env.DB.prepare('DELETE FROM token_locks').run();
    }
    expect(sent.token).toHaveLength(0);
    expect((await accessStatus(env, agent, rid)).status).toBe('approved');
  });

  it('gives the upstream call its full time however long the token took', async () => {
    const { sid, auth } = await clientSecret();
    const cid = await connection(auth);
    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    const { rid, pay } = await approved(cid);
    const realNow = Date.now.bind(Date);
    const spy = vi.spyOn(Date, 'now');
    // The token endpoint answers 19.99 seconds in (a slow endpoint, or a long wait for the lock).
    tokenEndpoint = () => {
      spy.mockImplementation(() => realNow() + 19990);
      return granted();
    };
    upstreamDelay = 50;
    try {
      expect((await send(cid, pay.path, pay)).status).toBe(200);
    } finally {
      spy.mockRestore();
    }
    expect((await accessStatus(env, agent, rid)).status).toBe('executed');
  });

  it('keeps the exchange running for a client that disconnects', async () => {
    const { sid, auth } = await clientSecret();
    const cid = await connection(auth);
    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    const kept: Promise<unknown>[] = [];
    const ctx = { waitUntil: (p: Promise<unknown>) => kept.push(p) } as unknown as ExecutionContext;
    await withContext(ctx, () => send(cid));
    expect(kept).toHaveLength(1);
    // A cache hit exchanges nothing and keeps nothing.
    await withContext(ctx, () => send(cid));
    expect(kept).toHaveLength(1);
  });

  it('hands the exchange to the waitUntil of the context the fetch entry was given', async () => {
    // The Owner's save of a refresh connection exchanges on the path every request takes, MCP and the
    // REST proxy included, all of which come in through the same entry.
    const { auth } = await refreshSecret();
    const kept: Promise<unknown>[] = [];
    const noop = context.waitUntil;
    context.waitUntil = (p: Promise<unknown>) => void kept.push(p);
    try {
      await connection(auth('entry'));
    } finally {
      context.waitUntil = noop;
    }
    expect(sent.token).toHaveLength(1);
    expect(kept).toHaveLength(1);
  });

  it('drops a cached token an upstream refuses once it is a minute old, without retrying', async () => {
    const { sid, auth } = await clientSecret();
    const cid = await connection(auth);
    sent.token = [];
    upstreamStatus = 401;
    expect((await send(cid)).status).toBe(401);
    expect(await cacheRows(sid)).toHaveLength(1);
    await env.DB.prepare('UPDATE token_cache SET created_at=created_at-61000 WHERE secret_id=?').bind(sid).run();
    expect((await send(cid)).status).toBe(401);
    expect(await cacheRows(sid)).toEqual([]);
    expect(sent.token).toHaveLength(0);
    expect(sent.upstream).toHaveLength(2);
    upstreamStatus = 200;
    await send(cid);
    expect(sent.token).toHaveLength(1);
  });

  it('maps every answer of the endpoint to an error that carries none of the values', async () => {
    const { sid, auth } = await clientSecret();
    const cid = await connection(auth);
    const { values } = await boundSecret(env, owner, sid);
    const echo = Object.values(values).join(' ');
    const cases: [() => Response | Promise<Response>, string, string][] = [
      () => Response.json({ error: 'invalid_client', error_description: echo }, { status: 400 }),
      () => Response.json({ error: values.client_secret, error_description: echo }, { status: 401 }),
      () => new Response(echo, { status: 503 }),
      () => new Response(echo, { status: 429 }),
      () => new Response(null, { status: 302, headers: { location: `https://elsewhere.example/?${echo}` } }),
      () => Response.json({ token_type: 'Bearer', note: echo }),
      () => Response.json({ access_token: `has space ${echo}`, expires_in: 60 }),
      () => new Response(`not json ${echo}`),
      () => Response.json({ access_token: 'x'.repeat(70000) }),
      () => Promise.reject(new TypeError(echo)),
      // Only the codes of RFC 6749 §5.2 pass, however much another looks like one.
      () => Response.json({ error: values.client_id.toLowerCase() }, { status: 400 }),
    ].map((endpoint, i) => [
      endpoint,
      [
        'token_exchange_failed',
        'token_exchange_failed',
        'token_unavailable',
        'token_unavailable',
        'token_exchange_failed',
        'token_exchange_failed',
        'token_exchange_failed',
        'token_exchange_failed',
        'token_exchange_failed',
        'token_unavailable',
        'token_exchange_failed',
      ][i],
      [
        'invalid_client',
        'unrecognized',
        'unavailable',
        'unavailable',
        'redirect',
        'no_access_token',
        'no_access_token',
        'no_access_token',
        'response_too_large',
        'unavailable',
        'unrecognized',
      ][i],
    ]);
    const before = (await exchangeResults(sid)).length;
    for (const [endpoint, code] of cases) {
      await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
      tokenEndpoint = endpoint;
      const e = await failure(cid);
      expect(e.code).toBe(code);
      expect(e.message).toContain('auth.example');
      for (const v of [...secretValues, echo, values.client_id.toLowerCase()]) expect(e.message).not.toContain(v);
    }
    expect((await exchangeResults(sid)).slice(before)).toEqual(cases.map(([, , result]) => `client:${result}`));
    const audit = JSON.stringify(await rows('SELECT * FROM audit_events'));
    for (const v of [...secretValues, values.client_id.toLowerCase()]) expect(audit).not.toContain(v);
    expect(sent.upstream).toHaveLength(0);
  });

  it('spends a one-time approval only once the token is there, and exchanges none without one', async () => {
    const { sid, auth } = await clientSecret();
    const cid = await connection(auth);
    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    sent.token = [];
    const pay = { method: 'POST', path: '/v1/pay', body: '{}' };
    expect(await failure(cid, pay.path, pay)).toMatchObject({ code: 'approval_required' });
    expect(sent.token).toHaveLength(0);
    const { id: rid } = await accessRequest(
      env,
      agent,
      { requested: { invocation: { connection: cid, ...pay } } },
      origin,
    );
    await env.DB.prepare("UPDATE access_requests SET status='approved',expires_at=? WHERE id=?")
      .bind(Date.now() + 600000, rid)
      .run();
    tokenEndpoint = () => new Response('down', { status: 503 });
    expect(await failure(cid, pay.path, pay)).toMatchObject({ code: 'token_unavailable' });
    expect((await accessStatus(env, agent, rid)).status).toBe('approved');
    tokenEndpoint = () => granted();
    expect((await send(cid, pay.path, pay)).status).toBe(200);
    expect((await accessStatus(env, agent, rid)).status).toBe('executed');
  });
});

describe('rotating a refresh token', () => {
  it('keeps one token per recipe when two recipes share a rotating refresh token', async () => {
    tokenEndpoint = rotating();
    const { sid, auth } = await refreshSecret();
    const graph = await connection(auth('graph'));
    const arm = await connection(auth('arm'));
    expect(await version(sid)).toBe(3);
    // The second save's rotation carried the first recipe's token over to the new version.
    expect((await cacheRows(sid)).map((r) => r.version)).toEqual([3, 3]);
    sent.token = [];
    for (let i = 0; i < 3; i++) {
      await send(graph);
      await send(arm);
    }
    expect(sent.token).toHaveLength(0);
    expect(await version(sid)).toBe(3);

    // An edit by the Owner ends every cached token; each recipe exchanges again.
    expect(
      await call(`/admin/secrets/${sid}`, 'PUT', {
        name: `Credential edited ${sid}`,
        values: { client_secret: value() },
        expectedVersion: 3,
      }),
    ).toMatchObject({ status: 200 });
    await send(graph);
    await send(arm);
    await send(graph);
    expect(sent.token).toHaveLength(2);
    expect(await version(sid)).toBe(6);
  });

  it('keeps the refresh token when the response has none, and writes a new one as the next version', async () => {
    const { sid, auth } = await refreshSecret();
    const { values } = await boundSecret(env, owner, sid);
    await connection(auth('read'));
    expect(await version(sid)).toBe(1);
    expect(new URLSearchParams(sent.token[0].body).get('refresh_token')).toBe(values.refresh_token);
    tokenEndpoint = () => granted({ refresh_token: values.refresh_token });
    await connection(auth('write'));
    expect(await version(sid)).toBe(1);
  });

  it('puts a rotated token on top of an edit the Owner saved meanwhile, and gives up on a replaced one', async () => {
    const { sid, auth } = await refreshSecret();
    const cid = await connection(auth('read'));
    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    sent.token = [];
    const newSecret = value();
    // The Owner saves another field while the exchange is under way.
    tokenEndpoint = async () => {
      if (sent.token.length === 1)
        expect(
          await call(`/admin/secrets/${sid}`, 'PUT', {
            name: `Credential moved ${sid}`,
            values: { client_secret: newSecret },
            expectedVersion: 1,
          }),
        ).toMatchObject({ status: 200 });
      return granted({ refresh_token: 'RT-after-edit' });
    };
    await send(cid);
    expect(await version(sid)).toBe(3);
    expect((await boundSecret(env, owner, sid)).values).toEqual({
      client_secret: newSecret,
      refresh_token: 'RT-after-edit',
    });
    // The token came from the credential before the edit, so it is not cached for the version after it.
    expect(await cacheRows(sid)).toEqual([]);

    // The Owner replaces the refresh token itself meanwhile: the rotated one is dropped and the exchange
    // starts over with the Owner's.
    sent.token = [];
    tokenEndpoint = async (request) => {
      if (sent.token.length === 1) {
        expect(
          await call(`/admin/secrets/${sid}`, 'PUT', {
            name: `Credential moved ${sid}`,
            values: { refresh_token: 'RT-from-owner' },
            expectedVersion: 3,
          }),
        ).toMatchObject({ status: 200 });
        return granted({ refresh_token: 'RT-lost' });
      }
      expect(new URLSearchParams(request.body).get('refresh_token')).toBe('RT-from-owner');
      return granted({ refresh_token: 'RT-final' });
    };
    await send(cid);
    expect(sent.token).toHaveLength(2);
    expect(await version(sid)).toBe(5);
    expect((await boundSecret(env, owner, sid)).values.refresh_token).toBe('RT-final');
    // The Owner's form now sees the system's version.
    expect(
      await call(`/admin/secrets/${sid}`, 'PUT', {
        name: `Credential moved ${sid}`,
        values: { client_secret: value() },
        expectedVersion: 4,
      }),
    ).toMatchObject({ status: 409, body: { error: 'version_conflict' } });
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
  });

  it('writes an authorization over any version, ends every cached token and may add the field', async () => {
    tokenEndpoint = rotating();
    const { sid, auth } = await refreshSecret();
    await connection(auth('graph'));
    await connection(auth('arm'));
    expect((await cacheRows(sid)).map((r) => r.version)).toEqual([3, 3]);
    const stale = await boundSecret(env, owner, sid);
    // A version later than the one the authorization started from.
    await call(`/admin/secrets/${sid}`, 'PUT', {
      name: `Credential authorized ${sid}`,
      values: { client_secret: 'edited' },
      expectedVersion: 3,
    });
    expect(await takeLock(env, sid, 'holder')).toBe(true);
    expect(
      await writeRefreshToken(env, {
        owner,
        secretId: sid,
        field: 'second_refresh',
        token: 'RT-authorized',
        mode: 'authorization',
        base: { version: stale.version, values: stale.values },
        holder: 'holder',
        exchange: { actor: 'owner', result: 'ok' },
        cache: { recipe: 'r', token: 'AT-authorized', expiresAt: Date.now() + 3600000, createdAt: Date.now() },
      }),
    ).toBe(true);
    expect(await version(sid)).toBe(5);
    expect((await boundSecret(env, owner, sid)).values).toMatchObject({
      client_secret: 'edited',
      second_refresh: 'RT-authorized',
    });
    // No token cached before it carries over, and the one from a stale base is not cached either.
    expect((await cacheRows(sid)).map((r) => r.version)).toEqual([3, 3]);
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
    const rotations = await rows<{ client_id: string }>(
      "SELECT client_id FROM audit_events WHERE action='secret:rotate' AND resource_id=? ORDER BY created_at,rowid",
      sid,
    );
    expect(rotations.map((r) => r.client_id)).toEqual(['system', 'system', 'owner', 'owner']);
  });

  it('writes nothing for a rotation whose refresh token the Owner replaced, and still ends the exchange', async () => {
    const { sid } = await refreshSecret();
    const base = await boundSecret(env, owner, sid);
    await call(`/admin/secrets/${sid}`, 'PUT', {
      name: `Credential replaced ${sid}`,
      values: { refresh_token: 'RT-owner' },
      expectedVersion: 1,
    });
    expect(await takeLock(env, sid, 'holder')).toBe(true);
    expect(
      await writeRefreshToken(env, {
        owner,
        secretId: sid,
        field: 'refresh_token',
        token: 'RT-rotated',
        mode: 'rotation',
        used: base.values.refresh_token,
        base,
        holder: 'holder',
        exchange: { actor: 'client', result: 'ok' },
      }),
    ).toBe(false);
    expect(await version(sid)).toBe(2);
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
    expect(await exchangeResults(sid)).toEqual(['client:ok']);
  });

  it('answers the Owner’s edit that a rotation overtook with version_conflict', async () => {
    const { sid } = await refreshSecret();
    const base = await boundSecret(env, owner, sid);
    // The rotation commits between the Owner's read of the version and the batch that writes the edit.
    let armed = false;
    const db = new Proxy(env.DB, {
      get(target, prop) {
        if (prop === 'prepare')
          return (sql: string) => {
            if (sql.startsWith('INSERT INTO secret_versions')) armed = true;
            return target.prepare(sql);
          };
        if (prop === 'batch')
          return async (statements: D1PreparedStatement[]) => {
            if (armed) {
              armed = false;
              expect(await takeLock(saved, sid, 'holder')).toBe(true);
              expect(
                await writeRefreshToken(saved, {
                  owner,
                  secretId: sid,
                  field: 'refresh_token',
                  token: 'RT-rotated',
                  mode: 'rotation',
                  used: base.values.refresh_token,
                  base,
                  holder: 'holder',
                  exchange: { actor: 'client', result: 'ok' },
                }),
              ).toBe(true);
            }
            return target.batch(statements);
          };
        const member = Reflect.get(target, prop);
        return typeof member === 'function' ? member.bind(target) : member;
      },
    });
    const saved = env;
    env = { ...env, DB: db } as Bindings;
    try {
      expect(
        await call(`/admin/secrets/${sid}`, 'PUT', {
          name: `Credential raced ${sid}`,
          values: { client_secret: value() },
          expectedVersion: 1,
        }),
      ).toMatchObject({ status: 409, body: { error: 'version_conflict' } });
    } finally {
      env = saved;
    }
    expect(await version(sid)).toBe(2);
    expect((await boundSecret(env, owner, sid)).values).toEqual({ ...base.values, refresh_token: 'RT-rotated' });
  });
});

describe('migration 0002', () => {
  it('fails as a whole on a rule with a literal brace, which the new syntax would read as a wildcard', async () => {
    const fresh = new Miniflare(
      convertV4MiniflareOptions({
        modules: true,
        script: 'export default {fetch:()=>new Response("unused")}',
        compatibilityDate: '2026-09-11',
        log: new Log(LogLevel.ERROR),
        d1Databases: ['DB'],
      }),
    );
    try {
      const db = await fresh.getD1Database('DB');
      await applyMigrations(db, 'migrations', ['0001_initial.sql']);
      const insert = (id: string, policy: object) =>
        db
          .prepare(
            "INSERT INTO connections (id,owner_id,name,origin,auth_json,policy_json,created_at,updated_at) VALUES (?,'o',?,'https://a.example','{\"type\":\"none\"}',?,0,0)",
          )
          .bind(id, id, JSON.stringify(policy))
          .run();
      // A draft still waiting for the Owner, as stored; a decided or expired one is never approved.
      const request = (id: string, requested: object, status = 'pending', expiresAt = Date.now() + 86400000) =>
        db
          .prepare(
            "INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at) VALUES (?,'o','c',?,'',?,0,?)",
          )
          .bind(id, JSON.stringify(requested), status, expiresAt)
          .run();
      const setup = (rule: string) => ({
        setup: { connections: [{ name: 'n', deny: [], approval: [], free: [rule], tests: [{ path: '/{x}' }] }] },
      });
      const update = (rule: string) => ({ update: { connection: 'x', changes: { deny: [rule] } } });
      // Braces anywhere but a rule, and rules spelled with %7B, pass.
      await insert('encoded', { paths: ['/'], methods: ['GET'], deny: ['* /a/%7Bx%7D'], free: [] });
      await insert('old', { paths: ['/'], methods: ['GET'] });
      await request('fine', { invocation: { path: '/{x}', headers: { deny: '{x}' } } });
      await request('denied', setup('GET /{x}'), 'denied');
      await request('expired', update('* /{x}'), 'pending', Date.now() - 1000);
      const tables = async () =>
        (
          await db
            .prepare(
              "SELECT name FROM sqlite_master WHERE name IN ('brace_check','token_cache','token_locks','oauth_flows')",
            )
            .all()
        ).results.length;
      for (const [add, remove] of [
        [() => insert('braced', { paths: ['/'], methods: ['GET'], approval: ['* /a/{x}'] }), 'connections'],
        [() => request('braced', setup('GET /v1/{x}')), 'access_requests'],
        [() => request('braced', update('* /a}')), 'access_requests'],
      ] as const) {
        await add();
        await expect(applyMigrations(db, 'migrations', ['0002_token_auth.sql'])).rejects.toThrow(
          /rules_hold_no_literal_brace/,
        );
        // Nothing of the migration stays behind, so it runs again once the rule is rewritten.
        expect(await tables()).toBe(0);
        await db.prepare(`DELETE FROM ${remove} WHERE id='braced'`).run();
      }
      await applyMigrations(db, 'migrations', ['0002_token_auth.sql']);
      expect(await tables()).toBe(3);
    } finally {
      await fresh.dispose();
    }
  });
});
