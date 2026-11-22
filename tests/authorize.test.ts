import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { applyMigrations } from '../scripts/migrations.mjs';
import { issueSql, newToken } from '../scripts/bootstrap-token.mjs';
import worker from '../apps/worker/src/index';
import { accessRequest, boundSecret, invoke, invokeInput } from '../apps/worker/src/vault';
import { type Bindings, type Principal } from '../apps/worker/src/context';

// Authorizing a connection in the console (design §2.12), on real D1 and the Owner's real routes. The
// upstream's authorization server is simulated: authorizeAt reads the URL the start answered as the
// browser would carry it there and issues a code bound to its PKCE challenge, which the stubbed token
// endpoint checks as a real one does. The API host is a stub too. Every field value is random, so a test
// can look for any of them in what an Agent, the Owner's hints or the audit table see.
const origin = 'http://localhost:8787';
const tokenUrl = 'https://auth.example/oauth/token';
const authorizeUrl = 'https://accounts.example/o/authorize';
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const password = 'synthetic-password-for-authorize';
const key1 = `1:${Buffer.from('a'.repeat(32)).toString('base64url')}`;
const key2 = `2:${Buffer.from('b'.repeat(32)).toString('base64url')}`;
const ring = `${key1},${key2}`;
let mf: Miniflare,
  env: Bindings,
  cookie = '',
  owner = '',
  agent: Principal;

type Sent = { url: string; headers: Headers; body: string };
const sent: { token: Sent[]; upstream: Sent[] } = { token: [], upstream: [] };
const assets: string[] = [];
// Every field value and refresh token, and every hint a refusal carried.
const values: string[] = [];
const hints: string[] = [];
const fresh = (prefix: string) => {
  const v = `${prefix}-${crypto.randomUUID().toUpperCase()}`;
  values.push(v);
  return v;
};
let issued = 0;
const granted = (extra: object = {}) =>
  Response.json({ access_token: `AT-${++issued}`, token_type: 'Bearer', expires_in: 3600, ...extra });
// The codes the authorization server issued, each with what its authorization request named.
const codes = new Map<string, { challenge: string; redirect: string; clientId: string }>();
function authorizeAt(url: string) {
  const at = new URL(url);
  const code = `C-${crypto.randomUUID()}`;
  codes.set(code, {
    challenge: at.searchParams.get('code_challenge')!,
    redirect: at.searchParams.get('redirect_uri')!,
    clientId: at.searchParams.get('client_id')!,
  });
  return { code, state: at.searchParams.get('state')! };
}
// A token endpoint: a code is good once, for the redirect URI, client and PKCE verifier it was issued
// for, and answers a refresh token; a refresh token answers an access token alone.
const endpoint = (answer: (extra: object) => Response) => (request: Sent) => {
  const body = new URLSearchParams(request.body);
  if (body.get('grant_type') !== 'authorization_code') return granted();
  const code = codes.get(body.get('code')!);
  codes.delete(body.get('code')!);
  const verifier = body.get('code_verifier') ?? '';
  if (
    !code ||
    code.redirect !== body.get('redirect_uri') ||
    code.clientId !== body.get('client_id') ||
    !/^[A-Za-z0-9_-]{43}$/.test(verifier) ||
    createHash('sha256').update(verifier).digest('base64url') !== code.challenge
  )
    return Response.json({ error: 'invalid_grant' }, { status: 400 });
  return answer({ refresh_token: fresh('RT') });
};
let tokenEndpoint: (request: Sent) => Response = endpoint((extra) => granted(extra));
const stub = vi.fn(async (input: string | URL, init?: RequestInit) => {
  const request = { url: String(input), headers: new Headers(init?.headers), body: String(init?.body ?? '') };
  if (new URL(request.url).host === 'auth.example') {
    sent.token.push(request);
    return tokenEndpoint(request);
  }
  sent.upstream.push(request);
  return new Response('ok');
});

async function call(path: string, method = 'GET', body?: unknown, as = cookie) {
  const response = await worker.fetch(
    new Request(origin + path, {
      method,
      headers: {
        'cf-connecting-ip': '127.0.0.1',
        origin,
        cookie: as,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    }),
    env,
    context,
  );
  const text = await response.text();
  const result = { status: response.status, body: text ? (JSON.parse(text) as Record<string, any>) : {} };
  if (typeof result.body.hint === 'string') hints.push(result.body.hint);
  return result;
}
const cookieOf = (response: Response) =>
  response.headers
    .getSetCookie()
    .map((value) => value.split(';')[0])
    .join('; ');

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
    ROOT_KEY: ring,
    // The console's files, as the assets binding with single-page-application answers any path, cacheable.
    ASSETS: {
      fetch: async (request: Request) => {
        assets.push(request.url);
        return new Response('<!doctype html><title>Clavifer</title>', {
          headers: { 'content-type': 'text/html', 'cache-control': 'public, max-age=3600' },
        });
      },
    },
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
        password,
        backupRecipient: await identityToRecipient(await generateIdentity()),
      }),
    }),
    env,
    context,
  );
  expect(setup.status).toBe(201);
  cookie = cookieOf(setup);
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
  tokenEndpoint = endpoint((extra) => granted(extra));
  env.ROOT_KEY = ring;
});
/** Holds the secret's exchange lock for someone else, then lets it go 11 seconds later by the clock
 * (Date.now, which the Worker and its rows read), after 300 ms of real time. */
async function lockedFor11Seconds<T>(sid: string, run: () => Promise<T>) {
  const real = Date.now.bind(Date);
  let skew = 0;
  const clock = vi.spyOn(Date, 'now').mockImplementation(() => real() + skew);
  try {
    await env.DB.prepare('INSERT INTO token_locks (secret_id,holder,until) VALUES (?,?,?)')
      .bind(sid, 'someone', Date.now() + 60000)
      .run();
    setTimeout(() => {
      skew = 11000;
      void env.DB.prepare('DELETE FROM token_locks WHERE secret_id=?').bind(sid).run();
    }, 300);
    return await run();
  } finally {
    clock.mockRestore();
  }
}

let serial = 0;
async function secret(fields: string[]) {
  const result = await call('/admin/secrets', 'POST', {
    name: `Credential ${++serial}`,
    values: Object.fromEntries(fields.map((field) => [field, fresh('V')])),
  });
  expect(result.status).toBe(201);
  return result.body.id as string;
}
const authorizing = (sid: string, extra: object = {}) => ({
  type: 'oauth-refresh',
  secretId: sid,
  refreshField: 'refresh_token',
  client: { method: 'post', id: { $field: 'client_id' }, secretField: 'client_secret' },
  tokenUrl,
  authorize: { url: authorizeUrl, scope: 'mail.read offline_access', params: { access_type: 'offline' } },
  ...extra,
});
const policy = { paths: ['/v1'], methods: ['GET'], free: ['GET /v1/*'] };
const save = (auth: object, id?: string) =>
  call(id ? `/admin/connections/${id}` : '/admin/connections', id ? 'PUT' : 'POST', {
    name: `Connection ${id ? 'edited' : ++serial}`,
    origin: 'https://api.example',
    ...policy,
    auth,
  });
async function connection(auth: object) {
  const result = await save(auth);
  expect(result).toMatchObject({ status: 200 });
  return result.body.id as string;
}
const start = (cid: string, as = cookie) => call(`/admin/connections/${cid}/authorize`, 'POST', undefined, as);
const complete = (cid: string, at: { code: string; state: string }, as = cookie) =>
  call('/admin/oauth/complete', 'POST', { connection: cid, ...at }, as);
/** The browser's whole trip: start, sign in and consent upstream, come back and complete. */
async function authorize(cid: string) {
  const started = await start(cid);
  expect(started.status).toBe(200);
  return complete(cid, authorizeAt(started.body.url));
}
const send = (connection: string) => invoke(env, agent, invokeInput.parse({ connection, path: '/v1/items' }));
const rows = async <T = Record<string, unknown>>(sql: string, ...args: unknown[]) =>
  (
    await env.DB.prepare(sql)
      .bind(...args)
      .all<T>()
  ).results;
const version = async (sid: string) =>
  (await rows<{ current_version: number }>('SELECT current_version FROM secrets WHERE id=?', sid))[0].current_version;
const cacheRows = (sid: string) =>
  rows<{ version: number }>('SELECT version FROM token_cache WHERE secret_id=? ORDER BY created_at', sid);
const audits = (sid: string) =>
  rows<{ action: string; client_id: string; result: string; request_id: string }>(
    "SELECT action,client_id,result,request_id FROM audit_events WHERE resource_id=? AND action IN ('token:exchange','secret:rotate') ORDER BY created_at,rowid",
    sid,
  );

describe('saving a connection that is authorized in the console', () => {
  it('needs no refresh token yet and tries none, while one without authorize still needs it', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    expect(sent.token).toHaveLength(0);
    const { authorize, ...plain } = authorizing(sid);
    expect(await save(plain)).toMatchObject({ status: 404, body: { error: 'secret_field_not_found' } });
    // The client id it names is still required.
    const other = await secret(['client_secret']);
    expect(await save(authorizing(other))).toMatchObject({ status: 404, body: { error: 'secret_field_not_found' } });
    const status = await call('/admin/status');
    expect(status.body.connections.find((c: { id: string }) => c.id === cid)).toMatchObject({
      callback: `${origin}/oauth/callback/${cid}`,
    });
    expect(authorize.url).toBe(authorizeUrl);
  });

  it('answers a request before the authorization with not_authorized, asking no endpoint', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    const e = await send(cid).then(
      () => {
        throw new Error('expected a refusal');
      },
      (e: { code: string; status: number; message: string; result: string }) => e,
    );
    expect(e).toMatchObject({ code: 'token_exchange_failed', status: 502, result: 'not_authorized' });
    expect(e.message).toContain('authorize the connection');
    hints.push(e.message);
    expect(sent.token).toHaveLength(0);
    expect(sent.upstream).toHaveLength(0);
    expect(await audits(sid)).toEqual([]);
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
  });

  it('keeps the names the service writes out of the parameters in any case', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    for (const params of [{ Redirect_Uri: 'https://evil.example/cb' }, { RESPONSE_TYPE: 'token' }, { State: 's' }])
      expect(await save(authorizing(sid, { authorize: { url: authorizeUrl, params } }))).toMatchObject({
        status: 400,
        body: { error: 'invalid_input' },
      });
    for (const params of [{ Code_Verifier: 'x' }, { GRANT_TYPE: 'password' }])
      expect(await save(authorizing(sid, { params }))).toMatchObject({ status: 400, body: { error: 'invalid_input' } });
    expect(
      await save(authorizing(sid, { authorize: { url: authorizeUrl, params: { Prompt: 'consent' } } })),
    ).toMatchObject({ status: 200 });
  });

  it('sends no token request with less than 10 seconds left after waiting for the lock', async () => {
    const sid = await secret(['client_id', 'client_secret', 'refresh_token']);
    const cid = await connection(authorizing(sid));
    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    sent.token = [];
    const e = await lockedFor11Seconds(sid, () =>
      send(cid).then(
        () => {
          throw new Error('expected a refusal');
        },
        (e: { code: string; message: string }) => e,
      ),
    );
    expect(e.code).toBe('token_unavailable');
    hints.push(e.message);
    expect(sent.token).toHaveLength(0);
    expect(sent.upstream).toHaveLength(0);
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
    expect((await send(cid)).status).toBe(200);
  });
});

describe('starting an authorization', () => {
  it('needs a recent login and a connection with authorize and a client id', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    await env.DB.prepare('UPDATE session SET createdAt=createdAt-700000').run();
    expect(await start(cid)).toMatchObject({ status: 403, body: { error: 'recent_login_required' } });
    await env.DB.prepare('UPDATE session SET createdAt=createdAt+700000').run();
    const plain = await connection({ type: 'none' });
    expect(await start(plain)).toMatchObject({ status: 400, body: { error: 'authorization_not_configured' } });
    const publicClient = await connection(authorizing(sid, { client: { method: 'none' } }));
    expect(await start(publicClient)).toMatchObject({ status: 400, body: { error: 'client_id_required' } });
    expect(await start('missing')).toMatchObject({ status: 404, body: { error: 'connection_not_found' } });
    expect(await rows('SELECT * FROM oauth_flows WHERE connection_id IN (?,?)', plain, publicClient)).toEqual([]);
  });

  it('answers the authorization URL and stores only digests, auditing nothing', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    const { values: stored } = await boundSecret(env, owner, sid);
    const before = (await rows('SELECT id FROM audit_events')).length;
    const started = await start(cid);
    expect(started.status).toBe(200);
    expect(started.body.host).toBe('accounts.example');
    const url = new URL(started.body.url);
    expect(url.origin + url.pathname).toBe(authorizeUrl);
    const state = url.searchParams.get('state')!;
    expect(Object.fromEntries(url.searchParams)).toEqual({
      access_type: 'offline',
      response_type: 'code',
      client_id: stored.client_id,
      redirect_uri: `${origin}/oauth/callback/${cid}`,
      scope: 'mail.read offline_access',
      state,
      code_challenge: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      code_challenge_method: 'S256',
    });
    // It names the root key its verifier is derived under, the current one.
    expect(state).toMatch(/^1\.[A-Za-z0-9_-]{43}$/);
    const [flow] = await rows<{ state_hash: string; session_id: string; connection_id: string; expires_at: number }>(
      'SELECT * FROM oauth_flows WHERE connection_id=?',
      cid,
    );
    expect(flow.state_hash).toBe(createHash('sha256').update(state).digest('base64url'));
    // The Owner has signed in once so far.
    expect(await rows('SELECT id FROM session')).toEqual([{ id: flow.session_id }]);
    expect(flow.expires_at).toBeGreaterThan(Date.now() + 590000);
    expect(JSON.stringify(await rows('SELECT * FROM oauth_flows'))).not.toContain(state);
    expect((await rows('SELECT id FROM audit_events')).length).toBe(before);
    expect(sent.token).toHaveLength(0);
  });
});

describe('completing an authorization', () => {
  it('exchanges the code with its PKCE verifier once and stores the refresh token as the Owner', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    const started = await start(cid);
    const at = authorizeAt(started.body.url);
    expect(await complete(cid, at)).toEqual({ status: 200, body: { ok: true } });
    expect(sent.token).toHaveLength(1);
    const body = new URLSearchParams(sent.token[0].body);
    expect(Object.fromEntries(body)).toEqual({
      grant_type: 'authorization_code',
      code: at.code,
      redirect_uri: `${origin}/oauth/callback/${cid}`,
      code_verifier: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      client_id: expect.any(String),
      client_secret: expect.any(String),
    });
    expect(await version(sid)).toBe(2);
    const { values: stored } = await boundSecret(env, owner, sid);
    expect(stored.refresh_token).toMatch(/^RT-/);
    expect(await cacheRows(sid)).toEqual([{ version: 2 }]);
    const rowsOf = await audits(sid);
    expect(rowsOf.map((r) => `${r.action}:${r.client_id}:${r.result}`)).toEqual([
      'token:exchange:owner:ok',
      'secret:rotate:owner:ok',
    ]);
    expect(rowsOf[0].request_id).toBe(rowsOf[1].request_id);
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
    // The state works once.
    expect(await complete(cid, at)).toMatchObject({ status: 400, body: { error: 'authorization_expired' } });
    // The Agent's request uses the token the authorization cached, then refreshes with the stored token.
    expect((await send(cid)).status).toBe(200);
    expect(sent.token).toHaveLength(1);
    expect(sent.upstream[0].headers.get('authorization')).toMatch(/^Bearer AT-/);
    await env.DB.prepare('DELETE FROM token_cache WHERE secret_id=?').bind(sid).run();
    expect((await send(cid)).status).toBe(200);
    expect(new URLSearchParams(sent.token[1].body).get('refresh_token')).toBe(stored.refresh_token);
  });

  it('refuses a code issued for another authorization, since its verifier does not match', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    const first = authorizeAt((await start(cid)).body.url);
    const second = authorizeAt((await start(cid)).body.url);
    const refused = await complete(cid, { code: first.code, state: second.state });
    expect(refused).toMatchObject({
      status: 502,
      body: { error: 'token_exchange_failed', token_endpoint: { status: 400, error: 'invalid_grant' } },
    });
    expect(await version(sid)).toBe(1);
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
    expect((await audits(sid)).map((r) => `${r.action}:${r.client_id}:${r.result}`)).toEqual([
      'token:exchange:owner:invalid_grant',
    ]);
  });

  it('refuses a state past 10 minutes, of another session or connection, or of a changed connection', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    const other = await connection(authorizing(sid, { scope: 'other' }));
    const expired = authorizeAt((await start(cid)).body.url);
    await env.DB.prepare('UPDATE oauth_flows SET expires_at=? WHERE connection_id=?')
      .bind(Date.now() - 1, cid)
      .run();
    expect(await complete(cid, expired)).toMatchObject({ status: 400, body: { error: 'authorization_expired' } });
    // The next start clears what has expired.
    const elsewhere = authorizeAt((await start(cid)).body.url);
    expect(await rows('SELECT * FROM oauth_flows WHERE expires_at<=?', Date.now())).toEqual([]);
    expect(await complete(other, elsewhere)).toMatchObject({ status: 400, body: { error: 'authorization_expired' } });
    // Refused, the state is spent all the same.
    expect(await complete(cid, elsewhere)).toMatchObject({ status: 400, body: { error: 'authorization_expired' } });
    const signIn = await worker.fetch(
      new Request(`${origin}/api/auth/sign-in/email`, {
        method: 'POST',
        headers: { origin, 'cf-connecting-ip': '127.0.0.2', 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'owner@example.com', password }),
      }),
      env,
      context,
    );
    expect(signIn.status).toBe(200);
    const second = cookieOf(signIn);
    const theirs = authorizeAt((await start(cid)).body.url);
    expect(await complete(cid, theirs, second)).toMatchObject({
      status: 400,
      body: { error: 'authorization_expired' },
    });
    const changed = authorizeAt((await start(cid)).body.url);
    expect(
      await save({ ...authorizing(sid), authorize: { url: authorizeUrl, scope: 'mail.send offline_access' } }, cid),
    ).toMatchObject({ status: 200 });
    expect(await complete(cid, changed)).toMatchObject({ status: 409, body: { error: 'connection_changed' } });
    expect(sent.token).toHaveLength(0);
    expect(await version(sid)).toBe(1);
  });

  it('stores nothing for an answer without a refresh token, and warns of one without an expiry', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    tokenEndpoint = endpoint(() => granted());
    expect(await authorize(cid)).toMatchObject({ status: 502, body: { error: 'no_refresh_token' } });
    expect(await version(sid)).toBe(1);
    expect(await cacheRows(sid)).toEqual([]);
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
    tokenEndpoint = endpoint((extra) => Response.json({ access_token: 'AT-without-expiry', ...extra }));
    expect(await authorize(cid)).toEqual({
      status: 200,
      body: { ok: true, warnings: [{ connection: cid, error: 'ttl_required', hint: expect.any(String) }] },
    });
    expect(await version(sid)).toBe(2);
    expect(await cacheRows(sid)).toEqual([]);
    expect((await audits(sid)).map((r) => `${r.action}:${r.client_id}:${r.result}`)).toEqual([
      'token:exchange:owner:no_refresh_token',
      'token:exchange:owner:no_expiry',
      'secret:rotate:owner:ok',
    ]);
  });

  it('ends every token cached before, where a rotation would carry them over', async () => {
    const sid = await secret(['client_id', 'client_secret', 'refresh_token']);
    // With a refresh token already in the secret, saving tries it and caches a token per recipe.
    const graph = await connection(authorizing(sid, { scope: 'graph' }));
    const arm = await connection(authorizing(sid, { scope: 'arm' }));
    expect(await cacheRows(sid)).toEqual([{ version: 1 }, { version: 1 }]);
    expect((await authorize(graph)).status).toBe(200);
    expect(await version(sid)).toBe(2);
    expect((await cacheRows(sid)).map((r) => r.version).sort()).toEqual([1, 2]);
    // The other connection's token is no longer used; it refreshes with the authorized token.
    sent.token = [];
    expect((await send(arm)).status).toBe(200);
    expect(sent.token).toHaveLength(1);
    expect(new URLSearchParams(sent.token[0].body).get('refresh_token')).toBe(
      (await boundSecret(env, owner, sid)).values.refresh_token,
    );
  });

  it('completes one of two concurrent completions of a state, with one exchange', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    const at = authorizeAt((await start(cid)).body.url);
    const results = await Promise.all([complete(cid, at), complete(cid, at)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
    expect(sent.token).toHaveLength(1);
    expect(await version(sid)).toBe(2);
  });

  it('derives the verifier under the key the state names, and expires one whose key left the ring', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    const reordered = authorizeAt((await start(cid)).body.url);
    env.ROOT_KEY = `${key2},${key1}`;
    expect(await complete(cid, reordered)).toEqual({ status: 200, body: { ok: true } });
    // Started under key 2, which is current now, and completed after it left.
    const removed = authorizeAt((await start(cid)).body.url);
    expect(removed.state).toMatch(/^2\./);
    env.ROOT_KEY = key1;
    expect(await complete(cid, removed)).toMatchObject({ status: 400, body: { error: 'authorization_expired' } });
    expect(sent.token).toHaveLength(1);
  });

  it('tells the Owner to start again when waiting for the lock left too little time, sending nothing', async () => {
    const sid = await secret(['client_id', 'client_secret']);
    const cid = await connection(authorizing(sid));
    const at = authorizeAt((await start(cid)).body.url);
    const late = await lockedFor11Seconds(sid, () => complete(cid, at));
    expect(late).toMatchObject({ status: 503, body: { error: 'token_unavailable' } });
    expect(late.body.hint).toContain('start it again from the connection');
    expect(late.body.hint).not.toContain('identical request');
    expect(sent.token).toHaveLength(0);
    expect(await rows('SELECT * FROM token_locks')).toEqual([]);
    expect(await complete(cid, at)).toMatchObject({ status: 400, body: { error: 'authorization_expired' } });
    expect((await authorize(cid)).status).toBe(200);
  });
});

describe('a setup with a connection the Owner authorizes', () => {
  const setup = (connections: object[], fields = ['client_id', 'client_secret', 'refresh_token']) =>
    accessRequest(
      env,
      agent,
      {
        requested: {
          setup: {
            secret: { name: `Mail ${++serial}`, fields },
            connections: connections.map((auth, i) => ({
              name: `Mail connection ${serial}.${i}`,
              origin: 'https://api.example',
              ...policy,
              auth,
              tests: [{ method: 'GET', path: '/v1/items', expect: 'run' }],
            })),
          },
        },
      },
      origin,
    );
  const { secretId, ...draft } = authorizing('unused');

  it('may leave out the refresh token, shows the callback and tries nothing', async () => {
    const { id: rid } = await setup([draft]);
    const status = await call('/admin/status');
    const pending = status.body.pending.find((r: { id: string }) => r.id === rid);
    const [cid] = JSON.parse(pending.requested_json).ids.connectionIds;
    expect(pending.callbacks).toEqual({ [cid]: `${origin}/oauth/callback/${cid}` });
    expect(
      await call(`/admin/access-requests/${rid}/approve`, 'POST', { values: { client_id: fresh('V') } }),
    ).toMatchObject({ status: 400, body: { error: 'secret_fields_mismatch' } });
    expect(
      await call(`/admin/access-requests/${rid}/approve`, 'POST', {
        values: { client_id: fresh('V'), client_secret: fresh('V') },
      }),
    ).toEqual({ status: 200, body: { ok: true } });
    expect(sent.token).toHaveLength(0);
    const sid = JSON.parse(pending.requested_json).ids.secretId;
    expect(Object.keys((await boundSecret(env, owner, sid)).values).sort()).toEqual(['client_id', 'client_secret']);
    expect((await authorize(cid)).status).toBe(200);
    expect(Object.keys((await boundSecret(env, owner, sid)).values).sort()).toEqual([
      'client_id',
      'client_secret',
      'refresh_token',
    ]);
  });

  it('needs the refresh token when a connection without authorize reads it', async () => {
    const { authorize, ...plain } = draft;
    const { id: rid } = await setup([draft, { ...plain, scope: 'plain' }]);
    expect(
      await call(`/admin/access-requests/${rid}/approve`, 'POST', {
        values: { client_id: fresh('V'), client_secret: fresh('V') },
      }),
    ).toMatchObject({ status: 400, body: { error: 'secret_fields_mismatch' } });
    expect(authorize.url).toBe(authorizeUrl);
  });

  it('is approved without any value when its one field is the refresh token of a public client', async () => {
    const { id: rid } = await setup([{ ...draft, client: { method: 'none', id: 'public-client' } }], ['refresh_token']);
    expect(await call(`/admin/access-requests/${rid}/approve`, 'POST', { values: {} })).toEqual({
      status: 200,
      body: { ok: true },
    });
    const { secretId: sid, connectionIds } = (
      await rows<{ requested_json: string }>('SELECT requested_json FROM access_requests WHERE id=?', rid)
    ).map((r) => JSON.parse(r.requested_json).ids)[0];
    expect((await boundSecret(env, owner, sid)).values).toEqual({});
    expect((await authorize(connectionIds[0])).status).toBe(200);
    expect(Object.keys((await boundSecret(env, owner, sid)).values)).toEqual(['refresh_token']);
    // A value is still at least one character.
    const { id: other } = await setup(
      [{ ...draft, client: { method: 'none', id: 'public-client' } }],
      ['refresh_token'],
    );
    expect(
      await call(`/admin/access-requests/${other}/approve`, 'POST', { values: { refresh_token: '' } }),
    ).toMatchObject({ status: 400, body: { error: 'invalid_input' } });
  });
});

describe('the callback address', () => {
  it('is a page of the console, served from its files and never cached', async () => {
    const response = await worker.fetch(
      new Request(`${origin}/oauth/callback/some-connection?code=C-1&state=S-1`, { headers: { cookie } }),
      env,
      context,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(assets).toEqual([`${origin}/oauth/callback/some-connection?code=C-1&state=S-1`]);
    // The console's other files keep what the assets answered.
    const script = await worker.fetch(new Request(`${origin}/assets/app.js`), env, context);
    expect(script.headers.get('cache-control')).toBe('public, max-age=3600');
  });
});

describe('what the Owner and the audit see', () => {
  it('carries no field value and no refresh token', async () => {
    expect(hints.length).toBeGreaterThan(5);
    const audit = JSON.stringify(await rows('SELECT * FROM audit_events'));
    for (const v of values) {
      for (const hint of hints) expect(hint).not.toContain(v);
      expect(audit).not.toContain(v);
    }
  });
});
