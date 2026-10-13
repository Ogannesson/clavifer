import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { applyMigrations } from '../scripts/migrations.mjs';
import { canonicalPath, checkPath, matchHost, matchRule, parseRule, targetUrl } from '../packages/core/proxy';
import {
  accessRequest,
  accessStatus,
  connectionInput,
  invoke,
  invokeInput,
  metadata,
  parseProxyRequest,
  policyJson,
} from '../apps/worker/src/vault';
import { decideRequest, grantStatements } from '../apps/worker/src/index';
import { type Bindings, type Principal, issuesHint } from '../apps/worker/src/context';
import { handleMcp } from '../apps/worker/src/mcp';
import { ZodError } from 'zod';

describe('connection rules', () => {
  it('matches a path exactly unless the rule ends with /*', () => {
    expect(matchRule(['GET /v1/items'], 'GET', '/v1/items')).toBe(true);
    expect(matchRule(['GET /v1/items'], 'GET', '/v1/items/1')).toBe(false);
    expect(matchRule(['GET /v1/items'], 'GET', '/v1/itemsx')).toBe(false);
    expect(matchRule(['GET /v1/items/*'], 'GET', '/v1/items')).toBe(true);
    expect(matchRule(['GET /v1/items/*'], 'GET', '/v1/items/1/sub')).toBe(true);
    expect(matchRule(['GET /v1/items/*'], 'GET', '/v1/itemsx')).toBe(false);
    expect(matchRule(['GET /*'], 'GET', '/anything/below')).toBe(true);
  });

  it('matches any method with * and only the named method otherwise', () => {
    expect(matchRule(['* /v1/items'], 'DELETE', '/v1/items')).toBe(true);
    expect(matchRule(['DELETE /v1/items'], 'GET', '/v1/items')).toBe(false);
    expect(matchRule(['delete /v1/items'], 'DELETE', '/v1/items')).toBe(true);
  });

  it('lets a GET rule cover HEAD but not the reverse', () => {
    expect(matchRule(['GET /v1/items'], 'HEAD', '/v1/items')).toBe(true);
    expect(matchRule(['HEAD /v1/items'], 'GET', '/v1/items')).toBe(false);
    expect(matchRule(['GET /v1/items'], 'POST', '/v1/items')).toBe(false);
  });

  it('ignores ASCII case and one trailing slash so the same route cannot be spelled around a rule', () => {
    expect(matchRule(['DELETE /Zones/ABC'], 'DELETE', '/zones/abc')).toBe(true);
    expect(matchRule(['DELETE /zones/abc'], 'DELETE', '/ZONES/abc/')).toBe(true);
    expect(matchRule(['DELETE /zones/abc/*'], 'DELETE', '/Zones/ABC/Records')).toBe(true);
  });

  it('folds only ASCII letters, so the Kelvin sign is not read as k', () => {
    expect(matchRule(['GET /v1/k/*'], 'GET', canonicalPath('/v1/%E2%84%AA/x'))).toBe(false);
    expect(matchRule(['GET /v1/K/*'], 'GET', '/v1/k/x')).toBe(true);
  });

  it.each(['/v1/secret;x', '/v1/secret%3Bx', '/v1/a%E2%80%AEb', '/v1/a%E2%80%8Bb', '/v1/a\u2066b', '/v1/a%7Fb'])(
    'refuses a semicolon or a control or format character in the path %j',
    (path) => {
      expect(() => canonicalPath(path)).toThrow(expect.objectContaining({ code: 'invalid_path' }));
    },
  );

  it('accepts an encoded slash or space inside a segment and matches rules against the decoded path', () => {
    expect(canonicalPath('/x/a%2Fb')).toBe('/x/a/b');
    expect(canonicalPath('/x/my%20key')).toBe('/x/my key');
    expect(checkPath('/x/a%2Fb', ['/x'])).toBe(true);
    expect(checkPath('/x/a%2Fb/c', ['/x/a%2fb'])).toBe(true);
    expect(matchRule(['DELETE /x/*'], 'DELETE', canonicalPath('/x/a%2Fb'))).toBe(true);
    expect(parseRule('DELETE /x/a%2Fb').path).toBe('/x/a/b');
  });

  // Decoding only splits a segment, so every spelling of a denied resource still meets the rule.
  it.each(['/x/a%2Fsecret', '/x%2Fa/secret', '/X/A%2FSECRET/', '/x/a%2Fsecret%2Fdeeper', '/x/a%2fs%65cret'])(
    'cannot route around a deny rule with %%2F: %s',
    (path) => {
      expect(matchRule(['* /x/a/secret/*'], 'GET', canonicalPath(path))).toBe(true);
    },
  );

  it.each([
    ['/x/a%2F%2Fb', 'empty'],
    ['/x/a/%2Fb', 'empty'],
    ['/%2Fevil.example/x', 'empty'],
    ['/x/%2F..%2Fadmin', 'empty'],
    ['/x/a%2F..%2Fadmin', '".."'],
    ['/x/%2e%2e/admin', '".."'],
    ['/x/a%2F.', '"."'],
    ['/x/my key', 'literal space'],
    ['/x/a%2F%3Bb', '";"'],
    ['/x/a%252Fb', '"%"'],
    ['/x/a%2F%00', 'control'],
  ])('refuses %s and says why', (path, reason) => {
    expect(() => canonicalPath(path)).toThrow(
      expect.objectContaining({ code: 'invalid_path', message: expect.stringContaining(reason) }),
    );
  });

  it('compares decoded paths, matching an encoded rule or request against its plain form', () => {
    expect(parseRule('GET /v1/%61').path).toBe('/v1/a');
    expect(matchRule(['DELETE /v1/%61/*'], 'DELETE', canonicalPath('/v1/a/%62'))).toBe(true);
    expect(matchRule(['DELETE /v1/a/*'], 'DELETE', canonicalPath('/v1/%61'))).toBe(true);
  });

  it.each([
    'GET',
    '/v1/items',
    'GET /v1 extra',
    'FETCH /v1',
    'GET v1',
    'GET /v1/*/items',
    'GET /v1*',
    'GET /v1/../admin',
    'GET /v1?x=1',
    'GET /v1/%2fadmin',
    'GET //v1',
    'GET /v1;x',
    'GET /v1/%E2%80%AE',
    'GET /' + 'a'.repeat(320),
  ])('rejects the malformed rule %j', (text) => {
    expect(() => parseRule(text)).toThrow('invalid_rule');
  });

  const base = { name: 'n', origin: 'https://api.example.com', paths: ['/v1'] };
  const saved = (rules: object) => JSON.parse(policyJson(connectionInput.parse({ ...base, ...rules })));

  it('normalizes rules when a connection is saved, giving a bare path its default method', () => {
    expect(saved({ deny: ['  delete   /v1/x/* ', '/v1/y/*'] }).deny).toEqual(['DELETE /v1/x/*', '* /v1/y/*']);
    expect(saved({ approval: ['/v1/z'] }).approval).toEqual(['* /v1/z']);
    expect(saved({ free: ['/v1/public/*', 'POST /v1/ping'] }).free).toEqual(['GET /v1/public/*', 'POST /v1/ping']);
  });

  it('names the list and line of a malformed rule and the list over the 50 rule limit', () => {
    expect(() => saved({ free: ['GET /v1/*', 'nope /v1'] })).toThrow(
      expect.objectContaining({ code: 'invalid_rule', message: 'free line 2' }),
    );
    expect(() => saved({ deny: ['/v1;x'] })).toThrow(
      expect.objectContaining({ code: 'invalid_rule', message: 'deny line 1' }),
    );
    expect(() => saved({ approval: Array(51).fill('GET /v1') })).toThrow(
      expect.objectContaining({ code: 'too_many_rules', message: 'approval' }),
    );
    expect(saved({ approval: Array(50).fill('GET /v1') }).approval).toHaveLength(50);
  });
});

describe('extra hosts of a connection', () => {
  const base = { name: 'n', origin: 'https://api.example.com', paths: ['/v1'] };
  const saved = (rules: object, allowLocal = false) =>
    JSON.parse(policyJson(connectionInput.parse({ ...base, ...rules }), allowLocal));
  // A request's origin is compared by the hostname URL gives it.
  const hostname = (origin: string) => targetUrl(origin, '/').hostname;
  const hosts = ['artifacts.example.com', '*.dev.example.net'];

  it('covers every host below a *.suffix at any depth, never the suffix itself or a name that only ends alike', () => {
    expect(matchHost(hosts, 'a.dev.example.net')).toBe('*.dev.example.net');
    expect(matchHost(hosts, 'a.b.dev.example.net')).toBe('*.dev.example.net');
    expect(matchHost(hosts, 'dev.example.net')).toBeUndefined();
    expect(matchHost(hosts, 'xdev.example.net')).toBeUndefined();
    expect(matchHost(hosts, 'evildev.example.net')).toBeUndefined();
    expect(matchHost(hosts, '.dev.example.net')).toBeUndefined();
    expect(matchHost(hosts, 'a.dev.example.net.evil.example')).toBeUndefined();
    expect(matchHost(hosts, 'artifacts.example.com')).toBe('artifacts.example.com');
    expect(matchHost(hosts, 'x.artifacts.example.com')).toBeUndefined();
    expect(matchHost(hosts, 'xartifacts.example.com')).toBeUndefined();
    expect(matchHost(undefined, 'a.dev.example.net')).toBeUndefined();
  });

  it('reads an origin the way URL writes its hostname: case and IDN fold, a port plays no part', () => {
    expect(matchHost(hosts, hostname('https://A.Dev.EXAMPLE.net'))).toBe('*.dev.example.net');
    expect(matchHost(hosts, hostname('https://a.dev.example.net:8443'))).toBe('*.dev.example.net');
    expect(matchHost(hosts, hostname('https://ARTIFACTS.example.com:444'))).toBe('artifacts.example.com');
    const idn = ['xn--bcher-kva.example', '*.xn--bcher-kva.example'];
    expect(matchHost(idn, hostname('https://bücher.example'))).toBe('xn--bcher-kva.example');
    expect(matchHost(idn, hostname('https://shop.BÜCHER.example'))).toBe('*.xn--bcher-kva.example');
    expect(matchHost(idn, hostname('https://bucher.example'))).toBeUndefined();
    // What can never be an extra host is no origin either.
    // URL keeps an empty label as written, where it would pass for a host below the suffix.
    for (const origin of [
      'https://a.dev.example.net.',
      'https://a..dev.example.net',
      'https://.dev.example.net',
      'https://10.0.0.1',
      'https://[::1]',
      'https://localhost',
    ])
      expect(() => targetUrl(origin, '/'), origin).toThrow(expect.objectContaining({ code: 'public_origin_required' }));
  });

  it('saves an entry only as a lowercase public hostname or a *.suffix of two labels, naming the line', () => {
    const good = ['artifacts.dev.example.net', '*.dev.example.net', 'xn--bcher-kva.example', '*.a-b.example.co.uk'];
    expect(saved({ hosts: good })).toMatchObject({ hosts: good, anyHost: false });
    expect(saved({})).toMatchObject({ hosts: [], anyHost: false });
    expect(saved({ anyHost: true }).anyHost).toBe(true);
    for (const bad of [
      '*.com',
      'com',
      '*',
      '*.',
      '',
      'Dev.Example.net',
      'bücher.example',
      'https://a.example.com',
      'a.example.com:443',
      'a.example.com/v1',
      'a.example.com.',
      ' a.example.com',
      'a..example.com',
      '-a.example.com',
      '*.*.example.com',
      'a.*.example.com',
      'a*.example.com',
      '10.0.0.1',
      '1.2.3',
      '0x7f.1',
      '[::1]',
      'localhost',
      'db.internal',
      '*.corp.local',
    ])
      expect(() => saved({ hosts: ['ok.example.com', bad] }), bad).toThrow(
        expect.objectContaining({ code: 'invalid_host', message: 'hosts line 2' }),
      );
    expect(() => saved({ hosts: Array(21).fill('a.example.com') })).toThrow(ZodError);
    expect(saved({ hosts: Array(20).fill('a.example.com') }).hosts).toHaveLength(20);
    // A local deployment may name the local upstream, as its origin may.
    expect(saved({ hosts: ['localhost', '127.0.0.1'] }, true).hosts).toEqual(['localhost', '127.0.0.1']);
    expect(() => saved({ hosts: ['*.localhost'] }, true)).toThrow(expect.objectContaining({ code: 'invalid_host' }));
  });
});

// Real D1 so the one-time consumption, its fingerprint lookup and the metadata query run as deployed.
const owner = 'owner',
  client = 'client',
  conn = 'conn',
  hidden = 'hidden';
const principal: Principal = {
  userId: owner,
  clientId: client,
  scopes: ['metadata:list', 'connection:invoke', 'access:request'],
};
const policy = {
  paths: ['/v1'],
  methods: ['GET', 'HEAD', 'POST', 'DELETE'],
  deny: ['* /v1/secret/*', 'GET /v1/public/hidden'],
  approval: ['DELETE /v1/items/*', 'GET /v1/public/guarded'],
  free: ['GET /v1/public/*'],
};
let mf: Miniflare, env: Bindings;
const upstream = vi.fn(async () => new Response('ok'));

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
  env = { DB: db, ALLOW_LOCAL_HTTP: 'false' } as unknown as Bindings;
  const connection = (id: string, p: object, description = '') =>
    db
      .prepare(
        'INSERT INTO connections (id,owner_id,name,origin,description,auth_json,policy_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
      )
      .bind(
        id,
        owner,
        id,
        'https://api.example.com',
        description,
        '{"type":"none"}',
        JSON.stringify(p),
        Date.now(),
        Date.now(),
      );
  await db.batch([
    db.prepare("INSERT INTO system_state (key,value,updated_at) VALUES ('owner_user_id',?,?)").bind(owner, Date.now()),
    db
      .prepare('INSERT INTO "oauthClient" (id,clientId,userId,name,redirectUris) VALUES (?,?,?,?,?)')
      .bind(client, client, owner, 'Installation', '[]'),
    connection(conn, policy),
    connection(hidden, { paths: ['/v1'], methods: ['GET'] }, 'Send X-Account: synthetic.'),
  ]);
  vi.stubGlobal('fetch', upstream);
});
afterAll(async () => {
  vi.unstubAllGlobals();
  await mf.dispose();
});
beforeEach(async () => {
  upstream.mockClear();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM grants'),
    env.DB.prepare('DELETE FROM access_requests'),
    env.DB.prepare('DELETE FROM audit_events'),
    env.DB.prepare('UPDATE connections SET policy_json=? WHERE id=?').bind(JSON.stringify(policy), conn),
  ]);
});

type Call = {
  origin?: string;
  method?: string;
  path: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: string;
};
const call = (c: Call) => invoke(env, principal, invokeInput.parse({ connection: conn, ...c }));
const grant = () =>
  env.DB.prepare(
    "INSERT INTO grants (id,owner_id,client_id,resource_type,resource_id,permission,status,created_at,expires_at) VALUES (?,?,?,'connection',?,'connection:invoke','active',?,NULL)",
  )
    .bind(crypto.randomUUID(), owner, client, conn, Date.now())
    .run();
// The Owner's grant form, which sets (and replaces) the extension.
const grantWith = async (extension: object) =>
  env.DB.batch(
    await grantStatements(
      env,
      owner,
      client,
      [{ resourceType: 'connection', resourceId: conn, permission: 'connection:invoke', ...extension }],
      null,
    ),
  );
// An invocation request names its method, so GET is spelled out here where a test leaves it out.
const submit = async (c: Call) =>
  (
    await accessRequest(
      env,
      principal,
      { requested: { invocation: { connection: conn, method: 'GET', ...c } } },
      'https://vault',
    )
  ).id;
// Mirrors the approval route: an approved invocation gets a 10 minute window for its one run.
const approve = (rid: string, expiresAt = Date.now() + 600000) =>
  env.DB.prepare("UPDATE access_requests SET status='approved',expires_at=? WHERE id=?").bind(expiresAt, rid).run();
const status = async (rid: string) => (await accessStatus(env, principal, rid)).status;
const write = { method: 'POST', path: '/v1/items', headers: { 'Content-Type': 'application/json' }, body: '{"a":1}' };

describe('connection policy decisions', () => {
  it('lets a deny rule override a live grant and an already approved invocation', async () => {
    await grant();
    await expect(call({ path: '/v1/secret/key' })).rejects.toMatchObject({
      code: 'path_denied',
      status: 403,
      message: expect.stringContaining('"deny * /v1/secret/*"'),
    });
    await expect(submit({ path: '/v1/secret/key' })).rejects.toMatchObject({ code: 'path_denied' });
    const rid = await submit(write);
    await approve(rid);
    await env.DB.prepare('UPDATE connections SET policy_json=? WHERE id=?')
      .bind(JSON.stringify({ ...policy, deny: ['POST /v1/items'] }), conn)
      .run();
    await expect(call(write)).rejects.toMatchObject({ code: 'path_denied' });
    expect(await status(rid)).toBe('approved');
    expect(upstream).not.toHaveBeenCalled();
  });

  it('requires a one-time approval for an approval rule even with a live grant', async () => {
    await grant();
    const remove = { method: 'DELETE', path: '/v1/items/7' };
    await expect(call(remove)).rejects.toMatchObject({ code: 'approval_required', status: 403 });
    await approve(await submit(remove));
    expect((await call(remove)).status).toBe(200);
    await expect(call(remove)).rejects.toMatchObject({ code: 'approval_required' });
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('runs a free request without any grant, still audited, but never past allowed paths or deny', async () => {
    expect((await call({ path: '/v1/public/list' })).status).toBe(200);
    const audited = await env.DB.prepare("SELECT result FROM audit_events WHERE action='connection:invoke'").all();
    expect(audited.results.map((r) => r.result)).toEqual(['started', 'http_200']);
    await env.DB.prepare('UPDATE connections SET policy_json=? WHERE id=?')
      .bind(JSON.stringify({ ...policy, free: ['GET /*'] }), conn)
      .run();
    await expect(call({ path: '/v2/other' })).rejects.toMatchObject({ code: 'path_not_allowed' });
    await expect(call({ path: '/v1/public/hidden' })).rejects.toMatchObject({ code: 'path_denied' });
    await expect(call({ path: '/v1/public/%68idden' })).rejects.toMatchObject({ code: 'path_denied' });
    await expect(call({ path: '/v1/Secret/KEY/' })).rejects.toMatchObject({ code: 'path_denied' });
    await expect(call({ path: '/v1/public/guarded' })).rejects.toMatchObject({ code: 'approval_required' });
    await expect(call({ method: 'POST', path: '/v1/public/list' })).rejects.toMatchObject({ code: 'grant_required' });
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('lets a free GET rule run HEAD and refuses a semicolon path that a servlet upstream would trim', async () => {
    expect((await call({ method: 'HEAD', path: '/v1/public/list' })).status).toBe(200);
    await grant();
    await expect(call({ path: '/v1/secret;x' })).rejects.toMatchObject({ code: 'invalid_path' });
    await expect(submit({ path: '/v1/secret;x' })).rejects.toMatchObject({ code: 'invalid_path' });
  });

  it('keeps insufficient_scope for a token without connection:invoke', async () => {
    await expect(
      invoke(
        env,
        { ...principal, scopes: ['metadata:list'] },
        invokeInput.parse({ connection: conn, path: '/v1/public/a' }),
      ),
    ).rejects.toMatchObject({ code: 'insufficient_scope', status: 403 });
  });
});

describe('one-time invocation approval', () => {
  it('runs an approved invocation once and reports it as executed', async () => {
    await expect(call(write)).rejects.toMatchObject({ code: 'grant_required', status: 403 });
    const rid = await submit(write);
    expect(await status(rid)).toBe('pending');
    await approve(rid);
    expect(await status(rid)).toBe('approved');
    expect((await call(write)).status).toBe(200);
    expect(await status(rid)).toBe('executed');
    await expect(call(write)).rejects.toMatchObject({ code: 'grant_required' });
    expect(upstream).toHaveBeenCalledTimes(1);
    const consumed = await env.DB.prepare("SELECT resource_id FROM audit_events WHERE action='access:consume'").all();
    expect(consumed.results).toEqual([{ resource_id: rid }]);
  });

  it('refuses an approval whose 10 minute window has passed', async () => {
    const rid = await submit(write);
    await approve(rid, Date.now() - 1000);
    await expect(call(write)).rejects.toMatchObject({ code: 'grant_required' });
    expect(await status(rid)).toBe('expired');
  });

  it('reports a denied invocation request', async () => {
    const rid = await submit(write);
    await env.DB.prepare("UPDATE access_requests SET status='denied' WHERE id=?").bind(rid).run();
    expect(await status(rid)).toBe('denied');
    await expect(call(write)).rejects.toMatchObject({ code: 'grant_required' });
  });

  it.each([
    ['body', { ...write, body: '{"a":2}' }],
    ['header value', { ...write, headers: { 'Content-Type': 'text/plain' } }],
    ['extra header', { ...write, headers: { ...write.headers, 'X-Extra': '1' } }],
    ['query', { ...write, query: { dry: '1' } }],
    ['path', { ...write, path: '/v1/items/1' }],
  ])('binds the approval to the exact request: a different %s is refused', async (_label, changed) => {
    await approve(await submit(write));
    await expect(call(changed)).rejects.toMatchObject({ code: 'grant_required' });
    expect((await call(write)).status).toBe(200);
  });

  it('binds the approval to the path as sent, so another encoding of the same route needs its own', async () => {
    const encoded = { ...write, path: '/v1/items/%61' };
    await approve(await submit(encoded));
    await expect(call({ ...write, path: '/v1/items/a' })).rejects.toMatchObject({ code: 'grant_required' });
    expect((await call(encoded)).status).toBe(200);
  });

  it('ignores header-name case, query order and dropped control headers in the fingerprint', async () => {
    await approve(
      await submit({ ...write, query: { b: '2', a: '1' }, headers: { 'content-type': 'application/json' } }),
    );
    const replay = await invoke(env, principal, {
      connection: conn,
      method: 'POST',
      path: '/v1/items',
      query: [
        ['a', '1'],
        ['b', '2'],
      ],
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer caller-token', Cookie: 'c=1' },
      body: new TextEncoder().encode('{"a":1}'),
    });
    expect(replay.status).toBe(200);
  });

  it('checks only the input, the connection and deny rules at submission, and bounds the body to 64 KiB', async () => {
    expect(await submit({ path: '/v2/x' })).toBeTruthy();
    expect(await submit({ method: 'PUT', path: '/v1/items' })).toBeTruthy();
    await expect(submit({ method: 'DELETE', path: '/v1/secret/x' })).rejects.toMatchObject({ code: 'path_denied' });
    await expect(submit({ path: '/v2/a%2F%2Fb' })).rejects.toMatchObject({ code: 'invalid_path' });
    const ask = (requested: object) => accessRequest(env, principal, { requested }, 'https://vault');
    await expect(ask({ invocation: { connection: 'absent', method: 'GET', path: '/' } })).rejects.toMatchObject({
      code: 'connection_not_found',
      message: expect.stringContaining('origin'),
    });
    // Nothing is filled in by default: the Owner approves the method and path the Agent wrote.
    const missing = await ask({ invocation: { connection: conn } }).catch((e: unknown) => e);
    expect(missing).toBeInstanceOf(ZodError);
    expect(issuesHint(missing as ZodError)).toMatch(/requested\.invocation\.path: .*requested\.invocation\.method: /);
    await expect(
      ask({ grants: [{ resourceType: 'connection', resourceId: 'absent', permission: 'connection:invoke' }] }),
    ).rejects.toMatchObject({ code: 'connection_not_found', message: expect.stringContaining('credentials.list') });
    await expect(
      ask({ grants: [{ resourceType: 'secret', resourceId: 'absent', permission: 'secret:read' }] }),
    ).rejects.toMatchObject({ code: 'secret_not_found', message: expect.stringContaining('Ask the user') });
    await expect(submit({ ...write, body: 'x'.repeat(70000) })).rejects.toMatchObject({ code: 'body_too_large' });
    await expect(submit({ path: '/v1/items', body: 'x' })).rejects.toMatchObject({ code: 'body_not_allowed' });
    await expect(submit({ ...write, body: 'é'.repeat(40000) })).rejects.toMatchObject({
      code: 'body_too_large',
      status: 413,
      message: expect.stringContaining('64 KiB'),
    });
    expect(await submit({ ...write, body: 'x'.repeat(65536) })).toBeTruthy();
    const headers = Object.fromEntries(Array.from({ length: 3 }, (_, i) => [`x-h${i}`, 'v'.repeat(8000)]));
    await expect(submit({ path: '/v1/items', headers })).rejects.toMatchObject({
      code: 'headers_too_large',
      status: 413,
      message: expect.stringContaining('16 KiB'),
    });
    const both = await ask({
      grants: [{ resourceType: 'connection', resourceId: conn, permission: 'connection:invoke' }],
      invocation: { connection: conn, method: 'GET', path: '/v1/items' },
    }).catch((e: unknown) => e);
    expect(issuesHint(both as ZodError)).toContain('exactly one of grants or invocation');
  });
});

describe('a request to another origin than the connection’s own', () => {
  const own = 'https://api.example.com',
    files = 'https://files.example.net',
    mirror = 'https://mirror.example.net';
  const covering = (extra: object) =>
    env.DB.prepare('UPDATE connections SET policy_json=? WHERE id=?')
      .bind(JSON.stringify({ ...policy, ...extra }), conn)
      .run();
  const sent = () => upstream.mock.calls.map((args) => String((args as unknown[])[0]));
  // In the regular scope and under no rule, so on the connection's own origin only a grant runs it.
  const read = { path: '/v1/items' };

  // Each row: where the approval was given, where the same request is then sent, and the refusal there.
  it.each([
    ['one extra host is refused on another', files, mirror, 'approval_required'],
    ['an extra host is refused on the connection’s own origin', files, undefined, 'grant_required'],
    ['the connection’s own origin is refused on an extra host', undefined, files, 'approval_required'],
  ])('binds an approval to its origin: one for %s', async (_label, approved, resent, code) => {
    await covering({ hosts: ['files.example.net', 'mirror.example.net'] });
    const rid = await submit({ ...read, origin: approved });
    await approve(rid);
    await expect(call({ ...read, origin: resent })).rejects.toMatchObject({ code });
    expect(await status(rid)).toBe('approved');
    expect(sent()).toEqual([]);
    expect((await call({ ...read, origin: approved })).status).toBe(200);
    expect(await status(rid)).toBe('executed');
    await expect(call({ ...read, origin: approved })).rejects.toMatchObject({ code: expect.any(String) });
    expect(sent()).toEqual([(approved ?? own) + '/v1/items']);
    const consumed = await env.DB.prepare("SELECT resource_id FROM audit_events WHERE action='access:consume'").all();
    expect(consumed.results).toEqual([{ resource_id: rid }]);
  });

  it('stores the origin as URL writes it and reads the connection’s own origin, however spelled, as none', async () => {
    await covering({ hosts: ['*.example.net'] });
    const stored = async (rid: string) =>
      JSON.parse(
        (await env.DB.prepare('SELECT requested_json FROM access_requests WHERE id=?')
          .bind(rid)
          .first<{ requested_json: string }>())!.requested_json,
      ).invocation;
    const elsewhere = await submit({ ...read, origin: 'HTTPS://Files.Example.NET:443/' });
    expect((await stored(elsewhere)).origin).toBe(files);
    await approve(elsewhere);
    expect((await call({ ...read, origin: 'https://FILES.example.net' })).status).toBe(200);
    // A port is part of the origin, though not of what an extra host matches.
    await approve(await submit({ ...read, origin: files + ':8443' }));
    await expect(call({ ...read, origin: files })).rejects.toMatchObject({ code: 'approval_required' });
    expect((await call({ ...read, origin: files + ':8443' })).status).toBe(200);
    const home = await submit({ ...write, origin: 'https://API.example.com:443/' });
    expect(await stored(home)).not.toHaveProperty('origin');
    expect(await submit(write)).toBe(home);
    await approve(home);
    expect((await call(write)).status).toBe(200);
    expect((await call({ path: '/v1/public/list', origin: own + '/' })).status).toBe(200);
    expect(sent()).toEqual([files + '/v1/items', files + ':8443/v1/items', own + '/v1/items', own + '/v1/public/list']);
  });

  it('runs nothing there on a free rule, a grant or an extension, and still refuses what a deny rule names', async () => {
    await covering({ hosts: ['files.example.net'] });
    await grantWith({ paths: ['/v2'], methods: ['GET'] });
    await expect(call({ path: '/v1/public/list', origin: files })).rejects.toMatchObject({
      code: 'approval_required',
      status: 403,
      message: expect.stringContaining('must carry the same origin'),
    });
    await expect(call({ ...read, origin: files })).rejects.toMatchObject({ code: 'approval_required' });
    await expect(call({ path: '/v2/zones', origin: files })).rejects.toMatchObject({ code: 'approval_required' });
    await expect(call({ path: '/v1/secret/key', origin: files })).rejects.toMatchObject({ code: 'path_denied' });
    await expect(submit({ path: '/v1/secret/key', origin: files })).rejects.toMatchObject({ code: 'path_denied' });
    expect(sent()).toEqual([]);
    // The same three run on the connection's own origin, and an approval runs each of them there.
    for (const path of ['/v1/public/list', '/v1/items', '/v2/zones']) expect((await call({ path })).status).toBe(200);
    await approve(await submit({ path: '/v1/public/list', origin: files }));
    expect((await call({ path: '/v1/public/list', origin: files })).status).toBe(200);
    expect(sent().at(-1)).toBe(files + '/v1/public/list');
  });

  it('refuses an origin the connection does not cover, on submission and again when the request runs', async () => {
    const refused = { code: 'host_not_allowed', status: 403, message: expect.stringContaining('files.example.net') };
    await expect(submit({ ...read, origin: files })).rejects.toMatchObject(refused);
    await expect(call({ ...read, origin: files })).rejects.toMatchObject(refused);
    await covering({ hosts: ['*.example.net'] });
    await expect(submit({ ...read, origin: 'https://example.net' })).rejects.toMatchObject({
      code: 'host_not_allowed',
    });
    await expect(submit({ ...read, origin: 'https://files.example.net.evil.example' })).rejects.toMatchObject({
      code: 'host_not_allowed',
    });
    for (const [origin, code] of [
      ['http://files.example.net', 'origin_must_be_https'],
      ['https://files.example.net/v1', 'origin_must_not_contain_path'],
      ['https://user@files.example.net', 'origin_must_not_contain_path'],
      ['https://files.example.net.', 'public_origin_required'],
      ['https://10.0.0.1', 'public_origin_required'],
    ]) {
      await expect(submit({ ...read, origin }), origin).rejects.toMatchObject({ code });
      await expect(call({ ...read, origin }), origin).rejects.toMatchObject({ code });
    }
    await expect(submit({ ...read, origin: 'files.example.net' })).rejects.toBeInstanceOf(ZodError);
    expect(await env.DB.prepare('SELECT 1 FROM access_requests').first()).toBeNull();
    // An approval lasts only as long as the entry it relied on.
    const listed = await submit({ ...read, origin: files });
    await approve(listed);
    await covering({ hosts: ['mirror.example.net'] });
    await expect(call({ ...read, origin: files })).rejects.toMatchObject(refused);
    expect(await status(listed)).toBe('approved');
    await covering({ hosts: ['*.example.net'] });
    expect((await call({ ...read, origin: files })).status).toBe(200);
    expect(sent()).toEqual([files + '/v1/items']);
  });

  it('lets a connection that reaches any host take any public origin, until the Owner turns that off', async () => {
    const anywhere = 'https://unlisted.example.org';
    await expect(submit({ ...read, origin: anywhere })).rejects.toMatchObject({ code: 'host_not_allowed' });
    await covering({ anyHost: true });
    await expect(submit({ ...read, origin: 'https://10.0.0.1' })).rejects.toMatchObject({
      code: 'public_origin_required',
    });
    const rid = await submit({ ...read, origin: anywhere });
    await expect(call({ ...read, origin: anywhere })).rejects.toMatchObject({ code: 'approval_required' });
    await approve(rid);
    await covering({ anyHost: false });
    await expect(call({ ...read, origin: anywhere })).rejects.toMatchObject({ code: 'host_not_allowed' });
    expect(await status(rid)).toBe('approved');
    await covering({ anyHost: true });
    expect((await call({ ...read, origin: anywhere })).status).toBe(200);
    expect(sent()).toEqual([anywhere + '/v1/items']);
  });

  it('gives the REST proxy no way to name an origin', async () => {
    await covering({ hosts: ['files.example.net'], anyHost: true });
    const parsed = await parseProxyRequest(
      new Request(`https://vault.example.com/v1/proxy/${conn}/v1/public/list?origin=${encodeURIComponent(files)}`, {
        headers: { 'x-origin': files, 'x-forwarded-host': 'files.example.net' },
      }),
      conn,
    );
    expect(parsed).not.toHaveProperty('origin');
    expect((await invoke(env, principal, parsed)).status).toBe(200);
    expect(sent()).toEqual([`${own}/v1/public/list?origin=${encodeURIComponent(files)}`]);
  });
});

describe('Owner decision on a request', () => {
  const pending = (rid: string) =>
    env.DB.prepare('SELECT client_id,requested_json FROM access_requests WHERE id=?')
      .bind(rid)
      .first<{ client_id: string; requested_json: string }>();
  const approvals = async () =>
    (
      await env.DB.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE action='access:approve'").first<{
        n: number;
      }>()
    )?.n;

  it('gives an approved invocation a 10 minute window and records the approval', async () => {
    const rid = await submit(write);
    await decideRequest(env, owner, rid, (await pending(rid))!, true, null);
    const row = await env.DB.prepare('SELECT status,expires_at FROM access_requests WHERE id=?')
      .bind(rid)
      .first<{ status: string; expires_at: number }>();
    expect(row!.status).toBe('approved');
    expect(row!.expires_at - Date.now()).toBeGreaterThan(590000);
    expect(await approvals()).toBe(1);
  });

  it.each([
    ['an invocation', { invocation: { connection: conn, method: 'GET', path: '/v1/items' } }],
    [
      'a grant request',
      { grants: [{ resourceType: 'connection', resourceId: conn, permission: 'connection:invoke' }] },
    ],
  ])('fails without granting or auditing when %s expired after it was read', async (_label, requested) => {
    const rid = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at) VALUES (?,?,?,?,'','pending',?,?)",
    )
      .bind(rid, owner, client, JSON.stringify(requested), Date.now(), Date.now() - 1000)
      .run();
    await expect(decideRequest(env, owner, rid, (await pending(rid))!, true, null)).rejects.toMatchObject({
      code: 'request_not_found',
      status: 404,
    });
    expect(await env.DB.prepare('SELECT 1 FROM grants').first()).toBeNull();
    expect(await approvals()).toBe(0);
    expect(await status(rid)).toBe('expired');
  });
});

describe('credentials.list visibility', () => {
  it('lists every connection with its policy and description, and only this installation’s grant', async () => {
    await env.DB.prepare(
      "INSERT INTO grants (id,owner_id,client_id,resource_type,resource_id,permission,extensions_json,status,created_at) VALUES ('other-grant',?,'other','connection',?,'connection:invoke','[{\"methods\":[\"DELETE\"],\"expiresAt\":null}]','active',?)",
    )
      .bind(owner, hidden, Date.now())
      .run();
    const listed = (await metadata(env, principal)).connections;
    expect(listed.map((c) => c.id)).toEqual([conn, hidden]);
    expect(listed[1]).toEqual({
      id: hidden,
      name: hidden,
      origin: 'https://api.example.com',
      description: 'Send X-Account: synthetic.',
      policy_json: JSON.stringify({ paths: ['/v1'], methods: ['GET'] }),
      granted: false,
      expires_at: null,
      extensions: [],
    });
    await grantWith({ paths: ['/v2/tokens'], methods: ['DELETE'] });
    expect((await metadata(env, principal)).connections[0]).toMatchObject({
      id: conn,
      granted: true,
      extensions: [{ paths: ['/v2/tokens'], methods: ['DELETE'], expiresAt: null }],
    });
  });
});

describe('regular scope and temporary extensions', () => {
  const revokeToken = { method: 'DELETE', path: '/v2/tokens/abc' };
  const pending = (rid: string) =>
    env.DB.prepare('SELECT client_id,requested_json FROM access_requests WHERE id=?')
      .bind(rid)
      .first<{ client_id: string; requested_json: string }>();
  // The approval route: an Agent asks for a grant with an extension and the Owner approves it.
  const approveGrant = async (extension: object, expiresAt: number | null = null) => {
    const { id: rid } = await accessRequest(
      env,
      principal,
      {
        requested: {
          grants: [{ resourceType: 'connection', resourceId: conn, permission: 'connection:invoke', ...extension }],
        },
        reason: 'Revoke the token "ci-deploy" created 2026-09-01, found by name in GET /v2/tokens.',
      },
      'https://vault',
    );
    await decideRequest(env, owner, rid, (await pending(rid))!, true, expiresAt);
    return rid;
  };
  const extensions = async () => (await metadata(env, principal)).connections[0].extensions;

  it('reports the grant as it stands, not as approved, with each extension keeping its own expiry', async () => {
    const month = Date.now() + 2592000000;
    const first = await approveGrant({}, month);
    const standing = { resource_type: 'connection', resource_id: conn, permission: 'connection:invoke' };
    expect(await accessStatus(env, principal, first)).toEqual({
      id: first,
      status: 'approved',
      grants: [{ ...standing, expires_at: month, extensions: [] }],
    });
    // A one hour extension leaves the month-long grant in place; both the status and the list say so.
    const hour = Date.now() + 3600000;
    const rid = await approveGrant({ paths: ['/v2/tokens'], methods: ['DELETE'] }, hour);
    expect((await accessStatus(env, principal, rid)).grants).toEqual([
      { ...standing, expires_at: month, extensions: [{ paths: ['/v2/tokens'], methods: ['DELETE'], expiresAt: hour }] },
    ]);
    expect((await metadata(env, principal)).connections[0]).toMatchObject({ granted: true, expires_at: month });
    await env.DB.prepare("UPDATE grants SET status='revoked'").run();
    expect((await accessStatus(env, principal, rid)).grants).toEqual([]);
    const permanent = await approveGrant({}, null);
    expect((await accessStatus(env, principal, permanent)).grants).toMatchObject([{ expires_at: null }]);
  });

  it('runs an out-of-scope request on a one-time approval, not on a plain grant or a free rule', async () => {
    await env.DB.prepare('UPDATE connections SET policy_json=? WHERE id=?')
      .bind(JSON.stringify({ ...policy, free: ['* /*'] }), conn)
      .run();
    await grant();
    await expect(call(revokeToken)).rejects.toMatchObject({
      code: 'path_not_allowed',
      message: expect.stringMatching(/not a prohibition.*requested\.invocation.*paths/),
    });
    await expect(call({ method: 'PUT', path: '/v1/items' })).rejects.toMatchObject({
      code: 'method_not_allowed',
      message: expect.stringContaining('methods (and paths if needed)'),
    });
    await approve(await submit(revokeToken));
    expect((await call(revokeToken)).status).toBe(200);
    await expect(call(revokeToken)).rejects.toMatchObject({ code: 'path_not_allowed' });
    await approve(await submit({ method: 'PUT', path: '/v1/items' }));
    expect((await call({ method: 'PUT', path: '/v1/items' })).status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(2);
  });

  it('runs exactly what an extension covers outside the regular scope', async () => {
    await grantWith({ paths: ['/v2/tokens'], methods: ['DELETE'] });
    expect((await call(revokeToken)).status).toBe(200);
    expect((await call({ method: 'DELETE', path: '/v2/tokens' })).status).toBe(200);
    await expect(call({ method: 'GET', path: '/v2/tokens' })).rejects.toMatchObject({ code: 'path_not_allowed' });
    await expect(call({ method: 'DELETE', path: '/v2/tokensx' })).rejects.toMatchObject({ code: 'path_not_allowed' });
    await expect(call({ method: 'PUT', path: '/v1/items' })).rejects.toMatchObject({ code: 'method_not_allowed' });
    // An absent list stands for the connection's own paths or methods.
    await grantWith({ methods: ['PUT'] });
    expect((await call({ method: 'PUT', path: '/v1/items' })).status).toBe(200);
    await expect(call({ method: 'PUT', path: '/v2/items' })).rejects.toMatchObject({ code: 'path_not_allowed' });
    await grantWith({ paths: ['/v2/zones'] });
    expect((await call({ method: 'POST', path: '/v2/zones/1' })).status).toBe(200);
    await expect(call({ method: 'PUT', path: '/v2/zones/1' })).rejects.toMatchObject({ code: 'path_not_allowed' });
  });

  it('lets deny rules beat an extension and a one-time approval, and approval rules beat an extension', async () => {
    const root = { method: 'DELETE', path: '/v2/tokens/root' };
    await grantWith({ paths: ['/v2/tokens'], methods: ['DELETE'] });
    const rid = await submit(root);
    await approve(rid);
    await env.DB.prepare('UPDATE connections SET policy_json=? WHERE id=?')
      .bind(JSON.stringify({ ...policy, deny: ['DELETE /v2/tokens/root'], approval: ['DELETE /v2/tokens/*'] }), conn)
      .run();
    await expect(call(root)).rejects.toMatchObject({ code: 'path_denied' });
    await expect(submit(root)).rejects.toMatchObject({ code: 'path_denied' });
    expect(await status(rid)).toBe('approved');
    await expect(call(revokeToken)).rejects.toMatchObject({ code: 'approval_required' });
    await approve(await submit(revokeToken));
    expect((await call(revokeToken)).status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('ends an extension with its grant, and never revives it with a later grant', async () => {
    await approveGrant({ paths: ['/v2/tokens'], methods: ['DELETE'] });
    expect((await call(revokeToken)).status).toBe(200);
    await env.DB.prepare("UPDATE grants SET status='revoked'").run();
    await expect(call(revokeToken)).rejects.toMatchObject({ code: 'path_not_allowed' });
    await approveGrant({});
    await expect(call(revokeToken)).rejects.toMatchObject({ code: 'path_not_allowed' });
    expect(await extensions()).toEqual([]);
    await approveGrant({ paths: ['/v2/tokens'], methods: ['DELETE'] });
    await env.DB.prepare('UPDATE grants SET expires_at=?')
      .bind(Date.now() - 1000)
      .run();
    await expect(call(revokeToken)).rejects.toMatchObject({ code: 'path_not_allowed' });
  });

  it('keeps the expiry chosen for an extension even when the grant already lasts longer', async () => {
    await grantWith({});
    const hour = Date.now() + 3600000;
    await approveGrant({ paths: ['/v2/tokens'], methods: ['DELETE'] }, hour);
    expect(await extensions()).toEqual([{ paths: ['/v2/tokens'], methods: ['DELETE'], expiresAt: hour }]);
    expect((await env.DB.prepare('SELECT expires_at FROM grants').first())?.expires_at).toBeNull();
    await approveGrant({ paths: ['/v2/keys'] }, Date.now() - 1000);
    await expect(call({ path: '/v2/keys' })).rejects.toMatchObject({ code: 'path_not_allowed' });
    expect((await call({ path: '/v1/items' })).status).toBe(200);
  });

  it('adds an approved extension to the live ones, while the Owner form replaces them', async () => {
    await approveGrant({ paths: ['/v2/tokens'], methods: ['DELETE'] });
    await approveGrant({ paths: ['/v2/keys'], methods: ['PATCH'] });
    await approveGrant({ paths: ['/v2/tokens'], methods: ['DELETE'] });
    expect(await extensions()).toHaveLength(2);
    expect((await call(revokeToken)).status).toBe(200);
    expect((await call({ method: 'PATCH', path: '/v2/keys/1' })).status).toBe(200);
    // The union keeps each approved pair; it never crosses one path with another's method.
    await expect(call({ method: 'PATCH', path: '/v2/tokens/abc' })).rejects.toMatchObject({
      code: 'path_not_allowed',
    });
    await grantWith({ paths: ['/v2/zones'] });
    expect(await extensions()).toEqual([{ paths: ['/v2/zones'], methods: policy.methods, expiresAt: null }]);
    await expect(call(revokeToken)).rejects.toMatchObject({ code: 'path_not_allowed' });
    await grantWith({});
    expect(await extensions()).toEqual([]);
  });

  it('validates extension paths like allowed paths and only accepts them on connection grants', async () => {
    const ask = (g: object) =>
      accessRequest(
        env,
        principal,
        {
          requested: {
            grants: [{ resourceType: 'connection', resourceId: conn, permission: 'connection:invoke', ...g }],
          },
        },
        'https://vault',
      );
    await expect(ask({ paths: ['/v2/*'] })).rejects.toMatchObject({ code: 'use_path_prefix_not_glob' });
    await expect(ask({ paths: ['/v2/../x'] })).rejects.toMatchObject({ code: 'invalid_path' });
    await expect(ask({ methods: ['TRACE'] })).rejects.toThrow();
    await expect(
      accessRequest(
        env,
        principal,
        {
          requested: {
            grants: [{ resourceType: 'secret', resourceId: 's', permission: 'secret:read', methods: ['GET'] }],
          },
        },
        'https://vault',
      ),
    ).rejects.toThrow();
  });

  it('sends an encoded slash to the upstream as written and matches it by its decoded segments', async () => {
    expect((await call({ path: '/v1/public/a%2Fb' })).status).toBe(200);
    expect(String((upstream.mock.calls[0] as unknown[])[0])).toBe('https://api.example.com/v1/public/a%2Fb');
    expect((await call({ path: '/v1/public/my%20key' })).status).toBe(200);
    for (const path of ['/v1/public%2Fhidden', '/v1%2Fpublic%2Fhidden', '/v1/PUBLIC%2FHIDDEN', '/v1/secret%2Fkey'])
      await expect(call({ path })).rejects.toMatchObject({ code: 'path_denied' });
    await expect(call({ path: '/v1/public/my key' })).rejects.toMatchObject({ code: 'invalid_path' });
    await expect(call({ path: '/v1/public/a%2F%2Fb' })).rejects.toMatchObject({ code: 'invalid_path' });
    await expect(call({ path: '/v1/public/%2F..%2F..%2Fsecret' })).rejects.toMatchObject({ code: 'invalid_path' });
  });

  it('fixes a list the extension leaves out to the connection as approved, so editing it later widens nothing', async () => {
    await approveGrant({ methods: ['DELETE'] });
    await approveGrant({ paths: ['/v2/zones'] });
    const fixed = await extensions();
    expect(fixed).toHaveLength(2);
    expect(fixed).toEqual(
      expect.arrayContaining([
        { paths: ['/v1'], methods: ['DELETE'], expiresAt: null },
        { paths: ['/v2/zones'], methods: policy.methods, expiresAt: null },
      ]),
    );
    await env.DB.prepare('UPDATE connections SET policy_json=? WHERE id=?')
      .bind(JSON.stringify({ ...policy, paths: ['/v1', '/v3'], methods: ['GET', 'HEAD', 'POST', 'PUT'] }), conn)
      .run();
    await expect(call({ method: 'DELETE', path: '/v3/x' })).rejects.toMatchObject({ code: 'method_not_allowed' });
    await expect(call({ method: 'PUT', path: '/v2/zones/1' })).rejects.toMatchObject({ code: 'path_not_allowed' });
    expect((await call({ method: 'DELETE', path: '/v1/x' })).status).toBe(200);
    expect((await call({ method: 'POST', path: '/v2/zones/1' })).status).toBe(200);
  });

  it('gives every refusal a next step', async () => {
    const hint = async (c: Call) => {
      const e = await call(c).catch((e: unknown) => e as { code: string; message: string });
      expect(e).toBeTruthy();
      return e as { code: string; message: string };
    };
    for (const [c, code] of [
      [revokeToken, 'path_not_allowed'],
      [{ method: 'PUT', path: '/v1/items' }, 'method_not_allowed'],
      [write, 'grant_required'],
      [{ method: 'DELETE', path: '/v1/items/1' }, 'approval_required'],
      [{ path: '/v1/secret/x' }, 'path_denied'],
      [{ path: '/v1/a;b' }, 'invalid_path'],
    ] as const) {
      const e = await hint(c);
      expect(e.code).toBe(code);
      expect(e.message.length).toBeGreaterThan(code.length + 20);
    }
    await expect(call({ ...write, body: 'é'.repeat(600000) })).rejects.toMatchObject({
      code: 'body_too_large',
      message: expect.stringContaining('host’s own tools'),
    });
    upstream.mockRejectedValueOnce(new Error('lost'));
    await expect(call({ path: '/v1/public/x' })).rejects.toMatchObject({
      code: 'upstream_outcome_unknown',
      message: expect.stringContaining('Read the upstream state'),
    });
  });
});

describe('MCP tool errors', () => {
  // One tools/call through the real MCP handler, returning the transport status and the tool result.
  const tool = async (name: string, args: object) => {
    const response = await handleMcp(
      new Request('https://vault.example.com/v1/mcp', {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
      }),
      env,
      principal,
    );
    const message = (await response.json()) as { result: { isError?: boolean; content: { text: string }[] } };
    return {
      status: response.status,
      isError: !!message.result.isError,
      ...(JSON.parse(message.result.content[0].text) as { error?: string; hint?: string }),
    };
  };

  it('answers an oversized http.request body as a tool error with a hint, not a transport 413', async () => {
    expect(
      await tool('http.request', { connection: conn, method: 'PUT', path: '/v1/x', body: '汉'.repeat(400000) }),
    ).toMatchObject({ status: 200, isError: true, error: 'body_too_large', hint: expect.stringContaining('1 MiB') });
    expect(
      await tool('http.request', { connection: conn, method: 'PUT', path: '/v1/x', body: 'x'.repeat(1100000) }),
    ).toMatchObject({ isError: true, error: 'body_too_large' });
    expect(upstream).not.toHaveBeenCalled();
  });

  it.each([
    ['an illegal connection id', 'http.request', { connection: 'bad id!', path: '/v1/x' }, /^connection: an id is/],
    [
      'more than 100 query parameters',
      'http.request',
      {
        connection: conn,
        path: '/v1/x',
        query: Object.fromEntries(Array.from({ length: 101 }, (_, i) => [`q${i}`, '1'])),
      },
      /^query: at most 100 query parameters/,
    ],
    [
      'paths on a secret grant',
      'access.request',
      {
        requested: { grants: [{ resourceType: 'secret', resourceId: 's', permission: 'secret:read', paths: ['/x'] }] },
      },
      /^requested\.grants\.0: paths and methods apply only to connection grants/,
    ],
    [
      'an invocation without method and path',
      'access.request',
      { requested: { invocation: { connection: conn } } },
      /requested\.invocation\.path: .*requested\.invocation\.method: /,
    ],
  ])('names the field behind invalid_arguments: %s', async (_label, name, args, hint) => {
    expect(await tool(name, args)).toMatchObject({
      isError: true,
      error: 'invalid_arguments',
      hint: expect.stringMatching(hint),
    });
  });

  it('gives a next step for an unknown request, an oversized URL and a glob in an extension path', async () => {
    expect(await tool('access.status', { id: 'does-not-exist' })).toMatchObject({
      error: 'request_not_found',
      hint: expect.stringContaining('access.request'),
    });
    expect(
      await tool('http.request', {
        connection: conn,
        path: '/v1/public/x',
        query: { a: 'b'.repeat(8000), c: 'd'.repeat(8000), e: 'f'.repeat(1000) },
      }),
    ).toMatchObject({ error: 'query_too_large', hint: expect.stringContaining('16 KiB') });
    expect(
      await tool('access.request', {
        requested: {
          grants: [{ resourceType: 'connection', resourceId: conn, permission: 'connection:invoke', paths: ['/v2/*'] }],
        },
      }),
    ).toMatchObject({ error: 'use_path_prefix_not_glob', hint: expect.stringContaining('literal prefix') });
  });

  it('takes an origin on http.request and access.request, naming the host a connection does not list', async () => {
    const elsewhere = { connection: conn, method: 'GET', path: '/v1/items', origin: 'https://files.example.net' };
    const unlisted = {
      status: 200,
      isError: true,
      error: 'host_not_allowed',
      hint: expect.stringContaining('files'),
    };
    expect(await tool('http.request', elsewhere)).toMatchObject(unlisted);
    expect(await tool('access.request', { requested: { invocation: elsewhere } })).toMatchObject(unlisted);
    await env.DB.prepare('UPDATE connections SET policy_json=? WHERE id=?')
      .bind(JSON.stringify({ ...policy, hosts: ['files.example.net'] }), conn)
      .run();
    expect(await tool('http.request', elsewhere)).toMatchObject({
      error: 'approval_required',
      hint: expect.stringContaining('same origin'),
    });
    const submitted = (await tool('access.request', { requested: { invocation: elsewhere } })) as { id?: string };
    await approve(submitted.id!);
    expect(await tool('http.request', elsewhere)).toMatchObject({ status: 200, isError: false });
    expect(String((upstream.mock.calls[0] as unknown[])[0])).toBe('https://files.example.net/v1/items');
    // The connection's policy tells an installation which other hosts it may ask for.
    const listed = (await metadata(env, principal)).connections.find((c) => c.id === conn)!;
    expect(JSON.parse(listed.policy_json)).toMatchObject({ hosts: ['files.example.net'] });
  });
});
