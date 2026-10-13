import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { ZodError } from 'zod';
import { applyMigrations } from '../scripts/migrations.mjs';
import worker from '../apps/worker/src/index';
import { accessRequest, accessStatus, boundSecret, invoke, invokeInput } from '../apps/worker/src/vault';
import { type Bindings, type Principal, issuesHint } from '../apps/worker/src/context';

// Real D1 and the real approval route, so a setup's credential, connection and approval are observed
// as one batch and its values pass through the same encryption as the Owner's own form.
const origin = 'http://localhost:8787';
const token = Buffer.from('bootstrap-token-for-proposals').toString('base64url');
const password = 'synthetic-password-for-proposals';
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let mf: Miniflare,
  env: Bindings,
  cookie = '',
  agent: Principal;
const upstream = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response('ok'));

const digest = async (value: string) =>
  Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))).toString('base64url');
async function call(path: string, method = 'GET', body?: unknown, bindings = env) {
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
    bindings,
    context,
  );
  const text = await response.text();
  return { status: response.status, body: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
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
    AUTH_SECRET: 'synthetic-auth-secret-for-proposals',
    KEK_RING: `v1:${Buffer.from('p'.repeat(32)).toString('base64url')}`,
    ACTIVE_KEK_ID: 'v1',
    BOOTSTRAP_HASH: await digest(token),
  } as unknown as Bindings;
  const bootstrap = await worker.fetch(
    new Request(origin + '/bootstrap', {
      method: 'POST',
      headers: { origin, 'content-type': 'application/json', 'x-bootstrap-token': token },
      body: JSON.stringify({ name: 'Owner', email: 'owner@example.com', password }),
    }),
    env,
    context,
  );
  expect(bootstrap.status).toBe(201);
  const login = await worker.fetch(
    new Request(origin + '/api/auth/sign-in/email', {
      method: 'POST',
      headers: { origin, 'cf-connecting-ip': '127.0.0.1', 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'owner@example.com', password }),
    }),
    env,
    context,
  );
  expect(login.status).toBe(200);
  cookie = login.headers
    .getSetCookie()
    .map((value) => value.split(';')[0])
    .join('; ');
  const owner = await db.prepare("SELECT value FROM system_state WHERE key='owner_user_id'").first<{ value: string }>();
  agent = { userId: owner!.value, clientId: 'client', scopes: ['connection:invoke', 'access:request'] };
  vi.stubGlobal('fetch', upstream);
});
afterAll(async () => {
  vi.unstubAllGlobals();
  await mf.dispose();
});
beforeEach(() => upstream.mockClear());

let serial = 0;
// Names stay taken after deletion, so every draft gets its own.
const draft = () => {
  const n = ++serial;
  return {
    secret: { name: `Vendor key ${n}`, description: 'Synthetic', fields: ['token'] },
    connections: [
      {
        name: `Vendor ${n}`,
        origin: 'https://api.vendor.example',
        paths: ['/v1'],
        methods: ['GET', 'POST'],
        deny: ['/v1/admin/*'],
        approval: ['POST /v1/payments/*'],
        free: ['/v1/status'],
        auth: { type: 'bearer', field: 'token' },
        tests: [
          { method: 'GET', path: '/v1/status', expect: 'run' },
          { method: 'GET', path: '/v1/items', expect: 'grant_required' },
          { method: 'GET', path: '/v1/items', grant: true, expect: 'run' },
          { method: 'DELETE', path: '/v1/admin/users', grant: true, expect: 'path_denied' },
          { method: 'POST', path: '/v1/payments/1', grant: true, expect: 'approval_required' },
          { method: 'GET', path: '/v2/x', grant: true, expect: 'path_not_allowed' },
          { method: 'PUT', path: '/v1/items', grant: true, expect: 'method_not_allowed' },
        ],
      },
    ],
  };
};
type Draft = ReturnType<typeof draft>;
// The same credential for a second host of the vendor, under another header; its downloads come from
// hosts below one more name, which the draft lists for one-time approvals.
const twoHosts = () => {
  const d = draft();
  const [api] = d.connections;
  const files = {
    ...structuredClone(api),
    name: api.name + ' files',
    origin: 'https://files.vendor.example',
    hosts: ['*.cdn.vendor.example'],
    auth: { type: 'header', field: 'token', name: 'X-Vendor-Key' },
  };
  return { ...d, connections: [api, files] };
};
const submit = async (requested: object) =>
  (await accessRequest(env, agent, { requested, reason: 'Connect the vendor API' }, origin)).id;
const refusal = (requested: object) =>
  accessRequest(env, agent, { requested, reason: 'r' }, origin).catch((e: unknown) => e);
const hint = async (requested: object) => issuesHint((await refusal(requested)) as ZodError);
const stored = async (rid: string) =>
  JSON.parse(
    (await env.DB.prepare('SELECT requested_json FROM access_requests WHERE id=?')
      .bind(rid)
      .first<{ requested_json: string }>())!.requested_json,
  );
const requestStatus = async (rid: string) =>
  (await env.DB.prepare('SELECT status FROM access_requests WHERE id=?').bind(rid).first<{ status: string }>())!.status;
const count = async (table: string) =>
  (await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>())!.n;
// What the Owner's side recorded about a resource; invocations are audited separately.
const actions = async (resource: string) =>
  (
    await env.DB.prepare(
      "SELECT action FROM audit_events WHERE resource_id=? AND client_id='owner' ORDER BY created_at",
    )
      .bind(resource)
      .all<{ action: string }>()
  ).results.map((r) => r.action);
const send = (connection: string, method: string, path: string) =>
  invoke(env, agent, invokeInput.parse({ connection, method, path })).then(
    () => 'run',
    (e: { code: string }) => e.code,
  );

describe('setup submission', () => {
  it('runs each connection’s tests on its draft policy and refuses any mismatch, naming each', async () => {
    const d = twoHosts();
    d.connections[0].tests[1].expect = 'run';
    d.connections[1].tests[3].expect = 'approval_required';
    await expect(submit({ setup: d })).rejects.toMatchObject({
      code: 'tests_failed',
      status: 400,
      message: expect.stringMatching(
        /^2 of 14 tests .*connections\.0 "Vendor \d+" tests\.1 GET \/v1\/items without a grant: expected run, got grant_required; connections\.1 "Vendor \d+ files" tests\.3 DELETE \/v1\/admin\/users with a grant: expected approval_required, got path_denied from "deny \* \/v1\/admin\/\*"$/,
      ),
    });
    expect(await count('access_requests')).toBe(0);
  });

  it('reports a malformed draft at submission, naming the connection, the field and the line', async () => {
    // The fault lies in the second connection, so the hint has to say which one it is.
    const with_ = (connection: object) => {
      const d = twoHosts();
      return { setup: { ...d, connections: [d.connections[0], { ...d.connections[1], ...connection }] } };
    };
    await expect(submit(with_({ deny: ['GET /v1/x', 'nope'] }))).rejects.toMatchObject({
      code: 'invalid_rule',
      message: expect.stringMatching(/^connections\.1 "Vendor \d+ files": deny line 2$/),
    });
    await expect(submit(with_({ paths: ['/v1', '/v2/*'] }))).rejects.toMatchObject({
      code: 'use_path_prefix_not_glob',
      message: expect.stringMatching(/^connections\.1 "Vendor \d+ files": paths line 2: /),
    });
    await expect(submit(with_({ origin: 'http://api.vendor.example' }))).rejects.toMatchObject({
      code: 'origin_must_be_https',
      message: expect.stringMatching(/^connections\.1 "Vendor \d+ files": /),
    });
    await expect(submit(with_({ origin: 'https://api.vendor.example/v1' }))).rejects.toMatchObject({
      code: 'origin_must_not_contain_path',
    });
    const bad = draft();
    bad.connections[0].tests[0].path = '/v1/a;b';
    expect(await hint({ setup: bad })).toMatch(/^requested\.setup\.connections\.0\.tests\.0\.path: The path contains/);
    expect(await hint(with_({ tests: [] }))).toMatch(/^requested\.setup\.connections\.1\.tests: /);
    expect(await hint({ setup: { ...draft(), connections: [] } })).toMatch(/^requested\.setup\.connections: /);
    // A setup lists its connections, each with its own tests; a single connection beside one shared
    // test table is not read as one.
    const { secret, connections } = draft();
    const { tests, ...connection } = connections[0];
    expect(await hint({ setup: { secret, connection, tests } })).toContain('requested.setup.connections: ');
    const update = { connection: 'x', changes: { name: 'y' }, tests: [{ method: 'GET', path: '/', expect: 'run' }] };
    expect(await hint({ setup: draft(), update })).toContain('exactly one of grants or invocation or setup or update');
    expect(await count('access_requests')).toBe(0);
  });

  it('never binds an existing secret and keeps every auth within the fields it creates', async () => {
    const d = twoHosts();
    // Only the second connection departs from the draft; the first stays a valid bearer binding.
    const auth = (a: object, withSecret = true) => ({
      setup: {
        secret: withSecret ? d.secret : undefined,
        connections: [d.connections[0], { ...d.connections[1], auth: a }],
      },
    });
    expect(await hint(auth({ type: 'bearer', secretId: 'existing', field: 'token' }))).toBe(
      'requested.setup.connections.1.auth: Unrecognized key: "secretId"',
    );
    expect(await hint(auth({ type: 'header', field: 'key', name: 'X-Key' }))).toBe(
      'requested.setup.connections.1.auth: every field auth names must be listed in secret.fields',
    );
    expect(await hint(auth({ type: 'basic', usernameField: 'token', passwordField: 'password' }))).toContain(
      'every field auth names must be listed in secret.fields',
    );
    // With a secret no connection may go without it; without one, none may inject.
    expect(await hint(auth({ type: 'none' }))).toMatch(
      /^requested\.setup\.connections\.1\.auth: a setup with secret injects it in every connection/,
    );
    expect(await hint(auth({ type: 'none' }, false))).toMatch(
      /^requested\.setup\.connections\.0\.auth: a setup with secret injects it in every connection/,
    );
    expect(await hint({ setup: { ...d, secret: { ...d.secret, values: { token: 'x' } } } })).toBe(
      'requested.setup.secret: Unrecognized key: "values"',
    );
    expect(await hint({ setup: { ...d, secret: { ...d.secret, fields: ['token', 'token'] } } })).toContain(
      'field names must be unique',
    );
    expect(await count('access_requests')).toBe(0);
  });

  it('lets a connection list extra hosts but never reach any host, which only the Owner sets', async () => {
    const d = twoHosts();
    const [api, files] = d.connections;
    expect(await hint({ setup: { ...d, connections: [api, { ...files, anyHost: true }] } })).toBe(
      'requested.setup.connections.1.anyHost: only the Owner can let a connection reach any host, on the connections page; list hosts instead',
    );
    await expect(
      submit({ setup: { ...d, connections: [api, { ...files, hosts: ['*.cdn.vendor.example', '*.example'] }] } }),
    ).rejects.toMatchObject({
      code: 'invalid_host',
      message: expect.stringMatching(/^connections\.1 "Vendor \d+ files": hosts line 2$/),
    });
    expect(await count('access_requests')).toBe(0);
  });

  it('refuses two connections of one draft under the same name, and allows the same origin', async () => {
    const d = twoHosts();
    const [api, files] = d.connections;
    expect(await hint({ setup: { ...d, connections: [api, { ...files, name: ` ${api.name} ` }] } })).toBe(
      'requested.setup.connections: connection names must be unique',
    );
    expect(await count('access_requests')).toBe(0);
    await submit({ setup: { ...d, connections: [api, { ...files, origin: api.origin }] } });
  });

  it('refuses a name already taken, since approval could never create it', async () => {
    const d = twoHosts();
    await call('/admin/connections', 'POST', { ...d.connections[1], auth: { type: 'none' } });
    await expect(submit({ setup: d })).rejects.toMatchObject({
      code: 'name_taken',
      status: 409,
      message: expect.stringContaining(`"${d.connections[1].name}"`),
    });
  });

  // An installation lists only the credentials granted to it, so a submission must not reveal whether a
  // credential it cannot see has a given name; only the Owner learns it, on approval.
  it('answers a credential name the installation cannot see like a free one, and tells the Owner', async () => {
    await call('/admin/secrets', 'POST', { name: 'Hidden key', values: { token: 'synthetic-hidden-value' } });
    const named = (name: string) => {
      const d = draft();
      return { ...d, secret: { ...d.secret, name } };
    };
    const probe = (name: string) => {
      const d = named(name);
      d.connections[0].tests[0].expect = 'path_denied';
      return submit({ setup: d }).then(
        () => 'accepted',
        (e: { code: string }) => e.code,
      );
    };
    const before = [await count('access_requests'), await count('audit_events')];
    expect(await probe('Hidden key')).toBe('tests_failed');
    expect(await probe('Never used name')).toBe('tests_failed');
    expect([await count('access_requests'), await count('audit_events')]).toEqual(before);
    const rid = await submit({ setup: named('Hidden key') });
    const created = [await count('secrets'), await count('connections')];
    expect(
      await call(`/admin/access-requests/${rid}/approve`, 'POST', { values: { token: 'vendor-token' } }),
    ).toMatchObject({ status: 409, body: { error: 'secret_name_taken', hint: expect.stringContaining('Deny it') } });
    expect([await count('secrets'), await count('connections')]).toEqual(created);
    expect(await requestStatus(rid)).toBe('pending');
  });

  it('matches a resubmitted draft to the pending request', async () => {
    const d = twoHosts();
    const rid = await submit({ setup: d });
    const { ids } = await stored(rid);
    expect(await submit({ setup: d })).toBe(rid);
    expect((await stored(rid)).ids).toEqual(ids);
    const [api, files] = d.connections;
    expect(await submit({ setup: { ...d, connections: [api, { ...files, tests: files.tests.slice(1) }] } })).not.toBe(
      rid,
    );
  });
});

describe('setup approval', () => {
  it('refuses values that differ from the draft fields or fail the binding checks, creating nothing', async () => {
    const rid = await submit({ setup: draft() });
    const before = [await count('secrets'), await count('connections')];
    for (const [values, code] of [
      [{ token: 'a', extra: 'b' }, 'secret_fields_mismatch'],
      [{ other: 'a' }, 'secret_fields_mismatch'],
      [{}, 'invalid_input'],
      [{ token: ' padded ' }, 'invalid_header_credential'],
      [{ token: 'x'.repeat(16385) }, 'invalid_input'],
    ] as const)
      expect(await call(`/admin/access-requests/${rid}/approve`, 'POST', { values })).toMatchObject({
        status: 400,
        body: { error: code },
      });
    expect((await call(`/admin/access-requests/${rid}/approve`, 'POST')).status).toBe(400);
    expect([await count('secrets'), await count('connections')]).toEqual(before);
    expect(await requestStatus(rid)).toBe('pending');
  });

  it('creates the credential, the connection and the approval together under the ids fixed on submission', async () => {
    const d = draft();
    const rid = await submit({ setup: d });
    const { ids } = await stored(rid);
    expect(await accessStatus(env, agent, rid)).toEqual({ id: rid, status: 'pending', expires_at: expect.any(Number) });
    expect(
      await call(`/admin/access-requests/${rid}/approve`, 'POST', { values: { token: 'vendor-token' } }),
    ).toMatchObject({ status: 200 });
    const [connectionId] = ids.connectionIds;
    expect(await accessStatus(env, agent, rid)).toEqual({
      id: rid,
      status: 'approved',
      connectionIds: [connectionId],
      secretId: ids.secretId,
    });
    const conn = await env.DB.prepare('SELECT name,origin,auth_json,policy_json FROM connections WHERE id=?')
      .bind(connectionId)
      .first<{ name: string; origin: string; auth_json: string; policy_json: string }>();
    expect(conn).toMatchObject({ name: d.connections[0].name, origin: 'https://api.vendor.example' });
    expect(JSON.parse(conn!.auth_json)).toEqual({ type: 'bearer', secretId: ids.secretId, field: 'token' });
    expect(JSON.parse(conn!.policy_json)).toEqual({
      paths: ['/v1'],
      methods: ['GET', 'POST'],
      deny: ['* /v1/admin/*'],
      approval: ['POST /v1/payments/*'],
      free: ['GET /v1/status'],
      hosts: [],
      anyHost: false,
    });
    expect(await boundSecret(env, agent.userId, ids.secretId)).toEqual({
      version: 1,
      values: { token: 'vendor-token' },
    });
    expect(await actions(ids.secretId)).toEqual(['secret:create']);
    expect(await actions(connectionId)).toEqual(['connection:save']);
    expect(await actions(rid)).toEqual(['access:approve']);
    // A setup carries no grant: only the free rule runs, with the new credential injected.
    expect(await count('grants')).toBe(0);
    expect(await send(connectionId, 'GET', '/v1/status')).toBe('run');
    expect(new Headers(upstream.mock.calls[0][1]!.headers).get('authorization')).toBe('Bearer vendor-token');
    expect(await send(connectionId, 'GET', '/v1/items')).toBe('grant_required');
    // A second approval finds nothing pending and audits nothing.
    expect(
      await call(`/admin/access-requests/${rid}/approve`, 'POST', { values: { token: 'vendor-token' } }),
    ).toMatchObject({ status: 404 });
    expect(await actions(ids.secretId)).toEqual(['secret:create']);
    expect(await actions(connectionId)).toEqual(['connection:save']);
    expect(await actions(rid)).toEqual(['access:approve']);
  });

  // The first connection's query binding takes any value and only the second one's header binding
  // refuses this one, so the check has to reach every connection.
  it('checks the entered values against the binding of every connection, creating nothing when one refuses', async () => {
    const d = twoHosts();
    const [api, files] = d.connections;
    const rid = await submit({
      setup: { ...d, connections: [{ ...api, auth: { type: 'query', field: 'token', name: 'api_key' } }, files] },
    });
    const before = [await count('secrets'), await count('connections')];
    expect(await call(`/admin/access-requests/${rid}/approve`, 'POST', { values: { token: 'töken' } })).toMatchObject({
      status: 400,
      body: { error: 'invalid_header_credential' },
    });
    expect([await count('secrets'), await count('connections')]).toEqual(before);
    expect(await requestStatus(rid)).toBe('pending');
  });

  it('binds every connection of a draft to the one credential the Owner entered once', async () => {
    const d = twoHosts();
    const rid = await submit({ setup: d });
    const { ids, setup } = await stored(rid);
    expect(ids.connectionIds).toHaveLength(2);
    expect(new Set([ids.secretId, ...ids.connectionIds]).size).toBe(3);
    // No draft holds a secretId: the binding is written on approval, from the id the server fixed.
    expect(JSON.stringify(setup)).not.toContain('secretId');
    const secrets = await count('secrets');
    expect(
      await call(`/admin/access-requests/${rid}/approve`, 'POST', { values: { token: 'shared-token' } }),
    ).toMatchObject({ status: 200 });
    expect(await count('secrets')).toBe(secrets + 1);
    expect(await accessStatus(env, agent, rid)).toEqual({
      id: rid,
      status: 'approved',
      connectionIds: ids.connectionIds,
      secretId: ids.secretId,
    });
    const rows = await Promise.all(
      (ids.connectionIds as string[]).map((cid) =>
        env.DB.prepare('SELECT name,origin,auth_json,policy_json FROM connections WHERE id=?')
          .bind(cid)
          .first<{ name: string; origin: string; auth_json: string; policy_json: string }>(),
      ),
    );
    expect(rows.map((r) => [r!.name, r!.origin])).toEqual(d.connections.map((c) => [c.name, c.origin]));
    // The extra hosts the draft listed are saved; no draft makes a connection reach any host.
    expect(rows.map((r) => JSON.parse(r!.policy_json)).map((p) => [p.hosts, p.anyHost])).toEqual([
      [[], false],
      [['*.cdn.vendor.example'], false],
    ]);
    expect(rows.map((r) => JSON.parse(r!.auth_json))).toEqual([
      { type: 'bearer', secretId: ids.secretId, field: 'token' },
      { type: 'header', secretId: ids.secretId, field: 'token', name: 'X-Vendor-Key' },
    ]);
    expect(await actions(ids.secretId)).toEqual(['secret:create']);
    for (const cid of ids.connectionIds) expect(await actions(cid)).toEqual(['connection:save']);
    // Each host receives the same value, the way its own connection injects it.
    for (const cid of ids.connectionIds) expect(await send(cid, 'GET', '/v1/status')).toBe('run');
    const sent = upstream.mock.calls.map(([url, init]) => [String(url), new Headers(init!.headers)] as const);
    expect(sent.map(([url]) => new URL(url).origin)).toEqual(d.connections.map((c) => c.origin));
    expect(sent[0][1].get('authorization')).toBe('Bearer shared-token');
    expect(sent[1][1].get('x-vendor-key')).toBe('shared-token');
    expect(sent[1][1].get('authorization')).toBeNull();
  });

  it('creates neither the credential nor any connection when one name was taken after submission', async () => {
    const d = twoHosts();
    const rid = await submit({ setup: d });
    const { ids } = await stored(rid);
    await call('/admin/connections', 'POST', { ...d.connections[1], auth: { type: 'none' } });
    const before = [await count('secrets'), await count('secret_versions'), await count('connections')];
    expect(
      await call(`/admin/access-requests/${rid}/approve`, 'POST', { values: { token: 'shared-token' } }),
    ).toMatchObject({ status: 409, body: { error: 'conflict' } });
    expect([await count('secrets'), await count('secret_versions'), await count('connections')]).toEqual(before);
    expect(await env.DB.prepare('SELECT 1 FROM secrets WHERE id=?').bind(ids.secretId).first()).toBeNull();
    expect(await env.DB.prepare('SELECT 1 FROM connections WHERE id=?').bind(ids.connectionIds[0]).first()).toBeNull();
    expect(await requestStatus(rid)).toBe('pending');
    expect(await accessStatus(env, agent, rid)).toEqual({ id: rid, status: 'pending', expires_at: expect.any(Number) });
    expect(await actions(rid)).toEqual([]);
  });

  it('creates connections without a credential and takes no values for them', async () => {
    const d = twoHosts();
    const rid = await submit({
      setup: { connections: d.connections.map((c) => ({ ...c, auth: { type: 'none' } })) },
    });
    const secrets = await count('secrets');
    expect((await call(`/admin/access-requests/${rid}/approve`, 'POST')).status).toBe(200);
    const status = await accessStatus(env, agent, rid);
    expect(status).toMatchObject({ status: 'approved', connectionIds: [expect.any(String), expect.any(String)] });
    expect(status).not.toHaveProperty('secretId');
    expect(await count('secrets')).toBe(secrets);
    for (const cid of status.connectionIds!) expect(await send(cid, 'GET', '/v1/status')).toBe('run');
  });

  it('creates nothing when denied', async () => {
    const rid = await submit({ setup: twoHosts() });
    const { ids } = await stored(rid);
    expect((await call(`/admin/access-requests/${rid}/deny`, 'POST')).status).toBe(200);
    expect(await accessStatus(env, agent, rid)).toEqual({ id: rid, status: 'denied' });
    for (const cid of ids.connectionIds)
      expect(await env.DB.prepare('SELECT 1 FROM connections WHERE id=?').bind(cid).first()).toBeNull();
    expect(await env.DB.prepare('SELECT 1 FROM secrets WHERE id=?').bind(ids.secretId).first()).toBeNull();
  });
});

describe('update of a connection', () => {
  let cid = '';
  const saved = {
    origin: 'https://api.update.example',
    paths: ['/v1'],
    methods: ['GET', 'DELETE'],
    // The Owner's own settings of where else a request may go; no update can name them.
    hosts: ['*.files.update.example'],
    anyHost: true,
    auth: { type: 'none' },
  };
  beforeEach(async () => {
    cid = String((await call('/admin/connections', 'POST', { ...saved, name: `Update target ${++serial}` })).body.id);
  });
  const tests = [
    { method: 'DELETE', path: '/v1/items/1', grant: true, expect: 'path_denied' },
    { method: 'GET', path: '/v1/status', expect: 'run' },
  ];
  const proposal = () => ({
    connection: cid,
    changes: { deny: ['DELETE /v1/items/*'], free: ['/v1/status'] },
    tests,
  });
  const grantFor = (connection: string) =>
    env.DB.prepare(
      "INSERT INTO grants (id,owner_id,client_id,resource_type,resource_id,permission,status,created_at) VALUES (?,?,?,'connection',?,'connection:invoke','active',?)",
    )
      .bind(crypto.randomUUID(), agent.userId, agent.clientId, connection, Date.now())
      .run();

  it('accepts only changes that never decide where a credential goes', async () => {
    expect(await hint({ update: { ...proposal(), changes: { origin: 'https://other.example' } } })).toContain(
      'requested.update.changes: Unrecognized key: "origin"',
    );
    expect(await hint({ update: { ...proposal(), changes: { auth: { type: 'none' } } } })).toContain(
      'requested.update.changes: Unrecognized key: "auth"',
    );
    expect(await hint({ update: { ...proposal(), changes: { hosts: ['*.other.example'] } } })).toContain(
      'requested.update.changes: Unrecognized key: "hosts"',
    );
    expect(await hint({ update: { ...proposal(), changes: { anyHost: false } } })).toContain(
      'requested.update.changes: Unrecognized key: "anyHost"',
    );
    expect(await hint({ update: { ...proposal(), changes: {} } })).toBe(
      'requested.update.changes: changes holds at least one of name, description, paths, methods, deny, approval, free',
    );
    await expect(submit({ update: { ...proposal(), connection: 'absent' } })).rejects.toMatchObject({
      code: 'connection_not_found',
    });
    await expect(
      submit({ update: { ...proposal(), changes: { approval: ['GET /v1', 'GET v1'] } } }),
    ).rejects.toMatchObject({ code: 'invalid_rule', message: 'approval line 2' });
  });

  it('runs the tests on the proposed policy and records the current decisions for comparison', async () => {
    await expect(
      submit({ update: { ...proposal(), tests: [{ ...tests[0], expect: 'run' }, tests[1]] } }),
    ).rejects.toMatchObject({
      code: 'tests_failed',
      message: expect.stringContaining('tests.0 DELETE /v1/items/1 with a grant: expected run, got path_denied'),
    });
    const rid = await submit({ update: proposal() });
    expect(await stored(rid)).toEqual({
      update: {
        connection: cid,
        changes: { deny: ['DELETE /v1/items/*'], free: ['GET /v1/status'] },
        tests: tests.map((t) => ({ grant: false, ...t })),
      },
      current: ['run', 'grant_required'],
      updatedAt: expect.any(Number),
    });
  });

  it('refuses approval once the connection changed after submission', async () => {
    const rid = await submit({ update: proposal() });
    await new Promise((done) => setTimeout(done, 5));
    await call(`/admin/connections/${cid}`, 'PUT', { ...saved, name: 'Renamed by the Owner' + serial });
    expect(await call(`/admin/access-requests/${rid}/approve`, 'POST')).toMatchObject({
      status: 409,
      body: { error: 'connection_changed' },
    });
    expect(await requestStatus(rid)).toBe('pending');
    expect((await call(`/admin/access-requests/${rid}/deny`, 'POST')).status).toBe(200);
    const deleted = await submit({ update: proposal() });
    await call(`/admin/connections/${cid}`, 'DELETE');
    expect(await call(`/admin/access-requests/${deleted}/approve`, 'POST')).toMatchObject({
      status: 409,
      body: { error: 'connection_changed' },
    });
  });

  it('applies an approved update, leaving origin and auth as they were', async () => {
    const grant = (status: string) =>
      env.DB.prepare('UPDATE grants SET status=? WHERE resource_id=?').bind(status, cid).run();
    await grantFor(cid);
    expect(await send(cid, 'DELETE', '/v1/items/1')).toBe('run');
    await grant('revoked');
    expect(await send(cid, 'GET', '/v1/status')).toBe('grant_required');
    const rid = await submit({
      update: { ...proposal(), changes: { ...proposal().changes, name: 'Renamed' + serial } },
    });
    expect((await call(`/admin/access-requests/${rid}/approve`, 'POST')).status).toBe(200);
    expect(await accessStatus(env, agent, rid)).toEqual({ id: rid, status: 'approved' });
    const conn = await env.DB.prepare('SELECT name,origin,auth_json,policy_json FROM connections WHERE id=?')
      .bind(cid)
      .first<{ name: string; origin: string; auth_json: string; policy_json: string }>();
    expect(conn).toMatchObject({ name: 'Renamed' + serial, origin: saved.origin, auth_json: '{"type":"none"}' });
    expect(JSON.parse(conn!.policy_json)).toEqual({
      paths: ['/v1'],
      methods: ['GET', 'DELETE'],
      deny: ['DELETE /v1/items/*'],
      approval: [],
      free: ['GET /v1/status'],
      hosts: ['*.files.update.example'],
      anyHost: true,
    });
    expect(await send(cid, 'GET', '/v1/status')).toBe('run');
    await grant('active');
    expect(await send(cid, 'DELETE', '/v1/items/1')).toBe('path_denied');
    expect(await actions(cid)).toEqual(['connection:save', 'connection:save']);
    expect(await actions(rid)).toEqual(['access:approve']);
  });

  it('keeps the extra hosts and anyHost of a connection through an update of its notes alone', async () => {
    const policy = async () =>
      (await env.DB.prepare('SELECT description,policy_json FROM connections WHERE id=?')
        .bind(cid)
        .first<{ description: string; policy_json: string }>())!;
    const before = await policy();
    expect(JSON.parse(before.policy_json)).toMatchObject({ hosts: ['*.files.update.example'], anyHost: true });
    const rid = await submit({
      update: {
        connection: cid,
        changes: { description: 'Send X-Team: synthetic.' },
        tests: [{ method: 'GET', path: '/v1/status', expect: 'grant_required' }],
      },
    });
    expect((await call(`/admin/access-requests/${rid}/approve`, 'POST')).status).toBe(200);
    expect(await policy()).toEqual({ description: 'Send X-Team: synthetic.', policy_json: before.policy_json });
  });
});

describe('an invocation to another origin', () => {
  const hostname = 'eu.files.blobs.example';
  // A connection the Owner saved with a credential and two extra hosts, and a request to a host under
  // the second of them.
  const blobs = async () => {
    const n = ++serial;
    const sid = String(
      (await call('/admin/secrets', 'POST', { name: `Blob key ${n}`, values: { token: 'blob-token' } })).body.id,
    );
    const save = (hosts: string[]) =>
      call('/admin/connections', 'POST', {
        name: `Blobs ${n}`,
        origin: 'https://api.blobs.example',
        paths: ['/v1'],
        methods: ['GET'],
        hosts,
        auth: { type: 'bearer', secretId: sid, field: 'token' },
      });
    const cid = String((await save(['downloads.blobs.example', '*.files.blobs.example'])).body.id);
    const invocation = { connection: cid, method: 'GET', path: '/v1/blob/7', origin: 'https://EU.files.blobs.example' };
    // What the Owner's form then changes about where else a request may go.
    const edit = (extra: object) =>
      env.DB.prepare('UPDATE connections SET policy_json=json_patch(policy_json,?) WHERE id=?')
        .bind(JSON.stringify(extra), cid)
        .run();
    return { edit, invocation };
  };

  it('names the line of a malformed extra host on the Owner’s connection form', async () => {
    expect(
      await call('/admin/connections', 'POST', {
        name: `Blobs ${++serial}`,
        origin: 'https://api.blobs.example',
        paths: ['/v1'],
        hosts: ['*.files.blobs.example', '*.example'],
      }),
    ).toMatchObject({ status: 400, body: { error: 'invalid_host', hint: 'hosts line 2' } });
  });

  it('tells the Owner where the origin stands under the connection as it is now', async () => {
    const { edit, invocation } = await blobs();
    const rid = await submit({ invocation });
    const home = await submit({ invocation: { ...invocation, origin: undefined } });
    const pending = async () =>
      (await call('/admin/status')).body.pending as { id: string; requested_json: string; elsewhere?: object }[];
    const listed = await pending();
    const elsewhere = listed.find((p) => p.id === rid)!;
    // Of the two entries the one that covers the host, not the first.
    expect(elsewhere.elsewhere).toEqual({ hostname, host: '*.files.blobs.example', anyHost: false });
    expect(JSON.parse(elsewhere.requested_json).invocation.origin).toBe('https://' + hostname);
    expect(listed.find((p) => p.id === home)).not.toHaveProperty('elsewhere');
    // The same pending request under the connection as the Owner then leaves it: no entry covers the
    // host, which is what turns the card into a warning, though the connection still lists another.
    await edit({ hosts: ['downloads.blobs.example'], anyHost: true });
    expect((await pending()).find((p) => p.id === rid)!.elsewhere).toEqual({ hostname, host: null, anyHost: true });
    await edit({ anyHost: false });
    expect((await pending()).find((p) => p.id === rid)!.elsewhere).toEqual({ hostname, host: null, anyHost: false });
  });

  it('approves it only when the approval names the origin back as stored', async () => {
    const cid = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO connections (id,owner_id,name,origin,description,auth_json,policy_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
    )
      .bind(
        cid,
        agent.userId,
        `Blobs ${++serial}`,
        'https://api.blobs.example',
        '',
        '{"type":"none"}',
        JSON.stringify({ paths: ['/v1'], methods: ['GET'], hosts: ['*.files.blobs.example'] }),
        Date.now(),
        Date.now(),
      )
      .run();
    const rid = await submit({
      invocation: { connection: cid, method: 'GET', path: '/v1/blob/7', origin: 'https://EU.files.blobs.example' },
    });
    const approve = (body?: object) => call(`/admin/access-requests/${rid}/approve`, 'POST', body);
    const stale = { status: 409, body: { error: 'origin_mismatch', hint: expect.stringContaining('Reload') } };
    // A page that never showed the origin sends none; no other spelling or address passes for it.
    for (const body of [
      undefined,
      { origin: 'https://api.blobs.example' },
      { origin: 'https://EU.files.blobs.example' },
    ])
      expect(await approve(body)).toMatchObject(stale);
    expect(await requestStatus(rid)).toBe('pending');
    expect(await actions(rid)).toEqual([]);
    expect((await approve({ origin: 'https://' + hostname })).status).toBe(200);
    expect(await requestStatus(rid)).toBe('approved');
  });

  it('holds an extra host to the public rule where local upstreams are off', async () => {
    const strict = { ...env, ALLOW_LOCAL_HTTP: 'false' } as Bindings;
    const connection = { ...draft().connections[0], auth: { type: 'none' }, hosts: ['localhost'] };
    expect(await call('/admin/connections', 'POST', connection, strict)).toMatchObject({
      status: 400,
      body: { error: 'invalid_host', hint: 'hosts line 1' },
    });
    await expect(
      accessRequest(strict, agent, { requested: { setup: { connections: [connection] } }, reason: 'r' }, origin),
    ).rejects.toMatchObject({ code: 'invalid_host', message: expect.stringMatching(/: hosts line 1$/) });
    // This suite's own environment allows the local upstream, as an origin and so as an extra host.
    expect(await submit({ setup: { connections: [connection] } })).toBeTruthy();
  });

  it('injects the connection’s credential at the approved origin, while the connection still covers it', async () => {
    const { edit, invocation } = await blobs();
    const rid = await submit({ invocation });
    const run = () => invoke(env, agent, invokeInput.parse(invocation));
    expect(
      (await call(`/admin/access-requests/${rid}/approve`, 'POST', { origin: 'https://' + hostname })).status,
    ).toBe(200);
    await edit({ hosts: [] });
    await expect(run()).rejects.toMatchObject({ code: 'host_not_allowed' });
    await edit({ hosts: ['*.files.blobs.example'] });
    expect((await run()).status).toBe(200);
    const [url, init] = upstream.mock.calls[0];
    expect(String(url)).toBe(`https://${hostname}/v1/blob/7`);
    expect(new Headers(init!.headers).get('authorization')).toBe('Bearer blob-token');
    await expect(run()).rejects.toMatchObject({ code: 'approval_required' });
    expect(await accessStatus(env, agent, rid)).toMatchObject({ status: 'executed' });
  });
});

describe('the pending requests of one installation', () => {
  // Each test counts on an installation of its own, apart from what the suite left pending.
  const installation = (): Principal => ({ ...agent, clientId: `installation-${++serial}` });
  const ask = async (p: Principal, setup: Draft) =>
    (await accessRequest(env, p, { requested: { setup }, reason: 'r' }, origin)).id;
  // Requests as accessRequest stores them, written directly: the limit counts rows, whatever they ask.
  const waiting = async (p: Principal, n: number, expiresAt = Date.now() + 3600000) => {
    const rids = Array.from({ length: n }, () => crypto.randomUUID());
    await env.DB.batch(
      rids.map((rid) =>
        env.DB.prepare(
          "INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at) VALUES (?,?,?,'{}','','pending',?,?)",
        ).bind(rid, p.userId, p.clientId, Date.now(), expiresAt),
      ),
    );
    return rids;
  };
  const pending = async (p: Principal) =>
    (
      await env.DB.prepare("SELECT id FROM access_requests WHERE client_id=? AND status='pending' ORDER BY id")
        .bind(p.clientId)
        .all<{ id: string }>()
    ).results.map((row) => row.id);

  it('stop at 20: one more is refused, a resubmission still finds its request, an expired one frees a place', async () => {
    const p = installation();
    const d = draft();
    const first = await ask(p, d);
    const rids = [first, ...(await waiting(p, 19))].sort();
    const refused = await ask(p, draft()).catch((e: unknown) => e);
    expect(refused).toMatchObject({ code: 'too_many_pending', status: 429 });
    expect((refused as Error).message).toContain('do not submit this request again');
    expect(await ask(p, d)).toBe(first);
    expect(await pending(p)).toEqual(rids);
    // Another installation is counted on its own.
    expect(await ask(installation(), draft())).toBeTruthy();
    await env.DB.prepare('UPDATE access_requests SET expires_at=? WHERE id=?')
      .bind(Date.now() - 1, rids[0])
      .run();
    expect(await ask(p, draft())).toBeTruthy();
  });

  it('are denied when the Owner revokes it, and leave the list the Owner decides from', async () => {
    const p = { ...agent, clientId: String((await call('/admin/clients', 'POST', { name: 'Revoked' })).body.clientId) };
    const first = await ask(p, draft());
    const [lapsed] = await waiting(p, 1, Date.now() - 1);
    const [kept] = await waiting(installation(), 1);
    expect((await call('/admin/clients/' + p.clientId, 'DELETE')).status).toBe(200);
    const left = ((await call('/admin/status')).body.pending as { id: string }[]).map((request) => request.id);
    expect(left).toContain(kept);
    expect(left).not.toContain(first);
    expect(await accessStatus(env, p, first)).toEqual({ id: first, status: 'denied' });
    expect(await accessStatus(env, p, lapsed)).toMatchObject({ status: 'expired' });
  });
});
