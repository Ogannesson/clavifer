import { Miniflare, Log, LogLevel, convertV4MiniflareOptions } from 'miniflare';
import { mkdir } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { generateIdentity, identityToRecipient, Decrypter } from 'age-encryption';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { resolve } from 'node:path';
import { hostSmoke } from './host-smoke.mjs';
import { oauthAcceptance } from './oauth-local-acceptance.mjs';
import { applyMigrations } from './migrations.mjs';
import { issueSql, newToken } from './bootstrap-token.mjs';

// Isolated runtime and database; credentials never leave this process or enter logs.
const origin = 'http://localhost:8787';
const password = randomBytes(24).toString('base64url');
// Retain synthetic database/backup artifacts in a unique directory for every run.
// No test cleanup removes the user's files or previous test evidence.
const runDirectory = resolve('work', 'e2e-local-' + randomUUID());
await mkdir(runDirectory, { recursive: true });
const rootKey = () => `1:${randomBytes(32).toString('base64url')}`;
// setOptions with the same state and another key restarts the Worker on the same data.
const runtime = (state, key) =>
  convertV4MiniflareOptions({
    modules: true,
    scriptPath: process.env.CLAVIFER_E2E_WORKER_PATH ?? 'dist/worker/index.js',
    compatibilityDate: '2026-09-11',
    compatibilityFlags: ['nodejs_compat'],
    log: new Log(LogLevel.ERROR),
    d1Databases: ['DB'],
    d1Persist: resolve(runDirectory, state, 'd1'),
    r2Buckets: ['BACKUPS'],
    r2Persist: resolve(runDirectory, state, 'r2'),
    serviceBindings: {
      ASSETS: () => new Response('web', { headers: { 'content-type': 'text/html; charset=utf-8' } }),
    },
    bindings: {
      APP_ORIGIN: origin,
      ALLOW_LOCAL_HTTP: 'true',
      ROOT_KEY: key,
    },
  });
const firstKey = rootKey();
let mf = new Miniflare(runtime('1', firstKey));
let upstreamCalls = 0;
const upstream = createServer((req, res) => {
  upstreamCalls++;
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/echo') {
    res.end(req.headers.authorization);
    return;
  }
  if (url.pathname === '/query-echo') {
    res.end(encodeURIComponent(url.searchParams.get('api_key')));
    return;
  }
  if (url.pathname === '/query') {
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        credentialCorrect: url.searchParams.get('api_key') === 'rotated-test-only',
        sensitiveCount: [...url.searchParams.keys()].filter((name) => name.toLowerCase() === 'api_key').length,
        duplicates: url.searchParams.getAll('tag'),
      }),
    );
    return;
  }
  if (url.pathname === '/basic') {
    res.setHeader('content-type', 'application/json');
    res.end(
      JSON.stringify({
        credentialCorrect:
          req.headers.authorization === 'Basic ' + Buffer.from('test-user:test-password').toString('base64'),
      }),
    );
    return;
  }
  if (url.pathname === '/binary') {
    res.setHeader('content-type', 'application/octet-stream');
    req.pipe(res);
    return;
  }
  if (url.pathname === '/oversize') {
    res.end('a'.repeat(1024 * 1024 + 1));
    return;
  }
  if (url.pathname === '/redirect') {
    res.writeHead(302, { location: 'https://example.com/' });
    res.end();
    return;
  }
  res.setHeader('content-type', 'application/json');
  res.setHeader('set-cookie', 'must-not-propagate');
  res.end(
    JSON.stringify({
      ok: true,
      credentialCorrect: req.headers.authorization === 'Bearer rotated-test-only',
      cookieAbsent: !req.headers.cookie,
      method: req.method,
    }),
  );
});
await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
const upstreamOrigin = `http://127.0.0.1:${upstream.address().port}`;
let cookie = '';
let token = '';
let passed = 0;
async function call(path, { method = 'GET', body, expected = 200, owner = false, bearer = false, headers = {} } = {}) {
  const r = await mf.dispatchFetch(origin + path, {
    method,
    headers: {
      'cf-connecting-ip': '127.0.0.1',
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(owner ? { origin, cookie } : {}),
      ...(bearer ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = await r.text();
  let v;
  try {
    v = JSON.parse(t);
  } catch {
    v = t;
  }
  assert.equal(
    r.status,
    expected,
    `${method} ${path}: ${typeof v === 'object' ? (v.error ?? v.message ?? 'unexpected status') : 'unexpected content'}`,
  );
  passed++;
  return { r, v };
}
// Issues a one-time token into the database as the deployment does; it stays in this process.
async function issue(database) {
  const { token: value, binds } = newToken();
  await database
    .prepare(issueSql)
    .bind(...binds)
    .run();
  return { 'x-bootstrap-token': value };
}
const backupIdentity = await generateIdentity();
const backupRecipient = await identityToRecipient(backupIdentity);
try {
  const db = await mf.getD1Database('DB');
  await applyMigrations(db);
  const health = async () => (await call('/healthz')).v;
  assert.deepEqual(
    { ...(await health()), version: undefined },
    { ok: true, service: 'clavifer', version: undefined, keys: 'uninitialized', initialized: false },
  );
  const setupToken = await issue(db);
  assert.deepEqual((await call('/api/setup/token', { method: 'POST', owner: true, headers: setupToken })).v, {
    initialized: false,
  });
  // A setup token resets no Owner.
  await call('/api/setup/password', {
    method: 'POST',
    body: { password },
    owner: true,
    headers: setupToken,
    expected: 409,
  });
  const owner = { name: 'Test Owner', email: 'owner@example.com', password, backupRecipient };
  await call('/api/setup/owner', { method: 'POST', body: owner, headers: setupToken, expected: 403 });
  const ownerSetup = await call('/api/setup/owner', {
    method: 'POST',
    body: owner,
    owner: true,
    headers: setupToken,
    expected: 201,
  });
  assert(
    ownerSetup.r.headers.getSetCookie().some((c) => c.includes('session_token')),
    'setup signs the Owner in',
  );
  assert.equal((await health()).keys, 'ok');
  assert.equal((await health()).initialized, true);
  await call('/api/setup/owner', {
    method: 'POST',
    body: { ...owner, email: 'another@example.com' },
    owner: true,
    headers: setupToken,
    expected: 401,
  });
  await call('/api/auth/sign-up/email', {
    method: 'POST',
    body: { name: 'Intruder', email: 'intruder@example.com', password },
    owner: true,
    expected: 403,
  });
  const login = await call('/api/auth/sign-in/email', {
    method: 'POST',
    body: { email: 'owner@example.com', password },
    owner: true,
  });
  cookie = login.r.headers
    .getSetCookie()
    .map((s) => s.split(';')[0])
    .join('; ');
  assert(cookie.includes('session_token'), 'owner session cookie');
  // No session lookup signs a JWT that nothing reads (disableSettingJwtHeader).
  const ownerSession = await call('/api/auth/get-session', { owner: true });
  assert(ownerSession.v?.user && !ownerSession.r.headers.has('set-auth-jwt'), 'get-session without set-auth-jwt');
  // The site's pages and Better Auth answer with their own Response, past the headers a JSON route
  // prepares; both still carry them, a page with the policy written for it.
  const page = await call('/login');
  for (const { r } of [page, login]) {
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    assert(r.headers.get('content-security-policy').includes("frame-ancestors 'none'"));
  }
  const pagePolicy = page.r.headers.get('content-security-policy');
  assert(pagePolicy.startsWith("default-src 'none'; script-src 'self'; style-src 'self';"), 'page policy');
  assert(!pagePolicy.includes('unsafe'), 'a page runs no inline script or style');
  passed += await oauthAcceptance({ mf, origin, cookie, db, password });
  const client = (
    await call('/admin/clients', { method: 'POST', owner: true, body: { name: 'Installation A' }, expected: 201 })
  ).v.clientId;
  const second = (
    await call('/admin/clients', { method: 'POST', owner: true, body: { name: 'Installation B' }, expected: 201 })
  ).v.clientId;
  async function deviceLogin(clientId) {
    const device = (
      await call('/api/auth/device/code', {
        method: 'POST',
        body: {
          client_id: clientId,
          scope: 'offline_access metadata:list secret:read connection:invoke access:request',
          resource: origin + '/v1',
        },
      })
    ).v;
    await call(`/api/auth/device?user_code=${device.user_code}`, { expected: 401 });
    await call(`/api/auth/device?user_code=${device.user_code}`, { owner: true });
    if (clientId === client)
      for (let i = 0; i < 6; i++) await call(`/api/auth/device?user_code=${device.user_code}`, { owner: true });
    await call('/api/auth/device/approve', { method: 'POST', owner: true, body: { userCode: device.user_code } });
    const r = await mf.dispatchFetch(origin + '/api/auth/oauth2/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: device.device_code,
        client_id: clientId,
      }),
    });
    const value = await r.json();
    assert.equal(r.status, 200, `device token: ${value.error ?? 'unexpected'}`);
    assert(value.access_token);
    return value;
  }
  const firstToken = await deviceLogin(client);
  token = firstToken.access_token;
  assert.equal((await call('/v1/secrets', { bearer: true })).v.items.length, 0);
  const sid = (
    await call('/admin/secrets', {
      method: 'POST',
      owner: true,
      body: {
        name: 'Test key',
        values: {
          token: 'synthetic-upstream-test-only',
          account: 'preserve-other-field',
          username: 'test-user',
          password: 'test-password',
        },
      },
      expected: 201,
    })
  ).v.id;
  assert.equal((await call('/v1/secrets', { bearer: true })).v.items.length, 0, 'ungranted metadata is hidden');
  await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true, expected: 403 });
  await call('/admin/grants', {
    method: 'POST',
    owner: true,
    body: { clientId: client, grants: [{ resourceType: 'secret', resourceId: sid, permission: 'secret:read' }] },
  });
  const read = await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true });
  assert.equal(read.v.values.token, 'synthetic-upstream-test-only');
  assert.equal(read.r.headers.get('cache-control'), 'no-store');
  assert.equal((await call('/v1/secrets', { bearer: true })).v.items.length, 1);
  await call('/admin/secrets', {
    method: 'POST',
    body: { name: 'CSRF', values: { token: 'synthetic' } },
    headers: { cookie },
    expected: 403,
  });
  await call(`/admin/secrets/${sid}`, {
    method: 'PUT',
    owner: true,
    body: { name: 'Test key', values: { token: 'rotated-test-only' }, expectedVersion: 1 },
  });
  await call(`/admin/secrets/${sid}`, {
    method: 'PUT',
    owner: true,
    body: { name: 'Test key', values: { token: 'stale' }, expectedVersion: 1 },
    expected: 409,
  });
  const rows = await db.prepare('SELECT envelope_json FROM secret_versions').all();
  assert(
    rows.results.every(
      (r) =>
        !r.envelope_json.includes('rotated-test-only') && !r.envelope_json.includes('synthetic-upstream-test-only'),
    ),
  );
  const refresh = await mf.dispatchFetch(origin + '/api/auth/oauth2/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: firstToken.refresh_token,
      client_id: client,
      resource: origin + '/v1',
    }),
  });
  const refreshed = await refresh.json();
  assert.equal(refresh.status, 200, `refresh: ${refreshed.error ?? 'unexpected'}`);
  assert(refreshed.refresh_token !== firstToken.refresh_token);
  token = refreshed.access_token;
  const rotated = await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true });
  assert.equal(rotated.v.values.token, 'rotated-test-only');
  assert.equal(rotated.v.values.account, 'preserve-other-field', 'single-field rotation preserves other fields');
  const secretGrant = await db
    .prepare('SELECT id FROM grants WHERE client_id=? AND resource_id=?')
    .bind(client, sid)
    .first();
  await db
    .prepare('UPDATE grants SET expires_at=? WHERE id=?')
    .bind(Date.now() - 1000, secretGrant.id)
    .run();
  await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true, expected: 403 });
  assert.equal((await call('/v1/secrets', { bearer: true })).v.items.length, 0, 'expired grant hides metadata');
  await call('/admin/grants', {
    method: 'POST',
    owner: true,
    body: {
      clientId: client,
      grants: [{ resourceType: 'secret', resourceId: sid, permission: 'secret:read', fields: ['token'] }],
    },
  });
  const subset = await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true });
  assert.deepEqual(Object.keys(subset.v.values), ['token'], 'a field-limited grant returns only its own fields');
  assert.deepEqual(
    (await call('/v1/secrets', { bearer: true })).v.items[0].fields,
    ['token'],
    'metadata advertises the granted fields',
  );
  await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true, body: { fields: ['account'] }, expected: 403 });
  await call('/admin/grants', {
    method: 'POST',
    owner: true,
    body: { clientId: client, grants: [{ resourceType: 'secret', resourceId: sid, permission: 'secret:read' }] },
  });
  await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true, body: { fields: ['absent'] }, expected: 404 });
  await call('/admin/grants', {
    method: 'POST',
    owner: true,
    body: {
      clientId: client,
      grants: [{ resourceType: 'secret', resourceId: sid, permission: 'secret:read', fields: ['token'] }],
    },
  });
  const widening = (
    await call('/v1/access-requests', {
      method: 'POST',
      bearer: true,
      body: {
        requested: { grants: [{ resourceType: 'secret', resourceId: sid, permission: 'secret:read' }] },
        reason: 'widen',
      },
      expected: 202,
    })
  ).v;
  await call(`/admin/access-requests/${widening.id}/approve`, { method: 'POST', owner: true, expected: 409 });
  assert.deepEqual(
    (await call('/v1/secrets', { bearer: true })).v.items[0].fields,
    ['token'],
    'approving a client request must not widen the Owner field subset',
  );
  assert.equal(
    (await call('/v1/access-requests/' + widening.id, { bearer: true })).v.status,
    'pending',
    'a refused approval leaves the request visible',
  );
  await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true, body: { fields: ['account'] }, expected: 403 });
  await call('/admin/grants', {
    method: 'POST',
    owner: true,
    body: { clientId: client, grants: [{ resourceType: 'secret', resourceId: sid, permission: 'secret:read' }] },
  });
  const mcp = await call('/v1/mcp', {
    method: 'POST',
    bearer: true,
    headers: { accept: 'application/json, text/event-stream' },
    body: {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
    },
  });
  assert.equal(mcp.v.result.serverInfo.name, 'clavifer');
  const tools = await call('/v1/mcp', {
    method: 'POST',
    bearer: true,
    headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' },
    body: { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  });
  assert.equal(tools.v.result.tools.length, 4);
  assert(tools.v.result.tools.every((t) => t.inputSchema));
  // A tool schema describes what a caller sends, so a field with a default is not required.
  const schemaOf = (name) => tools.v.result.tools.find((t) => t.name === name).inputSchema;
  assert.deepEqual(schemaOf('http.request').required, ['connection']);
  assert.deepEqual(schemaOf('access.request').required, ['requested', 'reason']);
  const draft = schemaOf('access.request').properties.requested.properties;
  assert.deepEqual(draft.setup.properties.connections.items.required, ['name', 'origin', 'paths', 'tests']);
  assert.deepEqual(draft.invocation.required, ['connection', 'path', 'method']);
  const connection = (
    await call('/admin/connections', {
      method: 'POST',
      owner: true,
      body: {
        name: 'Controlled upstream',
        origin: upstreamOrigin,
        paths: ['/get', '/redirect', '/oversize', '/echo'],
        methods: ['GET'],
        auth: { type: 'bearer', secretId: sid, field: 'token' },
      },
    })
  ).v.id;
  await call('/admin/connections/' + connection, {
    method: 'PUT',
    owner: true,
    body: {
      name: 'Controlled upstream',
      origin: upstreamOrigin,
      paths: ['/get', '/redirect', '/oversize', '/echo'],
      methods: ['GET'],
      auth: { type: 'bearer', secretId: sid, field: 'token' },
    },
  });
  await call('/admin/secrets/' + sid, { method: 'DELETE', owner: true, expected: 409 });
  const requestBody = {
    requested: { grants: [{ resourceType: 'connection', resourceId: connection, permission: 'connection:invoke' }] },
    reason: 'E2E',
  };
  const pending = (
    await call('/v1/access-requests', { method: 'POST', bearer: true, body: requestBody, expected: 202 })
  ).v;
  assert.equal(
    (await call('/v1/access-requests', { method: 'POST', bearer: true, body: requestBody, expected: 202 })).v.id,
    pending.id,
  );
  await call(`/admin/access-requests/${pending.id}/approve`, { method: 'POST', owner: true });
  const approvedGrant = await db
    .prepare('SELECT expires_at FROM grants WHERE client_id=? AND resource_id=?')
    .bind(client, connection)
    .first();
  assert(
    approvedGrant.expires_at > Date.now() + 86340000 && approvedGrant.expires_at <= Date.now() + 86400000,
    'an approval without a chosen expiry lasts 24 hours',
  );
  const permanentGrant = await db
    .prepare('SELECT expires_at FROM grants WHERE client_id=? AND resource_id=?')
    .bind(client, sid)
    .first();
  assert.equal(permanentGrant.expires_at, null, 'an unlimited grant survives a 24 hour approval');
  assert.equal((await call('/v1/access-requests/' + pending.id, { bearer: true })).v.status, 'approved');
  // The Owner may choose the expiry when approving; it takes the same validation as a direct grant.
  const shorter = (
    await call('/v1/access-requests', { method: 'POST', bearer: true, body: requestBody, expected: 202 })
  ).v;
  const oneHour = Date.now() + 3600000;
  await call(`/admin/access-requests/${shorter.id}/approve`, {
    method: 'POST',
    owner: true,
    body: { expiresAt: oneHour },
  });
  assert.equal(
    (
      await db
        .prepare('SELECT expires_at FROM grants WHERE client_id=? AND resource_id=?')
        .bind(client, connection)
        .first()
    ).expires_at,
    approvedGrant.expires_at,
    'a shorter approval must not cut a live grant short',
  );
  await db
    .prepare("UPDATE grants SET status='revoked' WHERE client_id=? AND resource_id=?")
    .bind(client, connection)
    .run();
  const chosen = (await call('/v1/access-requests', { method: 'POST', bearer: true, body: requestBody, expected: 202 }))
    .v;
  await call(`/admin/access-requests/${chosen.id}/approve`, {
    method: 'POST',
    owner: true,
    body: { expiresAt: Date.now() - 1000 },
    expected: 400,
  });
  await call(`/admin/access-requests/${chosen.id}/approve`, {
    method: 'POST',
    owner: true,
    body: { expiresAt: oneHour },
  });
  assert.equal(
    (
      await db
        .prepare('SELECT expires_at FROM grants WHERE client_id=? AND resource_id=?')
        .bind(client, connection)
        .first()
    ).expires_at,
    oneHour,
    'an approval applies the expiry the Owner chose',
  );
  await call(`/v1/proxy/${connection}/get`, { bearer: true, method: 'POST', expected: 403 });
  await call(`/v1/proxy/${connection}/forbidden`, { bearer: true, expected: 403 });
  assert.equal(upstreamCalls, 0);
  const proxy = await call(`/v1/proxy/${connection}/get`, { bearer: true, headers: { cookie: 'must-not-propagate' } });
  assert.equal(proxy.v.credentialCorrect, true);
  assert.equal(proxy.v.cookieAbsent, true);
  assert.equal(proxy.r.headers.get('set-cookie'), null);
  const oversize = await mf.dispatchFetch(origin + `/v1/proxy/${connection}/oversize`, {
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(oversize.status, 200);
  assert.equal(
    (await oversize.arrayBuffer()).byteLength,
    1024 * 1024 + 1,
    'REST responses stream without a size limit',
  );
  passed++;
  const redirectResponse = await mf.dispatchFetch(origin + `/v1/proxy/${connection}/redirect`, {
    headers: { authorization: `Bearer ${token}` },
    redirect: 'manual',
  });
  assert.equal(redirectResponse.status, 302);
  assert.equal(redirectResponse.headers.get('location'), null);
  assert.equal(upstreamCalls, 3);
  assert(
    (await call(`/v1/proxy/${connection}/echo`, { bearer: true })).v.startsWith('Bearer '),
    'the server injects the bound credential into the upstream request',
  );
  const invoked = await call('/v1/mcp', {
    method: 'POST',
    bearer: true,
    headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' },
    body: {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'http.request', arguments: { connection, path: '/get' } },
    },
  });
  const invokedAudit = await db
    .prepare("SELECT result FROM audit_events WHERE action='connection:invoke' AND request_id=? ORDER BY created_at")
    .bind(invoked.r.headers.get('x-request-id'))
    .all();
  assert.deepEqual(
    invokedAudit.results.map((row) => row.result),
    ['started', 'http_200'],
    'both audit rows carry the response request id',
  );
  const bounded = await call('/v1/mcp', {
    method: 'POST',
    bearer: true,
    headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' },
    body: {
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'http.request', arguments: { connection, path: '/oversize' } },
    },
  });
  assert.equal(JSON.parse(bounded.v.result.content[0].text).error, 'response_too_large');
  const boundedAudit = await db
    .prepare("SELECT result FROM audit_events WHERE action='connection:invoke' AND request_id=? ORDER BY created_at")
    .bind(bounded.r.headers.get('x-request-id'))
    .all();
  assert.deepEqual(
    boundedAudit.results.map((row) => row.result),
    ['started', 'http_200'],
    'an oversized MCP read still records the upstream status',
  );
  // Without a grant an Agent submits the exact request for a one-time approval, then resends it unchanged.
  const tool = async (name, args) =>
    JSON.parse(
      (
        await call('/v1/mcp', {
          method: 'POST',
          bearer: true,
          headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' },
          body: { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name, arguments: args } },
        })
      ).v.result.content[0].text,
    );
  await db
    .prepare("UPDATE grants SET status='revoked' WHERE client_id=? AND resource_id=?")
    .bind(client, connection)
    .run();
  const exact = { connection, method: 'GET', path: '/get', headers: { accept: 'application/json' } };
  const refused = await tool('http.request', exact);
  assert.equal(refused.error, 'grant_required');
  assert(refused.hint.includes('requested.invocation'), 'a refusal names the next step');
  const once = await tool('access.request', { requested: { invocation: exact }, reason: 'E2E one request' });
  const stale = await tool('access.request', {
    requested: { invocation: { ...exact, query: { page: '2' } } },
    reason: 'E2E stale approval',
  });
  const session = await db.prepare('SELECT createdAt FROM session').first();
  await db
    .prepare('UPDATE session SET createdAt=?')
    .bind(Date.now() - 700_000)
    .run();
  await call(`/admin/access-requests/${stale.id}/approve`, { method: 'POST', owner: true, expected: 403 });
  await db.prepare('UPDATE session SET createdAt=?').bind(session.createdAt).run();
  await call(`/admin/access-requests/${once.id}/approve`, { method: 'POST', owner: true });
  assert.equal((await tool('access.status', { id: once.id })).status, 'approved');
  assert.equal((await tool('http.request', { ...exact, headers: { accept: 'text/plain' } })).error, 'grant_required');
  assert.equal(JSON.parse((await tool('http.request', exact)).body).credentialCorrect, true);
  assert.equal((await tool('access.status', { id: once.id })).status, 'executed');
  assert.equal((await tool('http.request', exact)).error, 'grant_required', 'an approval runs once');
  await db
    .prepare("UPDATE grants SET status='active' WHERE client_id=? AND resource_id=?")
    .bind(client, connection)
    .run();
  // An Agent drafts a credential (field names only) and two connections using it, each with its own
  // tests, which the server runs on submission. The Owner enters the value once on approval, and the
  // Agent reads the new ids from access.status and runs a free-rule request on each connection with
  // that value injected the way the connection says.
  const setup = {
    secret: { name: 'Proposed key', fields: ['token'] },
    connections: [
      {
        name: 'Proposed upstream',
        origin: upstreamOrigin,
        paths: ['/echo'],
        methods: ['GET'],
        free: ['/echo'],
        auth: { type: 'bearer', field: 'token' },
        tests: [
          { method: 'GET', path: '/echo', expect: 'run' },
          { method: 'POST', path: '/echo', grant: true, expect: 'method_not_allowed' },
          { method: 'GET', path: '/get', expect: 'path_not_allowed' },
        ],
      },
      {
        name: 'Proposed upstream by query',
        origin: upstreamOrigin,
        paths: ['/query-echo'],
        methods: ['GET'],
        free: ['/query-echo'],
        auth: { type: 'query', field: 'token', name: 'api_key' },
        tests: [
          { method: 'GET', path: '/query-echo', expect: 'run' },
          { method: 'GET', path: '/echo', grant: true, expect: 'path_not_allowed' },
        ],
      },
    ],
  };
  const [byBearer, byQuery] = setup.connections;
  const mismatch = await tool('access.request', {
    requested: {
      setup: {
        ...setup,
        connections: [byBearer, { ...byQuery, tests: [{ method: 'GET', path: '/get', expect: 'run' }] }],
      },
    },
    reason: 'E2E setup with a wrong expectation',
  });
  assert.equal(mismatch.error, 'tests_failed');
  assert(
    mismatch.hint.includes('connections.1 "Proposed upstream by query" tests.0 GET /get') &&
      mismatch.hint.includes('expected run, got path_not_allowed'),
    mismatch.hint,
  );
  const proposed = await tool('access.request', { requested: { setup }, reason: 'E2E setup proposal' });
  await call(`/admin/access-requests/${proposed.id}/approve`, {
    method: 'POST',
    owner: true,
    body: { values: { token: 'proposed-test-only' } },
  });
  const created = await tool('access.status', { id: proposed.id });
  assert.equal(created.status, 'approved');
  assert.equal(created.connectionIds.length, 2);
  assert.equal(
    (await tool('http.request', { connection: created.connectionIds[0], path: '/echo' })).body,
    'Bearer proposed-test-only',
    'an approved setup injects the value the Owner entered',
  );
  assert.equal(
    (await tool('http.request', { connection: created.connectionIds[1], path: '/query-echo' })).body,
    'proposed-test-only',
    'every connection of an approved setup injects the same credential',
  );
  for (const cid of created.connectionIds) await call('/admin/connections/' + cid, { method: 'DELETE', owner: true });
  await call('/admin/secrets/' + created.secretId, { method: 'DELETE', owner: true });
  // A connection lists the local upstream under its other name as an extra host. A request there runs
  // on no free rule, only on a one-time approval that names that origin: once, with the connection's
  // credential, and on no other origin.
  const elsewhere = upstreamOrigin.replace('127.0.0.1', 'localhost');
  const reaching = (
    await call('/admin/connections', {
      method: 'POST',
      owner: true,
      body: {
        name: 'Upstream with an extra host',
        origin: upstreamOrigin,
        paths: ['/echo'],
        methods: ['GET'],
        free: ['/echo'],
        hosts: ['localhost'],
        auth: { type: 'bearer', secretId: sid, field: 'token' },
      },
    })
  ).v.id;
  const there = { connection: reaching, method: 'GET', path: '/echo', origin: elsewhere };
  assert.equal(
    (await tool('credentials.list', {})).connections.find((c) => c.id === reaching).policy_json.includes('"localhost"'),
    true,
    'credentials.list shows the extra hosts',
  );
  assert.equal((await tool('http.request', there)).error, 'approval_required', 'no free rule runs on another origin');
  const unlisted = await tool('access.request', {
    requested: { invocation: { ...there, connection } },
    reason: 'E2E origin the connection does not list',
  });
  assert.equal(unlisted.error, 'host_not_allowed');
  assert(unlisted.hint.includes('localhost'), unlisted.hint);
  const asked = await tool('access.request', { requested: { invocation: there }, reason: 'E2E another origin' });
  // The approval names the origin back; one that names none is refused.
  await call(`/admin/access-requests/${asked.id}/approve`, { method: 'POST', owner: true, expected: 409 });
  await call(`/admin/access-requests/${asked.id}/approve`, {
    method: 'POST',
    owner: true,
    body: { origin: elsewhere },
  });
  // Another port of the listed host is another origin. On the connection's own origin the free rule
  // runs the request, which leaves the approval for the other origin unspent.
  assert.equal((await tool('http.request', { ...there, origin: 'http://localhost:9' })).error, 'approval_required');
  assert.equal((await tool('http.request', { ...there, origin: undefined })).body, 'Bearer rotated-test-only');
  assert.equal((await tool('access.status', { id: asked.id })).status, 'approved');
  const callsBefore = upstreamCalls;
  assert.equal(
    (await tool('http.request', there)).body,
    'Bearer rotated-test-only',
    'an approved request runs on the extra host with the connection’s credential',
  );
  assert.equal(upstreamCalls, callsBefore + 1);
  assert.equal((await tool('access.status', { id: asked.id })).status, 'executed');
  assert.equal((await tool('http.request', there)).error, 'approval_required', 'an approval runs once');
  await call('/admin/connections/' + reaching, { method: 'DELETE', owner: true });
  const sdk = new Client({ name: 'host-contract-test', version: '1' });
  // The test binary stands in for clavifer, both as the bridge and as the waitCommand it names.
  const helperEnv = {
    ...process.env,
    CLAVIFER_E2E_PROFILE: JSON.stringify({ server: (await mf.ready).origin, client_id: client }),
    CLAVIFER_E2E_TOKEN: JSON.stringify({ ...refreshed, expires_at: Math.floor(Date.now() / 1000) + 600 }),
    CLAVIFER_TEST_ARTIFACTS: runDirectory,
  };
  const transport = new StdioClientTransport({
    command: resolve('work/clavifer-integration.test.exe'),
    args: ['-test.run=^TestMCPHostHelper$'],
    env: helperEnv,
    stderr: 'pipe',
  });
  try {
    await sdk.connect(transport);
    assert.equal((await sdk.listTools()).tools.length, 4);
    const listed = await sdk.callTool({ name: 'credentials.list', arguments: {} });
    assert.equal(JSON.parse(listed.content[0].text).items.length, 1);
    const invoked = await sdk.callTool({ name: 'http.request', arguments: { connection, path: '/get' } });
    assert.equal(JSON.parse(JSON.parse(invoked.content[0].text).body).credentialCorrect, true);
    // Through the bridge a submitted request names the command that waits for the Owner. Run in a
    // host's shell, it keeps waiting while the request is pending and exits with the decision.
    const submitted = JSON.parse(
      (
        await sdk.callTool({
          name: 'access.request',
          arguments: {
            requested: { invocation: { ...exact, query: { wait: '1' } } },
            reason: 'E2E wait for the Owner',
          },
        })
      ).content[0].text,
    );
    assert(submitted.waitCommand.includes('clavifer-integration.test.exe'), 'waitCommand names the running executable');
    assert(submitted.waitCommand.endsWith(` --profile default status ${submitted.id} --wait`), submitted.waitCommand);
    const [shell, shellArgs] =
      process.platform === 'win32'
        ? ['powershell.exe', ['-NoProfile', '-Command', `& ${submitted.waitCommand}`]]
        : ['sh', ['-c', submitted.waitCommand]];
    const waiting = spawn(shell, shellArgs, { env: helperEnv, timeout: 30_000 });
    let printed = '';
    let complaint = '';
    waiting.stdout.on('data', (chunk) => (printed += chunk));
    waiting.stderr.on('data', (chunk) => (complaint += chunk));
    const exited = new Promise((done) => waiting.on('close', done));
    await new Promise((done) => setTimeout(done, 1500));
    assert.equal(waiting.exitCode, null, 'the wait lasts while the request is pending: ' + complaint);
    await call(`/admin/access-requests/${submitted.id}/approve`, { method: 'POST', owner: true });
    assert.equal(await exited, 0, complaint);
    assert.equal(JSON.parse(printed).status, 'approved');
  } finally {
    await sdk.close();
  }
  if (process.argv.includes('--hosts'))
    await hostSmoke({ server: (await mf.ready).origin, client_id: client }, refreshed);
  // Real HTTP sockets verify auth injection and binary byte fidelity end to end.
  const basicConnection = (
    await call('/admin/connections', {
      method: 'POST',
      owner: true,
      body: {
        name: 'Basic upstream',
        origin: upstreamOrigin,
        paths: ['/basic', '/echo'],
        methods: ['GET'],
        auth: { type: 'basic', secretId: sid, usernameField: 'username', passwordField: 'password' },
      },
    })
  ).v.id;
  const queryConnection = (
    await call('/admin/connections', {
      method: 'POST',
      owner: true,
      body: {
        name: 'Query upstream',
        origin: upstreamOrigin,
        paths: ['/query', '/query-echo'],
        methods: ['GET'],
        auth: { type: 'query', secretId: sid, field: 'token', name: 'api_key' },
      },
    })
  ).v.id;
  const binaryConnection = (
    await call('/admin/connections', {
      method: 'POST',
      owner: true,
      body: {
        name: 'Binary upstream',
        origin: upstreamOrigin,
        paths: ['/binary'],
        methods: ['POST', 'HEAD'],
        auth: { type: 'none' },
      },
    })
  ).v.id;
  await call('/admin/grants', {
    method: 'POST',
    owner: true,
    body: {
      clientId: client,
      grants: [basicConnection, queryConnection, binaryConnection].map((resourceId) => ({
        resourceType: 'connection',
        resourceId,
        permission: 'connection:invoke',
      })),
    },
  });
  assert.equal((await call(`/v1/proxy/${basicConnection}/basic`, { bearer: true })).v.credentialCorrect, true);
  assert(
    (await call(`/v1/proxy/${basicConnection}/echo`, { bearer: true })).v.startsWith('Basic '),
    'Basic credentials reach the upstream unchanged',
  );
  const queryProxy = (
    await call(`/v1/proxy/${queryConnection}/query?tag=a&tag=b&API_KEY=untrusted&api_key=untrusted`, { bearer: true })
  ).v;
  assert.equal(queryProxy.credentialCorrect, true);
  assert.equal(queryProxy.sensitiveCount, 1);
  assert.deepEqual(queryProxy.duplicates, ['a', 'b']);
  assert.equal(
    (await call(`/v1/proxy/${queryConnection}/query-echo`, { bearer: true })).v.length > 0,
    true,
    'query credentials reach the upstream unchanged',
  );
  const binaryInput = Uint8Array.from([0, 128, 255, 240, 159, 65, 13, 10, 0, 254]);
  const binaryResponse = await mf.dispatchFetch(origin + `/v1/proxy/${binaryConnection}/binary`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/octet-stream' },
    body: binaryInput,
  });
  assert.equal(binaryResponse.status, 200);
  assert.deepEqual(
    new Uint8Array(await binaryResponse.arrayBuffer()),
    binaryInput,
    'binary REST request and response preserve every byte',
  );
  passed++;
  const headResponse = await mf.dispatchFetch(origin + `/v1/proxy/${binaryConnection}/binary`, {
    method: 'HEAD',
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(headResponse.status, 200);
  assert.equal((await headResponse.arrayBuffer()).byteLength, 0);
  passed++;
  for (const cid of [basicConnection, queryConnection, binaryConnection])
    await call('/admin/connections/' + cid, { method: 'DELETE', owner: true });
  // Sealing, by the scheduled handler of the built Worker: 2 MB of access requests over 25 hours old
  // leave the hot table for an archive/ object that R2 checked against its SHA-256, and access.status
  // no longer finds them. The automatic backup runs after it in the same invocation.
  const old = Date.now() - 26 * 3600000;
  await db
    .prepare(
      "INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<2000) SELECT printf('sealed-%06d',i),(SELECT value FROM system_state WHERE key='owner_user_id'),?,json_object('invocation',json_object('body',printf('%.*c',1000,'x'))),'r','denied',?+i,?+i+86400000 FROM n",
    )
    .bind(client, old, old)
    .run();
  assert.equal((await call('/v1/access-requests/sealed-000001', { bearer: true })).v.status, 'denied');
  await (await mf.getWorker()).scheduled({ cron: '*/15 * * * *' });
  const segments = (await db.prepare('SELECT kind,object_key,sha256 FROM archive_segments').all()).results;
  assert.deepEqual(
    segments.map((s) => s.kind),
    ['access-request'],
  );
  const sealedObject = await (await mf.getR2Bucket('BACKUPS')).head(segments[0].object_key);
  assert.equal(Buffer.from(sealedObject.checksums.sha256).toString('hex'), segments[0].sha256);
  await call('/v1/access-requests/sealed-000001', { bearer: true, expected: 404 });
  assert.equal((await call('/v1/access-requests/sealed-002000', { bearer: true })).v.status, 'denied');
  assert.equal((await call('/admin/backup/status', { owner: true })).v.lastError, null);
  // The automatic backup that followed: the v1 snapshot, naming the segment by its key and checksum.
  const latest = await mf.dispatchFetch(origin + '/admin/backup/latest', { headers: { cookie } });
  assert.equal(latest.status, 200);
  const decrypter = new Decrypter();
  decrypter.addIdentity(backupIdentity);
  const snapshot = (await decrypter.decrypt(new Uint8Array(await latest.arrayBuffer()), 'text'))
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  assert.deepEqual(
    [snapshot[0].format, snapshot[0].kind, snapshot.at(-1).type],
    ['clavifer-backup-v1', 'automatic', 'end'],
  );
  assert(snapshot.some((r) => r.type === 'secret-version' && r.values.token === 'rotated-test-only'));
  assert.equal(snapshot.filter((r) => r.type === 'archive-identity').length, 1);
  assert.deepEqual(
    snapshot.filter((r) => r.type === 'segment').map((r) => [r.key, r.sha256, r.data]),
    [[segments[0].object_key, segments[0].sha256, null]],
  );
  passed++;
  // Recovering the Owner: a 1-hour token creates no Owner on an initialized instance; it shows the login
  // email, sets a new password and signs every browser out, while the installation keeps calling.
  const beforeReset = await deviceLogin(second);
  const recovery = await issue(db);
  await call('/api/setup/owner', { method: 'POST', body: owner, owner: true, headers: recovery, expected: 409 });
  assert.deepEqual((await call('/api/setup/token', { method: 'POST', owner: true, headers: recovery })).v, {
    initialized: true,
    email: 'owner@example.com',
  });
  const recovered = randomBytes(24).toString('base64url');
  await call('/api/setup/password', { method: 'POST', body: { password: recovered }, owner: true, headers: recovery });
  await call('/admin/status', { owner: true, expected: 401 });
  assert.equal(
    (await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true })).v.values.token,
    'rotated-test-only',
    'an installation keeps working after the Owner was recovered',
  );
  // Its refresh token outlives the reset too.
  const renewal = await mf.dispatchFetch(origin + '/api/auth/oauth2/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: beforeReset.refresh_token,
      client_id: second,
      resource: origin + '/v1',
    }),
  });
  const renewed = await renewal.json();
  assert.equal(renewal.status, 200, `refresh after reset: ${renewed.error ?? 'unexpected'}`);
  passed++;
  await call('/v1/secrets', { headers: { authorization: `Bearer ${renewed.access_token}` } });
  const signInAs = (password, expected = 200) =>
    call('/api/auth/sign-in/email', {
      method: 'POST',
      body: { email: 'owner@example.com', password },
      headers: { origin, 'cf-connecting-ip': '127.0.0.3' },
      expected,
    });
  await signInAs(password, 401);
  cookie = (await signInAs(recovered)).r.headers
    .getSetCookie()
    .map((s) => s.split(';')[0])
    .join('; ');
  await call('/admin/status', { owner: true });
  await call(`/admin/grants/${secretGrant.id}`, { method: 'DELETE', owner: true });
  await call(`/v1/secrets/${sid}/read`, { method: 'POST', bearer: true, expected: 403 });
  const remaining = (await call('/v1/secrets', { bearer: true })).v;
  assert.equal(remaining.items.length, 0);
  assert.equal(remaining.connections.length, 1, 'revoking one grant does not revoke other resources');
  await call(`/admin/clients/${client}`, { method: 'DELETE', owner: true });
  await call('/v1/secrets', { bearer: true, expected: 401 });
  token = (await deviceLogin(second)).access_token;
  assert.equal(
    (await call('/v1/secrets', { bearer: true })).v.items.length,
    0,
    'second installation independently active and ungranted',
  );
  await call('/v1/logout', { method: 'POST', bearer: true });
  await call('/v1/secrets', { bearer: true, expected: 401 });
  // The same database under another root key refuses everything but /healthz, which tells only that.
  await mf.setOptions(runtime('1', rootKey()));
  assert.deepEqual(
    { ...(await health()), version: undefined },
    { ok: false, service: 'clavifer', version: undefined, keys: 'mismatch', initialized: true },
  );
  assert.equal((await call('/admin/status', { owner: true, expected: 503 })).v.error, 'root_key_mismatch');
  await call('/api/auth/get-session', { owner: true, expected: 503 });
  await call('/v1/secrets', { bearer: true, expected: 503 });
  await mf.setOptions(runtime('1', firstKey));
  assert.equal((await health()).keys, 'ok');
  await call('/admin/status', { owner: true });
  await mf.dispose();
  mf = new Miniflare(runtime('2', rootKey()));
  cookie = '';
  token = '';
  // A second instance under another root key, set up from its own token; the Owner's setup response
  // is its first session.
  const freshDB = await mf.getD1Database('DB');
  await applyMigrations(freshDB);
  cookie = (
    await call('/api/setup/owner', {
      method: 'POST',
      owner: true,
      body: { name: 'Second Owner', email: 'Second@Example.com', password, backupRecipient },
      headers: await issue(freshDB),
      expected: 201,
    })
  ).r.headers
    .getSetCookie()
    .map((s) => s.split(';')[0])
    .join('; ');
  const fresh = (await call('/admin/status', { owner: true })).v;
  assert.deepEqual(
    [fresh.secrets, fresh.connections, fresh.grants, fresh.clients].map((rows) => rows.length),
    [0, 0, 0, 0],
  );
  assert.equal(fresh.backup.recipient, backupRecipient, 'the backup recipient comes with the Owner');
  const freshSid = (
    await call('/admin/secrets', {
      method: 'POST',
      owner: true,
      body: { name: 'Second key', values: { token: 'second-instance-test-only' } },
      expected: 201,
    })
  ).v.id;
  const freshConnection = (
    await call('/admin/connections', {
      method: 'POST',
      owner: true,
      body: {
        name: 'Second upstream',
        origin: upstreamOrigin,
        paths: ['/get'],
        methods: ['GET'],
        auth: { type: 'bearer', secretId: freshSid, field: 'token' },
      },
    })
  ).v.id;
  const freshClient = (
    await call('/admin/clients', {
      method: 'POST',
      owner: true,
      body: { name: 'Second installation' },
      expected: 201,
    })
  ).v.clientId;
  token = (await deviceLogin(freshClient)).access_token;
  await call('/admin/grants', {
    method: 'POST',
    owner: true,
    body: {
      clientId: freshClient,
      grants: [{ resourceType: 'secret', resourceId: freshSid, permission: 'secret:read' }],
    },
  });
  assert.equal(
    (await call(`/v1/secrets/${freshSid}/read`, { method: 'POST', bearer: true })).v.values.token,
    'second-instance-test-only',
  );
  await call('/admin/connections/' + freshConnection, { method: 'DELETE', owner: true });
  await call('/admin/secrets/' + freshSid, { method: 'DELETE', owner: true });
  await call(`/v1/secrets/${freshSid}/read`, { method: 'POST', bearer: true, expected: 403 });
  await freshDB
    .prepare(
      'INSERT INTO "oauthClient" (id,clientId,userId,name,redirectUris,disabled,createdAt) VALUES (?,?,NULL,?,?,0,?)',
    )
    .bind('orphan', 'orphan-client', 'Unowned client', '[]', Date.now())
    .run();
  const withOrphan = (await call('/admin/status', { owner: true })).v.clients;
  assert.equal(
    withOrphan.filter((c) => c.clientId === 'orphan-client').length,
    1,
    'an unowned installation is visible to the Owner',
  );
  await call('/admin/clients/orphan-client', { method: 'DELETE', owner: true });
  assert.equal(
    (await freshDB.prepare('SELECT disabled FROM "oauthClient" WHERE clientId=?').bind('orphan-client').first())
      .disabled,
    1,
    'an unowned installation can be revoked',
  );
  await freshDB
    .prepare('UPDATE session SET createdAt=?')
    .bind(Date.now() - 700_000)
    .run();
  const staleClient = (
    await call('/admin/clients', { method: 'POST', owner: true, body: { name: 'Stale owner session' }, expected: 201 })
  ).v.clientId;
  await call('/admin/grants', {
    method: 'POST',
    owner: true,
    body: {
      clientId: staleClient,
      grants: [{ resourceType: 'secret', resourceId: freshSid, permission: 'secret:read' }],
    },
    expected: 403,
  });
  await call('/admin/backup/config', { method: 'PUT', owner: true, body: { recipient: null }, expected: 403 });
  const staleConnection = {
    name: 'Stale edit target',
    origin: upstreamOrigin,
    paths: ['/get'],
    methods: ['GET'],
    auth: { type: 'none' },
  };
  await call('/admin/connections', { method: 'POST', owner: true, body: staleConnection, expected: 403 });
  await call('/admin/connections/' + freshConnection, {
    method: 'PUT',
    owner: true,
    body: staleConnection,
    expected: 403,
  });
  await call('/admin/status', { owner: true });
  await call('/api/auth/passkey/delete-passkey', {
    method: 'POST',
    owner: true,
    body: { id: 'test-not-real' },
    expected: 403,
  });
  await call('/api/auth/device/approve/', {
    method: 'POST',
    owner: true,
    body: { userCode: 'test-not-real' },
    expected: 403,
  });
  await call('/api/auth/oauth2/client/rotate-secret', {
    method: 'POST',
    owner: true,
    body: { client_id: freshClient },
    expected: 403,
  });
  // /admin/clients is the only writer of installations, whoever asks.
  for (const route of ['create-client', 'update-client', 'delete-client'])
    assert.equal(
      (
        await call(`/api/auth/oauth2/${route}`, {
          method: 'POST',
          owner: true,
          body: { client_id: freshClient },
          expected: 403,
        })
      ).v.error,
      'endpoint_disabled',
    );
  await call('/api/auth/oauth2/update-consent', {
    method: 'POST',
    owner: true,
    body: { id: 'test-not-real' },
    expected: 403,
  });
  await call('/api/auth/oauth2/delete-consent', {
    method: 'POST',
    owner: true,
    body: { id: 'test-not-real' },
    expected: 403,
  });
  const changedPassword = randomBytes(24).toString('base64url');
  await call('/api/auth/change-password', {
    method: 'POST',
    owner: true,
    body: { currentPassword: password, newPassword: changedPassword, revokeOtherSessions: true },
  });
  await call('/api/auth/sign-out', { method: 'POST', owner: true, body: {} });
  await call('/admin/status', { owner: true, expected: 401 });
  await call('/api/auth/sign-in/email', {
    method: 'POST',
    owner: true,
    body: { email: 'second@example.com', password },
    expected: 401,
  });
  await call('/api/auth/sign-in/email', {
    method: 'POST',
    owner: true,
    body: { email: 'second@example.com', password: changedPassword },
  });
  console.log(
    `Local E2E passed: ${passed} HTTP assertions plus SDK-to-Go-to-Worker MCP, proxy boundaries, encrypted backup, sealing of old access requests, Owner setup and recovery through one-time tokens, and a second instance under another root key.`,
  );
} finally {
  await mf.dispose();
  await new Promise((resolve) => upstream.close(resolve));
}
