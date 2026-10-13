// Moves one database to a different APP_ORIGIN and checks what survives. An installation created
// under the old origin keeps working after the move: audience validation rejects a resource that is
// not configured, and a client is not pinned to the resource row it was created with.
// The origin moves through setOptions because a second Miniflare instance does not reopen the
// persisted D1 of the first one; setOptions keeps the data and still rebuilds the isolate.
import { Miniflare, Log, LogLevel, convertV4MiniflareOptions } from 'miniflare';
import { mkdir } from 'node:fs/promises';
import { randomBytes, createHash, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';
import { applyMigrations } from './migrations.mjs';

const before = 'http://localhost:8787',
  after = 'https://clavifer.example';
const bootstrap = randomBytes(32).toString('base64url'),
  password = randomBytes(24).toString('base64url');
const state = resolve('work', 'e2e-origin-' + randomUUID());
await mkdir(state, { recursive: true });
// Server keys survive an origin change, so the JWKS private key stays decryptable.
const authSecret = randomBytes(32).toString('base64url'),
  kek = randomBytes(32).toString('base64url');
const scopes = 'offline_access metadata:list secret:read connection:invoke access:request';
const options = (origin) =>
  convertV4MiniflareOptions({
    modules: true,
    scriptPath: 'dist/worker/index.js',
    compatibilityDate: '2026-09-11',
    compatibilityFlags: ['nodejs_compat'],
    log: new Log(LogLevel.ERROR),
    d1Databases: ['DB'],
    d1Persist: resolve(state, 'd1'),
    r2Buckets: ['BACKUPS'],
    r2Persist: resolve(state, 'r2'),
    serviceBindings: { ASSETS: () => new Response('web') },
    bindings: {
      APP_ORIGIN: origin,
      ALLOW_LOCAL_HTTP: 'true',
      AUTH_SECRET: authSecret,
      KEK_RING: `v1:${kek}`,
      ACTIVE_KEK_ID: 'v1',
      BOOTSTRAP_HASH: createHash('sha256').update(bootstrap).digest('base64url'),
    },
  });

const mf = new Miniflare(options(before));
let origin = before,
  cookie = '',
  checks = 0;
async function call(path, { method = 'GET', body, expected = 200, owner = false, headers = {} } = {}) {
  const r = await mf.dispatchFetch(origin + path, {
    method,
    headers: {
      'cf-connecting-ip': '127.0.0.1',
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(owner ? { origin, cookie } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    value = text;
  }
  assert.equal(
    r.status,
    expected,
    `${method} ${path}: ${typeof value === 'object' ? (value.error ?? 'unexpected status') : 'unexpected content'}`,
  );
  checks++;
  return { value, headers: r.headers };
}
async function signIn() {
  const r = await call('/api/auth/sign-in/email', {
    method: 'POST',
    owner: true,
    body: { email: 'owner@example.com', password },
  });
  cookie = r.headers
    .getSetCookie()
    .map((s) => s.split(';')[0])
    .join('; ');
}
const deviceCode = (clientId, { resource = origin + '/v1', expected = 200 } = {}) =>
  call('/api/auth/device/code', { method: 'POST', expected, body: { client_id: clientId, scope: scopes, resource } });
async function deviceToken(clientId, resource) {
  const device = (await deviceCode(clientId, resource ? { resource } : {})).value;
  await call(`/api/auth/device?user_code=${device.user_code}`, { owner: true });
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
  checks++;
  return value.access_token;
}
const read = (sid, token) =>
  call(`/v1/secrets/${sid}/read`, { method: 'POST', headers: { authorization: `Bearer ${token}` } });

try {
  const db = await mf.getD1Database('DB');
  await applyMigrations(db);
  await call('/bootstrap', {
    method: 'POST',
    owner: true,
    expected: 201,
    body: { name: 'Origin Owner', email: 'owner@example.com', password },
    headers: { 'x-bootstrap-token': bootstrap },
  });
  await signIn();
  const client = (
    await call('/admin/clients', {
      method: 'POST',
      owner: true,
      expected: 201,
      body: { name: 'Existing installation' },
    })
  ).value.clientId;
  const sid = (
    await call('/admin/secrets', {
      method: 'POST',
      owner: true,
      expected: 201,
      body: { name: 'Origin key', values: { token: 'synthetic-origin-test' } },
    })
  ).value.id;
  await call('/admin/grants', {
    method: 'POST',
    owner: true,
    body: { clientId: client, grants: [{ resourceType: 'secret', resourceId: sid, permission: 'secret:read' }] },
  });
  assert.equal((await read(sid, await deviceToken(client))).value.values.token, 'synthetic-origin-test');
  const links = await db.prepare('SELECT resourceId FROM oauthClientResource').all();
  assert(
    links.results.every((l) => l.resourceId === before + '/v1'),
    'the installation is created against the origin of the day',
  );

  // The same database now answers on a different origin. Nothing is repaired in between.
  await mf.setOptions(options(after));
  origin = after;
  cookie = '';
  await signIn();
  const token = await deviceToken(client);
  assert.equal(
    (await read(sid, token)).value.values.token,
    'synthetic-origin-test',
    'the existing installation keeps working after the move',
  );
  assert.equal(
    (await call('/v1/secrets', { headers: { authorization: `Bearer ${token}` } })).value.items.length,
    1,
    'the resource grant survives the move',
  );
  const stale = await mf.getD1Database('DB').then((d) => d.prepare('SELECT resourceId FROM oauthClientResource').all());
  assert(
    stale.results.some((l) => l.resourceId === before + '/v1'),
    'the retired link is left in place and is not consulted',
  );

  // Audience validation is unchanged: a resource that was never configured is refused.
  assert.equal(
    (await deviceCode(client, { resource: 'https://untrusted.example/v1', expected: 400 })).value.error,
    'invalid_target',
    'an unknown resource is rejected',
  );
  assert.equal(
    (await deviceCode(client, { resource: after + '/mcp', expected: 400 })).value.error,
    'invalid_target',
    'a path of this origin other than /v1 is rejected as a resource',
  );
  const created = (
    await call('/admin/clients', {
      method: 'POST',
      owner: true,
      expected: 201,
      body: { name: 'Installation created after the move' },
    })
  ).value.clientId;
  await deviceCode(created);

  // The resource row of the previous origin survives and can still be asked for, but the API only
  // accepts its own audience, so such a token is useless. One statement removes the residue.
  const retired = await deviceToken(client, before + '/v1');
  await call('/v1/secrets', { expected: 401, headers: { authorization: `Bearer ${retired}` } });
  await (
    await mf.getD1Database('DB')
  )
    .prepare('DELETE FROM oauthResource WHERE identifier<>?')
    .bind(after + '/v1')
    .run();
  await mf.setOptions(options(after));
  cookie = '';
  await signIn();
  assert.equal(
    (await deviceCode(client, { resource: before + '/v1', expected: 400 })).value.error,
    'invalid_target',
    'the retired resource is gone after the cleanup',
  );
  assert.equal(
    (await read(sid, await deviceToken(client))).value.values.token,
    'synthetic-origin-test',
    'the cleanup leaves the current audience working',
  );
  console.log(
    `Origin change acceptance passed: ${checks} checks; an installation from the previous origin still logs in and keeps its grant, only configured resources are accepted, and a token for the retired audience is refused by the API.`,
  );
} finally {
  await mf.dispose();
}
