// Moves an instance of the built Worker to another origin, as a migration does: a full export of the
// instance at the old origin, imported through the console's own importer into a new instance (a new
// database, bucket and root key) at the new origin. The Owner signs in with the old password, an
// installation logs in again under its old client id and keeps its grant, the Passkey stays behind with its
// hostname, and nothing issued under the old origin is accepted. A move that keeps the hostname keeps the
// Passkey. Runs under tsx, which loads the importer.
import { Miniflare, Log, LogLevel, convertV4MiniflareOptions } from 'miniflare';
import { mkdir } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { applyMigrations } from './migrations.mjs';
import { issueSql, newToken } from './bootstrap-token.mjs';
import { importSnapshot } from '../apps/web/src/import.ts';

const before = 'http://localhost:8787',
  after = 'https://clavifer.example';
const password = randomBytes(24).toString('base64url');
const state = resolve('work', 'e2e-origin-' + randomUUID());
await mkdir(state, { recursive: true });
const scopes = 'offline_access metadata:list secret:read connection:invoke access:request';
// Each instance has a database, a bucket and a root key of its own.
const options = (origin, name) =>
  convertV4MiniflareOptions({
    modules: true,
    scriptPath: 'dist/worker/index.js',
    compatibilityDate: '2026-09-11',
    compatibilityFlags: ['nodejs_compat'],
    log: new Log(LogLevel.ERROR),
    d1Databases: { DB: name },
    d1Persist: resolve(state, 'd1'),
    r2Buckets: { BACKUPS: name },
    r2Persist: resolve(state, 'r2'),
    serviceBindings: { ASSETS: () => new Response('web') },
    bindings: {
      APP_ORIGIN: origin,
      ALLOW_LOCAL_HTTP: 'true',
      ROOT_KEY: `1:${randomBytes(32).toString('base64url')}`,
    },
  });

const mf = new Miniflare(options(before, 'old'));
let origin = before,
  cookie = '',
  checks = 0,
  signIns = 0;
async function call(path, { method = 'GET', body, expected = 200, owner = false, headers = {} } = {}) {
  const r = await mf.dispatchFetch(origin + path, {
    method,
    headers: {
      'cf-connecting-ip': '127.0.0.1',
      ...(body instanceof URLSearchParams
        ? { 'content-type': 'application/x-www-form-urlencoded' }
        : body
          ? { 'content-type': 'application/json' }
          : {}),
      ...(owner ? { origin, cookie, 'sec-fetch-site': 'same-origin' } : {}),
      ...headers,
    },
    body: body instanceof URLSearchParams ? body : body ? JSON.stringify(body) : undefined,
  });
  const bytes = new Uint8Array(await r.arrayBuffer());
  let value;
  try {
    value = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    value = bytes;
  }
  assert.equal(
    r.status,
    expected,
    `${method} ${path}: ${typeof value === 'object' ? (value.error ?? 'unexpected status') : 'unexpected content'}`,
  );
  checks++;
  return { value, headers: r.headers };
}
async function signIn(expected = 200) {
  const r = await call('/api/auth/sign-in/email', {
    method: 'POST',
    owner: true,
    expected,
    body: { email: 'owner@example.com', password },
    headers: { 'cf-connecting-ip': `127.0.1.${++signIns}` },
  });
  cookie = r.headers
    .getSetCookie()
    .map((s) => s.split(';')[0])
    .join('; ');
}
const deviceCode = (clientId, { resource = origin + '/v1', expected = 200 } = {}) =>
  call('/api/auth/device/code', { method: 'POST', expected, body: { client_id: clientId, scope: scopes, resource } });
async function deviceLogin(clientId) {
  const device = (await deviceCode(clientId)).value;
  await call(`/api/auth/device?user_code=${device.user_code}`, { owner: true });
  await call('/api/auth/device/approve', { method: 'POST', owner: true, body: { userCode: device.user_code } });
  return (
    await call('/api/auth/oauth2/token', {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: device.device_code,
        client_id: clientId,
      }),
    })
  ).value;
}
const read = (sid, token, expected = 200) =>
  call(`/v1/secrets/${sid}/read`, { method: 'POST', expected, headers: { authorization: `Bearer ${token}` } });
/** Makes the instance at origin a new one from name and imports the file into it. */
async function moveTo(to, name, file, identity) {
  await mf.setOptions(options(to, name));
  origin = to;
  cookie = '';
  const db = await mf.getD1Database('DB');
  await applyMigrations(db);
  const { token, binds } = newToken();
  await db
    .prepare(issueSql)
    .bind(...binds)
    .run();
  const header = await importSnapshot({
    file: new Response(file).body,
    identity,
    token,
    send: async (path, body, headers) =>
      (
        await call(path, {
          method: 'POST',
          owner: true,
          body,
          headers,
          expected: path === '/api/setup/import' ? 201 : 200,
        })
      ).value,
    missing: async () => false,
  });
  assert.equal(header.source.origin, before);
  return db;
}

try {
  const db = await mf.getD1Database('DB');
  await applyMigrations(db);
  const setup = newToken();
  await db
    .prepare(issueSql)
    .bind(...setup.binds)
    .run();
  await call('/api/setup/owner', {
    method: 'POST',
    owner: true,
    expected: 201,
    body: {
      name: 'Origin Owner',
      email: 'owner@example.com',
      password,
      backupRecipient: await identityToRecipient(await generateIdentity()),
    },
    headers: { 'x-bootstrap-token': setup.token },
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
  const old = await deviceLogin(client);
  assert.equal((await read(sid, old.access_token)).value.values.token, 'synthetic-origin-test');
  const { value: owner } = await db.prepare("SELECT value FROM system_state WHERE key='owner_user_id'").first();
  await db
    .prepare(
      "INSERT INTO passkey (id,name,publicKey,userId,credentialID,counter,deviceType,backedUp,transports,createdAt,aaguid) VALUES ('passkey-1','Laptop',?,?,'c3ludGhldGljLWNyZWRlbnRpYWw',0,'multiDevice',1,'internal',?,NULL)",
    )
    .bind(Buffer.from('synthetic-cose-public-key').toString('base64'), owner, Date.now())
    .run();
  const identity = await generateIdentity();
  const exported = (
    await call(
      `/admin/backup/export?${new URLSearchParams({ recipient: await identityToRecipient(identity), id: randomBytes(16).toString('base64url') })}`,
      { owner: true },
    )
  ).value;

  // The new instance at the new origin, from the file alone.
  const moved = await moveTo(after, 'new', exported, identity);
  await signIn();
  assert.deepEqual(
    (await moved.prepare('SELECT id FROM passkey').all()).results,
    [],
    'the Passkey stays with its hostname',
  );
  // Nothing issued by the old instance is accepted: its tokens were never carried over, and its audience is
  // not this instance's.
  await read(sid, old.access_token, 401);
  assert.equal(
    (
      await call('/api/auth/oauth2/token', {
        method: 'POST',
        expected: 400,
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: old.refresh_token, client_id: client }),
      })
    ).value.error,
    'invalid_grant',
  );
  assert.equal(
    (await deviceCode(client, { resource: before + '/v1', expected: 400 })).value.error,
    'invalid_target',
    'the old audience is no resource of the new instance',
  );
  const token = (await deviceLogin(client)).access_token;
  assert.equal(
    (await read(sid, token)).value.values.token,
    'synthetic-origin-test',
    'the installation logs in again under its client id and keeps its grant',
  );
  assert.equal(
    (await call('/admin/status', { owner: true })).value.clients.find((c) => c.clientId === client).name,
    'Existing installation',
  );

  // A move that keeps the hostname keeps the Passkey.
  const same = await moveTo(before, 'same-host', exported, identity);
  assert.deepEqual(
    (await same.prepare('SELECT id,userId FROM passkey').all()).results,
    [{ id: 'passkey-1', userId: owner }],
    'the Passkey comes along on its own hostname',
  );
  await signIn();
  assert.equal((await read(sid, (await deviceLogin(client)).access_token)).value.values.token, 'synthetic-origin-test');
  console.log(
    `Origin change acceptance passed: ${checks} checks; a full export imported at another origin under another root key keeps the Owner's password, the installation's client id and grant, drops the Passkey, accepts nothing the old instance issued, and keeps the Passkey on the same hostname.`,
  );
} finally {
  await mf.dispose();
}
