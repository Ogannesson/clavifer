import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { randomBytes, createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { generateIdentity, identityToRecipient, Decrypter } from 'age-encryption';
import { applyMigrations } from './migrations.mjs';

const root = `work/backup-e2e-${Date.now()}`;
await mkdir(root, { recursive: true });
const origin = 'http://localhost:8787',
  bootstrap = randomBytes(24).toString('base64url'),
  password = randomBytes(24).toString('base64url');
const mf = new Miniflare(
  convertV4MiniflareOptions({
    modules: true,
    scriptPath: 'dist/worker/index.js',
    compatibilityDate: '2026-09-11',
    compatibilityFlags: ['nodejs_compat'],
    log: new Log(LogLevel.ERROR),
    d1Databases: ['DB'],
    r2Buckets: ['BACKUPS'],
    d1Persist: root + '/d1',
    r2Persist: root + '/r2',
    serviceBindings: { ASSETS: () => new Response('fixture') },
    bindings: {
      APP_ORIGIN: origin,
      ALLOW_LOCAL_HTTP: 'true',
      AUTH_SECRET: randomBytes(32).toString('base64url'),
      KEK_RING: 'v1:' + randomBytes(32).toString('base64url'),
      ACTIVE_KEK_ID: 'v1',
      BOOTSTRAP_HASH: createHash('sha256').update(bootstrap).digest('base64url'),
    },
  }),
);
let cookie = '',
  checks = 0;
async function call(path, { method = 'GET', body, status = 200, owner = true } = {}) {
  const r = await mf.dispatchFetch(origin + path, {
    method,
    headers: {
      ...(owner ? { origin, cookie } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(path === '/bootstrap' ? { 'x-bootstrap-token': bootstrap } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  assert.equal(r.status, status, `${method} ${path}`);
  checks++;
  return r;
}
async function json(path, options) {
  return (await call(path, options)).json();
}
async function decrypt(identity, bytes) {
  const d = new Decrypter();
  d.addIdentity(identity);
  return JSON.parse(await d.decrypt(new Uint8Array(bytes), 'text'));
}
try {
  const db = await mf.getD1Database('DB');
  await applyMigrations(db);
  await call('/bootstrap', {
    method: 'POST',
    status: 201,
    body: { email: 'backup@example.com', name: 'Backup test', password },
  });
  const login = await call('/api/auth/sign-in/email', {
    method: 'POST',
    body: { email: 'backup@example.com', password },
  });
  cookie = login.headers
    .getSetCookie()
    .map((v) => v.split(';')[0])
    .join('; ');
  await login.arrayBuffer();
  assert.equal((await json('/admin/backup/status')).configured, false);
  await call('/admin/backup/status', { owner: false, status: 401 });
  await call('/admin/backup/latest', { status: 404 });
  assert.equal((await json('/admin/backup/run', { method: 'POST' })).outcome, 'not_configured');
  await call('/admin/backup/config', { method: 'PUT', body: { recipient: 'age1not-valid' }, status: 400 });
  const secret = await json('/admin/secrets', {
    method: 'POST',
    status: 201,
    body: { name: 'Backup values', values: { username: 'backup-test-user', password: 'synthetic-backup-password' } },
  });
  const connection = await json('/admin/connections', {
    method: 'POST',
    body: {
      name: 'Basic connection',
      origin: 'https://example.com',
      paths: ['/'],
      auth: { type: 'basic', secretId: secret.id, usernameField: 'username', passwordField: 'password' },
    },
  });
  const identity = await generateIdentity(),
    recipient = await identityToRecipient(identity);
  await call('/admin/backup/config', { method: 'PUT', body: { recipient } });
  assert.equal((await json('/admin/backup/status')).pending, true);
  const results = await Promise.all([
    json('/admin/backup/run', { method: 'POST' }),
    json('/admin/backup/run', { method: 'POST' }),
  ]);
  assert(results.some((r) => r.outcome === 'saved'));
  assert(results.every((r) => ['saved', 'running'].includes(r.outcome)));
  const status = await json('/admin/backup/status');
  assert.equal(status.pending, false);
  assert.equal(status.revision, status.savedRevision);
  assert.equal(status.lastError, null);
  const download = await call('/admin/backup/latest'),
    bytes = await download.arrayBuffer();
  assert.equal(
    createHash('sha256').update(new Uint8Array(bytes)).digest('hex'),
    download.headers.get('x-backup-sha256'),
  );
  const snapshot = await decrypt(identity, bytes);
  assert.equal(snapshot.secrets[0].values.password, 'synthetic-backup-password');
  assert.equal(snapshot.connections[0].auth.type, 'basic');
  assert.equal(snapshot.clients, undefined);
  assert.equal(snapshot.grants, undefined);
  await writeFile(root + '/verified-snapshot.age', new Uint8Array(bytes), { flag: 'wx' });
  await call(`/admin/secrets/${secret.id}`, {
    method: 'PUT',
    body: { name: 'Backup values', values: { password: 'rotated-backup-test' }, expectedVersion: 1 },
  });
  assert.equal((await json('/admin/backup/status')).pending, true);
  await json('/admin/backup/run', { method: 'POST' });
  assert.equal(
    (await decrypt(identity, await (await call('/admin/backup/latest')).arrayBuffer())).secrets[0].values.password,
    'rotated-backup-test',
  );
  // Corruption must not replace the last recoverable object or claim success.
  const before = await db.prepare('SELECT * FROM backup_state').first();
  await db
    .prepare('UPDATE connections SET auth_json=? WHERE id=?')
    .bind(
      JSON.stringify({ type: 'basic', secretId: 'missing', usernameField: 'username', passwordField: 'password' }),
      connection.id,
    )
    .run();
  const failure = await json('/admin/backup/run', { method: 'POST', status: 409 });
  assert.equal(failure.error, 'backup_has_broken_connection');
  const failed = await json('/admin/backup/status');
  assert.equal(failed.savedRevision, before.success_revision);
  assert.equal(failed.pending, true);
  assert.equal(failed.running, false);
  assert.equal(failed.lastError, 'backup_has_broken_connection');
  await call('/admin/backup/latest');
  await call(`/admin/connections/${connection.id}`, {
    method: 'PUT',
    body: {
      name: 'Basic connection',
      origin: 'https://example.com',
      paths: ['/'],
      auth: { type: 'basic', secretId: secret.id, usernameField: 'username', passwordField: 'password' },
    },
  });
  await json('/admin/backup/run', { method: 'POST' });
  assert.equal((await json('/admin/backup/status')).lastError, null);
  // An abandoned lease is recoverable; the next attempt must retain old snapshots.
  await db
    .prepare("UPDATE backup_state SET lease_token='abandoned',lease_until=?")
    .bind(Date.now() + 60000)
    .run();
  assert.equal((await json('/admin/backup/run', { method: 'POST' })).outcome, 'running');
  await db.prepare('UPDATE backup_state SET lease_until=0').run();
  assert.equal((await json('/admin/backup/run', { method: 'POST' })).outcome, 'saved');
  const secondIdentity = await generateIdentity();
  await call('/admin/backup/config', { method: 'PUT', body: { recipient: await identityToRecipient(secondIdentity) } });
  assert.equal((await json('/admin/backup/status')).pending, true);
  await json('/admin/backup/run', { method: 'POST' });
  const rotatedBytes = await (await call('/admin/backup/latest')).arrayBuffer();
  await decrypt(secondIdentity, rotatedBytes);
  await assert.rejects(() => decrypt(identity, rotatedBytes));
  await decrypt(identity, bytes);
  await call('/admin/backup/config', { method: 'PUT', body: { recipient: null } });
  assert.equal((await json('/admin/backup/run', { method: 'POST' })).outcome, 'not_configured');
  await call('/admin/backup/latest');
  // Every run of this script happens on one day, so retention keeps exactly the newest snapshot.
  const bucket = await mf.getR2Bucket('BACKUPS'),
    objects = await bucket.list();
  assert.equal(objects.objects.length, 1, 'same-day retention keeps one snapshot');
  const current = await db.prepare('SELECT object_key FROM backup_state WHERE id=1').first();
  assert.equal(objects.objects[0].key, current.object_key, 'the retained snapshot is the downloadable one');
  // Trigger revisions are committed or rolled back with the business write.
  const revision = (await json('/admin/backup/status')).revision;
  await assert.rejects(() =>
    db.batch([
      db.prepare("UPDATE secrets SET name='rollback-test' WHERE id=?").bind(secret.id),
      db.prepare('INSERT INTO backup_state (id) VALUES (1)'),
    ]),
  );
  assert.equal((await json('/admin/backup/status')).revision, revision);
  const report = {
    passed: true,
    httpChecks: checks,
    retainedSnapshots: objects.objects.length,
    scenarios: [
      'public-key validation',
      'Owner-only download',
      'concurrent lease',
      'consistent revision',
      'age decrypt',
      'Basic restore binding',
      'rotation',
      'broken-binding retry',
      'abandoned lease',
      'recipient rotation',
      'same-day retention',
      'transaction rollback',
    ],
    retainedArtifacts: root,
  };
  await writeFile(root + '/result.json', JSON.stringify(report, null, 2));
  await writeFile('work/backup-e2e-result.json', JSON.stringify(report, null, 2));
  console.log(
    `Backup acceptance passed: ${checks} HTTP checks; ${objects.objects.length} encrypted snapshots retained.`,
  );
} finally {
  await mf.dispose();
}
