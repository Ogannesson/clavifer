// Automatic backups of the built Worker, and the recovery they exist for. The instance backs up to R2 and
// seals old audit rows into archive/; then its root key is lost: a new database and a new root key on the
// same bucket, into which the latest automatic backup is imported through the console's own importer, after
// which the Owner, the installation and its grant work as before. Runs under tsx, which loads the importer.
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { randomBytes, createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { generateIdentity, identityToRecipient, Decrypter } from 'age-encryption';
import { applyMigrations } from './migrations.mjs';
import { issueSql, newToken } from './bootstrap-token.mjs';
import { importSnapshot } from '../apps/web/src/import.ts';

const root = `work/backup-e2e-${Date.now()}`;
await mkdir(root, { recursive: true });
const origin = 'http://localhost:8787',
  password = randomBytes(24).toString('base64url');
const scopes = 'offline_access metadata:list secret:read connection:invoke access:request';
// setOptions with another database and root key and the same bucket is the recovery from a lost root key.
// The persisted data stays where it is; another database is another id under it.
const options = (database) =>
  convertV4MiniflareOptions({
    modules: true,
    scriptPath: 'dist/worker/index.js',
    compatibilityDate: '2026-09-11',
    compatibilityFlags: ['nodejs_compat'],
    log: new Log(LogLevel.ERROR),
    d1Databases: { DB: database },
    r2Buckets: ['BACKUPS'],
    d1Persist: root + '/d1',
    r2Persist: root + '/r2',
    serviceBindings: { ASSETS: () => new Response('fixture') },
    bindings: {
      APP_ORIGIN: origin,
      ALLOW_LOCAL_HTTP: 'true',
      ROOT_KEY: '1:' + randomBytes(32).toString('base64url'),
    },
  });
const mf = new Miniflare(options('original'));
let cookie = '',
  checks = 0;
async function call(path, { method = 'GET', body, status = 200, owner = true, headers = {} } = {}) {
  const r = await mf.dispatchFetch(origin + path, {
    method,
    headers: {
      'cf-connecting-ip': '127.0.0.1',
      ...(owner ? { origin, cookie } : {}),
      ...(body instanceof URLSearchParams
        ? { 'content-type': 'application/x-www-form-urlencoded' }
        : body
          ? { 'content-type': 'application/json' }
          : {}),
      ...headers,
    },
    body: body instanceof URLSearchParams ? body : body ? JSON.stringify(body) : undefined,
  });
  assert.equal(r.status, status, `${method} ${path}`);
  checks++;
  return r;
}
async function json(path, options) {
  return (await call(path, options)).json();
}
const signIn = async () => {
  cookie = (
    await call('/api/auth/sign-in/email', { method: 'POST', body: { email: 'backup@example.com', password } })
  ).headers
    .getSetCookie()
    .map((v) => v.split(';')[0])
    .join('; ');
};
async function deviceToken(clientId) {
  const device = await json('/api/auth/device/code', {
    method: 'POST',
    body: { client_id: clientId, scope: scopes, resource: origin + '/v1' },
  });
  await call(`/api/auth/device?user_code=${device.user_code}`);
  await call('/api/auth/device/approve', { method: 'POST', body: { userCode: device.user_code } });
  return (
    await json('/api/auth/oauth2/token', {
      method: 'POST',
      owner: false,
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: device.device_code,
        client_id: clientId,
      }),
    })
  ).access_token;
}
/** The records of a v1 snapshot (JSON Lines). */
async function decrypt(identity, bytes) {
  const d = new Decrypter();
  d.addIdentity(identity);
  return (await d.decrypt(new Uint8Array(bytes), 'text'))
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}
// The values of a credential's current version in a snapshot.
const values = (records, secretId) => {
  const { currentVersion } = records.find((r) => r.type === 'secret' && r.id === secretId);
  return records.find((r) => r.type === 'secret-version' && r.secretId === secretId && r.version === currentVersion)
    .values;
};
try {
  const db = await mf.getD1Database('DB');
  await applyMigrations(db);
  const { token, binds } = newToken();
  await db
    .prepare(issueSql)
    .bind(...binds)
    .run();
  // The Owner is created with a backup recipient; the first backup waits for the first run.
  const identity = await generateIdentity(),
    recipient = await identityToRecipient(identity);
  const setup = await call('/api/setup/owner', {
    method: 'POST',
    status: 201,
    body: { email: 'backup@example.com', name: 'Backup test', password, backupRecipient: recipient },
    headers: { 'x-bootstrap-token': token },
  });
  cookie = setup.headers
    .getSetCookie()
    .map((v) => v.split(';')[0])
    .join('; ');
  await setup.arrayBuffer();
  assert.equal((await json('/admin/backup/status')).recipient, recipient);
  await call('/admin/backup/status', { owner: false, status: 401 });
  await call('/admin/backup/latest', { status: 404 });
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
  const client = (await json('/admin/clients', { method: 'POST', status: 201, body: { name: 'Backup CLI' } })).clientId;
  await call('/admin/grants', {
    method: 'POST',
    body: { clientId: client, grants: [{ resourceType: 'secret', resourceId: secret.id, permission: 'secret:read' }] },
  });
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
  assert.deepEqual([snapshot[0].format, snapshot[0].kind], ['clavifer-backup-v1', 'automatic']);
  assert.equal(values(snapshot, secret.id).password, 'synthetic-backup-password');
  assert.equal(snapshot.find((r) => r.type === 'connection').auth.type, 'basic');
  assert.equal(snapshot.find((r) => r.type === 'owner').email, 'backup@example.com');
  await writeFile(root + '/verified-snapshot.age', new Uint8Array(bytes), { flag: 'wx' });
  await call(`/admin/secrets/${secret.id}`, {
    method: 'PUT',
    body: { name: 'Backup values', values: { password: 'rotated-backup-test' }, expectedVersion: 1 },
  });
  assert.equal((await json('/admin/backup/status')).pending, true);
  await json('/admin/backup/run', { method: 'POST' });
  assert.equal(
    values(await decrypt(identity, await (await call('/admin/backup/latest')).arrayBuffer()), secret.id).password,
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
  // The scheduled run seals 2 MB of audit rows an hour old into archive/ and backs up after it: the backup
  // names the segment by its key in this bucket.
  const { value: owner } = await db.prepare("SELECT value FROM system_state WHERE key='owner_user_id'").first();
  await db
    .prepare(
      "INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<2000) SELECT printf('cold-%06d',i),?,'client',printf('%.*c',1000,'x'),NULL,'ok','request',?+i FROM n",
    )
    .bind(owner, Date.now() - 3_600_000)
    .run();
  await (await mf.getWorker()).scheduled({ cron: '*/15 * * * *' });
  const segments = (await db.prepare('SELECT kind,seq,object_key FROM archive_segments').all()).results;
  assert.deepEqual(
    segments.map((s) => [s.kind, s.seq]),
    [['audit', 1]],
  );
  const latest = new Uint8Array(await (await call('/admin/backup/latest')).arrayBuffer());
  assert.deepEqual(
    (await decrypt(secondIdentity, latest)).filter((r) => r.type === 'segment').map((r) => r.key),
    [segments[0].object_key],
  );
  await call('/admin/backup/config', { method: 'PUT', body: { recipient: null } });
  assert.equal((await json('/admin/backup/run', { method: 'POST' })).outcome, 'not_configured');
  await call('/admin/backup/latest');
  // Every run of this script happens on one day, so retention keeps exactly the newest snapshot, and it
  // never touches the sealed segments.
  const bucket = await mf.getR2Bucket('BACKUPS'),
    objects = await bucket.list({ prefix: 'vault/' });
  assert.equal(objects.objects.length, 1, 'same-day retention keeps one snapshot');
  const current = await db.prepare('SELECT object_key FROM backup_state WHERE id=1').first();
  assert.equal(objects.objects[0].key, current.object_key, 'the retained snapshot is the downloadable one');
  assert(await bucket.head(segments[0].object_key), 'retention leaves archive/ alone');
  // Trigger revisions are committed or rolled back with the business write.
  const revision = (await json('/admin/backup/status')).revision;
  await assert.rejects(() =>
    db.batch([
      db.prepare("UPDATE secrets SET name='rollback-test' WHERE id=?").bind(secret.id),
      db.prepare('INSERT INTO backup_state (id) VALUES (1)'),
    ]),
  );
  assert.equal((await json('/admin/backup/status')).revision, revision);

  // The root key is lost. A new database and a new root key on the same bucket: the instance starts
  // uninitialized, and the latest automatic backup, taken from the bucket, brings everything back.
  await mf.setOptions(options('rebuilt'));
  const rebuilt = await mf.getD1Database('DB');
  await applyMigrations(rebuilt);
  cookie = '';
  assert.equal((await json('/healthz', { owner: false })).initialized, false);
  const recovery = newToken();
  await rebuilt
    .prepare(issueSql)
    .bind(...recovery.binds)
    .run();
  const header = await importSnapshot({
    file: new Response(latest).body,
    identity: secondIdentity,
    token: recovery.token,
    send: (path, body, headers) =>
      json(path, { method: 'POST', body, headers, status: path === '/api/setup/import' ? 201 : 200 }),
    missing: async () => false,
  });
  assert.equal(header.kind, 'automatic');
  assert.equal((await json('/healthz', { owner: false })).keys, 'ok');
  assert.deepEqual((await rebuilt.prepare('SELECT kind,seq,object_key FROM archive_segments').all()).results, segments);
  await signIn();
  const restored = await json('/admin/status');
  assert.deepEqual(
    restored.secrets.map((s) => [s.id, s.fields.sort()]),
    [[secret.id, ['password', 'username']]],
  );
  assert.equal(restored.backup.recipient, await identityToRecipient(secondIdentity), 'the recipient came along');
  // The installation logs in again under its client id; its grant and the rotated value came along.
  const agent = await deviceToken(client);
  assert.deepEqual(
    (
      await json(`/v1/secrets/${secret.id}/read`, {
        method: 'POST',
        owner: false,
        headers: { authorization: `Bearer ${agent}` },
      })
    ).values,
    { username: 'backup-test-user', password: 'rotated-backup-test' },
  );
  // The rebuilt instance backs up again, naming the same segment.
  await json('/admin/backup/run', { method: 'POST' });
  assert.equal((await json('/admin/backup/status')).lastError, null);
  const report = {
    passed: true,
    httpChecks: checks,
    scenarios: [
      'public-key validation',
      'Owner-only download',
      'concurrent lease',
      'consistent revision',
      'age decrypt',
      'v1 snapshot',
      'rotation',
      'broken-binding retry',
      'abandoned lease',
      'recipient rotation',
      'sealing before the backup',
      'same-day retention',
      'transaction rollback',
      'recovery from a lost root key by import',
    ],
    retainedArtifacts: root,
  };
  await writeFile(root + '/result.json', JSON.stringify(report, null, 2));
  console.log(
    `Backup acceptance passed: ${checks} HTTP checks; the latest automatic backup rebuilt the instance under a new root key from the same bucket.`,
  );
} finally {
  await mf.dispose();
}
