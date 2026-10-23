// Writes the v1 sample files of the 0.5.0 release code next to full-a.age, which the first exporter
// (before the 0.5.0 release) wrote, in tests/fixtures/v1 (see its README): an
// automatic backup, a full export of the same instance and the segment files the automatic backup names,
// from synthetic data, by the Worker's own code on miniflare, encrypted to the test identity there.
// Run: npx tsx scripts/fixtures-v1.ts. It never overwrites a file; the samples may be regenerated, by
// deleting them first, only until the release that freezes them, and tests/snapshot.test.ts pins their
// SHA-256 then. The segments are a few rows each, sealed here as archive.ts seals about 1 MB, so the
// samples stay small.
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { Encrypter, identityToRecipient } from 'age-encryption';
import { applyMigrations } from './migrations.mjs';
import { issueSql, newToken } from './bootstrap-token.mjs';
import worker from '../apps/worker/src/index';
import { type Bindings } from '../apps/worker/src/context';
import { CARRIED, runAutomaticBackup } from '../apps/worker/src/backup';
import { auditRecord, requestRecord, serialized } from '../apps/worker/src/export';
import { decryptArchiveIdentity, parseRootKeys } from '../packages/core/crypto';
import { ARCHIVE_FORMAT, archiveHeader, snapshotRecord } from '../packages/core/snapshot';

const directory = 'tests/fixtures/v1';
const origin = 'http://localhost:8787';
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const LS = String.fromCharCode(0x2028);
// Recorded in the README: NFKC turns its "ﬁ" ligature into "fi", so only an importer that normalizes the
// password and takes the salt as text verifies it.
const password = 'synthetic-ﬁxture-password';
const recipient = await identityToRecipient((await readFile(`${directory}/test-identity.txt`, 'utf8')).trim());
const mf = new Miniflare(
  convertV4MiniflareOptions({
    modules: true,
    script: 'export default {fetch:()=>new Response("unused")}',
    compatibilityDate: '2026-09-11',
    compatibilityFlags: ['nodejs_compat'],
    log: new Log(LogLevel.ERROR),
    d1Databases: ['DB'],
    r2Buckets: ['BACKUPS'],
  }),
);
let cookie = '';
try {
  const env = {
    DB: await mf.getD1Database('DB'),
    BACKUPS: await mf.getR2Bucket('BACKUPS'),
    APP_ORIGIN: origin,
    ALLOW_LOCAL_HTTP: 'true',
    ROOT_KEY: `1:${randomBytes(32).toString('base64url')}`,
  } as unknown as Bindings;
  const fetchWorker = (path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) =>
    worker.fetch(
      new Request(origin + path, {
        method,
        headers: {
          'cf-connecting-ip': '127.0.0.1',
          origin,
          cookie,
          'sec-fetch-site': 'same-origin',
          ...(body ? { 'content-type': 'application/json' } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
      }),
      env,
      context,
    );
  const call = async (path: string, method = 'GET', body?: unknown) => {
    const response = await fetchWorker(path, method, body);
    const text = await response.text();
    if (response.status >= 300) throw new Error(`${method} ${path}: ${response.status} ${text}`);
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };
  const run = (sql: string, ...args: unknown[]) =>
    env.DB.prepare(sql)
      .bind(...args)
      .run();
  await applyMigrations(env.DB);
  const { token, binds } = newToken();
  await run(issueSql, ...binds);
  const setup = await fetchWorker(
    '/api/setup/owner',
    'POST',
    {
      name: 'Owner',
      email: 'owner@example.com',
      password,
      backupRecipient: recipient,
    },
    { 'x-bootstrap-token': token },
  );
  if (setup.status !== 201) throw new Error(`setup: ${setup.status} ${await setup.text()}`);
  cookie = setup.headers
    .getSetCookie()
    .map((value) => value.split(';')[0])
    .join('; ');
  const owner = (await env.DB.prepare('SELECT id FROM "user"').first<{ id: string }>())!.id;

  // Credentials: one rotated twice (a value holds U+2028 and a line break), a deleted one, one for Basic.
  const multi = String((await call('/admin/secrets', 'POST', { name: 'Multi', values: { token: 'first' } })).id);
  for (const [values, expectedVersion] of [
    [{ token: 'second', note: `line${LS}separated\nand broken` }, 1],
    [{ token: 'third' }, 2],
  ] as const)
    await call(`/admin/secrets/${multi}`, 'PUT', {
      name: 'Multi',
      description: 'Rotated twice',
      values,
      expectedVersion,
    });
  const gone = String((await call('/admin/secrets', 'POST', { name: 'Gone', values: { token: 'gone' } })).id);
  await call(`/admin/secrets/${gone}`, 'DELETE');
  const plain = String(
    (await call('/admin/secrets', 'POST', { name: 'Plain', values: { username: 'user', password: 'pass' } })).id,
  );
  await run('UPDATE secrets SET description=NULL WHERE id=?', plain);
  // Connections: bound with every rule kind and extra hosts, Basic with a policy older than its optional
  // keys, a header and a query one, one reaching any host, and a deleted one.
  const bound = String(
    (
      await call('/admin/connections', 'POST', {
        name: 'Bound',
        origin: 'https://api.example.com',
        description: 'Send X-Account: synthetic.',
        paths: ['/v1'],
        methods: ['GET', 'POST'],
        deny: ['DELETE /v1/admin/*'],
        approval: ['POST /v1/payments'],
        free: ['/v1/status'],
        hosts: ['*.files.example.com'],
        auth: { type: 'bearer', secretId: multi, field: 'token' },
      })
    ).id,
  );
  const basic = String(
    (
      await call('/admin/connections', 'POST', {
        name: 'Basic',
        origin: 'https://basic.example.com',
        paths: ['/'],
        auth: { type: 'basic', secretId: plain, usernameField: 'username', passwordField: 'password' },
      })
    ).id,
  );
  await run('UPDATE connections SET policy_json=? WHERE id=?', JSON.stringify({ paths: ['/api'] }), basic);
  await call('/admin/connections', 'POST', {
    name: 'Header',
    origin: 'https://header.example.com',
    paths: ['/'],
    anyHost: true,
    auth: { type: 'header', secretId: multi, field: 'token', name: 'X-API-Key' },
  });
  await call('/admin/connections', 'POST', {
    name: 'Query',
    origin: 'https://query.example.com',
    paths: ['/'],
    auth: { type: 'query', secretId: plain, field: 'password', name: 'api_key' },
  });
  const removed = String(
    (await call('/admin/connections', 'POST', { name: 'Removed', origin: 'https://old.example.com', paths: ['/'] })).id,
  );
  await call(`/admin/connections/${removed}`, 'DELETE');
  // Installations: native and web as the console creates them, a revoked one, and a row without user,
  // scopes or grant types as an early version left one.
  const cli = String((await call('/admin/clients', 'POST', { name: 'CLI' })).clientId);
  await call('/admin/clients', 'POST', { name: 'Web', redirectUris: ['https://app.example.com/callback'] });
  const old = String((await call('/admin/clients', 'POST', { name: 'Old' })).clientId);
  await run(
    'INSERT INTO "oauthClient" (id,clientId,redirectUris,createdAt) VALUES (?,?,?,?)',
    'legacy-row',
    'legacy-client',
    '[]',
    Date.now(),
  );
  // Grants: a field subset, a scope extension without an expiry, and a timed one revoked with its client.
  await call('/admin/grants', 'POST', {
    clientId: cli,
    grants: [
      { resourceType: 'secret', resourceId: multi, permission: 'secret:read', fields: ['token'] },
      {
        resourceType: 'connection',
        resourceId: bound,
        permission: 'connection:invoke',
        paths: ['/v2'],
        methods: ['POST'],
      },
    ],
  });
  await call('/admin/grants', 'POST', {
    clientId: old,
    grants: [
      {
        resourceType: 'connection',
        resourceId: bound,
        permission: 'connection:invoke',
        paths: ['/v1/reports'],
        methods: ['GET'],
      },
    ],
    expiresAt: Date.now() + 86400000,
  });
  await call(`/admin/clients/${old}`, 'DELETE');
  // Access requests in each status, as stored: an invocation approved and run, a setup draft with its
  // fixed ids, an update draft with what it was compared against. Some are cold, sealed below.
  const request = (id: string, status: string, requested: unknown, at: number, more: unknown[] = [null, null, null]) =>
    run(
      'INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at,fingerprint,consumed_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
      id,
      owner,
      cli,
      JSON.stringify(requested),
      more[0],
      status,
      at,
      at + 86400000,
      more[1],
      more[2],
    );
  const grants = { grants: [{ resourceType: 'secret', resourceId: multi, permission: 'secret:read' }] };
  const now = Date.now(),
    cold = now - 3 * 86400000;
  await request('cold-denied', 'denied', grants, cold + 1, ['Not now', null, null]);
  await request('cold-approved', 'approved', grants, cold + 2);
  await request('pending-request', 'pending', grants, now);
  await request('denied-request', 'denied', grants, now, ['Need the token', null, null]);
  await request(
    'approved-request',
    'approved',
    { invocation: { connection: bound, method: 'POST', path: '/v1/items', body: `line${LS}` } },
    now,
    ['', 'f'.repeat(64), now],
  );
  await request(
    'setup-request',
    'pending',
    {
      setup: {
        secret: { name: 'Drafted', description: '', fields: ['token'] },
        connections: [
          {
            name: 'Drafted API',
            origin: 'https://drafted.example.com',
            description: '',
            paths: ['/v1'],
            methods: ['GET', 'HEAD'],
            deny: [],
            approval: [],
            free: [],
            hosts: [],
            anyHost: false,
            auth: { type: 'bearer', field: 'token' },
            tests: [{ method: 'GET', path: '/v1/items', grant: true, expect: 'run' }],
          },
        ],
      },
      ids: { secretId: 'drafted-secret', connectionIds: ['drafted-connection'] },
    },
    now,
  );
  await request(
    'update-request',
    'approved',
    {
      update: {
        connection: bound,
        changes: { paths: ['/v1', '/v3'] },
        tests: [{ method: 'GET', path: '/v3/items', grant: true, expect: 'run' }],
      },
      current: ['path_not_allowed'],
      updatedAt: now,
    },
    now,
  );
  // Cold audit rows, one without client or resource; the hot ones are what the routes above wrote.
  for (let i = 1; i <= 4; i++)
    await run(
      'INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) VALUES (?,?,?,?,?,?,?,?)',
      `cold-audit-${i}`,
      owner,
      i === 4 ? null : cli,
      'secret:read',
      i === 4 ? null : multi,
      'ok',
      `request-${i}`,
      cold + i,
    );
  await run('UPDATE "user" SET image=?,emailVerified=1', 'https://example.com/owner.png');
  // Passkeys: one with every field, and one without a name, a time or an authenticator id, not backed up,
  // with the empty transports Better Auth writes when the browser reports none.
  const passkey = (...values: unknown[]) =>
    run(
      'INSERT INTO passkey (id,name,publicKey,userId,credentialID,counter,deviceType,backedUp,transports,createdAt,aaguid) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      ...values,
    );
  await passkey(
    'passkey-1',
    'Laptop',
    Buffer.from('synthetic-cose-public-key').toString('base64'),
    owner,
    'c3ludGhldGljLWNyZWRlbnRpYWw',
    3,
    'multiDevice',
    1,
    'internal,hybrid',
    now,
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
  );
  await passkey(
    'passkey-2',
    null,
    Buffer.from('another-cose-public-key').toString('base64'),
    owner,
    'YW5vdGhlci1jcmVkZW50aWFs',
    0,
    'singleDevice',
    0,
    '',
    null,
    null,
  );

  // Two audit segments and one of access requests, sealed as archive.ts seals: the rows of a range go
  // into a file encrypted to the archive identity and leave the table in the batch that records it.
  const stored = await env.DB.prepare("SELECT value FROM system_state WHERE key='archive_identity'").first<{
    value: string;
  }>();
  const archive = await identityToRecipient(
    await decryptArchiveIdentity(parseRootKeys(env.ROOT_KEY!), owner, JSON.parse(stored!.value)),
  );
  const seal = async (kind: 'audit' | 'access-request', seq: number, ids: string[]) => {
    const table = kind === 'audit' ? 'audit_events' : 'access_requests';
    const rows = (
      await env.DB.prepare(
        `SELECT ${CARRIED[table]} FROM ${table} WHERE id IN (${ids.map(() => '?').join(',')}) ORDER BY created_at,id`,
      )
        .bind(...ids)
        .all<Record<string, unknown>>()
    ).results;
    const first = rows[0],
      last = rows[rows.length - 1],
      sealedAt = Date.now();
    const encrypter = new Encrypter();
    encrypter.addRecipient(archive);
    const file = new Uint8Array(
      await encrypter.encrypt(
        serialized([
          archiveHeader.parse({
            type: 'header',
            format: ARCHIVE_FORMAT,
            kind,
            seq,
            first: [first.created_at, first.id],
            last: [last.created_at, last.id],
            rows: rows.length,
            createdAt: sealedAt,
          }),
          ...rows.map((row) => snapshotRecord.parse((kind === 'audit' ? auditRecord : requestRecord)(row))),
        ]),
      ),
    );
    const sha256 = createHash('sha256').update(file).digest('hex');
    const key = `archive/${kind}/${String(seq).padStart(10, '0')}-${randomBytes(16).toString('base64url')}.age`;
    await env.BACKUPS.put(key, file, { sha256 });
    await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO archive_segments (kind,seq,object_key,sha256,first_at,first_id,last_at,last_id,rows,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
      ).bind(kind, seq, key, sha256, first.created_at, first.id, last.created_at, last.id, rows.length, sealedAt),
      env.DB.prepare(`DELETE FROM ${table} WHERE id IN (${ids.map(() => '?').join(',')})`).bind(...ids),
    ]);
  };
  await seal('audit', 1, ['cold-audit-1', 'cold-audit-2']);
  await seal('audit', 2, ['cold-audit-3', 'cold-audit-4']);
  await seal('access-request', 1, ['cold-denied', 'cold-approved']);

  const outcome = await runAutomaticBackup(env, owner, true);
  if (outcome.outcome !== 'saved') throw new Error(`automatic backup: ${outcome.outcome}`);
  const latest = await env.DB.prepare('SELECT object_key FROM backup_state WHERE id=1').first<{ object_key: string }>();
  const files: [string, Uint8Array][] = [
    ['automatic-b.age', new Uint8Array(await (await env.BACKUPS.get(latest!.object_key))!.arrayBuffer())],
  ];
  const id = randomBytes(16).toString('base64url');
  const full = await fetchWorker(`/admin/backup/export?${new URLSearchParams({ recipient, id })}`);
  if (full.status !== 200) throw new Error(`full export: ${full.status} ${await full.text()}`);
  files.push(['full-b.age', new Uint8Array(await full.arrayBuffer())]);
  if ((await call(`/admin/backup/exports/${id}`)).status !== 'complete') throw new Error('full export incomplete');
  for (const { object_key } of (
    await env.DB.prepare('SELECT object_key FROM archive_segments ORDER BY kind,seq').all<{ object_key: string }>()
  ).results)
    files.push([object_key, new Uint8Array(await (await env.BACKUPS.get(object_key))!.arrayBuffer())]);
  for (const [name, bytes] of files) {
    const path = `${directory}/${name}`;
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes, { flag: 'wx' });
    console.log(`${path}\t${bytes.length} bytes\tsha256 ${createHash('sha256').update(bytes).digest('hex')}`);
  }
} finally {
  await mf.dispose();
}
