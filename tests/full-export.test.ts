import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash, scryptSync } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { Decrypter, generateHybridIdentity, generateIdentity, identityToRecipient } from 'age-encryption';
import { applyMigrations } from '../scripts/migrations.mjs';
import { issueSql, newToken } from '../scripts/bootstrap-token.mjs';
import worker from '../apps/worker/src/index';
import { sealColdData } from '../apps/worker/src/archive';
import { type Bindings } from '../apps/worker/src/context';
import { decryptArchiveIdentity, parseRootKeys } from '../packages/core/crypto';
import { SnapshotValidator, readRecords, type RecordOf, type SnapshotRecord } from '../packages/core/snapshot';

// Real D1 and the real routes: an instance with every kind of row, exported whole and read back.
const origin = 'http://localhost:8787';
const password = 'synthetic-password-for-tests';
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const LS = String.fromCharCode(0x2028);
let mf: Miniflare,
  env: Bindings,
  cookie = '';
const ids: Record<string, string> = {};

const fetchWorker = (
  path: string,
  method = 'GET',
  body?: unknown,
  headers: Record<string, string> = {},
  bindings: Bindings = env,
) =>
  worker.fetch(
    new Request(origin + path, {
      method,
      headers: {
        'cf-connecting-ip': '127.0.0.1',
        origin,
        cookie,
        // What a browser sends for the console's own link download.
        'sec-fetch-site': 'same-origin',
        ...(body ? { 'content-type': 'application/json' } : {}),
        ...headers,
      },
      body: body ? JSON.stringify(body) : undefined,
    }),
    bindings,
    context,
  );
async function call(path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) {
  const response = await fetchWorker(path, method, body, headers);
  const text = await response.text();
  expect(response.status, `${method} ${path}: ${text}`).toBeLessThan(300);
  return text ? (JSON.parse(text) as Record<string, unknown>) : {};
}
const run = (sql: string, ...args: unknown[]) =>
  env.DB.prepare(sql)
    .bind(...args)
    .run();
const exportUrl = (recipient: string, id: string) => `/admin/backup/export?${new URLSearchParams({ recipient, id })}`;
const newExportId = () => Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url');

/** Exports the instance to a fresh identity and reads the file back through the format module. */
async function exportAll(id = newExportId()) {
  const identity = await generateIdentity();
  const response = await fetchWorker(exportUrl(await identityToRecipient(identity), id));
  expect(response.status).toBe(200);
  expect(response.headers.get('content-disposition')).toMatch(
    /^attachment; filename="clavifer-full-\d{4}-\d{2}-\d{2}\.age"$/,
  );
  expect(response.headers.get('cache-control')).toBe('no-store');
  const decrypter = new Decrypter();
  decrypter.addIdentity(identity);
  const plain = await decrypter.decrypt(response.body!);
  const [forRecords, forBytes] = plain.tee();
  const validator = new SnapshotValidator();
  const records: SnapshotRecord[] = [];
  for await (const value of readRecords(forRecords)) records.push(validator.push(value));
  validator.finish();
  const text = await new Response(forBytes).text();
  const of = <T extends SnapshotRecord['type']>(type: T) => records.filter((r): r is RecordOf<T> => r.type === type);
  return { response, records, text, of };
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
      r2Buckets: ['BACKUPS'],
    }),
  );
  const db = await mf.getD1Database('DB');
  await applyMigrations(db);
  env = {
    DB: db,
    BACKUPS: await mf.getR2Bucket('BACKUPS'),
    APP_ORIGIN: origin,
    ALLOW_LOCAL_HTTP: 'true',
    ROOT_KEY: `1:${Buffer.from('f'.repeat(32)).toString('base64url')}`,
  } as unknown as Bindings;
  const { token, binds } = newToken();
  await db
    .prepare(issueSql)
    .bind(...binds)
    .run();
  const setup = await fetchWorker(
    '/api/setup/owner',
    'POST',
    {
      name: 'Owner',
      email: 'owner@example.com',
      password,
      backupRecipient: await identityToRecipient(await generateIdentity()),
    },
    { 'x-bootstrap-token': token },
  );
  expect(setup.status).toBe(201);
  cookie = setup.headers
    .getSetCookie()
    .map((value) => value.split(';')[0])
    .join('; ');

  // A credential rotated twice, a deleted one, and one whose description is NULL.
  ids.multi = String((await call('/admin/secrets', 'POST', { name: 'Multi', values: { token: 'first' } })).id);
  await call(`/admin/secrets/${ids.multi}`, 'PUT', {
    name: 'Multi',
    description: 'Rotated twice',
    values: { token: 'second', note: `second${LS}value` },
    expectedVersion: 1,
  });
  await call(`/admin/secrets/${ids.multi}`, 'PUT', {
    name: 'Multi',
    description: 'Rotated twice',
    values: { region: '中文' },
    expectedVersion: 2,
  });
  ids.gone = String((await call('/admin/secrets', 'POST', { name: 'Gone', values: { token: 'gone' } })).id);
  await call(`/admin/secrets/${ids.gone}`, 'PUT', { name: 'Gone', values: { token: 'gone-2' }, expectedVersion: 1 });
  await call(`/admin/secrets/${ids.gone}`, 'DELETE');
  ids.plain = String(
    (await call('/admin/secrets', 'POST', { name: 'Plain', values: { username: 'user', password: 'pass' } })).id,
  );
  await run('UPDATE secrets SET description=NULL WHERE id=?', ids.plain);

  // A bound connection, one with a policy stored before the optional keys existed, and a deleted one.
  ids.bound = String(
    (
      await call('/admin/connections', 'POST', {
        name: 'Bound',
        origin: 'https://api.example.com',
        description: 'Send X-Account: synthetic.',
        paths: ['/v1'],
        methods: ['GET', 'POST'],
        deny: ['DELETE /v1/admin/*'],
        hosts: ['*.files.example.com'],
        auth: { type: 'bearer', secretId: ids.multi, field: 'token' },
      })
    ).id,
  );
  ids.legacy = String(
    (await call('/admin/connections', 'POST', { name: 'Legacy', origin: 'https://legacy.example.com', paths: ['/'] }))
      .id,
  );
  await run('UPDATE connections SET policy_json=? WHERE id=?', JSON.stringify({ paths: ['/api'] }), ids.legacy);
  ids.removed = String(
    (await call('/admin/connections', 'POST', { name: 'Removed', origin: 'https://old.example.com', paths: ['/'] })).id,
  );
  await call(`/admin/connections/${ids.removed}`, 'DELETE');

  // Installations: a CLI and a web client as the console creates them (disabled 0), a revoked one,
  // and a row without user, scopes, grant types or disabled flag (NULL) as an early version left one.
  ids.cli = String((await call('/admin/clients', 'POST', { name: 'CLI' })).clientId);
  ids.web = String(
    (await call('/admin/clients', 'POST', { name: 'Web', redirectUris: ['https://app.example.com/callback'] }))
      .clientId,
  );
  ids.old = String((await call('/admin/clients', 'POST', { name: 'Old' })).clientId);
  await run(
    'INSERT INTO "oauthClient" (id,clientId,redirectUris,createdAt) VALUES (?,?,?,?)',
    'legacy-row',
    'legacy-client',
    '[]',
    Date.now(),
  );
  await call('/admin/grants', 'POST', {
    clientId: ids.cli,
    grants: [
      { resourceType: 'secret', resourceId: ids.multi, permission: 'secret:read', fields: ['token'] },
      {
        resourceType: 'connection',
        resourceId: ids.bound,
        permission: 'connection:invoke',
        paths: ['/v2'],
        methods: ['POST'],
      },
    ],
  });
  // A timed grant whose scope extension expires with it.
  await call('/admin/grants', 'POST', {
    clientId: ids.old,
    grants: [
      {
        resourceType: 'connection',
        resourceId: ids.bound,
        permission: 'connection:invoke',
        paths: ['/v1/reports'],
        methods: ['GET'],
      },
    ],
    expiresAt: Date.now() + 86400000,
  });
  await call(`/admin/clients/${ids.old}`, 'DELETE');

  // Access requests in each state, and an audit row without client or resource.
  const request = (rid: string, status: string, requested: unknown, more: unknown[] = [null, null, null]) =>
    run(
      'INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at,fingerprint,consumed_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
      rid,
      'unused',
      ids.cli,
      JSON.stringify(requested),
      more[0],
      status,
      Date.now(),
      Date.now() + 86400000,
      more[1],
      more[2],
    );
  const grants = { grants: [{ resourceType: 'secret', resourceId: ids.multi, permission: 'secret:read' }] };
  await request('pending-request', 'pending', grants);
  await request('denied-request', 'denied', grants, ['Need the token', null, null]);
  await request(
    'approved-request',
    'approved',
    { invocation: { connection: ids.bound, method: 'POST', path: '/v1/items', body: `line${LS}` } },
    ['', 'f'.repeat(64), Date.now()],
  );
  // Drafts as stored on submission: a setup with the ids fixed for approval, an update with the
  // connection's updated_at and the tests' decisions under the current policy.
  await request('setup-request', 'pending', {
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
  });
  await request('update-request', 'approved', {
    update: {
      connection: ids.bound,
      changes: { paths: ['/v1', '/v3'] },
      tests: [{ method: 'GET', path: '/v3/items', grant: true, expect: 'run' }],
    },
    current: ['path_not_allowed'],
    updatedAt: Date.now(),
  });
  await run('UPDATE "user" SET image=?', 'https://example.com/owner.png');
  ids.recipient = await identityToRecipient(await generateIdentity());
  await call('/admin/backup/config', 'PUT', { recipient: ids.recipient });
  await run(
    "INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) VALUES ('system-row','unused',NULL,'backup:automatic',NULL,'ok','system',?)",
    Date.now(),
  );
  const owner = (await env.DB.prepare('SELECT id FROM "user"').first<{ id: string }>())!.id;
  await run(
    'INSERT INTO passkey (id,name,publicKey,userId,credentialID,counter,deviceType,backedUp,transports,createdAt,aaguid) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    'passkey-1',
    'Laptop',
    Buffer.from('synthetic-cose-public-key').toString('base64'),
    owner,
    'c3ludGhldGljLWNyZWRlbnRpYWw',
    3,
    'multiDevice',
    1,
    'internal,hybrid',
    Date.now(),
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
  );
  // 2 MB of audit rows an hour old, of which sealing moves the oldest into a segment.
  await run(
    "INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<2000) SELECT printf('old-%06d',i),?,'client',printf('%.*c',1000,'x'),NULL,'ok','request',?+i FROM n",
    owner,
    Date.now() - 3_600_000,
  );
  await sealColdData(env, owner);
});
afterAll(() => mf.dispose());

describe('full export', () => {
  it('carries every row of the instance in the v1 format', async () => {
    const audits = (await env.DB.prepare('SELECT COUNT(*) AS n FROM audit_events').first<{ n: number }>())!.n;
    const { records, of, text } = await exportAll();
    const end = of('end')[0];
    expect(end.counts).toEqual({
      owner: 1,
      settings: 1,
      'archive-identity': 1,
      secret: 3,
      'secret-version': 4,
      connection: 3,
      installation: 4,
      grant: 3,
      'access-request': 5,
      audit: audits,
      segment: 1,
    });
    expect(records[0]).toMatchObject({
      type: 'header',
      kind: 'full',
      source: { origin, rpId: 'localhost', version: '0.5.0' },
    });

    const owner = of('owner')[0];
    expect(owner).toMatchObject({ email: 'owner@example.com', name: 'Owner', emailVerified: false });
    expect(owner.image).toBe('https://example.com/owner.png');
    expect(owner.password).toMatchObject({
      algorithm: 'scrypt',
      N: 16384,
      r: 16,
      p: 1,
      dkLen: 64,
      normalization: 'NFKC',
    });
    // The salt is its 32 characters as bytes, not the 16 bytes they spell in hexadecimal.
    const { salt, key, N, r, p, dkLen } = owner.password;
    expect(salt).toMatch(/^[0-9a-f]{32}$/);
    expect(
      scryptSync(password.normalize('NFKC'), Buffer.from(salt, 'utf8'), dkLen, {
        N,
        r,
        p,
        maxmem: 64 * 1024 * 1024,
      }).toString('hex'),
    ).toBe(key);
    expect(owner.passkeys).toEqual([
      expect.objectContaining({
        id: 'passkey-1',
        name: 'Laptop',
        counter: 3,
        backedUp: true,
        transports: 'internal,hybrid',
      }),
    ]);
    expect(of('settings')[0]).toEqual({ type: 'settings', backupRecipient: ids.recipient });
    // The archive identity in the clear, as the database holds it encrypted under the root key.
    const stored = await env.DB.prepare("SELECT value FROM system_state WHERE key='archive_identity'").first<{
      value: string;
    }>();
    expect(of('archive-identity')).toEqual([
      {
        type: 'archive-identity',
        identity: await decryptArchiveIdentity(parseRootKeys(env.ROOT_KEY!), owner.id, JSON.parse(stored!.value)),
      },
    ]);

    const secret = (id: string) => of('secret').find((s) => s.id === id)!;
    expect(secret(ids.multi)).toMatchObject({ status: 'active', currentVersion: 3, description: 'Rotated twice' });
    expect(secret(ids.gone)).toMatchObject({ status: 'deleted', currentVersion: 2 });
    expect(secret(ids.plain).description).toBe('');
    const versions = (id: string) => of('secret-version').filter((v) => v.secretId === id);
    expect(versions(ids.multi).map((v) => [v.version, v.values])).toEqual([
      [1, { token: 'first' }],
      [2, { token: 'second', note: `second${LS}value` }],
      [3, { token: 'second', note: `second${LS}value`, region: '中文' }],
    ]);
    expect(versions(ids.gone)).toEqual([]);
    // The separator inside a value is escaped in the file.
    expect(text).not.toContain(LS);
    expect(text).toContain('second\\u2028value');

    const connection = (id: string) => of('connection').find((c) => c.id === id)!;
    expect(connection(ids.bound)).toMatchObject({
      status: 'active',
      description: 'Send X-Account: synthetic.',
      auth: { type: 'bearer', secretId: ids.multi, field: 'token' },
      policy: {
        paths: ['/v1'],
        methods: ['GET', 'POST'],
        deny: ['DELETE /v1/admin/*'],
        approval: [],
        free: [],
        hosts: ['*.files.example.com'],
        anyHost: false,
      },
    });
    expect(connection(ids.legacy).policy).toEqual({
      paths: ['/api'],
      methods: ['GET', 'HEAD'],
      deny: [],
      approval: [],
      free: [],
      hosts: [],
      anyHost: false,
    });
    expect(connection(ids.removed).status).toBe('deleted');

    const installation = (id: string) => of('installation').find((i) => i.clientId === id)!;
    expect(installation(ids.cli)).toMatchObject({
      name: 'CLI',
      applicationType: 'native',
      redirectUris: [],
      grantTypes: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
      disabled: false,
    });
    expect(installation(ids.cli).scopes).toContain('secret:read');
    expect(installation(ids.web)).toMatchObject({
      applicationType: 'web',
      redirectUris: ['https://app.example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      disabled: false,
    });
    expect(installation(ids.old).disabled).toBe(true);
    expect(installation('legacy-client')).toMatchObject({
      name: null,
      applicationType: null,
      scopes: null,
      grantTypes: null,
      disabled: false,
      updatedAt: null,
    });

    const grants = of('grant');
    expect(grants.find((g) => g.resourceType === 'secret')).toMatchObject({
      clientId: ids.cli,
      fields: ['token'],
      extensions: null,
      status: 'active',
      expiresAt: null,
    });
    expect(grants.find((g) => g.clientId === ids.cli && g.resourceType === 'connection')).toMatchObject({
      fields: null,
      extensions: [{ paths: ['/v2'], methods: ['POST'], expiresAt: null }],
    });
    const timed = grants.find((g) => g.clientId === ids.old)!;
    expect(timed).toMatchObject({ status: 'revoked', expiresAt: expect.any(Number) });
    expect(timed.extensions).toEqual([{ paths: ['/v1/reports'], methods: ['GET'], expiresAt: timed.expiresAt }]);

    const request = (id: string) => of('access-request').find((r) => r.id === id)!;
    expect(request('pending-request')).toMatchObject({
      status: 'pending',
      reason: null,
      fingerprint: null,
      consumedAt: null,
    });
    expect(request('denied-request')).toMatchObject({ status: 'denied', reason: 'Need the token' });
    expect(request('approved-request')).toMatchObject({
      status: 'approved',
      fingerprint: 'f'.repeat(64),
      consumedAt: expect.any(Number),
      requested: { invocation: { connection: ids.bound, method: 'POST', path: '/v1/items', body: `line${LS}` } },
    });
    expect(request('setup-request').requested).toMatchObject({
      ids: { secretId: 'drafted-secret', connectionIds: ['drafted-connection'] },
    });
    expect(request('update-request').requested).toMatchObject({ current: ['path_not_allowed'] });
    expect(of('audit').find((a) => a.id === 'system-row')).toMatchObject({ clientId: null, resourceId: null });
    expect(of('audit').map((a) => a.action)).toContain('secret:rotate');
  });

  it('records the start and, after the last byte, the completion under the export id', async () => {
    const id = newExportId();
    expect((await call(`/admin/backup/exports/${id}`)).status).toBe('unknown');
    const { response } = await exportAll(id);
    const rows = (
      await env.DB.prepare(
        "SELECT result,request_id,client_id FROM audit_events WHERE action='backup:export' AND resource_id=? ORDER BY created_at,rowid",
      )
        .bind(id)
        .all()
    ).results;
    const requestId = response.headers.get('x-request-id');
    expect(rows).toEqual([
      { result: 'started', request_id: requestId, client_id: 'owner' },
      { result: 'complete', request_id: requestId, client_id: 'owner' },
    ]);
    expect(await call(`/admin/backup/exports/${id}`)).toEqual({ status: 'complete' });
  });

  it('embeds every sealed segment byte for byte, in manifest order after the hot records', async () => {
    const manifest = (
      await env.DB.prepare('SELECT * FROM archive_segments ORDER BY kind,seq').all<Record<string, unknown>>()
    ).results;
    expect(manifest.length).toBe(1);
    const { records, of } = await exportAll();
    const segments = of('segment');
    // Last but for end.
    expect(records.slice(-1 - segments.length, -1)).toEqual(segments);
    expect(segments.map((s) => [s.kind, s.seq, s.first, s.last, s.rows, s.createdAt, s.sha256, s.key])).toEqual(
      manifest.map((m) => [
        m.kind,
        m.seq,
        [m.first_at, m.first_id],
        [m.last_at, m.last_id],
        m.rows,
        m.created_at,
        m.sha256,
        null,
      ]),
    );
    for (const [i, segment] of segments.entries()) {
      const stored = new Uint8Array(await (await env.BACKUPS.get(String(manifest[i].object_key)))!.arrayBuffer());
      const embedded = Buffer.from(segment.data!, 'base64');
      expect(embedded.equals(stored)).toBe(true);
      expect(createHash('sha256').update(embedded).digest('hex')).toBe(segment.sha256);
      // Standard base64 with padding.
      expect(segment.data).toBe(Buffer.from(stored).toString('base64'));
    }
  });

  it('refuses before the first byte when a segment is missing or not the one its manifest row names', async () => {
    const [segment] = (await env.DB.prepare('SELECT object_key FROM archive_segments').all<{ object_key: string }>())
      .results;
    const bucket = env.BACKUPS;
    for (const [what, head] of [
      ['missing', async () => null],
      [
        'another file',
        async (key: string) => ({ ...(await bucket.head(key)), checksums: { sha256: new Uint8Array(32).buffer } }),
      ],
      ['stored without a checksum', async (key: string) => ({ ...(await bucket.head(key)), checksums: {} })],
    ] as const) {
      const gets: string[] = [];
      const broken = {
        ...env,
        BACKUPS: {
          head: (key: string) => (key === segment.object_key ? head(key) : bucket.head(key)),
          get: (key: string) => {
            gets.push(key);
            return bucket.get(key);
          },
        },
      } as unknown as Bindings;
      const id = newExportId();
      const response = await fetchWorker(
        exportUrl(await identityToRecipient(await generateIdentity()), id),
        'GET',
        undefined,
        {},
        broken,
      );
      expect(response.status, what).toBe(409);
      expect(await response.json()).toMatchObject({ error: 'archive_segment_unavailable' });
      expect(gets).toEqual([]);
      expect(await call(`/admin/backup/exports/${id}`)).toEqual({
        status: 'failed',
        error: 'archive_segment_unavailable',
      });
    }
  });

  it('stays started when the download stops before the end', async () => {
    // Enough rows that the encrypted body spans several chunks.
    await run(
      "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<3000) INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) SELECT 'bulk-'||i,'unused','owner','bulk',NULL,'ok',hex(randomblob(50)),? FROM n",
      Date.now(),
    );
    const id = newExportId();
    const response = await fetchWorker(exportUrl(await identityToRecipient(await generateIdentity()), id));
    // As a browser does that stops a download it has started.
    const reader = response.body!.getReader();
    await reader.read();
    // Node's web streams, which run this test, leak an unhandled rejection when a chain of piped streams
    // is cancelled while chunks are still moving through it, so cancel once the pipes have filled up.
    await new Promise((resolve) => setTimeout(resolve, 0));
    await reader.cancel();
    expect(await call(`/admin/backup/exports/${id}`)).toEqual({ status: 'started' });
    await run("DELETE FROM audit_events WHERE action='bulk'");
  });

  it('refuses an inconsistent instance before writing anything, and the console can read why', async () => {
    await run(
      "INSERT INTO grants (id,owner_id,client_id,resource_type,resource_id,permission,status,created_at) VALUES ('ghost-grant','unused','ghost','secret',?,'secret:read','active',?)",
      ids.multi,
      Date.now(),
    );
    const id = newExportId();
    const response = await fetchWorker(exportUrl(await identityToRecipient(await generateIdentity()), id));
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: 'backup_has_dangling_reference', hint: 'grant ghost-grant' });
    expect(await call(`/admin/backup/exports/${id}`)).toEqual({
      status: 'failed',
      error: 'backup_has_dangling_reference',
    });
    await run("DELETE FROM grants WHERE id='ghost-grant'");

    await run("UPDATE connections SET policy_json='{}' WHERE id=?", ids.legacy);
    const unrepresentable = await fetchWorker(
      exportUrl(await identityToRecipient(await generateIdentity()), newExportId()),
    );
    expect(await unrepresentable.json()).toMatchObject({ error: 'backup_unrepresentable' });
    await run('UPDATE connections SET policy_json=? WHERE id=?', JSON.stringify({ paths: ['/api'] }), ids.legacy);

    const rejected = newExportId();
    expect((await fetchWorker(exportUrl('AGE-SECRET-KEY-1', rejected))).status).toBe(400);
    expect(await call(`/admin/backup/exports/${rejected}`)).toEqual({
      status: 'failed',
      error: 'invalid_backup_recipient',
    });
    // A post-quantum recipient is about 2000 characters long and works like any other.
    const hybrid = await generateHybridIdentity();
    const pq = await identityToRecipient(hybrid);
    expect(pq.length).toBeGreaterThan(1900);
    const quantum = await fetchWorker(exportUrl(pq, newExportId()));
    expect(quantum.status).toBe(200);
    const decrypter = new Decrypter();
    decrypter.addIdentity(hybrid);
    expect(await decrypter.decrypt(new Uint8Array(await quantum.arrayBuffer()), 'text')).toMatch(/^\{"type":"header"/);
    expect((await fetchWorker(exportUrl(pq, 'short'))).status).toBe(400);
  });

  it('needs a login within the last 10 minutes', async () => {
    await run('UPDATE session SET createdAt=createdAt-700000');
    const id = newExportId();
    const response = await fetchWorker(exportUrl(await identityToRecipient(await generateIdentity()), id));
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: 'recent_login_required' });
    expect((await fetchWorker(exportUrl('age1', id), 'HEAD')).status).toBe(403);
    // Asking how an export went needs only the Owner session.
    expect(await call(`/admin/backup/exports/${id}`)).toEqual({ status: 'unknown' });
    await run('UPDATE session SET createdAt=createdAt+700000');
  });

  it('refuses a download another site or a typed address started', async () => {
    const url = exportUrl(await identityToRecipient(await generateIdentity()), newExportId());
    for (const site of ['cross-site', 'same-site', 'none']) {
      const response = await fetchWorker(url, 'GET', undefined, { 'sec-fetch-site': site });
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ error: 'cross_site_request' });
    }
    const missing = await worker.fetch(
      new Request(origin + url, { headers: { 'cf-connecting-ip': '127.0.0.1', cookie } }),
      env,
      context,
    );
    expect(missing.status).toBe(403);
    expect(await missing.json()).toMatchObject({ error: 'cross_site_request' });
    // Nothing started, so there is nothing to report under the id.
    expect(await call(`/admin/backup/exports/${new URL(origin + url).searchParams.get('id')}`)).toEqual({
      status: 'unknown',
    });
  });
});
