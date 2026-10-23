import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { Decrypter, generateHybridIdentity, generateIdentity, identityToRecipient } from 'age-encryption';
import { applyMigrations } from '../scripts/migrations.mjs';
import { sealColdData } from '../apps/worker/src/archive';
import { backupStatus, pruneBackups, runAutomaticBackup } from '../apps/worker/src/backup';
import { type Bindings, audit } from '../apps/worker/src/context';
import { encryptArchiveIdentity, encryptSecret, parseRootKeys, rootKeyFingerprints } from '../packages/core/crypto';
import { SnapshotValidator, readRecords, type RecordOf, type SnapshotRecord } from '../packages/core/snapshot';

// Real D1 and R2, one fresh pair for each test. The Owner id, the root key check and the archive
// recipient are cached for the isolate, which is this module, so every instance has the same Owner,
// root key and archive identity.
const OWNER = 'owner';
const origin = 'http://localhost:8787';
const rootKey = `1:${Buffer.from('a'.repeat(32)).toString('base64url')}`;
const ring = parseRootKeys(rootKey);
const T = 1_700_000_000_000;
const SALT = '0123456789abcdef0123456789abcdef',
  KEY = 'ab'.repeat(64);
const instances = 24;
let mf: Miniflare, archiveIdentity: string, identity: string, recipient: string;
let next = 0;

beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default {fetch:()=>new Response("unused")}',
      compatibilityDate: '2026-09-11',
      compatibilityFlags: ['nodejs_compat'],
      log: new Log(LogLevel.ERROR),
      d1Databases: Array.from({ length: instances }, (_, i) => `DB${i}`),
      r2Buckets: Array.from({ length: instances }, (_, i) => `R2${i}`),
    }),
  );
  archiveIdentity = await generateHybridIdentity();
  identity = await generateIdentity();
  recipient = await identityToRecipient(identity);
});
afterAll(() => mf.dispose());

const insert = (env: Bindings, table: string, row: Record<string, unknown>) =>
  env.DB.prepare(
    `INSERT INTO "${table}" (${Object.keys(row)
      .map((k) => `"${k}"`)
      .join(',')}) VALUES (${Object.keys(row)
      .map(() => '?')
      .join(',')})`,
  ).bind(...Object.values(row));
const version = async (secretId: string, version: number, values: Record<string, string>) => ({
  id: `${secretId}-v${version}`,
  secret_id: secretId,
  version,
  envelope_json: JSON.stringify(await encryptSecret(ring, { ownerId: OWNER, secretId, version }, values)),
  created_at: T + version,
});
const value = async <T = number>(env: Bindings, sql: string, ...args: unknown[]) =>
  Object.values(
    (await env.DB.prepare(sql)
      .bind(...args)
      .first<Record<string, T>>())!,
  )[0];
const revision = (env: Bindings) => value(env, 'SELECT revision FROM backup_state WHERE id=1');
const vault = async (env: Bindings) =>
  (await env.BACKUPS.list({ prefix: 'vault/' })).objects.map((object) => object.key).sort();

/** A fresh initialized instance with a row of every kind a snapshot carries, in every state: an Owner
 * with a password and a Passkey, credentials active (with a version past the current one), deleted and
 * without a description, connections bound, with a policy older than its optional keys and deleted,
 * installations live, revoked and as an early version left one, grants with a field subset, with a scope
 * extension and revoked, access requests in each status, and audit rows. */
async function instance() {
  const n = next++;
  const env = {
    DB: await mf.getD1Database(`DB${n}`),
    BACKUPS: await mf.getR2Bucket(`R2${n}`),
    APP_ORIGIN: origin,
    ALLOW_LOCAL_HTTP: 'true',
    ROOT_KEY: rootKey,
  } as unknown as Bindings;
  await applyMigrations(env.DB);
  const state = (key: string, value: string) =>
    env.DB.prepare('INSERT INTO system_state (key,value,updated_at) VALUES (?,?,0)').bind(key, value);
  const scopes = JSON.stringify(['metadata:list', 'secret:read']);
  await env.DB.batch([
    insert(env, 'user', {
      id: OWNER,
      name: 'Owner',
      email: 'owner@example.com',
      emailVerified: 1,
      image: 'https://example.com/owner.png',
      createdAt: T,
      updatedAt: T + 1,
    }),
    insert(env, 'account', {
      id: 'account',
      accountId: OWNER,
      providerId: 'credential',
      userId: OWNER,
      password: `${SALT}:${KEY}`,
      createdAt: T,
      updatedAt: T + 2,
    }),
    insert(env, 'passkey', {
      id: 'passkey',
      name: 'Laptop',
      publicKey: Buffer.from('synthetic-cose-key').toString('base64'),
      userId: OWNER,
      credentialID: 'c3ludGhldGljLWNyZWRlbnRpYWw',
      counter: 7,
      deviceType: 'multiDevice',
      backedUp: 1,
      transports: 'internal,hybrid',
      createdAt: T,
      aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
    }),
    // Without a name, a time or an authenticator id, and with the empty transports Better Auth writes
    // when the browser reports none.
    insert(env, 'passkey', {
      id: 'passkey-bare',
      name: null,
      publicKey: Buffer.from('another-cose-key').toString('base64'),
      userId: OWNER,
      credentialID: 'YW5vdGhlcg',
      counter: 0,
      deviceType: 'singleDevice',
      backedUp: 0,
      transports: '',
      createdAt: null,
      aaguid: null,
    }),
    state('owner_user_id', OWNER),
    state('root_key_fingerprints', JSON.stringify(await rootKeyFingerprints(ring))),
    state('archive_identity', JSON.stringify(await encryptArchiveIdentity(ring, OWNER, archiveIdentity))),
    env.DB.prepare('UPDATE backup_state SET recipient=? WHERE id=1').bind(recipient),
    ...[
      { id: 's-active', name: 'Active', description: 'two versions', status: 'active', current_version: 2 },
      { id: 's-deleted', name: 'Deleted', description: '', status: 'deleted', current_version: 1 },
      { id: 's-plain', name: 'Plain', description: null, status: 'active', current_version: 1 },
    ].map((s) => insert(env, 'secrets', { ...s, owner_id: OWNER, created_at: T, updated_at: T + 3 })),
    // A version past the current one is not part of the credential.
    ...[
      await version('s-active', 1, { token: 'one' }),
      await version('s-active', 2, { token: 'two\nlines' }),
      await version('s-active', 3, { token: 'not current' }),
      await version('s-plain', 1, { username: 'user', password: 'pass' }),
    ].map((v) => insert(env, 'secret_versions', v)),
    ...[
      {
        id: 'c-bound',
        auth_json: JSON.stringify({ type: 'bearer', secretId: 's-active', field: 'token' }),
        policy_json: JSON.stringify({
          paths: ['/v1'],
          methods: ['GET', 'POST'],
          deny: ['DELETE /v1/admin/*'],
          approval: [],
          free: ['/v1/status'],
          hosts: ['*.files.example.com'],
          anyHost: false,
        }),
        status: 'active',
      },
      {
        id: 'c-legacy',
        auth_json: JSON.stringify({
          type: 'basic',
          secretId: 's-plain',
          usernameField: 'username',
          passwordField: 'password',
        }),
        policy_json: JSON.stringify({ paths: ['/api'] }),
        status: 'active',
      },
      {
        id: 'c-deleted',
        auth_json: JSON.stringify({ type: 'bearer', secretId: 's-deleted', field: 'token' }),
        policy_json: JSON.stringify({ paths: ['/'], methods: ['GET'] }),
        status: 'deleted',
      },
    ].map((c) =>
      insert(env, 'connections', {
        ...c,
        owner_id: OWNER,
        name: c.id,
        origin: 'https://api.example.com',
        description: `notes of ${c.id}`,
        created_at: T,
        updated_at: T + 4,
      }),
    ),
    ...[
      { clientId: 'cli', name: 'CLI', applicationType: 'native', disabled: null, updatedAt: T },
      { clientId: 'off', name: 'Off', applicationType: 'native', disabled: 1, updatedAt: T },
      { clientId: 'legacy', name: null, applicationType: null, disabled: null, updatedAt: null },
    ].map((c) =>
      insert(env, 'oauthClient', {
        ...c,
        id: `row-${c.clientId}`,
        userId: OWNER,
        redirectUris: '[]',
        scopes: c.name ? scopes : null,
        grantTypes: c.name ? JSON.stringify(['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token']) : null,
        createdAt: T,
      }),
    ),
    ...[
      {
        id: 'g-secret',
        client_id: 'cli',
        resource_type: 'secret',
        resource_id: 's-active',
        permission: 'secret:read',
        fields_json: '["token"]',
        extensions_json: null,
        status: 'active',
        expires_at: null,
      },
      {
        id: 'g-connection',
        client_id: 'cli',
        resource_type: 'connection',
        resource_id: 'c-bound',
        permission: 'connection:invoke',
        fields_json: null,
        extensions_json: JSON.stringify([{ paths: ['/v2'], methods: ['POST'], expiresAt: T + 1000 }]),
        status: 'active',
        expires_at: T + 1000,
      },
      {
        id: 'g-revoked',
        client_id: 'off',
        resource_type: 'secret',
        resource_id: 's-plain',
        permission: 'secret:read',
        fields_json: null,
        extensions_json: null,
        status: 'revoked',
        expires_at: null,
      },
    ].map((g) => insert(env, 'grants', { ...g, owner_id: OWNER, created_at: T })),
    // Recent, so that nothing but the filler rows of a test is sealed.
    ...[
      { id: 'r-pending', client_id: 'cli', status: 'pending', reason: null, fingerprint: null, consumed_at: null },
      {
        id: 'r-approved',
        client_id: 'cli',
        status: 'approved',
        reason: '',
        fingerprint: 'f'.repeat(64),
        consumed_at: Date.now(),
      },
      { id: 'r-denied', client_id: 'off', status: 'denied', reason: 'why', fingerprint: null, consumed_at: null },
    ].map((r) =>
      insert(env, 'access_requests', {
        ...r,
        owner_id: OWNER,
        requested_json: JSON.stringify({ grants: [{ resourceType: 'secret', resourceId: 's-active' }] }),
        created_at: Date.now(),
        expires_at: Date.now() + 86400000,
      }),
    ),
    insert(env, 'audit_events', {
      id: 'e-owner',
      owner_id: OWNER,
      client_id: 'owner',
      action: 'secret:create',
      resource_id: 's-active',
      result: 'ok',
      request_id: 'request',
      created_at: Date.now(),
    }),
    insert(env, 'audit_events', {
      id: 'e-bare',
      owner_id: OWNER,
      client_id: null,
      action: 'bare',
      resource_id: null,
      result: 'ok',
      request_id: 'request',
      created_at: Date.now(),
    }),
  ]);
  return env;
}
// Audit rows of 1000 characters, an hour old, enough to be sealed.
const fillAudit = (env: Bindings, n: number) =>
  env.DB.prepare(
    "INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) SELECT printf('a-%06d',i),?,'client',printf('%.*c',1000,'x'),NULL,'ok','request',?+i FROM n",
  )
    .bind(n, OWNER, Date.now() - 3_600_000)
    .run();

/** The records of the latest automatic backup, read back through the format module. */
async function latest(env: Bindings) {
  const key = await value<string>(env, 'SELECT object_key FROM backup_state WHERE id=1');
  const bytes = new Uint8Array(await (await env.BACKUPS.get(key))!.arrayBuffer());
  const decrypter = new Decrypter();
  decrypter.addIdentity(identity);
  const validator = new SnapshotValidator();
  const records: SnapshotRecord[] = [];
  for await (const record of readRecords(await decrypter.decrypt(new Response(bytes).body!)))
    records.push(validator.push(record));
  validator.finish();
  const of = <T extends SnapshotRecord['type']>(type: T) => records.filter((r): r is RecordOf<T> => r.type === type);
  return { key, bytes, records, of };
}

describe('the automatic backup', () => {
  it('carries every row of the instance in its full state, and each sealed segment by its key', async () => {
    const env = await instance();
    await fillAudit(env, 2000);
    await sealColdData(env, OWNER);
    const segments = (
      await env.DB.prepare('SELECT * FROM archive_segments ORDER BY kind,seq').all<Record<string, unknown>>()
    ).results;
    expect(segments.length).toBeGreaterThan(0);
    const before = Date.now();
    const saved = (await runAutomaticBackup(env, OWNER, true)) as { outcome: string; sha256: string };
    expect(saved).toMatchObject({ outcome: 'saved', revision: await revision(env) });
    const { key, bytes, records, of } = await latest(env);
    // R2 checked the upload against its SHA-256 and keeps it, as backup_state does.
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    expect(saved.sha256).toBe(sha256);
    expect(await value(env, 'SELECT sha256 FROM backup_state WHERE id=1')).toBe(sha256);
    expect(Buffer.from((await env.BACKUPS.head(key))!.checksums.sha256!).toString('hex')).toBe(sha256);
    expect(key).toMatch(/^vault\/\d{4}-\d{2}-\d{2}\/\d+-[0-9a-f-]+\.age$/);

    expect(records[0]).toMatchObject({
      type: 'header',
      format: 'clavifer-backup-v1',
      kind: 'automatic',
      source: { origin, rpId: 'localhost', version: '0.5.0' },
    });
    expect((records[0] as RecordOf<'header'>).createdAt).toBeGreaterThanOrEqual(before);
    expect(of('owner')).toEqual([
      {
        type: 'owner',
        id: OWNER,
        email: 'owner@example.com',
        name: 'Owner',
        emailVerified: true,
        image: 'https://example.com/owner.png',
        createdAt: T,
        updatedAt: T + 1,
        password: {
          algorithm: 'scrypt',
          N: 16384,
          r: 16,
          p: 1,
          dkLen: 64,
          normalization: 'NFKC',
          salt: SALT,
          key: KEY,
          createdAt: T,
          updatedAt: T + 2,
        },
        passkeys: [
          {
            id: 'passkey-bare',
            name: null,
            publicKey: Buffer.from('another-cose-key').toString('base64'),
            credentialID: 'YW5vdGhlcg',
            counter: 0,
            deviceType: 'singleDevice',
            backedUp: false,
            transports: '',
            createdAt: null,
            aaguid: null,
          },
          {
            id: 'passkey',
            name: 'Laptop',
            publicKey: Buffer.from('synthetic-cose-key').toString('base64'),
            credentialID: 'c3ludGhldGljLWNyZWRlbnRpYWw',
            counter: 7,
            deviceType: 'multiDevice',
            backedUp: true,
            transports: 'internal,hybrid',
            createdAt: T,
            aaguid: 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
          },
        ],
      },
    ]);
    expect(of('settings')).toEqual([{ type: 'settings', backupRecipient: recipient }]);
    expect(of('archive-identity')).toEqual([{ type: 'archive-identity', identity: archiveIdentity }]);
    expect(of('secret')).toEqual(
      [
        ['s-active', 'Active', 'two versions', 'active', 2],
        ['s-deleted', 'Deleted', '', 'deleted', 1],
        ['s-plain', 'Plain', '', 'active', 1],
      ].map(([id, name, description, status, currentVersion]) => ({
        type: 'secret',
        id,
        name,
        description,
        status,
        currentVersion,
        createdAt: T,
        updatedAt: T + 3,
      })),
    );
    expect(of('secret-version')).toEqual([
      { type: 'secret-version', secretId: 's-active', version: 1, values: { token: 'one' }, createdAt: T + 1 },
      { type: 'secret-version', secretId: 's-active', version: 2, values: { token: 'two\nlines' }, createdAt: T + 2 },
      {
        type: 'secret-version',
        secretId: 's-plain',
        version: 1,
        values: { username: 'user', password: 'pass' },
        createdAt: T + 1,
      },
    ]);
    const connection = (id: string, auth: unknown, policy: unknown, status = 'active') => ({
      type: 'connection',
      id,
      name: id,
      origin: 'https://api.example.com',
      description: `notes of ${id}`,
      auth,
      policy,
      status,
      createdAt: T,
      updatedAt: T + 4,
    });
    expect(of('connection')).toEqual([
      connection(
        'c-bound',
        { type: 'bearer', secretId: 's-active', field: 'token' },
        {
          paths: ['/v1'],
          methods: ['GET', 'POST'],
          deny: ['DELETE /v1/admin/*'],
          approval: [],
          free: ['/v1/status'],
          hosts: ['*.files.example.com'],
          anyHost: false,
        },
      ),
      connection(
        'c-deleted',
        { type: 'bearer', secretId: 's-deleted', field: 'token' },
        { paths: ['/'], methods: ['GET'], deny: [], approval: [], free: [], hosts: [], anyHost: false },
        'deleted',
      ),
      // The keys an older policy lacks, filled with what the proxy reads in their absence.
      connection(
        'c-legacy',
        { type: 'basic', secretId: 's-plain', usernameField: 'username', passwordField: 'password' },
        { paths: ['/api'], methods: ['GET', 'HEAD'], deny: [], approval: [], free: [], hosts: [], anyHost: false },
      ),
    ]);
    const device = ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'];
    expect(of('installation')).toEqual(
      [
        ['cli', 'CLI', 'native', ['metadata:list', 'secret:read'], device, false, T],
        ['legacy', null, null, null, null, false, null],
        ['off', 'Off', 'native', ['metadata:list', 'secret:read'], device, true, T],
      ].map(([clientId, name, applicationType, scopes, grantTypes, disabled, updatedAt]) => ({
        type: 'installation',
        clientId,
        name,
        applicationType,
        redirectUris: [],
        scopes,
        grantTypes,
        disabled,
        createdAt: T,
        updatedAt,
      })),
    );
    expect(of('grant')).toEqual([
      {
        type: 'grant',
        id: 'g-connection',
        clientId: 'cli',
        resourceType: 'connection',
        resourceId: 'c-bound',
        permission: 'connection:invoke',
        fields: null,
        extensions: [{ paths: ['/v2'], methods: ['POST'], expiresAt: T + 1000 }],
        status: 'active',
        expiresAt: T + 1000,
        createdAt: T,
      },
      {
        type: 'grant',
        id: 'g-revoked',
        clientId: 'off',
        resourceType: 'secret',
        resourceId: 's-plain',
        permission: 'secret:read',
        fields: null,
        extensions: null,
        status: 'revoked',
        expiresAt: null,
        createdAt: T,
      },
      {
        type: 'grant',
        id: 'g-secret',
        clientId: 'cli',
        resourceType: 'secret',
        resourceId: 's-active',
        permission: 'secret:read',
        fields: ['token'],
        extensions: null,
        status: 'active',
        expiresAt: null,
        createdAt: T,
      },
    ]);
    // The rows that change all the time, against the tables as they are now.
    const requests = (
      await env.DB.prepare('SELECT * FROM access_requests ORDER BY created_at,id').all<Record<string, unknown>>()
    ).results;
    expect(of('access-request')).toEqual(
      requests.map((r) => ({
        type: 'access-request',
        id: r.id,
        clientId: r.client_id,
        requested: JSON.parse(r.requested_json as string),
        reason: r.reason,
        status: r.status,
        fingerprint: r.fingerprint,
        consumedAt: r.consumed_at,
        createdAt: r.created_at,
        expiresAt: r.expires_at,
      })),
    );
    expect(new Set(of('access-request').map((r) => r.status))).toEqual(new Set(['pending', 'approved', 'denied']));
    const events = (
      await env.DB.prepare('SELECT * FROM audit_events ORDER BY created_at,id').all<Record<string, unknown>>()
    ).results;
    // Everything but the row recording this backup, written after the snapshot was read.
    expect(events.at(-1)).toMatchObject({ action: 'backup:automatic', client_id: 'system' });
    expect(of('audit')).toEqual(
      events.slice(0, -1).map((e) => ({
        type: 'audit',
        id: e.id,
        clientId: e.client_id,
        action: e.action,
        resourceId: e.resource_id,
        result: e.result,
        requestId: e.request_id,
        createdAt: e.created_at,
      })),
    );
    expect(of('audit').map((e) => e.id)).toEqual(expect.arrayContaining(['e-owner', 'e-bare']));
    expect(of('segment')).toEqual(
      segments.map((s) => ({
        type: 'segment',
        kind: s.kind,
        seq: s.seq,
        first: [s.first_at, s.first_id],
        last: [s.last_at, s.last_id],
        rows: s.rows,
        createdAt: s.created_at,
        sha256: s.sha256,
        key: s.object_key,
        data: null,
      })),
    );
    // Each names an object of the bucket with that checksum.
    for (const segment of of('segment'))
      expect(Buffer.from((await env.BACKUPS.head(segment.key!))!.checksums.sha256!).toString('hex')).toBe(
        segment.sha256,
      );
    // The backup is the system's: it writes no export row and no audit row of the Owner.
    expect(await value(env, "SELECT COUNT(*) FROM audit_events WHERE action='backup:export'")).toBe(0);
    expect(await value(env, "SELECT COUNT(*) FROM audit_events WHERE action='backup:automatic'")).toBe(1);
  });

  it('reads every table of the snapshot in the one batch that also reads the revision', async () => {
    const env = await instance();
    const db = env.DB;
    const log: { batch?: string[]; single?: string }[] = [];
    type Wrapped = { sql: string; real: D1PreparedStatement };
    const wrap = (real: D1PreparedStatement, sql: string): Wrapped & Record<string, unknown> => ({
      sql,
      real,
      bind: (...args: unknown[]) => wrap(real.bind(...args), sql),
      ...Object.fromEntries(
        (['first', 'all', 'run', 'raw'] as const).map((method) => [
          method,
          (...args: unknown[]) => {
            log.push({ single: sql });
            return (real[method] as (...a: unknown[]) => unknown)(...args);
          },
        ]),
      ),
    });
    const spying = {
      ...env,
      DB: {
        prepare: (sql: string) => wrap(db.prepare(sql), sql),
        batch: (statements: Wrapped[]) => {
          log.push({ batch: statements.map((s) => s.sql) });
          return db.batch(statements.map((s) => s.real));
        },
      },
    } as unknown as Bindings;
    await expect(runAutomaticBackup(spying, OWNER, true)).resolves.toMatchObject({ outcome: 'saved' });
    const carried = [
      'user',
      'account',
      'passkey',
      'secrets',
      'secret_versions',
      'connections',
      'oauthClient',
      'grants',
      'access_requests',
      'audit_events',
      'archive_segments',
      'backup_state',
      'system_state',
    ];
    const reads = (sql: string) =>
      carried.filter((table) => new RegExp(`FROM "?${table}"?[ )]|FROM "?${table}"?$`).test(sql));
    const batches = log.filter((entry) => entry.batch);
    expect(batches.length).toBe(1);
    expect(new Set(batches[0].batch!.flatMap(reads))).toEqual(new Set(carried));
    expect(batches[0].batch!.every((sql) => sql.startsWith('SELECT '))).toBe(true);
    // Outside it, nothing reads a row the snapshot carries: only the size check sums them, and the lease
    // and the result are written to backup_state.
    for (const { single } of log.filter((entry) => entry.single))
      expect(
        single!.startsWith('SELECT * FROM backup_state') ||
          single!.startsWith('UPDATE backup_state') ||
          single!.startsWith('INSERT INTO audit_events') ||
          /^SELECT \(SELECT IFNULL\(SUM\(/.test(single!),
        single,
      ).toBe(true);
  });

  it.each([
    [
      'a version of an active credential missing',
      'backup_has_missing_versions',
      "DELETE FROM secret_versions WHERE id='s-active-v1'",
    ],
    [
      'a connection binding a field its credential lacks',
      'backup_has_broken_connection',
      `UPDATE connections SET auth_json='{"type":"bearer","secretId":"s-active","field":"gone"}' WHERE id='c-bound'`,
    ],
    [
      'a connection binding a deleted credential',
      'backup_has_broken_connection',
      `UPDATE connections SET auth_json='{"type":"bearer","secretId":"s-deleted","field":"token"}' WHERE id='c-bound'`,
    ],
    [
      'a Basic connection whose credential lacks the password field',
      'backup_has_broken_connection',
      `UPDATE connections SET auth_json='{"type":"basic","secretId":"s-plain","usernameField":"username","passwordField":"gone"}' WHERE id='c-legacy'`,
    ],
    [
      'a grant of an installation that is gone',
      'backup_has_dangling_reference',
      "UPDATE grants SET client_id='gone' WHERE id='g-secret'",
    ],
    [
      'a grant of a resource that is gone',
      'backup_has_dangling_reference',
      "UPDATE grants SET resource_id='gone' WHERE id='g-connection'",
    ],
    [
      'an access request of an installation that is gone',
      'backup_has_dangling_reference',
      "UPDATE access_requests SET client_id='gone' WHERE id='r-pending'",
    ],
  ])('refuses an instance with %s and keeps the last good backup', async (_label, code, sql) => {
    const env = await instance();
    await runAutomaticBackup(env, OWNER);
    const good = await backupStatus(env);
    const kept = await vault(env);
    await env.DB.prepare(sql).run();
    await expect(runAutomaticBackup(env, OWNER, true)).rejects.toMatchObject({ code, status: 409 });
    expect(await backupStatus(env)).toMatchObject({
      savedRevision: good.savedRevision,
      sha256: good.sha256,
      lastSuccessAt: good.lastSuccessAt,
      downloadAvailable: true,
      lastError: code,
      running: false,
    });
    expect(await vault(env)).toEqual(kept);
    expect(
      await value<string>(
        env,
        "SELECT result FROM audit_events WHERE action='backup:automatic' AND client_id='system' ORDER BY created_at DESC,rowid DESC",
      ),
    ).toBe(code);
  });

  it('refuses an instance without its archive identity, naming why', async () => {
    const env = await instance();
    await env.DB.prepare("DELETE FROM system_state WHERE key='archive_identity'").run();
    await expect(runAutomaticBackup(env, OWNER, true)).rejects.toMatchObject({
      code: 'archive_identity_missing',
      status: 503,
    });
    expect(await backupStatus(env)).toMatchObject({ lastError: 'archive_identity_missing', downloadAvailable: false });
  });
});

describe('the backup revision', () => {
  it('moves exactly when something a snapshot carries changes', async () => {
    const env = await instance();
    const counted: [string, boolean][] = [
      [
        "INSERT INTO secrets (id,owner_id,name,status,current_version,created_at,updated_at) VALUES ('s2','owner','S2','active',0,0,0)",
        true,
      ],
      ["UPDATE secrets SET name='Renamed' WHERE id='s2'", true],
      ["INSERT INTO secret_versions (id,secret_id,version,envelope_json,created_at) VALUES ('v','s2',1,'{}',0)", true],
      ["UPDATE secret_versions SET created_at=1 WHERE id='v'", true],
      [
        "INSERT INTO connections (id,owner_id,name,origin,auth_json,created_at,updated_at) VALUES ('c2','owner','C2','https://a.example.com','{}',0,0)",
        true,
      ],
      ["UPDATE connections SET status='deleted' WHERE id='c2'", true],
      ["INSERT INTO oauthClient (id,clientId,redirectUris) VALUES ('row-c2','c2','[]')", true],
      ["UPDATE oauthClient SET disabled=1 WHERE clientId='c2'", true],
      [
        "INSERT INTO grants (id,owner_id,client_id,resource_type,resource_id,permission,created_at) VALUES ('g2','owner','cli','secret','s2','secret:read',0)",
        true,
      ],
      ["UPDATE grants SET status='revoked' WHERE id='g2'", true],
      [
        "INSERT INTO access_requests (id,owner_id,client_id,requested_json,created_at,expires_at) VALUES ('r2','owner','cli','{}',0,0)",
        true,
      ],
      ["UPDATE access_requests SET status='denied' WHERE id='r2'", true],
      [
        "INSERT INTO audit_events (id,owner_id,client_id,action,result,request_id,created_at) VALUES ('e2','owner','owner','x','ok','r',0)",
        true,
      ],
      [
        "INSERT INTO audit_events (id,owner_id,client_id,action,result,request_id,created_at) VALUES ('e3','owner','cli','x','ok','r',0)",
        true,
      ],
      [
        "INSERT INTO audit_events (id,owner_id,client_id,action,result,request_id,created_at) VALUES ('e4','owner',NULL,'x','ok','r',0)",
        true,
      ],
      // The system's own rows: a backup, a sealed segment, a failure of either.
      [
        "INSERT INTO audit_events (id,owner_id,client_id,action,result,request_id,created_at) VALUES ('e5','owner','system','x','ok','r',0)",
        false,
      ],
      [
        "INSERT INTO archive_segments (kind,seq,object_key,sha256,first_at,first_id,last_at,last_id,rows,created_at) VALUES ('audit',9,'k','s',0,'a',0,'b',1,0)",
        true,
      ],
      // Sealing deletes the rows it moved out in the batch that inserts their manifest row.
      ["DELETE FROM audit_events WHERE id='e2'", false],
      ["DELETE FROM access_requests WHERE id='r2'", false],
      [
        "INSERT INTO passkey (id,publicKey,userId,credentialID,counter,deviceType,backedUp) VALUES ('p2','AA==','owner','cA',0,'singleDevice',0)",
        true,
      ],
      // Every sign-in with a Passkey updates its counter.
      ["UPDATE passkey SET counter=counter+1 WHERE id='p2'", false],
      ["UPDATE passkey SET name='Phone' WHERE id='p2'", true],
      ["UPDATE passkey SET name='Phone' WHERE id='p2'", false],
      ["DELETE FROM passkey WHERE id='p2'", true],
      [`UPDATE account SET password='${'1'.repeat(32)}:${KEY}',updatedAt=5 WHERE id='account'`, true],
      ["UPDATE account SET updatedAt=6 WHERE id='account'", false],
      ["UPDATE \"user\" SET email='new@example.com' WHERE id='owner'", true],
      ["UPDATE \"user\" SET name='New' WHERE id='owner'", true],
      ['UPDATE "user" SET image=NULL WHERE id=\'owner\'', true],
      ['UPDATE "user" SET updatedAt=7,emailVerified=0 WHERE id=\'owner\'', false],
      // What only this instance holds.
      ["INSERT INTO session (id,expiresAt,token,createdAt,updatedAt,userId) VALUES ('x',0,'t',0,0,'owner')", false],
      ["INSERT INTO system_state (key,value,updated_at) VALUES ('other','v',0)", false],
      ['UPDATE backup_state SET attempt_at=1 WHERE id=1', false],
    ];
    for (const [sql, counts] of counted) {
      const before = await revision(env);
      await env.DB.prepare(sql).run();
      expect(await revision(env), sql).toBe(before + (counts ? 1 : 0));
    }
  });

  it('moves once for each sealed segment, not for the rows it moved out', async () => {
    const env = await instance();
    await fillAudit(env, 2000);
    const before = await revision(env);
    await sealColdData(env, OWNER);
    expect(await value(env, 'SELECT COUNT(*) FROM archive_segments')).toBe(1);
    expect(await revision(env)).toBe(before + 1);
  });
});

describe('automatic backup outcomes', () => {
  /** env with its bucket's put replaced; the original is passed in. */
  const withPut = (env: Bindings, put: (real: R2Bucket['put'], ...args: Parameters<R2Bucket['put']>) => unknown) => {
    const bucket = env.BACKUPS;
    return {
      ...env,
      BACKUPS: {
        head: bucket.head.bind(bucket),
        get: bucket.get.bind(bucket),
        list: bucket.list.bind(bucket),
        delete: bucket.delete.bind(bucket),
        put: (...args: Parameters<R2Bucket['put']>) => put(bucket.put.bind(bucket), ...args),
      },
    } as unknown as Bindings;
  };

  it('publishes a new object only after it was stored and the database recorded it', async () => {
    const env = await instance();
    const at = await revision(env);
    await expect(runAutomaticBackup(env, OWNER)).resolves.toMatchObject({ outcome: 'saved', revision: at });
    expect(await backupStatus(env)).toMatchObject({ savedRevision: at, pending: false, downloadAvailable: true });
    expect((await vault(env)).length).toBe(1);
  });

  it('keeps the previous known-good backup when the upload fails', async () => {
    const env = await instance();
    await runAutomaticBackup(env, OWNER);
    const good = await backupStatus(env);
    await audit(env, 'owner', 'secret:create', null);
    const failing = withPut(env, () => {
      throw new Error('synthetic R2 unavailable');
    });
    await expect(runAutomaticBackup(failing, OWNER)).rejects.toMatchObject({ code: 'backup_failed', status: 503 });
    expect(await backupStatus(env)).toMatchObject({
      savedRevision: good.savedRevision,
      sha256: good.sha256,
      pending: true,
      downloadAvailable: true,
      lastError: 'backup_failed',
      running: false,
    });
  });

  it('does not publish an object after the configuration changed during the upload', async () => {
    const env = await instance();
    const changing = withPut(env, async (put, ...args) => {
      await env.DB.prepare('UPDATE backup_state SET recipient=?,config_version=config_version+1 WHERE id=1')
        .bind(await identityToRecipient(await generateIdentity()))
        .run();
      return put(...args);
    });
    await expect(runAutomaticBackup(changing, OWNER)).resolves.toEqual({ outcome: 'superseded' });
    expect(await backupStatus(env)).toMatchObject({ savedRevision: 0, pending: true, downloadAvailable: false });
    expect((await vault(env)).length).toBe(1);
  });

  it('keeps an uploaded object when another run took the lease over', async () => {
    const env = await instance();
    const overtaken = withPut(env, async (put, ...args) => {
      await env.DB.prepare("UPDATE backup_state SET lease_token='other' WHERE id=1").run();
      return put(...args);
    });
    await expect(runAutomaticBackup(overtaken, OWNER)).resolves.toEqual({ outcome: 'superseded' });
    expect(await backupStatus(env)).toMatchObject({
      savedRevision: 0,
      pending: true,
      downloadAvailable: false,
      running: true,
    });
    expect((await vault(env)).length).toBe(1);
  });

  it('records the revision it read, so a change after the read is still pending', async () => {
    const env = await instance();
    const at = await revision(env);
    const changed = withPut(env, async (put, ...args) => {
      await audit(env, 'owner', 'secret:create', null);
      return put(...args);
    });
    await expect(runAutomaticBackup(changed, OWNER)).resolves.toMatchObject({ outcome: 'saved', revision: at });
    expect(await backupStatus(env)).toMatchObject({ savedRevision: at, revision: at + 1, pending: true });
  });

  it('skips a current backup but runs the daily refresh after 24 hours', async () => {
    const env = await instance();
    await runAutomaticBackup(env, OWNER);
    await expect(runAutomaticBackup(env, OWNER)).resolves.toEqual({ outcome: 'up_to_date' });
    expect((await vault(env)).length).toBe(1);
    await env.DB.prepare('UPDATE backup_state SET success_at=success_at-86400001 WHERE id=1').run();
    await expect(runAutomaticBackup(env, OWNER)).resolves.toMatchObject({ outcome: 'saved' });
  });

  it('reports a failed cleanup without marking the saved backup as failed', async () => {
    const env = await instance();
    const bucket = env.BACKUPS;
    const stale = {
      ...env,
      BACKUPS: {
        put: bucket.put.bind(bucket),
        list: async () => ({ objects: [{ key: 'vault/stale', uploaded: new Date(0) }], truncated: false }),
        delete: async () => {
          throw new Error('synthetic R2 delete unavailable');
        },
      },
    } as unknown as Bindings;
    await expect(runAutomaticBackup(stale, OWNER)).resolves.toMatchObject({ outcome: 'saved' });
    expect(await backupStatus(env)).toMatchObject({
      pending: false,
      lastError: null,
      retentionError: 'backup_retention_failed',
    });
  });
});

describe('retention', () => {
  it('keeps the newest copy of every recent day and older month, and never the current one', async () => {
    const day = 86400000,
      at = (days: number, hour: number) => {
        const value = new Date(Date.now() - days * day);
        value.setUTCHours(hour, 0, 0, 0);
        return value;
      };
    const objects = new Map<string, Date>([
      ['vault/recent-newest', at(2, 12)],
      ['vault/recent-older', at(2, 9)],
      ['vault/month-newest', at(200, 12)],
      ['vault/month-older', at(200, 9)],
      ['vault/expired', at(800, 12)],
      ['vault/current', at(900, 12)],
    ]);
    const env = {
      BACKUPS: {
        async list({ cursor }: { cursor?: string }) {
          const keys = [...objects.keys()].sort();
          // Two pages prove the caller follows the cursor instead of reading only the first.
          const page = cursor ? keys.slice(1) : keys.slice(0, 1);
          return {
            objects: page.map((key) => ({ key, uploaded: objects.get(key)! })),
            ...(cursor ? { truncated: false } : { truncated: true, cursor: 'next' }),
          };
        },
        async delete(keys: string[]) {
          for (const key of keys) objects.delete(key);
        },
      },
    } as unknown as Bindings;
    expect(await pruneBackups(env, 'vault/current')).toBe(3);
    expect([...objects.keys()].sort()).toEqual(['vault/current', 'vault/month-newest', 'vault/recent-newest']);
  });
});
