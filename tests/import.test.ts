import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { Decrypter, Encrypter, generateHybridIdentity, generateIdentity, identityToRecipient } from 'age-encryption';
import { hashPassword, verifyPassword } from 'better-auth/crypto';
import { applyMigrations } from '../scripts/migrations.mjs';
import { issueSql, newToken } from '../scripts/bootstrap-token.mjs';
import { importSnapshot, type Segment } from '../apps/web/src/import';
import { type Bindings } from '../apps/worker/src/context';
import { SCOPES } from '../packages/auth/policy';
import {
  COUNTED_TYPES,
  SCRYPT,
  SnapshotValidator,
  readRecords,
  serializeRecord,
  type RecordOf,
  type SnapshotRecord,
} from '../packages/core/snapshot';

// Real D1 and R2 and the real routes, one instance per database. The Worker keeps the Owner, its Better
// Auth instance and the root key check for the isolate, which is a module, so every instance gets a fresh
// copy of the Worker's modules. Every import request runs on a D1 that holds the service to D1's limits.
const A = 'http://localhost:8787';
const B = 'https://clavifer-b.example';
const SAMPLES = 'tests/fixtures/v1';
const SAMPLE_PASSWORD = 'synthetic-ﬁxture-password';
const PASSWORD = 'synthetic-password-for-import';
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const sampleIdentity = (await readFile(`${SAMPLES}/test-identity.txt`, 'utf8')).trim();
const rootKey = () => `1:${randomBytes(32).toString('base64url')}`;
const hex = (data: ArrayBuffer | Uint8Array) => Buffer.from(data as ArrayBuffer).toString('hex');
const sha256 = (data: Uint8Array) => createHash('sha256').update(data).digest('hex');
const slots = 60;
let mf: Miniflare,
  next = 0;

beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default {fetch:()=>new Response("unused")}',
      compatibilityDate: '2026-09-11',
      compatibilityFlags: ['nodejs_compat'],
      log: new Log(LogLevel.ERROR),
      d1Databases: Array.from({ length: slots }, (_, i) => `DB${i}`),
      r2Buckets: Array.from({ length: slots }, (_, i) => `R2${i}`),
    }),
  );
});
afterAll(() => mf.dispose());

const encoder = new TextEncoder();
/** D1 as the platform limits it: 100 bound parameters and 100 KB of text a statement, 2 MB a value and
 * 1000 queries an invocation, a statement in a batch counting as one. */
function limited(db: D1Database) {
  let queries = 0;
  const bound = new WeakMap<object, { statement: D1PreparedStatement; sql: string; values: unknown[] }>();
  const check = (sql: string, values: unknown[]) => {
    if (++queries > 1000) throw new Error('over 1000 D1 queries in one invocation');
    if (encoder.encode(sql).length > 100_000) throw new Error('a D1 statement over 100 KB');
    if (values.length > 100) throw new Error('over 100 bound parameters');
    for (const value of values)
      if (typeof value === 'string' && encoder.encode(value).length > 2_000_000)
        throw new Error('a D1 value over 2 MB');
  };
  const wrap = (statement: D1PreparedStatement, sql: string, values: unknown[] = []): D1PreparedStatement => {
    const proxy = new Proxy(statement, {
      get(target, property) {
        if (property === 'bind') return (...args: unknown[]) => wrap(target.bind(...args), sql, args);
        const value = Reflect.get(target, property, target) as unknown;
        if (typeof value !== 'function') return value;
        return (...args: unknown[]) => {
          if (['first', 'all', 'run', 'raw'].includes(String(property))) check(sql, values);
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        };
      },
    });
    bound.set(proxy, { statement, sql, values });
    return proxy;
  };
  return {
    prepare: (sql: string) => wrap(db.prepare(sql), sql),
    batch: (statements: D1PreparedStatement[]) =>
      db.batch(
        statements.map((s) => {
          const { statement, sql, values } = bound.get(s)!;
          check(sql, values);
          return statement;
        }),
      ),
  } as unknown as D1Database;
}

type Options = { method?: string; body?: unknown; headers?: Record<string, string>; bindings?: Bindings };
/** A new instance on a database of its own, with the Worker's modules fresh for it. */
async function instance({
  origin = A,
  bucket,
  key = rootKey(),
}: { origin?: string; bucket?: R2Bucket; key?: string } = {}) {
  const n = next++;
  vi.resetModules();
  const worker = (await import('../apps/worker/src/index')).default;
  const { snapshot } = await import('../apps/worker/src/export');
  const { sealColdData } = await import('../apps/worker/src/archive');
  const { runAutomaticBackup } = await import('../apps/worker/src/backup');
  const env = {
    DB: await mf.getD1Database(`DB${n}`),
    BACKUPS: bucket ?? (await mf.getR2Bucket(`R2${n}`)),
    APP_ORIGIN: origin,
    ALLOW_LOCAL_HTTP: 'true',
    ROOT_KEY: key,
  } as unknown as Bindings;
  await applyMigrations(env.DB);
  let cookie = '',
    signIns = 0;
  const fetch = (path: string, { method = 'GET', body, headers = {}, bindings = env }: Options = {}) =>
    worker.fetch(
      new Request(origin + path, {
        method,
        headers: {
          'cf-connecting-ip': '127.0.0.1',
          origin,
          cookie,
          'sec-fetch-site': 'same-origin',
          ...(body instanceof URLSearchParams
            ? { 'content-type': 'application/x-www-form-urlencoded' }
            : body
              ? { 'content-type': 'application/json' }
              : {}),
          ...headers,
        },
        body: body instanceof URLSearchParams ? body : body ? JSON.stringify(body) : undefined,
      }),
      bindings,
      context,
    );
  const call = async (path: string, options: Options = {}) => {
    const response = await fetch(path, options);
    const text = await response.text();
    return {
      status: response.status,
      body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
      headers: response.headers,
    };
  };
  const ok = async (path: string, options: Options = {}) => {
    const r = await call(path, options);
    expect(r.status, `${options.method ?? 'GET'} ${path}: ${JSON.stringify(r.body)}`).toBeLessThan(300);
    return r.body;
  };
  const sql = (statement: string, ...args: unknown[]) =>
    env.DB.prepare(statement)
      .bind(...args)
      .all()
      .then((r) => r.results as Record<string, unknown>[]);
  const issue = async () => {
    const { token, binds } = newToken();
    await env.DB.prepare(issueSql)
      .bind(...binds)
      .run();
    return token;
  };
  // Each sign-in from another address, past the library's limit of three a client per ten seconds.
  const signIn = async (email: string, password: string) => {
    const r = await call('/api/auth/sign-in/email', {
      method: 'POST',
      body: { email, password },
      headers: { 'cf-connecting-ip': `10.1.${n}.${++signIns}` },
    });
    if (r.status === 200)
      cookie = r.headers
        .getSetCookie()
        .map((value) => value.split(';')[0])
        .join('; ');
    return r.status;
  };
  // A request of the import, held to D1's limits; a refusal throws its code as the console's api() does.
  const post = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
    const r = await call(path, { method: 'POST', body, headers, bindings: { ...env, DB: limited(env.DB) } });
    if (r.status >= 300)
      throw Object.assign(new Error(`${r.body.error}: ${r.body.hint ?? ''}`), { code: r.body.error });
    return r.body;
  };
  /** Imports an encrypted snapshot as the console does. */
  const importFile = (
    file: Uint8Array<ArrayBuffer>,
    token: string,
    missing: (segments: Segment[]) => Promise<boolean> = async () => false,
    identity = sampleIdentity,
  ) => importSnapshot({ file: new Response(file).body!, identity, token, send: post, missing });
  const initialized = async () => (await ok('/healthz')).initialized;
  return {
    env,
    snapshot,
    sealColdData,
    runAutomaticBackup,
    fetch,
    call,
    ok,
    sql,
    issue,
    signIn,
    post,
    importFile,
    initialized,
    setCookie: (value: string) => (cookie = value),
  };
}
type Instance = Awaited<ReturnType<typeof instance>>;

/** The records of an age-encrypted snapshot, checked as the format requires. */
async function records(file: Uint8Array<ArrayBuffer>, identity = sampleIdentity) {
  const decrypter = new Decrypter();
  decrypter.addIdentity(identity);
  const validator = new SnapshotValidator();
  const out: SnapshotRecord[] = [];
  for await (const value of readRecords(await decrypter.decrypt(new Response(file).body!)))
    out.push(validator.push(value));
  validator.finish();
  return out;
}
const of = <T extends SnapshotRecord['type']>(list: SnapshotRecord[], type: T) =>
  list.filter((r): r is RecordOf<T> => r.type === type);
/** A file of these records, end with its counts appended, encrypted to the sample identity. */
async function file(list: SnapshotRecord[]) {
  const counts = Object.fromEntries(COUNTED_TYPES.map((type) => [type, list.filter((r) => r.type === type).length]));
  const lines = [...list, { type: 'end', counts } as SnapshotRecord].map(serializeRecord);
  const plain = new Uint8Array(lines.reduce((n, line) => n + line.length, 0));
  lines.reduce((offset, line) => (plain.set(line, offset), offset + line.length), 0);
  const encrypter = new Encrypter();
  encrypter.addRecipient(await identityToRecipient(sampleIdentity));
  return new Uint8Array(await encrypter.encrypt(plain));
}
/** The snapshot of an imported instance, as its automatic backup would carry it. */
async function exported(target: Instance) {
  const [{ value: owner }] = await target.sql("SELECT value FROM system_state WHERE key='owner_user_id'");
  return (await target.snapshot(target.env, owner as string)).records;
}
/** Every record of source came over unchanged: the instance's own snapshot holds them, besides the audit
 * row of the import itself, and the segments with their keys in this bucket. */
function expectImported(source: SnapshotRecord[], imported: SnapshotRecord[], passkeys: boolean) {
  const [owner] = of(source, 'owner');
  expect(of(imported, 'owner')).toEqual([{ ...owner, passkeys: passkeys ? owner.passkeys : [] }]);
  for (const type of [
    'settings',
    'secret',
    'secret-version',
    'connection',
    'installation',
    'grant',
    'access-request',
  ] as const)
    expect(of(imported, type), type).toEqual(of(source, type));
  expect(of(imported, 'audit').filter((a) => a.action !== 'instance:import')).toEqual(of(source, 'audit'));
  const bare = (s: RecordOf<'segment'>) => ({ ...s, key: undefined, data: undefined });
  expect(of(imported, 'segment').map(bare)).toEqual(of(source, 'segment').map(bare));
}
const importAudit = async (target: Instance) =>
  (await target.sql("SELECT client_id,resource_id,result FROM audit_events WHERE action='instance:import'")).map(
    (r) => ({
      ...r,
      resource_id: JSON.parse(r.resource_id as string),
    }),
  );
async function deviceToken(target: Instance, clientId: string) {
  const device = await target.ok('/api/auth/device/code', {
    method: 'POST',
    body: { client_id: clientId, scope: SCOPES.join(' '), resource: target.env.APP_ORIGIN + '/v1' },
  });
  await target.ok(`/api/auth/device?user_code=${device.user_code}`);
  await target.ok('/api/auth/device/approve', { method: 'POST', body: { userCode: device.user_code } });
  const token = await target.ok('/api/auth/oauth2/token', {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: String(device.device_code),
      client_id: clientId,
    }),
  });
  return String(token.access_token);
}
/** The sample segment files, in a bucket as their keys say. */
async function sampleBucket(slot: R2Bucket) {
  for (const kind of await readdir(`${SAMPLES}/archive`))
    for (const name of await readdir(`${SAMPLES}/archive/${kind}`)) {
      const bytes = new Uint8Array(await readFile(`${SAMPLES}/archive/${kind}/${name}`));
      await slot.put(`archive/${kind}/${name}`, bytes, { sha256: sha256(bytes) });
    }
  return slot;
}
const freeBucket = async () => (await mf.getR2Bucket(`R2${next++}`)) as unknown as R2Bucket;

describe('importing the v1 samples', { timeout: 120_000 }, () => {
  for (const name of ['full-a.age', 'full-b.age', 'automatic-b.age'])
    it(`imports ${name} whole`, async () => {
      const bytes = new Uint8Array(await readFile(`${SAMPLES}/${name}`));
      const source = await records(bytes);
      const automatic = name.startsWith('automatic');
      const target = await instance({ bucket: automatic ? await sampleBucket(await freeBucket()) : undefined });
      expect(await target.initialized()).toBe(false);
      expect(await target.importFile(bytes, await target.issue())).toEqual(source[0]);
      expect(await target.initialized()).toBe(true);
      const imported = await exported(target);
      // The sample was written on the hostname this instance has, so its Passkeys came along.
      expectImported(source, imported, true);
      const [owner] = of(source, 'owner');
      const [account] = await target.sql("SELECT accountId,userId,password FROM account WHERE providerId='credential'");
      expect(account).toEqual({
        accountId: owner.id,
        userId: owner.id,
        password: `${owner.password.salt}:${owner.password.key}`,
      });
      const [identity] = of(imported, 'archive-identity');
      if (name === 'full-a.age') {
        // Written before archive identities existed: the instance has a new one, for the segments it seals.
        expect(of(source, 'archive-identity')).toEqual([]);
        expect(identity.identity).toMatch(/^AGE-SECRET-KEY-PQ-1[0-9A-Z]+$/);
      } else {
        expect(identity).toEqual(of(source, 'archive-identity')[0]);
        // The library verifies the carried hash: NFKC of the password, the salt's characters as bytes.
        expect(await verifyPassword({ hash: account.password as string, password: SAMPLE_PASSWORD })).toBe(true);
        expect(await target.signIn(owner.email, SAMPLE_PASSWORD)).toBe(200);
        expect(await target.signIn(owner.email, SAMPLE_PASSWORD.normalize('NFKC') + 'x')).toBe(401);
      }
      // Each segment is in this instance's bucket with its checksum: the referenced ones under the key the
      // backup names, the embedded ones under a new key with the bytes the file carried.
      const segments = of(source, 'segment');
      for (const [i, segment] of of(imported, 'segment').entries()) {
        expect(hex((await target.env.BACKUPS.head(segment.key!))!.checksums.sha256!)).toBe(segment.sha256);
        const stored = new Uint8Array(await (await target.env.BACKUPS.get(segment.key!))!.arrayBuffer());
        if (automatic) expect(segment.key).toBe(segments[i].key);
        else expect(Buffer.from(stored).toString('base64')).toBe(segments[i].data);
      }
      expect(await importAudit(target)).toEqual([
        {
          client_id: 'owner',
          resource_id: { origin: A, createdAt: of(source, 'header')[0].createdAt, skipped: [] },
          result: 'ok',
        },
      ]);
      expect(await target.sql("SELECT key FROM system_state WHERE key IN ('import_id','import_guard')")).toEqual([]);
      expect(await target.sql('SELECT seq FROM import_chunks')).toEqual([]);
    });
});

/** Instance X with every kind of data: credentials with several versions and a tombstone, connections,
 * installations (one revoked), active and revoked grants, a request in every status, a Passkey, and audit
 * rows and access requests sealed in several segments. */
async function populated() {
  const x = await instance();
  await x.ok('/api/setup/owner', {
    method: 'POST',
    body: {
      name: 'Owner',
      email: 'owner@example.com',
      password: PASSWORD,
      backupRecipient: await identityToRecipient(await generateIdentity()),
    },
    headers: { 'x-bootstrap-token': await x.issue() },
  });
  expect(await x.signIn('owner@example.com', PASSWORD)).toBe(200);
  const ids: Record<string, string> = {};
  ids.multi = String(
    (await x.ok('/admin/secrets', { method: 'POST', body: { name: 'Multi', values: { token: 'v1' } } })).id,
  );
  for (const [version, token] of [
    [1, 'v2'],
    [2, 'v3'],
  ] as const)
    await x.ok(`/admin/secrets/${ids.multi}`, {
      method: 'PUT',
      body: { name: 'Multi', values: { token, note: '中文' }, expectedVersion: version },
    });
  ids.gone = String(
    (await x.ok('/admin/secrets', { method: 'POST', body: { name: 'Gone', values: { token: 'x' } } })).id,
  );
  await x.ok(`/admin/secrets/${ids.gone}`, { method: 'DELETE' });
  ids.bound = String(
    (
      await x.ok('/admin/connections', {
        method: 'POST',
        body: {
          name: 'Bound',
          origin: 'https://api.example.com',
          paths: ['/v1'],
          methods: ['GET', 'POST'],
          deny: ['DELETE /v1/admin/*'],
          auth: { type: 'bearer', secretId: ids.multi, field: 'token' },
        },
      })
    ).id,
  );
  ids.removed = String(
    (
      await x.ok('/admin/connections', {
        method: 'POST',
        body: { name: 'Removed', origin: 'https://old.example.com', paths: ['/'] },
      })
    ).id,
  );
  await x.ok(`/admin/connections/${ids.removed}`, { method: 'DELETE' });
  ids.cli = String((await x.ok('/admin/clients', { method: 'POST', body: { name: 'CLI' } })).clientId);
  ids.web = String(
    (
      await x.ok('/admin/clients', {
        method: 'POST',
        body: { name: 'Web', redirectUris: ['https://app.example.com/cb'] },
      })
    ).clientId,
  );
  ids.old = String((await x.ok('/admin/clients', { method: 'POST', body: { name: 'Old' } })).clientId);
  await x.ok('/admin/grants', {
    method: 'POST',
    body: {
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
    },
  });
  await x.ok('/admin/grants', {
    method: 'POST',
    body: { clientId: ids.old, grants: [{ resourceType: 'secret', resourceId: ids.multi, permission: 'secret:read' }] },
  });
  await x.ok(`/admin/clients/${ids.old}`, { method: 'DELETE' });
  const [{ value: owner }] = await x.sql("SELECT value FROM system_state WHERE key='owner_user_id'");
  ids.owner = owner as string;
  for (const [rid, status] of [
    ['pending-request', 'pending'],
    ['approved-request', 'approved'],
    ['denied-request', 'denied'],
  ])
    await x.sql(
      "INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at,fingerprint,consumed_at) VALUES (?,?,?,?,'why',?,?,?,?,?)",
      rid,
      owner,
      ids.cli,
      JSON.stringify({ invocation: { connection: ids.bound, method: 'GET', path: '/v1/x' } }),
      status,
      Date.now(),
      Date.now() + 86_400_000,
      status === 'approved' ? 'f'.repeat(64) : null,
      status === 'approved' ? Date.now() : null,
    );
  await x.sql(
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
    null,
  );
  // 3 MB of audit an hour old and 2.6 MB of access requests 26 hours old: two segments of each.
  await x.sql(
    "INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<3000) SELECT printf('cold-%06d',i),?,'client',printf('%.*c',1000,'x'),NULL,'ok','request',?+i FROM n",
    owner,
    Date.now() - 3_600_000,
  );
  await x.sql(
    "INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<2600) SELECT printf('old-%06d',i),?,?,json_object('invocation',json_object('connection',?,'method','GET','path','/v1/x','body',printf('%.*c',1000,'x'))),'r','denied',?+i,?+i+86400000 FROM n",
    owner,
    ids.cli,
    ids.bound,
    Date.now() - 26 * 3_600_000,
    Date.now() - 26 * 3_600_000,
  );
  await x.sealColdData(x.env, owner as string);
  expect(
    (await x.sql('SELECT kind,COUNT(*) AS n FROM archive_segments GROUP BY kind ORDER BY kind')).map((r) => r.n),
  ).toEqual([2, 2]);
  return { x, ids };
}
async function fullExport(x: Instance) {
  const identity = await generateIdentity();
  const id = randomBytes(16).toString('base64url');
  const response = await x.fetch(
    `/admin/backup/export?${new URLSearchParams({ recipient: await identityToRecipient(identity), id })}`,
  );
  expect(response.status).toBe(200);
  return { bytes: new Uint8Array(await response.arrayBuffer()), identity };
}

describe('moving to another instance', { timeout: 180_000 }, () => {
  let x: Instance,
    ids: Record<string, string>,
    bytes: Uint8Array<ArrayBuffer>,
    identity: string,
    source: SnapshotRecord[];
  beforeAll(async () => {
    ({ x, ids } = await populated());
    ({ bytes, identity } = await fullExport(x));
    source = await records(bytes, identity);
  }, 180_000);

  it('carries everything to another origin under another root key', async () => {
    const y = await instance({ origin: B });
    expect(await y.importFile(bytes, await y.issue(), undefined, identity)).toMatchObject({ kind: 'full' });
    const imported = await exported(y);
    // Every version decrypts under the new root key; audit rows and access requests, the hot ones and those
    // in the segments, keep their ids and times. The Passkey belongs to the old hostname and stayed behind.
    expectImported(source, imported, false);
    expect(await y.sql('SELECT id FROM passkey')).toEqual([]);
    expect(await importAudit(y)).toEqual([
      {
        client_id: 'owner',
        resource_id: { origin: A, createdAt: of(source, 'header')[0].createdAt, skipped: [] },
        result: 'ok',
      },
    ]);
    // The segments are in Y's own bucket, byte for byte.
    const xSegments = await x.sql('SELECT kind,seq,object_key,sha256 FROM archive_segments ORDER BY kind,seq');
    const ySegments = await y.sql('SELECT kind,seq,object_key,sha256 FROM archive_segments ORDER BY kind,seq');
    expect(ySegments.map((s) => [s.kind, s.seq, s.sha256])).toEqual(xSegments.map((s) => [s.kind, s.seq, s.sha256]));
    for (const [i, segment] of ySegments.entries()) {
      expect(segment.object_key).not.toBe(xSegments[i].object_key);
      const object = (await y.env.BACKUPS.get(segment.object_key as string))!;
      expect(hex(object.checksums.sha256!)).toBe(segment.sha256);
      expect(
        Buffer.from(await object.arrayBuffer()).equals(
          Buffer.from(await (await x.env.BACKUPS.get(xSegments[i].object_key as string))!.arrayBuffer()),
        ),
      ).toBe(true);
    }
    // An installation as the OAuth provider created it, column by column, apart from its row id.
    for (const client of [ids.cli, ids.web, ids.old]) {
      const [{ id: xId, ...xRow }] = await x.sql('SELECT * FROM "oauthClient" WHERE clientId=?', client);
      const [{ id: yId, ...yRow }] = await y.sql('SELECT * FROM "oauthClient" WHERE clientId=?', client);
      expect(yId).not.toBe(xId);
      expect(yRow).toEqual(xRow);
    }
    // The Owner signs in with the original password; the CLI logs in again under its original client id
    // and its grants work, the field subset included.
    expect(await y.signIn('owner@example.com', PASSWORD)).toBe(200);
    const token = await deviceToken(y, ids.cli);
    const read = await y.ok(`/v1/secrets/${ids.multi}/read`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(read.values).toEqual({ token: 'v3' });
    // The revoked installation stays revoked.
    expect(
      (
        await y.call('/api/auth/device/code', {
          method: 'POST',
          body: { client_id: ids.old, scope: SCOPES.join(' '), resource: B + '/v1' },
        })
      ).status,
    ).toBeGreaterThanOrEqual(400);
    // Y seals and backs up as its own: the archive identity came with the snapshot.
    expect(await y.runAutomaticBackup(y.env, ids.owner, true)).toMatchObject({ outcome: 'saved' });
  });

  it('keeps the Passkeys on the same hostname', async () => {
    const z = await instance({ origin: A });
    await z.importFile(bytes, await z.issue(), undefined, identity);
    const [owner] = of(source, 'owner');
    expect(owner.passkeys.length).toBe(1);
    expectImported(source, await exported(z), true);
  });
});

/** The smallest snapshot there is, of kind, plus the records given; end is added by file(). */
async function minimal(kind: 'full' | 'automatic' = 'full') {
  const [salt, key] = (await hashPassword(PASSWORD)).split(':');
  return [
    {
      type: 'header',
      format: 'clavifer-backup-v1',
      kind,
      createdAt: Date.now(),
      source: { origin: A, rpId: 'localhost', version: '0.5.0' },
    },
    {
      type: 'owner',
      id: 'crafted-owner',
      email: 'owner@example.com',
      name: 'Owner',
      emailVerified: false,
      image: null,
      createdAt: 1,
      updatedAt: 1,
      password: { ...SCRYPT, salt, key, createdAt: 1, updatedAt: 1 },
      passkeys: [],
    },
    { type: 'settings', backupRecipient: null },
  ] as SnapshotRecord[];
}
const installation = (clientId: string) =>
  ({
    type: 'installation',
    clientId,
    name: clientId,
    applicationType: 'native',
    redirectUris: [],
    scopes: SCOPES,
    grantTypes: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
    disabled: false,
    createdAt: 1,
    updatedAt: 1,
  }) as SnapshotRecord;
const audit = (id: string, createdAt: number) =>
  ({
    type: 'audit',
    id,
    clientId: null,
    action: 'test',
    resourceId: null,
    result: 'ok',
    requestId: 'r',
    createdAt,
  }) as SnapshotRecord;
const embedded = (
  seq: number,
  first: [number, string],
  last: [number, string],
  kind: 'audit' | 'access-request' = 'audit',
) => {
  const data = Buffer.from(`${kind} segment ${seq}`);
  return {
    type: 'segment',
    kind,
    seq,
    first,
    last,
    rows: 2,
    createdAt: 1,
    sha256: sha256(data),
    key: null,
    data: data.toString('base64'),
  } as SnapshotRecord;
};
const tables = async (target: Instance) =>
  (
    await target.sql(
      'SELECT (SELECT COUNT(*) FROM secrets)+(SELECT COUNT(*) FROM secret_versions)+(SELECT COUNT(*) FROM connections)+(SELECT COUNT(*) FROM "oauthClient")+(SELECT COUNT(*) FROM grants)+(SELECT COUNT(*) FROM access_requests)+(SELECT COUNT(*) FROM audit_events)+(SELECT COUNT(*) FROM archive_segments) AS n',
    )
  )[0].n;

describe('the import protocol', { timeout: 120_000 }, () => {
  it('starts only with a setup token, once, and a setup token resets nothing', async () => {
    const target = await instance();
    const [header, owner] = await minimal();
    expect(
      await target.call('/api/setup/password', {
        method: 'POST',
        body: { password: PASSWORD },
        headers: { 'x-bootstrap-token': await target.issue() },
      }),
    ).toMatchObject({
      status: 409,
      body: { error: 'not_initialized' },
    });
    // Two starts with one token: one import id.
    const token = await target.issue();
    const starts = await Promise.all(
      [1, 2].map(() =>
        target.call('/api/setup/import', {
          method: 'POST',
          body: { header, owner },
          headers: { 'x-bootstrap-token': token },
        }),
      ),
    );
    expect(starts.map((s) => s.status).sort()).toEqual([201, 401]);
    const id = String(starts.find((s) => s.status === 201)!.body.importId);
    expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const [{ value }] = await target.sql("SELECT value FROM system_state WHERE key='import_id'");
    expect(JSON.parse(value as string)).toEqual({ id, owner, header });
    // The Owner exists once the import commits; until then nobody signs in.
    expect(await target.initialized()).toBe(false);
    expect(await target.signIn('owner@example.com', PASSWORD)).toBe(401);

    // A 1-hour recovery token on an initialized instance cannot start one.
    const done = await instance();
    await done.importFile(await file(await minimal()), await done.issue());
    expect(await done.initialized()).toBe(true);
    expect(
      await done.call('/api/setup/import', {
        method: 'POST',
        body: { header, owner },
        headers: { 'x-bootstrap-token': await done.issue() },
      }),
    ).toMatchObject({
      status: 409,
      body: { error: 'already_initialized' },
    });
    expect(await done.signIn('owner@example.com', PASSWORD)).toBe(200);
  });

  it('refuses parameters of the password other than its own', async () => {
    const target = await instance();
    const [header, owner] = await minimal();
    const other = { ...(owner as RecordOf<'owner'>), password: { ...(owner as RecordOf<'owner'>).password, N: 32768 } };
    expect(
      await target.call('/api/setup/import', {
        method: 'POST',
        body: { header, owner: other },
        headers: { 'x-bootstrap-token': await target.issue() },
      }),
    ).toMatchObject({ status: 400, body: { error: 'invalid_snapshot' } });
  });

  it('stops every batch of an import that is no longer the current one', async () => {
    const target = await instance();
    const [header, owner] = await minimal();
    const start = async () =>
      String(
        (await target.post('/api/setup/import', { header, owner }, { 'x-bootstrap-token': await target.issue() }))
          .importId,
      );
    const chunk = (importId: string, seq: number) => ({ importId, seq, records: [installation(`client-${seq}`)] });
    const old = await start();
    await target.post('/api/setup/import/chunk', chunk(old, 0));
    // A new start clears the first import out and replaces its id.
    const current = await start();
    expect(current).not.toBe(old);
    expect(await tables(target)).toBe(0);
    await expect(target.post('/api/setup/import/chunk', chunk(old, 1))).rejects.toMatchObject({
      code: 'import_superseded',
    });
    // The guard itself: an import replaced, or the instance initialized, between the chunk's read and its
    // batch rolls the whole batch back instead of writing nothing and reporting success.
    for (const change of [
      "UPDATE system_state SET value=json_set(value,'$.id','replaced-by-another') WHERE key='import_id'",
      "INSERT INTO system_state (key,value,updated_at) VALUES ('owner_user_id','someone',0)",
    ]) {
      const db = target.env.DB;
      const racing = {
        prepare: (sql: string) => db.prepare(sql),
        batch: async (statements: D1PreparedStatement[]) => {
          await db.prepare(change).run();
          return db.batch(statements);
        },
      } as unknown as D1Database;
      expect(
        await target.call('/api/setup/import/chunk', {
          method: 'POST',
          body: chunk(current, 2),
          bindings: { ...target.env, DB: racing },
        }),
      ).toMatchObject({ status: 409, body: { error: 'import_superseded' } });
      expect(await tables(target)).toBe(0);
      expect(await target.sql('SELECT seq FROM import_chunks')).toEqual([]);
      await target.sql("UPDATE system_state SET value=json_set(value,'$.id',?) WHERE key='import_id'", current);
      await target.sql("DELETE FROM system_state WHERE key='owner_user_id'");
    }
    expect(await target.sql("SELECT key FROM system_state WHERE key='import_guard'")).toEqual([]);
    // A commit of a stale import is stopped as well.
    const commit = {
      importId: old,
      settings: { type: 'settings', backupRecipient: null },
      archiveIdentity: null,
      end: { type: 'end', counts: {} },
    };
    await expect(target.post('/api/setup/import/commit', commit)).rejects.toMatchObject({ code: 'import_superseded' });
  });

  it('writes a chunk sent again once, also while the first is still being written', async () => {
    const target = await instance();
    const [header, owner] = await minimal();
    const importId = String(
      (await target.post('/api/setup/import', { header, owner }, { 'x-bootstrap-token': await target.issue() }))
        .importId,
    );
    const chunk = {
      importId,
      seq: 0,
      records: [
        installation('client'),
        {
          type: 'secret',
          id: 's',
          name: 'S',
          description: '',
          status: 'active',
          currentVersion: 1,
          createdAt: 1,
          updatedAt: 1,
        },
        { type: 'secret-version', secretId: 's', version: 1, values: { token: 't' }, createdAt: 1 },
      ],
    };
    expect(await target.post('/api/setup/import/chunk', chunk)).toEqual({ written: true });
    expect(await target.post('/api/setup/import/chunk', chunk)).toEqual({ written: true });
    expect(await tables(target)).toBe(3);
    // An embedded segment sent again leaves no second object in the bucket, where it would stay for good.
    const segment = { importId, seq: 5, records: [embedded(1, [1, 'a'], [2, 'b'])] };
    for (let i = 0; i < 2; i++)
      expect(await target.post('/api/setup/import/chunk', segment)).toEqual({ written: true });
    expect((await target.env.BACKUPS.list()).objects.length).toBe(1);
    expect(await tables(target)).toBe(4);
    // Two copies that both read the chunk as unwritten: the second batch finds its seq taken.
    let arrived = 0,
      release!: () => void;
    const both = new Promise<void>((resolve) => (release = resolve));
    const db = target.env.DB;
    const racing = {
      prepare: (sql: string) => db.prepare(sql),
      batch: async (statements: D1PreparedStatement[]) => {
        if (++arrived === 2) release();
        await both;
        return db.batch(statements);
      },
    } as unknown as D1Database;
    const again = { ...chunk, seq: 1, records: [installation('other')] };
    const answers = await Promise.all(
      [1, 2].map(() =>
        target.call('/api/setup/import/chunk', {
          method: 'POST',
          body: again,
          bindings: { ...target.env, DB: racing },
        }),
      ),
    );
    expect(arrived).toBe(2);
    expect(answers.map((a) => [a.status, a.body])).toEqual([
      [200, { written: true }],
      [200, { written: true }],
    ]);
    expect(await tables(target)).toBe(5);
  });

  it('takes each segment as the kind of its snapshot says, by its own checksum and key', async () => {
    const start = async (target: Instance, kind: 'full' | 'automatic') => {
      const [header, owner] = await minimal(kind);
      return String(
        (await target.post('/api/setup/import', { header, owner }, { 'x-bootstrap-token': await target.issue() }))
          .importId,
      );
    };
    const full = await instance();
    const fullId = await start(full, 'full');
    const segment = embedded(1, [1, 'a'], [2, 'b']) as RecordOf<'segment'>;
    const key = `archive/audit/0000000001-${'k'.repeat(22)}.age`;
    for (const [record, hint] of [
      [{ ...segment, sha256: 'e'.repeat(64) }, 'does not have the checksum it names'],
      [{ ...segment, data: null, key }, 'of a full snapshot has no data'],
    ] as const)
      await expect(
        full.post('/api/setup/import/chunk', { importId: fullId, seq: 0, records: [record] }),
      ).rejects.toMatchObject({ code: 'invalid_snapshot', message: expect.stringContaining(hint) });
    expect((await full.env.BACKUPS.list()).objects).toEqual([]);

    // A referenced segment is in the bucket under a key of its own kind and seq, never anywhere else.
    const automatic = await instance();
    const automaticId = await start(automatic, 'automatic');
    const data = Buffer.from(segment.data!, 'base64');
    await automatic.env.BACKUPS.put(key, data, { sha256: sha256(data) });
    await automatic.env.BACKUPS.put('vault/2026-01-01/backup.age', data, { sha256: sha256(data) });
    const referenced = { ...segment, data: null, key };
    for (const [record, hint] of [
      [{ ...referenced, seq: 2 }, "has another's key"],
      [{ ...referenced, kind: 'access-request' }, "has another's key"],
      [{ ...referenced, key: 'vault/2026-01-01/backup.age' }, 'key'],
      [segment, 'of an automatic snapshot has no key'],
    ] as const)
      await expect(
        automatic.post('/api/setup/import/chunk', { importId: automaticId, seq: 0, records: [record] }),
      ).rejects.toMatchObject({ code: 'invalid_snapshot', message: expect.stringContaining(hint) });
    await expect(
      automatic.post('/api/setup/import/chunk', {
        importId: automaticId,
        seq: 0,
        records: [referenced],
        skip: [{ kind: 'audit', seq: 2 }],
      }),
    ).rejects.toMatchObject({ code: 'invalid_input' });
    // An object under the key whose checksum is not the record's is not that segment.
    const other = Buffer.from('other bytes');
    const otherKey = `archive/audit/0000000001-${'m'.repeat(22)}.age`;
    await automatic.env.BACKUPS.put(otherKey, other, { sha256: sha256(other) });
    expect(
      await automatic.post('/api/setup/import/chunk', {
        importId: automaticId,
        seq: 0,
        records: [{ ...referenced, key: otherKey }],
      }),
    ).toEqual({ written: false, missing: [{ kind: 'audit', seq: 1 }] });
    expect(
      await automatic.post('/api/setup/import/chunk', { importId: automaticId, seq: 0, records: [referenced] }),
    ).toEqual({ written: true });
    expect(await automatic.sql('SELECT seq,object_key FROM archive_segments')).toEqual([{ seq: 1, object_key: key }]);
  });

  it('commits only the chunks it checked, only while the import is the current one, and spends any token', async () => {
    const [header, owner, settings] = await minimal();
    const end = (extra: Record<string, number> = {}) => ({
      type: 'end',
      counts: { ...Object.fromEntries(COUNTED_TYPES.map((t) => [t, 0])), owner: 1, settings: 1, ...extra },
    });
    const begin = async (target: Instance) =>
      String(
        (await target.post('/api/setup/import', { header, owner }, { 'x-bootstrap-token': await target.issue() }))
          .importId,
      );
    // Runs before the commit's second batch, the one that writes: after its checks read what was written.
    const racing = (target: Instance, before: () => Promise<unknown>) => {
      const db = target.env.DB;
      let batches = 0;
      return {
        ...target.env,
        DB: {
          prepare: (sql: string) => db.prepare(sql),
          batch: async (statements: D1PreparedStatement[]) => {
            if (++batches === 2) await before();
            return db.batch(statements);
          },
        } as unknown as D1Database,
      };
    };
    const dangling = {
      type: 'grant',
      id: 'g',
      clientId: 'nobody',
      resourceType: 'secret',
      resourceId: 'nothing',
      permission: 'secret:read',
      fields: null,
      extensions: null,
      status: 'active',
      expiresAt: null,
      createdAt: 1,
    };
    // A chunk that arrives after the checks would be committed unchecked: here a grant for nothing, which
    // would make every later snapshot of the instance fail.
    const late = await instance();
    const lateId = await begin(late);
    await late.post('/api/setup/import/chunk', { importId: lateId, seq: 0, records: [installation('a')] });
    const commit = { importId: lateId, settings, archiveIdentity: null, end: end({ installation: 1 }) };
    expect(
      await late.call('/api/setup/import/commit', {
        method: 'POST',
        body: commit,
        bindings: racing(late, async () =>
          expect(await late.post('/api/setup/import/chunk', { importId: lateId, seq: 1, records: [dangling] })).toEqual(
            { written: true },
          ),
        ),
      }),
    ).toMatchObject({ status: 409, body: { error: 'import_superseded' } });
    expect(await late.initialized()).toBe(false);
    expect(await late.sql('SELECT id FROM "user"')).toEqual([]);
    // Committed again, it counts the chunk that came late.
    await expect(late.post('/api/setup/import/commit', commit)).rejects.toMatchObject({
      code: 'import_incomplete',
      message: expect.stringContaining('grant: 1 imported, the snapshot has 0'),
    });

    // An import replaced by a new start, or the instance initialized, after the checks: nothing is written.
    const replaced = await instance();
    const replacedId = await begin(replaced);
    for (const change of [
      "UPDATE system_state SET value=json_set(value,'$.id','replaced-by-another') WHERE key='import_id'",
      "INSERT INTO system_state (key,value,updated_at) VALUES ('owner_user_id','someone',0)",
    ]) {
      expect(
        await replaced.call('/api/setup/import/commit', {
          method: 'POST',
          body: { importId: replacedId, settings, archiveIdentity: null, end: end() },
          bindings: racing(replaced, () => replaced.sql(change)),
        }),
      ).toMatchObject({ status: 409, body: { error: 'import_superseded' } });
      expect(await replaced.sql('SELECT id FROM "user"')).toEqual([]);
      expect(
        await replaced.sql("SELECT key FROM system_state WHERE key IN ('archive_identity','import_guard')"),
      ).toEqual([]);
      await replaced.sql("UPDATE system_state SET value=json_set(value,'$.id',?) WHERE key='import_id'", replacedId);
      await replaced.sql("DELETE FROM system_state WHERE key='owner_user_id'");
    }

    // A token issued while the import ran is spent with it: on the initialized instance it would otherwise
    // reset the Owner's password for the 24 hours of a setup token.
    const target = await instance();
    const importId = await begin(target);
    const later = await target.issue();
    await target.post('/api/setup/import/commit', { importId, settings, archiveIdentity: null, end: end() });
    expect(await target.initialized()).toBe(true);
    expect(await target.sql("SELECT key FROM system_state WHERE key='bootstrap_token'")).toEqual([]);
    expect(
      await target.call('/api/setup/password', {
        method: 'POST',
        body: { password: 'another-password-for-import' },
        headers: { 'x-bootstrap-token': later },
      }),
    ).toMatchObject({ status: 401, body: { error: 'invalid_bootstrap_token' } });
    expect(await target.signIn('owner@example.com', PASSWORD)).toBe(200);
  });

  it('reads no chunk body while no import is in progress', async () => {
    const huge = { importId: 'x'.repeat(22), seq: 0, records: ['x'.repeat(9 * 1024 * 1024)] };
    const fresh = await instance();
    expect(await fresh.call('/api/setup/import/chunk', { method: 'POST', body: huge })).toMatchObject({
      status: 409,
      body: { error: 'import_superseded' },
    });
    await fresh.importFile(await file(await minimal()), await fresh.issue());
    expect(await fresh.call('/api/setup/import/chunk', { method: 'POST', body: huge })).toMatchObject({
      status: 409,
      body: { error: 'import_superseded' },
    });
  });

  it('refuses segments without an archive identity, and skipped segments out of order', async () => {
    const identity = { type: 'archive-identity', identity: await generateHybridIdentity() };
    const end = (extra: Record<string, number>) => ({
      type: 'end',
      counts: { ...Object.fromEntries(COUNTED_TYPES.map((t) => [t, 0])), owner: 1, settings: 1, ...extra },
    });
    const begin = async (target: Instance, kind: 'full' | 'automatic') => {
      const [header, owner, settings] = await minimal(kind);
      const importId = String(
        (await target.post('/api/setup/import', { header, owner }, { 'x-bootstrap-token': await target.issue() }))
          .importId,
      );
      return { importId, settings };
    };
    // Segments nobody could read again: the commit refuses them without the identity.
    const bare = await instance();
    const full = await begin(bare, 'full');
    await bare.post('/api/setup/import/chunk', {
      importId: full.importId,
      seq: 0,
      records: [embedded(1, [1, 'a'], [2, 'b'])],
    });
    await expect(
      bare.post('/api/setup/import/commit', { ...full, archiveIdentity: null, end: end({ segment: 1 }) }),
    ).rejects.toMatchObject({ code: 'invalid_snapshot', message: expect.stringContaining('no archive-identity') });

    // A skipped segment still has its range: one overlapping a segment that came, or one that ends after a
    // row of its kind, is refused like any other.
    const referenced = (seq: number, first: [number, string], last: [number, string]) => {
      const { data, ...segment } = embedded(seq, first, last) as RecordOf<'segment'>;
      return {
        record: { ...segment, data: null, key: `archive/audit/${String(seq).padStart(10, '0')}-${'k'.repeat(22)}.age` },
        file: Buffer.from(data!, 'base64'),
      };
    };
    for (const [present, records, counts] of [
      [[referenced(1, [100, 'a'], [200, 'b'])], [referenced(2, [150, 'c'], [250, 'd'])], { segment: 2 }],
      [[], [referenced(1, [100, 'a'], [300, 'b'])], { segment: 1, audit: 1 }],
    ] as const) {
      const target = await instance();
      for (const { record, file } of present) await target.env.BACKUPS.put(record.key, file, { sha256: record.sha256 });
      const automatic = await begin(target, 'automatic');
      const chunk = {
        importId: automatic.importId,
        seq: 0,
        records: [...(counts.audit ? [audit('hot', 200)] : []), ...[...present, ...records].map((s) => s.record)],
      };
      const answer = await target.post('/api/setup/import/chunk', chunk);
      expect(answer).toEqual({ written: false, missing: records.map((s) => ({ kind: 'audit', seq: s.record.seq })) });
      expect(await target.post('/api/setup/import/chunk', { ...chunk, skip: answer.missing })).toEqual({
        written: true,
      });
      await expect(
        target.post('/api/setup/import/commit', {
          ...automatic,
          archiveIdentity: identity,
          end: end({ 'archive-identity': 1, ...counts }),
        }),
      ).rejects.toMatchObject({ code: 'snapshot_inconsistent', message: expect.stringContaining('audit segments') });
    }
  });

  it('refuses a commit while a chunk is missing, and a new token starts over', async () => {
    const target = await instance();
    const list = [...(await minimal()), installation('a'), installation('b')];
    const [header, owner, settings] = list;
    const end = {
      type: 'end',
      counts: { ...Object.fromEntries(COUNTED_TYPES.map((t) => [t, 0])), owner: 1, settings: 1, installation: 2 },
    };
    const importId = String(
      (await target.post('/api/setup/import', { header, owner }, { 'x-bootstrap-token': await target.issue() }))
        .importId,
    );
    await target.post('/api/setup/import/chunk', { importId, seq: 0, records: [installation('a')] });
    const commit = { importId, settings, archiveIdentity: null, end };
    await expect(target.post('/api/setup/import/commit', commit)).rejects.toMatchObject({
      code: 'import_incomplete',
      message: expect.stringContaining('installation: 1 imported, the snapshot has 2'),
    });
    expect(await target.initialized()).toBe(false);
    // Starting again clears the half import out; the whole file then imports.
    expect(await target.importFile(await file(list), await target.issue())).toMatchObject({ kind: 'full' });
    expect(await target.sql('SELECT clientId,userId FROM "oauthClient" ORDER BY clientId')).toEqual([
      { clientId: 'a', userId: 'crafted-owner' },
      { clientId: 'b', userId: 'crafted-owner' },
    ]);
    expect(await target.signIn('owner@example.com', PASSWORD)).toBe(200);
  });

  it('leaves nothing of a failed import to a new Owner, whose backups then work', async () => {
    const target = await instance();
    const [header, owner] = await minimal();
    const importId = String(
      (await target.post('/api/setup/import', { header, owner }, { 'x-bootstrap-token': await target.issue() }))
        .importId,
    );
    // A credential encrypted for the snapshot's Owner, which no later export could decrypt.
    await target.post('/api/setup/import/chunk', {
      importId,
      seq: 0,
      records: [
        {
          type: 'secret',
          id: 's',
          name: 'S',
          description: '',
          status: 'active',
          currentVersion: 1,
          createdAt: 1,
          updatedAt: 1,
        },
        { type: 'secret-version', secretId: 's', version: 1, values: { token: 't' }, createdAt: 1 },
        installation('client'),
        audit('a', 1),
      ],
    });
    await target.ok('/api/setup/owner', {
      method: 'POST',
      body: {
        name: 'New',
        email: 'new@example.com',
        password: PASSWORD,
        backupRecipient: await identityToRecipient(await generateIdentity()),
      },
      headers: { 'x-bootstrap-token': await target.issue() },
    });
    expect(await target.sql('SELECT COUNT(*) AS n FROM secrets')).toEqual([{ n: 0 }]);
    expect(await target.sql('SELECT action FROM audit_events')).toEqual([{ action: 'owner:create' }]);
    expect(await target.sql('SELECT seq FROM import_chunks')).toEqual([]);
    expect(await target.sql("SELECT key FROM system_state WHERE key='import_id'")).toEqual([]);
    const [{ value: uid }] = await target.sql("SELECT value FROM system_state WHERE key='owner_user_id'");
    expect(await target.runAutomaticBackup(target.env, uid as string, true)).toMatchObject({ outcome: 'saved' });
    // The import id of the failed import is stopped for good.
    await expect(
      target.post('/api/setup/import/chunk', { importId, seq: 1, records: [audit('b', 2)] }),
    ).rejects.toMatchObject({
      code: 'import_superseded',
    });
  });

  it('writes rows of every size within D1’s limits, and none of today’s business rules', async () => {
    const target = await instance();
    // An access request of 1.9 MB of quotes takes twice that inside a JSON array, so it goes alone; 3000
    // audit rows of 1 KB take several arrays. Neither the 256 KiB limit of a request nor any other rule
    // of this version applies to what an instance once stored.
    const big = {
      type: 'access-request',
      id: 'big',
      clientId: 'client',
      requested: { invocation: { body: '"'.repeat(950_000) } },
      reason: null,
      status: 'denied',
      fingerprint: null,
      consumedAt: null,
      createdAt: 5,
      expiresAt: 6,
    } as SnapshotRecord;
    const rows = Array.from(
      { length: 3000 },
      (_, i) =>
        ({
          ...(audit(`row-${String(i).padStart(4, '0')}`, 10 + i) as object),
          action: 'x'.repeat(1000),
        }) as SnapshotRecord,
    );
    const list = [...(await minimal()), installation('client'), big, ...rows];
    await target.importFile(await file(list), await target.issue());
    expect(
      await target.sql("SELECT length(requested_json) AS n,created_at FROM access_requests WHERE id='big'"),
    ).toEqual([{ n: JSON.stringify(big.type === 'access-request' && big.requested).length, created_at: 5 }]);
    expect(
      await target.sql(
        "SELECT COUNT(*) AS n,MIN(created_at) AS first FROM audit_events WHERE action<>'instance:import'",
      ),
    ).toEqual([{ n: 3000, first: 10 }]);
    expectImported(list, await exported(target), true);
  });

  it('refuses a snapshot whose references or segments do not hold', async () => {
    const identity = { type: 'archive-identity', identity: await generateHybridIdentity() } as SnapshotRecord;
    const secret = (currentVersion: number) =>
      ({
        type: 'secret',
        id: 's',
        name: 'S',
        description: '',
        status: 'active',
        currentVersion,
        createdAt: 1,
        updatedAt: 1,
      }) as SnapshotRecord;
    const version = (n: number, values = { token: 't' }) =>
      ({ type: 'secret-version', secretId: 's', version: n, values, createdAt: 1 }) as SnapshotRecord;
    const connection = (field: string) =>
      ({
        type: 'connection',
        id: 'c',
        name: 'C',
        origin: 'https://api.example.com',
        description: '',
        auth: { type: 'bearer', secretId: 's', field },
        policy: { paths: ['/'], methods: ['GET'], deny: [], approval: [], free: [], hosts: [], anyHost: false },
        status: 'active',
        createdAt: 1,
        updatedAt: 1,
      }) as SnapshotRecord;
    const grant = (clientId: string, resourceId: string) =>
      ({
        type: 'grant',
        id: 'g',
        clientId,
        resourceType: 'secret',
        resourceId,
        permission: 'secret:read',
        fields: null,
        extensions: null,
        status: 'active',
        expiresAt: null,
        createdAt: 1,
      }) as SnapshotRecord;
    const request = {
      type: 'access-request',
      id: 'r',
      clientId: 'nobody',
      requested: {},
      reason: null,
      status: 'pending',
      fingerprint: null,
      consumedAt: null,
      createdAt: 500,
      expiresAt: 600,
    } as SnapshotRecord;
    const cases: [string, SnapshotRecord[]][] = [
      ['grant g names', [secret(1), version(1), installation('client'), grant('nobody', 's')]],
      ['grant g names', [secret(1), version(1), installation('client'), grant('client', 'nothing')]],
      ['access request r names', [installation('client'), request]],
      ['secret s does not have exactly', [secret(2), version(2)]],
      ['secret s does not have exactly', [secret(1), version(1), version(2)]],
      ['secret s does not have exactly', [secret(0)]],
      ['connection c injects', [secret(1), version(1), connection('missing')]],
      ['audit segments and rows', [identity, embedded(1, [100, 'a'], [200, 'b']), embedded(2, [150, 'c'], [250, 'd'])]],
      ['audit segments and rows', [identity, embedded(1, [200, 'a'], [100, 'b'])]],
      ['audit segments and rows', [identity, audit('early', 150), embedded(1, [100, 'a'], [200, 'b'])]],
      [
        'access-request segments and rows',
        [
          identity,
          installation('client'),
          { ...request, clientId: 'client', createdAt: 150 } as SnapshotRecord,
          embedded(1, [100, 'a'], [200, 'b'], 'access-request'),
        ],
      ],
    ];
    for (const [hint, extra] of cases) {
      const target = await instance();
      await expect(
        target.importFile(await file([...(await minimal()), ...extra]), await target.issue()),
        hint,
      ).rejects.toMatchObject({
        code: 'snapshot_inconsistent',
        message: expect.stringContaining(hint),
      });
      expect(await target.initialized()).toBe(false);
    }
    // The same records in order import.
    const target = await instance();
    await target.importFile(
      await file([
        ...(await minimal()),
        identity,
        secret(1),
        version(1),
        connection('token'),
        installation('client'),
        grant('client', 's'),
        audit('hot', 201),
        embedded(1, [100, 'a'], [150, 'b']),
        embedded(2, [160, 'c'], [200, 'b']),
      ]),
      await target.issue(),
    );
    expect(await target.initialized()).toBe(true);
  });
});

/** Audit rows of about 1 KB each, rows of them from at on. Sealing leaves about 1.5 MB of them: 2000 rows
 * make one segment, 1000 more one more. */
const fill = (target: Instance, owner: string, prefix: string, at: number, rows: number) =>
  target.sql(
    "INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) SELECT printf('%s-%06d',?,i),?,'client',printf('%.*c',1000,'x'),NULL,'ok','request',?+i FROM n",
    rows,
    prefix,
    owner,
    at,
  );
/** Instance X with a credential and the Owner's backups going to an identity the test keeps; seal adds
 * audit rows and seals them, backup writes an automatic backup and returns its key. */
async function backedUp() {
  const x = await instance();
  const identity = await generateIdentity();
  await x.ok('/api/setup/owner', {
    method: 'POST',
    body: {
      name: 'Owner',
      email: 'owner@example.com',
      password: PASSWORD,
      backupRecipient: await identityToRecipient(identity),
    },
    headers: { 'x-bootstrap-token': await x.issue() },
  });
  expect(await x.signIn('owner@example.com', PASSWORD)).toBe(200);
  const sid = String(
    (await x.ok('/admin/secrets', { method: 'POST', body: { name: 'Key', values: { token: 'kept' } } })).id,
  );
  const [{ value: owner }] = await x.sql("SELECT value FROM system_state WHERE key='owner_user_id'");
  const seal = async (prefix: string, at: number, rows: number) => {
    await fill(x, owner as string, prefix, at, rows);
    await x.sealColdData(x.env, owner as string);
  };
  const backup = async () => {
    await x.runAutomaticBackup(x.env, owner as string, true);
    return String((await x.sql('SELECT object_key FROM backup_state'))[0].object_key);
  };
  return { x, identity, sid, owner: owner as string, seal, backup };
}
const objects = async (bucket: R2Bucket) =>
  Object.fromEntries(
    await Promise.all(
      (await bucket.list({ prefix: 'archive/' })).objects.map(async (o) => [
        o.key,
        sha256(new Uint8Array(await (await bucket.get(o.key))!.arrayBuffer())),
      ]),
    ),
  ) as Record<string, string>;
const read = async (bucket: R2Bucket, key: string) => new Uint8Array(await (await bucket.get(key))!.arrayBuffer());

describe('disaster recovery from the same bucket', { timeout: 180_000 }, () => {
  it('rebuilds the instance under a new root key from the latest automatic backup', async () => {
    const { x, identity, sid, seal, backup } = await backedUp();
    await seal('first', Date.now() - 3 * 3_600_000, 2000);
    await seal('second', Date.now() - 2 * 3_600_000, 1000);
    expect((await x.sql('SELECT seq FROM archive_segments')).length).toBe(2);
    const bytes = await read(x.env.BACKUPS, await backup());
    const source = await records(bytes, identity);
    expect(source[0]).toMatchObject({ kind: 'automatic' });
    // A new database and a new root key on the same bucket.
    const y = await instance({ bucket: x.env.BACKUPS });
    const missing = vi.fn(async () => false);
    await y.importFile(bytes, await y.issue(), missing, identity);
    expect(missing).not.toHaveBeenCalled();
    expectImported(source, await exported(y), true);
    expect(await y.sql('SELECT object_key FROM archive_segments ORDER BY seq')).toEqual(
      await x.sql('SELECT object_key FROM archive_segments ORDER BY seq'),
    );
    expect(await y.signIn('owner@example.com', PASSWORD)).toBe(200);
    expect((await y.ok('/admin/status')).secrets).toMatchObject([{ id: sid, fields: ['token'] }]);
  });

  it('goes without missing segments only when the Owner says so, and records which', async () => {
    const { x, identity, seal, backup } = await backedUp();
    await seal('first', Date.now() - 3 * 3_600_000, 2000);
    await seal('second', Date.now() - 2 * 3_600_000, 1000);
    const bytes = await read(x.env.BACKUPS, await backup());
    const segments = await x.sql('SELECT seq,object_key FROM archive_segments ORDER BY seq');
    // A bucket holding everything but the first segment, and the second only without its checksum.
    const bucket = await freeBucket();
    await bucket.put(String(segments[1].object_key), await read(x.env.BACKUPS, String(segments[1].object_key)));
    const y = await instance({ bucket });
    expect(await y.importFile(bytes, await y.issue(), async () => false, identity)).toBeNull();
    expect(await y.initialized()).toBe(false);
    const asked: Segment[][] = [];
    await y.importFile(bytes, await y.issue(), async (list) => (asked.push(list), true), identity);
    expect(asked).toEqual([
      [
        { kind: 'audit', seq: 1 },
        { kind: 'audit', seq: 2 },
      ],
    ]);
    expect(await y.initialized()).toBe(true);
    expect(await y.sql('SELECT seq FROM archive_segments')).toEqual([]);
    expect(await importAudit(y)).toMatchObject([
      {
        resource_id: {
          skipped: [
            { kind: 'audit', seq: 1 },
            { kind: 'audit', seq: 2 },
          ],
        },
      },
    ]);
    // Its later backups name only the segments it has.
    const [{ value: owner }] = await y.sql("SELECT value FROM system_state WHERE key='owner_user_id'");
    expect(await y.runAutomaticBackup(y.env, owner as string, true)).toMatchObject({ outcome: 'saved' });
  });

  it('restores an older backup without touching the segments sealed after it', async () => {
    const { x, identity, owner, seal, backup } = await backedUp();
    await seal('first', Date.now() - 3 * 3_600_000, 2000);
    const older = await read(x.env.BACKUPS, await backup());
    await seal('second', Date.now() - 2 * 3_600_000, 1000);
    await backup();
    const before = await objects(x.env.BACKUPS);
    expect(Object.keys(before).length).toBe(2);
    const y = await instance({ bucket: x.env.BACKUPS });
    await y.importFile(older, await y.issue(), async () => false, identity);
    expect((await y.sql('SELECT seq FROM archive_segments')).map((s) => s.seq)).toEqual([1]);
    // Y goes on from the older state and seals its own second segment, under a key of its own: the one X
    // sealed second stays as it was, unreferenced.
    await fill(y, owner, 'later', Date.now() - 2 * 3_600_000, 1000);
    await y.sealColdData(y.env, owner);
    const after = await objects(x.env.BACKUPS);
    expect(Object.keys(after).length).toBe(3);
    expect(after).toMatchObject(before);
    const [second] = await y.sql('SELECT object_key FROM archive_segments WHERE seq=2');
    expect(Object.keys(before)).not.toContain(second.object_key);
  });
});

describe('the first requests after an import', { timeout: 120_000 }, () => {
  const login = (target: Instance, clientId: string, bindings?: Bindings) =>
    target.call('/api/auth/device/code', {
      method: 'POST',
      body: { client_id: clientId, scope: SCOPES.join(' '), resource: A + '/v1' },
      bindings,
    });

  it('serves logins that arrive together on a new isolate', async () => {
    const target = await instance();
    await target.importFile(
      await file([...(await minimal()), installation('cli-a'), installation('cli-b')]),
      await target.issue(),
    );
    // Each request starts a Better Auth instance of its own, as two isolates would.
    const logins = await Promise.all(['cli-a', 'cli-b', 'cli-a'].map((client) => login(target, client)));
    expect(logins.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(await target.sql('SELECT identifier FROM "oauthResource"')).toEqual([{ identifier: A + '/v1' }]);
  });

  it('keeps no Better Auth instance whose initialization failed', async () => {
    const target = await instance();
    await target.importFile(await file([...(await minimal()), installation('cli')]), await target.issue());
    // The provider's table cannot be read while the isolate's first instance starts.
    const unreachable = {
      ...target.env,
      DB: {
        prepare: (sql: string) => {
          if (sql.includes('"oauthResource"')) throw new Error('D1 unavailable');
          return target.env.DB.prepare(sql);
        },
        batch: (statements: D1PreparedStatement[]) => target.env.DB.batch(statements),
      } as unknown as D1Database,
    };
    expect((await login(target, 'cli', unreachable)).status).toBe(500);
    expect((await login(target, 'cli')).status).toBe(200);
  });
});
