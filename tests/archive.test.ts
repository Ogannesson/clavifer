import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { Decrypter, generateHybridIdentity, generateIdentity, identityToRecipient } from 'age-encryption';
import { applyMigrations } from '../scripts/migrations.mjs';
import worker from '../apps/worker/src/index';
import { sealColdData } from '../apps/worker/src/archive';
import { backupStatus, pruneBackups, rowBytes } from '../apps/worker/src/backup';
import { type Bindings, type Principal, audit } from '../apps/worker/src/context';
import { accessRequest, accessStatus } from '../apps/worker/src/vault';
import { encryptArchiveIdentity, parseRootKeys, rootKeyFingerprints } from '../packages/core/crypto';
import { ARCHIVE_FORMAT, archiveHeader, readRecords, snapshotRecord } from '../packages/core/snapshot';

// Real D1 and R2, one fresh pair for each test. The Owner id, the root key check and the archive
// recipient are cached for the isolate, which is this module, so every instance has the same Owner,
// root key and archive identity.
const OWNER = 'owner';
const rootKey = `1:${Buffer.from('s'.repeat(32)).toString('base64url')}`;
const MINUTE = 60_000,
  HOUR = 60 * MINUTE;
// The thresholds of archive.ts, which the tests observe from outside.
const KEEP = 1_500_000,
  SEGMENT = 1_000_000;
const instances = 16;
let mf: Miniflare, identity: string;
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
  identity = await generateHybridIdentity();
});
afterAll(() => mf.dispose());

/** A fresh initialized instance: its Owner with a password, root key fingerprints, archive identity and a
 * backup recipient. */
async function instance() {
  const n = next++;
  const env = {
    DB: await mf.getD1Database(`DB${n}`),
    BACKUPS: await mf.getR2Bucket(`R2${n}`),
    APP_ORIGIN: 'http://localhost:8787',
    ALLOW_LOCAL_HTTP: 'true',
    ROOT_KEY: rootKey,
  } as unknown as Bindings;
  await applyMigrations(env.DB);
  const ring = parseRootKeys(rootKey);
  const state = (key: string, value: string) =>
    env.DB.prepare('INSERT INTO system_state (key,value,updated_at) VALUES (?,?,0)').bind(key, value);
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO \"user\" (id,name,email,emailVerified,createdAt,updatedAt) VALUES (?,'Owner','owner@example.com',0,0,0)",
    ).bind(OWNER),
    env.DB.prepare(
      "INSERT INTO account (id,accountId,providerId,userId,password,createdAt,updatedAt) VALUES ('account',?,'credential',?,?,0,0)",
    ).bind(OWNER, OWNER, `${'0'.repeat(32)}:${'0'.repeat(128)}`),
    state('owner_user_id', OWNER),
    state('root_key_fingerprints', JSON.stringify(await rootKeyFingerprints(ring))),
    state('archive_identity', JSON.stringify(await encryptArchiveIdentity(ring, OWNER, identity))),
    env.DB.prepare('UPDATE backup_state SET recipient=? WHERE id=1').bind(
      await identityToRecipient(await generateIdentity()),
    ),
  ]);
  return env;
}

// Rows written straight into the tables, n at a time from created_at at + 1, each with text of size
// characters (char, repeated) so that their bytes are known.
const fillAudit = (env: Bindings, n: number, at: number, size: number, char = 'x', prefix = 'a') =>
  env.DB.prepare(
    "INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) SELECT printf('%s-%06d',?,i),?,'client',replace(printf('%.*c',?,'x'),'x',?),NULL,'ok','request',?+i FROM n",
  )
    .bind(n, prefix, OWNER, size, char, at)
    .run();
const fillRequests = (env: Bindings, n: number, at: number, size: number, prefix = 'r') =>
  env.DB.prepare(
    "INSERT INTO access_requests (id,owner_id,client_id,requested_json,reason,status,created_at,expires_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<?) SELECT printf('%s-%06d',?,i),?,'client',json_object('invocation',json_object('body',printf('%.*c',?,'x'))),'r','denied',?+i,?+i+86400000 FROM n",
  )
    .bind(n, prefix, OWNER, size, at, at)
    .run();
const value = async <T = number>(env: Bindings, sql: string, ...args: unknown[]) =>
  Object.values(
    (await env.DB.prepare(sql)
      .bind(...args)
      .first<Record<string, T>>())!,
  )[0];
const sealable = (env: Bindings, table: 'audit_events' | 'access_requests', age: number) =>
  value(env, `SELECT IFNULL(SUM(${rowBytes(table)}),0) FROM ${table} WHERE created_at<?`, Date.now() - age);
const manifest = async (env: Bindings, kind?: string) =>
  (
    await env.DB.prepare(`SELECT * FROM archive_segments ${kind ? 'WHERE kind=?' : ''} ORDER BY kind,seq`)
      .bind(...(kind ? [kind] : []))
      .all<{
        kind: string;
        seq: number;
        object_key: string;
        sha256: string;
        first_at: number;
        first_id: string;
        last_at: number;
        last_id: string;
        rows: number;
        created_at: number;
      }>()
  ).results;
const archived = async (env: Bindings) =>
  (await env.BACKUPS.list({ prefix: 'archive/' })).objects.map((object) => object.key).sort();
const hex = (data: ArrayBuffer | Uint8Array) => Buffer.from(data as ArrayBuffer).toString('hex');
const archiveError = async (env: Bindings) => (await backupStatus(env)).archiveError;

/** Reads every segment of the manifest back: its object's SHA-256 is the manifest's and R2's own, it
 * decrypts with the archive identity, and its records are the header the manifest describes followed by
 * that many records of its kind, in (created_at, id) order. Returns the ids of the rows in segments. */
async function readSegments(env: Bindings) {
  const ids: string[] = [];
  for (const segment of await manifest(env)) {
    expect(segment.object_key).toMatch(
      new RegExp(`^archive/${segment.kind}/${String(segment.seq).padStart(10, '0')}-[A-Za-z0-9_-]{22}\\.age$`),
    );
    const object = await env.BACKUPS.get(segment.object_key);
    const bytes = new Uint8Array(await object!.arrayBuffer());
    expect(hex(await crypto.subtle.digest('SHA-256', bytes))).toBe(segment.sha256);
    expect(hex((await env.BACKUPS.head(segment.object_key))!.checksums.sha256!)).toBe(segment.sha256);
    const decrypter = new Decrypter();
    decrypter.addIdentity(identity);
    const records = [];
    for await (const record of readRecords(new Response(new Uint8Array(await decrypter.decrypt(bytes))).body!))
      records.push(record);
    expect(archiveHeader.parse(records[0])).toEqual({
      type: 'header',
      format: ARCHIVE_FORMAT,
      kind: segment.kind,
      seq: segment.seq,
      first: [segment.first_at, segment.first_id],
      last: [segment.last_at, segment.last_id],
      rows: segment.rows,
      createdAt: segment.created_at,
    });
    const rows = records
      .slice(1)
      .map((record) => snapshotRecord.parse(record) as { type: string; id: string; createdAt: number });
    expect(rows.length).toBe(segment.rows);
    expect(rows.every((row) => row.type === segment.kind)).toBe(true);
    expect([rows[0].createdAt, rows[0].id]).toEqual([segment.first_at, segment.first_id]);
    expect([rows.at(-1)!.createdAt, rows.at(-1)!.id]).toEqual([segment.last_at, segment.last_id]);
    const keys = rows.map((row) => [row.createdAt, row.id] as const);
    expect(
      keys.every(([at, id], i) => i === 0 || at > keys[i - 1][0] || (at === keys[i - 1][0] && id > keys[i - 1][1])),
    ).toBe(true);
    ids.push(...rows.map((row) => row.id));
  }
  return ids;
}

describe('sealing', () => {
  it('seals the oldest rows into whole segments until under the threshold, and never rows too young', async () => {
    const env = await instance();
    const start = Date.now() - 30 * HOUR;
    // About 4.2 MB of audit an hour old and 2 MB of it 4 minutes old; 2.6 MB of access requests 26 hours
    // old and 2 MB 24 hours old.
    await fillAudit(env, 4000, start, 1000);
    await fillAudit(env, 2000, Date.now() - 4 * MINUTE, 1000, 'x', 'young');
    await fillRequests(env, 2500, Date.now() - 26 * HOUR, 1000);
    await fillRequests(env, 2000, Date.now() - 24 * HOUR, 1000, 'recent');
    const before = await sealable(env, 'audit_events', 5 * MINUTE);
    expect(before).toBeGreaterThan(4 * SEGMENT);

    await sealColdData(env, OWNER);

    const audits = await manifest(env, 'audit'),
      requests = await manifest(env, 'access-request');
    expect(audits.map((s) => s.seq)).toEqual([1, 2, 3]);
    expect(requests.map((s) => s.seq)).toEqual([1, 2]);
    // Whole segments of about 1 MB, until no more than the threshold is left.
    for (const [table, age] of [
      ['audit_events', 5 * MINUTE],
      ['access_requests', 25 * HOUR],
    ] as const) {
      const left = await sealable(env, table, age);
      expect(left).toBeLessThanOrEqual(KEEP);
      expect(left).toBeGreaterThan(KEEP - SEGMENT - 10_000);
    }
    // Contiguous from the oldest: every hot row comes after the last segment of its kind.
    for (const [kind, table] of [
      ['audit', 'audit_events'],
      ['access-request', 'access_requests'],
    ] as const) {
      const segments = await manifest(env, kind);
      const lastAt = segments.at(-1)!.last_at;
      expect(await value(env, `SELECT MIN(created_at) FROM ${table}`)).toBeGreaterThan(lastAt);
      for (let i = 1; i < segments.length; i++) expect(segments[i].first_at).toBeGreaterThan(segments[i - 1].last_at);
    }
    expect(await value(env, "SELECT COUNT(*) FROM audit_events WHERE id LIKE 'young-%'")).toBe(2000);
    expect(await value(env, "SELECT COUNT(*) FROM access_requests WHERE id LIKE 'recent-%'")).toBe(2000);
    // Every row is in exactly one place.
    const sealed = await readSegments(env);
    expect(new Set(sealed).size).toBe(sealed.length);
    expect(
      sealed.filter((id) => id.startsWith('a-')).length +
        (await value(env, "SELECT COUNT(*) FROM audit_events WHERE id LIKE 'a-%'")),
    ).toBe(4000);
    expect(
      sealed.filter((id) => id.startsWith('r-')).length +
        (await value(env, "SELECT COUNT(*) FROM access_requests WHERE id LIKE 'r-%'")),
    ).toBe(2500);
    expect(await archived(env)).toEqual((await manifest(env)).map((s) => s.object_key).sort());
    // Each segment is audited as the system's, naming its object.
    expect(
      (await env.DB.prepare("SELECT client_id,resource_id,result FROM audit_events WHERE action='archive:seal'").all())
        .results,
    ).toEqual(
      expect.arrayContaining(
        (await manifest(env)).map((s) => ({ client_id: 'system', resource_id: s.object_key, result: 'ok' })),
      ),
    );
    expect(await archiveError(env)).toBeNull();
    // A second run finds nothing more to seal.
    await sealColdData(env, OWNER);
    expect((await manifest(env)).length).toBe(5);
  });

  it('counts bytes, not characters, so Chinese text is not undercounted', async () => {
    const env = await instance();
    // 1200 rows of 500 Chinese characters: about 1.9 MB, though about 0.7 million characters.
    await fillAudit(env, 1200, Date.now() - HOUR, 500, '中');
    expect(await value(env, `SELECT SUM(${rowBytes('audit_events')}) FROM audit_events`)).toBeGreaterThan(1200 * 1500);
    await sealColdData(env, OWNER);
    expect((await manifest(env, 'audit')).length).toBe(1);
  });

  it('lets only one of two overlapping runs commit a segment; the other leaves an orphan object', async () => {
    const env = await instance();
    await fillAudit(env, 2000, Date.now() - HOUR, 1000);
    // Both runs have read the same rows before either commits.
    let arrived = 0,
      release!: () => void;
    const both = new Promise<void>((resolve) => (release = resolve));
    const bucket = env.BACKUPS;
    const racing = {
      ...env,
      BACKUPS: {
        put: async (...args: Parameters<R2Bucket['put']>) => {
          if (++arrived === 2) release();
          await both;
          return bucket.put(...args);
        },
      },
    } as unknown as Bindings;
    await Promise.all([sealColdData(racing, OWNER), sealColdData(racing, OWNER)]);
    expect(arrived).toBe(2);
    expect((await manifest(env)).length).toBe(1);
    expect((await archived(env)).length).toBe(2);
    // The loser rolled back whole: the rows went once, into the one segment.
    const sealed = await readSegments(env);
    expect(sealed.length + (await value(env, 'SELECT COUNT(*) FROM audit_events WHERE id LIKE ?', 'a-%'))).toBe(2000);
    // Losing the race is no failure: the loser recorded nothing.
    expect(await value(env, "SELECT COUNT(*) FROM audit_events WHERE action='archive:seal' AND result<>'ok'")).toBe(0);
    expect(await archiveError(env)).toBeNull();
  });

  it('never deletes a row it did not seal, even one that turns up inside the range it read', async () => {
    const env = await instance();
    const start = Date.now() - HOUR;
    await fillAudit(env, 2000, start, 1000);
    // A row dated between the first two, written after the run read them: the very thing the
    // created_at invariant rules out.
    const bucket = env.BACKUPS;
    const late = {
      ...env,
      BACKUPS: {
        put: async (...args: Parameters<R2Bucket['put']>) => {
          await audit(env, 'client', 'late', null);
          await env.DB.prepare("UPDATE audit_events SET id='a-000001z',created_at=? WHERE action='late'")
            .bind(start + 1)
            .run();
          return bucket.put(...args);
        },
      },
    } as unknown as Bindings;
    await sealColdData(late, OWNER);
    expect(await manifest(env)).toEqual([]);
    expect(await value(env, 'SELECT COUNT(*) FROM audit_events WHERE id LIKE ?', 'a-%')).toBe(2001);
    // No other run sealed the range, so this is no lost race: it is reported, not passed over.
    expect(await archiveError(env)).toBe('archive_conflict');
    expect(
      await value<string>(env, "SELECT result FROM audit_events WHERE action='archive:seal' AND client_id='system'"),
    ).toBe('archive_conflict');
    // The next run reads it with the others.
    await sealColdData(env, OWNER);
    const sealed = await readSegments(env);
    expect(sealed).toContain('a-000001z');
    expect(sealed.length + (await value(env, 'SELECT COUNT(*) FROM audit_events WHERE id LIKE ?', 'a-%'))).toBe(2001);
    expect(await archiveError(env)).toBeNull();
  });

  it('seals a row larger than a segment as a segment of its own', async () => {
    const env = await instance();
    const start = Date.now() - HOUR;
    // The oldest row takes 1.2 MB, as a large access request from an earlier version might; 1 MB follows.
    await env.DB.prepare(
      "INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) VALUES ('big',?,'client',replace(printf('%.*c',100000,'x'),'x','xxxxxxxxxxxx'),NULL,'ok','request',?)",
    )
      .bind(OWNER, start)
      .run();
    await fillAudit(env, 1000, start, 1000);
    await sealColdData(env, OWNER);
    expect((await manifest(env)).map((s) => [s.seq, s.first_id, s.last_id, s.rows])).toEqual([[1, 'big', 'big', 1]]);
    expect(await readSegments(env)).toEqual(['big']);
  });

  it('after an object was written and the commit failed, a rerun seals the rows once under a new key', async () => {
    const env = await instance();
    await fillAudit(env, 2000, Date.now() - HOUR, 1000);
    const db = env.DB;
    const failing = {
      ...env,
      DB: {
        prepare: (sql: string) => db.prepare(sql),
        // The commit is the batch of three statements: manifest row, delete and audit row.
        batch: async (statements: D1PreparedStatement[]) => {
          if (statements.length === 3) throw new Error('synthetic D1 failure');
          return db.batch(statements);
        },
      },
    } as unknown as Bindings;
    await sealColdData(failing, OWNER);
    expect(await manifest(env)).toEqual([]);
    const [orphan] = await archived(env);
    const orphanBytes = hex(await (await env.BACKUPS.get(orphan))!.arrayBuffer());
    expect(await archiveError(env)).toBe('archive_failed');
    expect(
      await value<string>(env, "SELECT result FROM audit_events WHERE action='archive:seal' AND client_id='system'"),
    ).toBe('archive_failed');

    await sealColdData(env, OWNER);
    const [segment] = await manifest(env);
    expect(segment.seq).toBe(1);
    expect(segment.object_key).not.toBe(orphan);
    expect((await archived(env)).sort()).toEqual([orphan, segment.object_key].sort());
    expect(hex(await (await env.BACKUPS.get(orphan))!.arrayBuffer())).toBe(orphanBytes);
    const sealed = await readSegments(env);
    expect(sealed.length + (await value(env, 'SELECT COUNT(*) FROM audit_events WHERE id LIKE ?', 'a-%'))).toBe(2000);
    expect(await archiveError(env)).toBeNull();
  });

  it('seals several segments in one run and stops at the first failure', async () => {
    const env = await instance();
    await fillAudit(env, 5000, Date.now() - HOUR, 1000);
    await fillRequests(env, 2500, Date.now() - 26 * HOUR, 1000);
    let puts = 0;
    const bucket = env.BACKUPS;
    const flaky = {
      ...env,
      BACKUPS: {
        put: async (...args: Parameters<R2Bucket['put']>) => {
          if (++puts === 3) throw new Error('synthetic R2 failure');
          return bucket.put(...args);
        },
      },
    } as unknown as Bindings;
    await sealColdData(flaky, OWNER);
    expect(puts).toBe(3);
    expect((await manifest(env)).map((s) => [s.kind, s.seq])).toEqual([
      ['audit', 1],
      ['audit', 2],
    ]);
    expect((await archived(env)).length).toBe(2);
    expect(await archiveError(env)).toBe('archive_failed');
  });

  it('removes a sealed access request from access.status', async () => {
    const env = await instance();
    await fillRequests(env, 2500, Date.now() - 26 * HOUR, 1000);
    const agent: Principal = { clientId: 'client', userId: OWNER, scopes: ['access:request'] };
    expect(await accessStatus(env, agent, 'r-000001')).toMatchObject({ status: 'denied' });
    await sealColdData(env, OWNER);
    await expect(accessStatus(env, agent, 'r-000001')).rejects.toMatchObject({ code: 'request_not_found' });
    expect(await accessStatus(env, agent, 'r-002500')).toMatchObject({ status: 'denied' });
  });
});

describe('the automatic backup', () => {
  const tick = (env: Bindings) =>
    worker.scheduled({ scheduledTime: Date.now(), cron: '*/15 * * * *' } as ScheduledController, env);

  it('is skipped while the hot data is over its limit and resumes once sealing caught up', async () => {
    const env = await instance();
    // A burst: 9.5 MB of audit rows in the last 4 minutes, none of them sealable yet.
    await fillAudit(env, 9500, Date.now() - 4 * MINUTE, 1000);
    await expect(tick(env)).rejects.toMatchObject({ code: 'hot_data_over_limit' });
    expect(await backupStatus(env)).toMatchObject({ lastError: 'hot_data_over_limit', downloadAvailable: false });
    expect((await env.BACKUPS.list({ prefix: 'vault/' })).objects).toEqual([]);
    expect(
      await value<string>(
        env,
        "SELECT result FROM audit_events WHERE action='backup:automatic' AND client_id='system'",
      ),
    ).toBe('hot_data_over_limit');

    // Ten minutes later the burst is sealable.
    await env.DB.prepare('UPDATE audit_events SET created_at=created_at-?')
      .bind(10 * MINUTE)
      .run();
    await tick(env);
    expect((await manifest(env, 'audit')).length).toBeGreaterThanOrEqual(7);
    expect(await backupStatus(env)).toMatchObject({ lastError: null, downloadAvailable: true, archiveError: null });
    expect((await env.BACKUPS.list({ prefix: 'vault/' })).objects.length).toBe(1);
  });

  it('counts every migratable table in bytes', async () => {
    const env = await instance();
    // 3.3 MB of Chinese text in credential versions (3 bytes a character) and 6.2 MB of fresh audit rows:
    // over the 9 MB limit only when the versions are counted, and counted in bytes. (SQLite's printf
    // repeats a character at most 100000 times.)
    await env.DB.prepare(
      "INSERT INTO secret_versions (id,secret_id,version,envelope_json,created_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<11) SELECT 'v'||i,'s',i,replace(printf('%.*c',100000,'x'),'x','中'),0 FROM n",
    ).run();
    await fillAudit(env, 6000, Date.now() - MINUTE, 1000);
    // The console warns from the part sealing never moves out: the versions, not the audit rows.
    const { unsealedBytes } = await backupStatus(env);
    expect(unsealedBytes).toBeGreaterThan(3_300_000);
    expect(unsealedBytes).toBeLessThan(3_400_000);
    await expect(tick(env)).rejects.toMatchObject({ code: 'hot_data_over_limit' });
    await env.DB.prepare('DELETE FROM secret_versions').run();
    await tick(env);
    expect(await backupStatus(env)).toMatchObject({ lastError: null, downloadAvailable: true });
  });

  it('keeps its retention to vault/ and never touches archive/', async () => {
    const env = await instance();
    await fillAudit(env, 2000, Date.now() - HOUR, 1000);
    await sealColdData(env, OWNER);
    await env.BACKUPS.put('vault/old.age', 'old');
    await env.BACKUPS.put('vault/current.age', 'current');
    const sealed = await archived(env);
    expect(sealed.length).toBe(1);
    // Three years on, every object is past every retention period.
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      vi.setSystemTime(Date.now() + 3 * 365 * 24 * HOUR);
      expect(await pruneBackups(env, 'vault/current.age')).toBe(1);
    } finally {
      vi.useRealTimers();
    }
    expect((await env.BACKUPS.list()).objects.map((o) => o.key).sort()).toEqual(
      [...sealed, 'vault/current.age'].sort(),
    );
  });
});

describe('created_at of audit rows and access requests', () => {
  // Sealing relies on every row of these two tables being dated when it is written. These are the only
  // statements that write them; one more needs the same guarantee, then a place in this list. The one
  // exception is import.ts, whose inserts name their table as ${table}: it writes the rows of a snapshot
  // with the created_at they had, into an instance that has no other rows yet, together with the segments
  // they came with, and its commit refuses a row dated at or before its kind's last segment.
  it('is written only by the statements that take it from the clock at the INSERT', async () => {
    const found: string[] = [];
    for (const file of await readdir('apps/worker/src'))
      for (const [, verb, table, rest] of (await readFile(`apps/worker/src/${file}`, 'utf8')).matchAll(
        /(INSERT INTO|INSERT OR \w+ INTO|REPLACE INTO|UPDATE)\s+"?(audit_events|access_requests|\$\{table\})"?\s([^\n]*)/g,
      )) {
        found.push(`${file} ${verb} ${table}`);
        if (verb === 'UPDATE') expect(rest.match(/SET (.*?) WHERE/)![1]).not.toContain('created_at');
      }
    expect(found).toEqual([
      'context.ts INSERT INTO audit_events',
      'import.ts INSERT INTO ${table}',
      'import.ts INSERT INTO ${table}',
      'index.ts UPDATE access_requests',
      'index.ts UPDATE access_requests',
      'index.ts UPDATE access_requests',
      'vault.ts INSERT INTO access_requests',
      'vault.ts UPDATE access_requests',
    ]);
  });

  it('is the time of the write', async () => {
    const env = await instance();
    await env.DB.prepare(
      'INSERT INTO connections (id,owner_id,name,origin,auth_json,policy_json,created_at,updated_at) VALUES (\'c\',?,\'c\',\'https://api.example.com\',\'{"type":"none"}\',\'{"paths":["/v1"],"methods":["GET"]}\',0,0)',
    )
      .bind(OWNER)
      .run();
    const agent: Principal = { clientId: 'client', userId: OWNER, scopes: ['access:request'] };
    const before = Date.now();
    await audit(env, 'client', 'secret:read', null);
    const { id } = await accessRequest(
      env,
      agent,
      { requested: { invocation: { connection: 'c', method: 'GET', path: '/v1/x' } }, reason: 'r' },
      'http://localhost:8787',
    );
    const after = Date.now();
    for (const at of [
      await value(env, "SELECT created_at FROM audit_events WHERE action='secret:read'"),
      await value(env, 'SELECT created_at FROM access_requests WHERE id=?', id),
    ]) {
      expect(at).toBeGreaterThanOrEqual(before);
      expect(at).toBeLessThanOrEqual(after);
    }
  });
});
