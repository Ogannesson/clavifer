import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { applyMigrations } from '../scripts/migrations.mjs';
import worker from '../apps/worker/src/index';
import { type Bindings, VERSION, createAuth } from '../apps/worker/src/context';
import { deriveKey, encode, parseRootKeys, rootKeyFingerprints } from '../packages/core/crypto';

// Real D1 and the real routes. A match is cached for the isolate, which is this module, so the cases
// run in order: uninitialized, each kind of mismatch, then a match.
const origin = 'http://localhost:8787';
const entry = (id: number, byte: string) => `${id}:${Buffer.from(byte.repeat(32)).toString('base64url')}`;
const current = entry(1, 'k'),
  older = entry(2, 'o');
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let mf: Miniflare, env: Bindings;

const fingerprint = async (rootKey: string) => Object.values(await rootKeyFingerprints(parseRootKeys(rootKey)))[0];
async function call(path: string, rootKey = current) {
  const response = await worker.fetch(
    new Request(origin + path, { headers: { origin } }),
    { ...env, ROOT_KEY: rootKey },
    context,
  );
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}
const record = (fingerprints: Record<string, string>) =>
  env.DB.prepare(
    "INSERT INTO system_state (key,value,updated_at) VALUES ('root_key_fingerprints',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
  )
    .bind(JSON.stringify(fingerprints), Date.now())
    .run();

beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default {fetch:()=>new Response("unused")}',
      compatibilityDate: '2026-09-11',
      compatibilityFlags: ['nodejs_compat'],
      log: new Log(LogLevel.ERROR),
      d1Databases: ['DB'],
    }),
  );
  const db = await mf.getD1Database('DB');
  await applyMigrations(db);
  env = { DB: db, APP_ORIGIN: origin, ALLOW_LOCAL_HTTP: 'true', ROOT_KEY: current } as unknown as Bindings;
});
afterAll(() => mf.dispose());

// Runs before the Owner exists, so createAuth builds a fresh instance instead of a cached one.
describe('Better Auth secrets', () => {
  it('derives one versioned secret per root key, the current key first', async () => {
    const ring = `${older},${current}`;
    const auth = await createAuth({ ...env, ROOT_KEY: ring });
    const config = (await auth.$context).secretConfig as { currentVersion: number; keys: Map<number, string> };
    expect(config.currentVersion).toBe(2);
    expect([...config.keys.keys()]).toEqual([2, 1]);
    for (const { id, key } of parseRootKeys(ring))
      expect(config.keys.get(Number(id))).toBe(encode(await deriveKey(key, 'better-auth')));
  });
});

describe('root key self-check', () => {
  it('lets an uninitialized instance through without caching that', async () => {
    expect(await call('/healthz')).toEqual({
      status: 200,
      body: { ok: true, service: 'clavifer', version: VERSION, keys: 'uninitialized', initialized: false },
    });
    // Another isolate creates the Owner; this one sees it on the next request.
    await env.DB.prepare("INSERT INTO system_state (key,value,updated_at) VALUES ('owner_user_id','owner',?)")
      .bind(Date.now())
      .run();
    expect((await call('/healthz')).body.keys).toBe('mismatch');
  });

  it.each([
    ['another key', async () => ({ 1: await fingerprint(older) }), current],
    [
      'a recorded key missing from the ring',
      async () => ({ 1: await fingerprint(current), 2: '0'.repeat(32) }),
      current,
    ],
    ['a current key that was never recorded', async () => ({ 1: await fingerprint(current) }), `${older},${current}`],
  ])('refuses everything but /healthz under %s', async (_name, recorded, ring) => {
    await record(await recorded());
    expect(await call('/healthz', ring)).toEqual({
      status: 200,
      body: { ok: false, service: 'clavifer', version: VERSION, keys: 'mismatch', initialized: true },
    });
    expect(await call('/admin/status', ring)).toMatchObject({ status: 503, body: { error: 'root_key_mismatch' } });
    expect(await call('/api/auth/get-session', ring)).toMatchObject({ status: 503 });
  });

  it('runs no scheduled work under a mismatched key', async () => {
    // With a recipient set, a backup run would at least take the lease and stamp attempt_at; with 2 MB
    // of audit an hour old, sealing would write a segment or record why it could not.
    await env.DB.prepare("UPDATE backup_state SET recipient='age1synthetic' WHERE id=1").run();
    await env.DB.prepare(
      "INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<2000) SELECT 'a'||i,'owner','client',printf('%.*c',1000,'x'),NULL,'ok','request',?+i FROM n",
    )
      .bind(Date.now() - 3600000)
      .run();
    await worker.scheduled({ scheduledTime: Date.now() } as ScheduledController, { ...env, ROOT_KEY: older });
    expect(await env.DB.prepare('SELECT attempt_at,archive_error FROM backup_state WHERE id=1').first()).toEqual({
      attempt_at: null,
      archive_error: null,
    });
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM archive_segments').first()).toEqual({ n: 0 });
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM audit_events').first()).toEqual({ n: 2000 });
    await env.DB.batch([
      env.DB.prepare('UPDATE backup_state SET recipient=NULL WHERE id=1'),
      env.DB.prepare('DELETE FROM audit_events'),
    ]);
  });

  it('accepts older keys of the ring and keeps a match for the isolate', async () => {
    await record({ 1: await fingerprint(current), 2: await fingerprint(older) });
    expect((await call('/healthz', `${current},${older}`)).body).toMatchObject({ ok: true, keys: 'ok' });
    await record({ 1: await fingerprint(older) });
    expect((await call('/healthz')).body).toMatchObject({ ok: true, keys: 'ok', initialized: true });
  });
});
