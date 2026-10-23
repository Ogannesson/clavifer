import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { generateHybridIdentity, identityToRecipient } from 'age-encryption';
import { applyMigrations } from '../scripts/migrations.mjs';
import { issueSql, issueToken, newToken } from '../scripts/bootstrap-token.mjs';
import worker from '../apps/worker/src/index';
import { type Bindings } from '../apps/worker/src/context';
import { deleteToken, tokenGuard } from '../apps/worker/src/setup';
import { decryptArchiveIdentity, digest, parseRootKeys, rootKeyFingerprints } from '../packages/core/crypto';

// Real D1 and the real routes. The Owner id is cached for the isolate, which is this module, so the
// routes run in order: create, then reset. The guard itself is tried on a database of its own.
const origin = 'http://localhost:8787';
const rootKey = `1:${Buffer.from('i'.repeat(32)).toString('base64url')}`;
const password = 'synthetic-password-for-setup';
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let mf: Miniflare, env: Bindings, guardDb: D1Database, recipient: string;

async function call(path: string, body?: unknown, headers: Record<string, string> = {}) {
  const response = await worker.fetch(
    new Request(origin + path, {
      method: body ? 'POST' : 'GET',
      headers: {
        'cf-connecting-ip': '127.0.0.1',
        origin,
        ...(body ? { 'content-type': 'application/json' } : {}),
        ...headers,
      },
      body: body ? JSON.stringify(body) : undefined,
    }),
    env,
    context,
  );
  const text = await response.text();
  return {
    status: response.status,
    body: text ? (JSON.parse(text) as Record<string, unknown>) : {},
    cookie: response.headers
      .getSetCookie()
      .map((value) => value.split(';')[0])
      .join('; '),
  };
}
async function issue(db = env.DB) {
  const { token, binds } = newToken();
  await db
    .prepare(issueSql)
    .bind(...binds)
    .run();
  return token;
}
const rows = (sql: string, ...args: unknown[]) =>
  env.DB.prepare(sql)
    .bind(...args)
    .all()
    .then((r) => r.results as Record<string, unknown>[]);
// Each sign-in from another address, past the library's limit of three a client per ten seconds.
let signIns = 0;
const signIn = (pass: string) =>
  call(
    '/api/auth/sign-in/email',
    { email: 'owner@example.com', password: pass },
    { 'cf-connecting-ip': `127.0.1.${++signIns}` },
  );
const owner = (token: string, name = 'Owner') =>
  call(
    '/api/setup/owner',
    { name, email: 'Owner@Example.com', password, backupRecipient: recipient },
    { 'x-bootstrap-token': token },
  );

beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default {fetch:()=>new Response("unused")}',
      compatibilityDate: '2026-09-11',
      compatibilityFlags: ['nodejs_compat'],
      log: new Log(LogLevel.ERROR),
      d1Databases: ['DB', 'GUARD'],
    }),
  );
  const db = await mf.getD1Database('DB');
  guardDb = await mf.getD1Database('GUARD');
  await applyMigrations(db);
  await applyMigrations(guardDb);
  env = { DB: db, APP_ORIGIN: origin, ALLOW_LOCAL_HTTP: 'true', ROOT_KEY: rootKey } as unknown as Bindings;
  // A post-quantum recipient (age1pq1…, about 1960 characters), the longest kind there is.
  recipient = await identityToRecipient(await generateHybridIdentity());
});
afterAll(() => mf.dispose());

describe('bootstrap token', () => {
  const g = () => ({ DB: guardDb }) as unknown as Bindings;
  const initialize = (on: boolean) =>
    guardDb
      .prepare(
        on
          ? "INSERT OR IGNORE INTO system_state (key,value,updated_at) VALUES ('owner_user_id','owner',0)"
          : "DELETE FROM system_state WHERE key='owner_user_id'",
      )
      .run();
  const marker = (name: string) =>
    guardDb.prepare("INSERT INTO system_state (key,value,updated_at) VALUES (?,'written',0)").bind(name);
  const written = async (name: string) =>
    !!(await guardDb.prepare('SELECT 1 FROM system_state WHERE key=?').bind(name).first());
  const tokenRow = () =>
    guardDb.prepare("SELECT value FROM system_state WHERE key='bootstrap_token'").first<{ value: string }>();
  const spendWith = async (token: string, initialized: boolean, name: string) =>
    guardDb.batch([tokenGuard(g(), await digest(token), initialized), marker(name), deleteToken(g())]).then(
      () => true,
      () => false,
    );

  it('lasts 24 hours on an uninitialized instance and 1 hour on an initialized one, by D1 clock', async () => {
    await initialize(false);
    await issue(guardDb);
    const first = JSON.parse((await tokenRow())!.value);
    expect(first.expiresAt - Date.now()).toBeGreaterThan(86_400_000 - 5000);
    expect(first.expiresAt - Date.now()).toBeLessThanOrEqual(86_400_000);
    await initialize(true);
    await issue(guardDb);
    const second = JSON.parse((await tokenRow())!.value);
    expect(second.expiresAt - Date.now()).toBeGreaterThan(3_600_000 - 5000);
    expect(second.expiresAt - Date.now()).toBeLessThanOrEqual(3_600_000);
    // Issuing again replaced the first token.
    expect(second.hash).not.toBe(first.hash);
    expect(await guardDb.prepare("SELECT COUNT(*) AS n FROM system_state WHERE key='bootstrap_token'").first()).toEqual(
      { n: 1 },
    );
  });

  it('rolls the whole batch back for a wrong token, an expired one, a spent one and the wrong state', async () => {
    await initialize(false);
    const token = await issue(guardDb);
    expect(await spendWith(newToken().token, false, 'wrong')).toBe(false);
    expect(await spendWith(token, true, 'state')).toBe(false);
    await guardDb
      .prepare("UPDATE system_state SET value=json_set(value,'$.expiresAt',?) WHERE key='bootstrap_token'")
      .bind(Date.now() - 1)
      .run();
    expect(await spendWith(token, false, 'expired')).toBe(false);
    for (const name of ['wrong', 'state', 'expired']) expect(await written(name)).toBe(false);
    // The refused attempts left the token as it was.
    expect(await tokenRow()).not.toBeNull();

    const fresh = await issue(guardDb);
    expect(await spendWith(fresh, false, 'once')).toBe(true);
    expect(await written('once')).toBe(true);
    expect(await spendWith(fresh, false, 'twice')).toBe(false);
    expect(await written('twice')).toBe(false);
    expect(await tokenRow()).toBeNull();
    expect(await guardDb.prepare("SELECT 1 FROM system_state WHERE key='token_spent'").first()).toBeNull();

    await initialize(true);
    const recovery = await issue(guardDb);
    expect(await spendWith(recovery, false, 'create-with-recovery')).toBe(false);
    expect(await spendWith(recovery, true, 'recover')).toBe(true);
  });

  it('lets only one of two concurrent batches spend a token', async () => {
    await initialize(false);
    const token = await issue(guardDb);
    const results = await Promise.all([spendWith(token, false, 'a'), spendWith(token, false, 'b')]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect([await written('a'), await written('b')].filter(Boolean)).toHaveLength(1);
  });

  it('writes the token to a new file and returns only the path and the statement', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'clavifer-token-'));
    try {
      const path = join(dir, 'setup.token');
      const issued = await issueToken(path);
      const token = await readFile(path, 'utf8');
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(issued).toEqual({ path, sql: issueSql, binds: [await digest(token)] });
      expect(JSON.stringify(issued)).not.toContain(token);
      if (process.platform !== 'win32') expect((await stat(path)).mode & 0o777).toBe(0o600);
      await expect(issueToken(path)).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('create the Owner', () => {
  it('starts from an empty instance, whatever an earlier attempt left', async () => {
    // A row in every table and setting, as an interrupted initialization might leave them.
    const tables = (await rows(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\' AND name NOT IN ('d1_migrations','sqlite_sequence','system_state','backup_state')",
    )) as { name: string }[];
    expect(tables.length).toBeGreaterThan(20);
    // How to find the stale row again: by its id, or by its first text column where it has no id.
    const stale: Record<string, string> = {};
    for (const { name } of tables) {
      const columns = (await rows(`SELECT name,type,"notnull",pk FROM pragma_table_info('${name}')`)) as {
        name: string;
        type: string;
        notnull: number;
        pk: number;
      }[];
      const filled = columns.filter((c) => c.notnull || c.pk);
      const text = filled.find((c) => c.name === 'id') ?? filled.find((c) => c.type === 'TEXT')!;
      stale[name] = `"${text.name}"='${text.name === 'id' ? 'stale' : `stale-${text.name}`}'`;
      await env.DB.prepare(
        `INSERT INTO "${name}" (${filled.map((c) => `"${c.name}"`).join(',')}) VALUES (${filled.map(() => '?').join(',')})`,
      )
        .bind(...filled.map((c) => (c.name === 'id' ? 'stale' : c.type === 'TEXT' ? `stale-${c.name}` : 0)))
        .run();
    }
    await env.DB.prepare(
      "INSERT INTO system_state (key,value,updated_at) VALUES ('import_id','stale',0),('archive_identity','stale',0)",
    ).run();
    await env.DB.prepare("UPDATE backup_state SET recipient='age1stale',object_key='vault/stale',revision=99").run();

    const token = await issue();
    // Without the token the page learns nothing; with it, which form to show.
    expect(await call('/api/setup/token', {}, { 'x-bootstrap-token': newToken().token })).toMatchObject({
      status: 401,
      body: { error: 'invalid_bootstrap_token' },
    });
    expect((await call('/api/setup/token', {}, { 'x-bootstrap-token': token })).body).toEqual({ initialized: false });
    expect((await call('/api/setup/token', {}, { 'x-bootstrap-token': token, origin: '' })).status).toBe(403);
    // A setup token resets nothing.
    expect(await call('/api/setup/password', { password }, { 'x-bootstrap-token': token })).toMatchObject({
      status: 409,
      body: { error: 'not_initialized' },
    });
    expect(
      (
        await call(
          '/api/setup/owner',
          { name: 'Owner', email: 'owner@example.com', password, backupRecipient: 'AGE-SECRET-KEY-1NOTARECIPIENT' },
          { 'x-bootstrap-token': token },
        )
      ).body.error,
    ).toBe('invalid_backup_recipient');

    // Two requests with the one token: exactly one creates an Owner.
    const [a, b] = await Promise.all([owner(token, 'A'), owner(token, 'B')]);
    expect([a.status, b.status].sort()).toEqual([201, 401]);
    const created = a.status === 201 ? a : b;
    expect(created.cookie).toContain('session_token');

    const users = await rows('SELECT id,email,name,emailVerified FROM "user"');
    expect(users).toEqual([
      { id: expect.any(String), email: 'owner@example.com', name: created === a ? 'A' : 'B', emailVerified: 0 },
    ]);
    const uid = String(users[0].id);
    for (const { name } of tables) expect(await rows(`SELECT 1 FROM "${name}" WHERE ${stale[name]}`), name).toEqual([]);
    expect(await rows('SELECT accountId,providerId,userId FROM account')).toEqual([
      { accountId: uid, providerId: 'credential', userId: uid },
    ]);
    const state = Object.fromEntries(
      (await rows('SELECT key,value FROM system_state')).map((r) => [r.key, String(r.value)]),
    );
    expect(Object.keys(state).sort()).toEqual(['archive_identity', 'owner_user_id', 'root_key_fingerprints']);
    expect(state.owner_user_id).toBe(uid);
    expect(JSON.parse(state.root_key_fingerprints)).toEqual(await rootKeyFingerprints(parseRootKeys(rootKey)));
    const identity = await decryptArchiveIdentity(parseRootKeys(rootKey), uid, JSON.parse(state.archive_identity));
    expect(identity).toMatch(/^AGE-SECRET-KEY-PQ-1[0-9A-Z]+$/);
    // The row the migration created, counted up once by the owner:create audit row.
    expect(await rows('SELECT recipient,object_key,revision FROM backup_state')).toEqual([
      { recipient, object_key: null, revision: 2 },
    ]);
    expect(await rows('SELECT owner_id,client_id,action,resource_id,result FROM audit_events')).toEqual([
      { owner_id: uid, client_id: 'owner', action: 'owner:create', resource_id: uid, result: 'ok' },
    ]);
    expect((await call('/healthz')).body).toMatchObject({ ok: true, keys: 'ok', initialized: true });
    // The cookie from setup is a session of the Owner.
    expect((await call('/api/auth/get-session', undefined, { cookie: created.cookie })).body.user).toMatchObject({
      id: uid,
    });
    // The token is spent.
    expect((await owner(token)).status).toBe(401);
  });

  it('closes the routes that would write installations behind /admin/clients', async () => {
    const { cookie } = await signIn(password);
    for (const route of ['create-client', 'update-client', 'delete-client'])
      expect(await call(`/api/auth/oauth2/${route}`, { client_id: 'x' }, { cookie })).toMatchObject({
        status: 403,
        body: { error: 'endpoint_disabled' },
      });
  });

  it('takes a post-quantum backup recipient in the backup settings as well', async () => {
    const { cookie } = await signIn(password);
    const other = await identityToRecipient(await generateHybridIdentity());
    const response = await worker.fetch(
      new Request(origin + '/admin/backup/config', {
        method: 'PUT',
        headers: { origin, cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ recipient: other }),
      }),
      env,
      context,
    );
    expect(response.status).toBe(200);
    expect(await rows('SELECT recipient FROM backup_state')).toEqual([{ recipient: other }]);
  });
});

describe('reset the Owner login', () => {
  it('changes the password and drops Passkeys and sessions, nothing else', async () => {
    const [{ value: uid }] = (await rows("SELECT value FROM system_state WHERE key='owner_user_id'")) as {
      value: string;
    }[];
    const now = Date.now();
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO passkey (id,publicKey,userId,credentialID,counter,deviceType,backedUp) VALUES ('pk',?,?,'cred',0,'singleDevice',0)",
      ).bind('AQID', uid),
      env.DB.prepare(
        "INSERT INTO oauthClient (id,clientId,userId,redirectUris,disabled) VALUES ('c','installation',?,'[]',0)",
      ).bind(uid),
      env.DB.prepare(
        "INSERT INTO oauthRefreshToken (id,token,clientId,userId,scopes,expiresAt) VALUES ('r','hashed','installation',?,'[]',?)",
      ).bind(uid, now + 86_400_000),
      env.DB.prepare(
        "INSERT INTO grants (id,owner_id,client_id,resource_type,resource_id,permission,created_at) VALUES ('g',?,'installation','secret','s','secret:read',?)",
      ).bind(uid, now),
    ]);
    const { cookie } = await signIn(password);
    const sessions = await rows('SELECT id FROM session');
    expect(sessions.length).toBeGreaterThan(0);

    const token = await issue();
    expect(await call('/api/setup/token', {}, { 'x-bootstrap-token': newToken().token })).toMatchObject({
      status: 401,
      body: { error: 'invalid_bootstrap_token' },
    });
    expect((await call('/api/setup/token', {}, { 'x-bootstrap-token': token })).body).toEqual({
      initialized: true,
      email: 'owner@example.com',
    });
    // A recovery token creates no Owner.
    expect((await owner(token)).body.error).toBe('already_initialized');
    expect((await call('/api/setup/password', { password: 'short' }, { 'x-bootstrap-token': token })).status).toBe(400);

    const changed = 'synthetic-new-password-for-setup';
    expect(await call('/api/setup/password', { password: changed }, { 'x-bootstrap-token': token })).toMatchObject({
      status: 200,
    });
    expect(await rows('SELECT id FROM passkey')).toEqual([]);
    expect(await rows('SELECT id FROM session')).toEqual([]);
    expect(await call('/admin/status', undefined, { cookie })).toMatchObject({ status: 401 });
    expect(await rows('SELECT clientId,disabled FROM oauthClient')).toEqual([
      { clientId: 'installation', disabled: 0 },
    ]);
    expect(await rows('SELECT id,revoked FROM oauthRefreshToken')).toEqual([{ id: 'r', revoked: null }]);
    expect(await rows("SELECT status FROM grants WHERE id='g'")).toEqual([{ status: 'active' }]);
    expect(await rows("SELECT owner_id,client_id,resource_id FROM audit_events WHERE action='owner:recover'")).toEqual([
      { owner_id: uid, client_id: 'owner', resource_id: uid },
    ]);
    expect((await signIn(password)).status).toBe(401);
    expect((await signIn(changed)).status).toBe(200);
    // Spent, and an expired one gives away no email either.
    expect((await call('/api/setup/password', { password }, { 'x-bootstrap-token': token })).status).toBe(401);
    const expired = await issue();
    await env.DB.prepare("UPDATE system_state SET value=json_set(value,'$.expiresAt',?) WHERE key='bootstrap_token'")
      .bind(Date.now() - 1)
      .run();
    expect(await call('/api/setup/token', {}, { 'x-bootstrap-token': expired })).toMatchObject({
      status: 401,
      body: { error: 'invalid_bootstrap_token' },
    });
  });
});
