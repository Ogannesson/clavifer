import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { applyMigrations } from '../scripts/migrations.mjs';
import { grantStatements } from '../apps/worker/src/index';
import { metadata, readSecret } from '../apps/worker/src/vault';
import { encryptSecret, parseRootKeys } from '../packages/core/crypto';
import { type Bindings, type Principal } from '../apps/worker/src/context';

// Real D1 so the upsert, its CASE expression and the stored field subset are exercised as deployed.
const rootKey = `1:${Buffer.from('g'.repeat(32)).toString('base64url')}`;
const owner = 'owner',
  client = 'client',
  secret = 'secret';
const principal: Principal = { userId: owner, clientId: client, scopes: ['metadata:list', 'secret:read'] };
let mf: Miniflare, env: Bindings;

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
  env = { DB: db, ROOT_KEY: rootKey } as unknown as Bindings;
  const envelope = await encryptSecret(
    parseRootKeys(rootKey),
    { ownerId: owner, secretId: secret, version: 1 },
    { token: 'synthetic-token', account: 'synthetic-account' },
  );
  await db.batch([
    db.prepare("INSERT INTO system_state (key,value,updated_at) VALUES ('owner_user_id',?,?)").bind(owner, Date.now()),
    db
      .prepare('INSERT INTO "oauthClient" (id,clientId,userId,name,redirectUris) VALUES (?,?,?,?,?)')
      .bind(client, client, owner, 'Installation', '[]'),
    db
      .prepare('INSERT INTO secrets (id,owner_id,name,current_version,created_at,updated_at) VALUES (?,?,?,1,?,?)')
      .bind(secret, owner, 'Synthetic', Date.now(), Date.now()),
    db
      .prepare('INSERT INTO secret_versions (id,secret_id,version,envelope_json,created_at) VALUES (?,?,1,?,?)')
      .bind('version', secret, JSON.stringify(envelope), Date.now()),
  ]);
});
afterAll(() => mf.dispose());
beforeEach(async () => {
  await env.DB.batch([env.DB.prepare('DELETE FROM grants'), env.DB.prepare('DELETE FROM access_requests')]);
});

const grant = async (expiresAt: number | null, fields?: string[]) =>
  env.DB.batch(
    await grantStatements(
      env,
      owner,
      client,
      [{ resourceType: 'secret', resourceId: secret, permission: 'secret:read', ...(fields ? { fields } : {}) }],
      expiresAt,
    ),
  );
// The approval path carries grants the client itself wrote into its pending request.
const approve = async (fields?: string[], expiresAt: number | null = Date.now() + 86400000) => {
  const rid = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO access_requests (id,owner_id,client_id,requested_json,status,created_at,expires_at) VALUES (?,?,?,'{}','pending',?,?)",
  )
    .bind(rid, owner, client, Date.now(), Date.now() + 3600000)
    .run();
  return env.DB.batch(
    await grantStatements(
      env,
      owner,
      client,
      [{ resourceType: 'secret', resourceId: secret, permission: 'secret:read', ...(fields ? { fields } : {}) }],
      expiresAt,
      rid,
    ),
  );
};
const stored = () =>
  env.DB.prepare('SELECT status,expires_at,fields_json FROM grants').first<{
    status: string;
    expires_at: number | null;
    fields_json: string | null;
  }>();

describe('grant upsert reach', () => {
  it('keeps an unlimited grant when a 24 hour request is approved', async () => {
    await grant(null);
    await grant(Date.now() + 86400000);
    expect(await stored()).toMatchObject({ status: 'active', expires_at: null });
  });

  it('keeps the later of two limited expiries', async () => {
    const later = Date.now() + 2592000000;
    await grant(later);
    await grant(Date.now() + 86400000);
    expect((await stored())?.expires_at).toBe(later);
  });

  it('replaces an expired grant with the new expiry', async () => {
    await grant(Date.now() - 1000);
    const renewed = Date.now() + 86400000;
    await grant(renewed);
    expect(await stored()).toMatchObject({ status: 'active', expires_at: renewed });
  });

  it('makes a live limited grant permanent when a request is approved until revoked', async () => {
    await grant(Date.now() + 3600000);
    await approve(undefined, null);
    expect(await stored()).toMatchObject({ status: 'active', expires_at: null });
  });

  it('does not let a new grant inherit the expiry of a revoked one', async () => {
    await grant(null);
    await env.DB.prepare("UPDATE grants SET status='revoked'").run();
    const renewed = Date.now() + 86400000;
    await grant(renewed);
    expect(await stored()).toMatchObject({ status: 'active', expires_at: renewed });
  });
});

describe('secret field subsets', () => {
  it('returns only the granted fields and advertises them in metadata', async () => {
    await grant(null, ['token']);
    expect(await readSecret(env, principal, secret)).toMatchObject({ values: { token: 'synthetic-token' } });
    expect((await metadata(env, principal)).items).toMatchObject([{ id: secret, fields: ['token'] }]);
  });

  it('rejects a field the grant does not cover and reports a field the credential lacks', async () => {
    await grant(null, ['token']);
    await expect(readSecret(env, principal, secret, ['account'])).rejects.toMatchObject({
      code: 'insufficient_scope',
      status: 403,
    });
    await grant(null);
    await expect(readSecret(env, principal, secret, ['absent'])).rejects.toMatchObject({
      code: 'secret_field_not_found',
      status: 404,
    });
    expect(await readSecret(env, principal, secret, ['account'])).toMatchObject({
      values: { account: 'synthetic-account' },
    });
  });

  it('takes the latest field subset the Owner specified in the administration form', async () => {
    await grant(null, ['token']);
    await grant(null, ['token', 'account']);
    expect(JSON.parse((await stored())!.fields_json!)).toEqual(['token', 'account']);
    await grant(null);
    expect((await stored())?.fields_json).toBeNull();
  });

  it.each([
    ['a wider request', ['token', 'account']],
    ['a request for every field', undefined],
  ])(
    'refuses to approve %s against a live grant instead of silently keeping the old subset',
    async (_label, fields) => {
      await grant(null, ['token']);
      await expect(approve(fields as string[] | undefined)).rejects.toMatchObject({
        code: 'existing_grant_conflict',
        status: 409,
      });
      expect(await stored()).toMatchObject({ status: 'active', expires_at: null });
      expect(JSON.parse((await stored())!.fields_json!)).toEqual(['token']);
      await expect(readSecret(env, principal, secret, ['account'])).rejects.toMatchObject({
        code: 'insufficient_scope',
        status: 403,
      });
    },
  );

  it('approves a request that matches the live subset in any order', async () => {
    await grant(null, ['token', 'account']);
    await approve(['account', 'token']);
    expect(JSON.parse((await stored())!.fields_json!)).toEqual(['token', 'account']);
  });

  it('applies the requested fields when the existing grant is revoked or expired', async () => {
    await grant(null, ['token', 'account']);
    await env.DB.prepare("UPDATE grants SET status='revoked'").run();
    await approve(['token']);
    expect(JSON.parse((await stored())!.fields_json!)).toEqual(['token']);
    await env.DB.prepare('UPDATE grants SET expires_at=?')
      .bind(Date.now() - 1000)
      .run();
    await approve(['account']);
    const row = await stored();
    expect(JSON.parse(row!.fields_json!)).toEqual(['account']);
    expect(row!.expires_at).toBeGreaterThan(Date.now());
    expect(await readSecret(env, principal, secret, ['account'])).toMatchObject({
      values: { account: 'synthetic-account' },
    });
  });
});
