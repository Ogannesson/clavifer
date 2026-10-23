import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { applyMigrations } from '../scripts/migrations.mjs';
import { issueSql, newToken } from '../scripts/bootstrap-token.mjs';
import worker from '../apps/worker/src/index';
import { type Bindings } from '../apps/worker/src/context';

// Real D1 and the real routes, so deletion is observed through the same transaction the Worker runs.
const origin = 'http://localhost:8787';
const password = 'synthetic-password-for-tests';
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let mf: Miniflare,
  env: Bindings,
  cookie = '';

async function call(path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) {
  const response = await worker.fetch(
    new Request(origin + path, {
      method,
      headers: {
        'cf-connecting-ip': '127.0.0.1',
        origin,
        cookie,
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
    headers: response.headers,
  };
}
const versions = async (sid: string) =>
  (await env.DB.prepare('SELECT COUNT(*) AS n FROM secret_versions WHERE secret_id=?')
    .bind(sid)
    .first<{ n: number }>())!.n;

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
  env = {
    DB: db,
    APP_ORIGIN: origin,
    ALLOW_LOCAL_HTTP: 'true',
    ROOT_KEY: `1:${Buffer.from('s'.repeat(32)).toString('base64url')}`,
  } as unknown as Bindings;
  const { token, binds } = newToken();
  await db
    .prepare(issueSql)
    .bind(...binds)
    .run();
  const setup = await call(
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
});
afterAll(() => mf.dispose());

describe('secret deletion', () => {
  it('removes the ciphertext of a deleted credential', async () => {
    const sid = String(
      (await call('/admin/secrets', 'POST', { name: 'Disposable', values: { token: 'synthetic-secret-value' } })).body
        .id,
    );
    await call(`/admin/secrets/${sid}`, 'PUT', {
      name: 'Disposable',
      values: { token: 'rotated-value' },
      expectedVersion: 1,
    });
    expect(await versions(sid)).toBe(2);
    expect((await call(`/admin/secrets/${sid}`, 'DELETE')).status).toBe(200);
    expect(await versions(sid)).toBe(0);
    const row = await env.DB.prepare('SELECT status FROM secrets WHERE id=?').bind(sid).first<{ status: string }>();
    expect(row?.status).toBe('deleted');
    expect((await call(`/admin/secrets/${sid}`, 'DELETE')).status).toBe(200);
  });

  it('keeps the ciphertext when a connection still binds the credential', async () => {
    const sid = String(
      (await call('/admin/secrets', 'POST', { name: 'Bound', values: { token: 'synthetic-bound-value' } })).body.id,
    );
    await call('/admin/connections', 'POST', {
      name: 'Bound upstream',
      origin: 'https://api.example.com',
      paths: ['/v1'],
      methods: ['GET'],
      auth: { type: 'bearer', secretId: sid, field: 'token' },
    });
    const refused = await call(`/admin/secrets/${sid}`, 'DELETE');
    expect(refused.status).toBe(409);
    expect(refused.body.error).toBe('secret_in_use');
    expect(await versions(sid)).toBe(1);
    expect(
      (await env.DB.prepare('SELECT status FROM secrets WHERE id=?').bind(sid).first<{ status: string }>())?.status,
    ).toBe('active');
  });

  it('saves and lists a connection description, bounded to 2000 characters', async () => {
    const connection = {
      name: 'Described upstream',
      origin: 'https://api.example.com',
      paths: ['/v1'],
      description: 'Send X-Account: synthetic on every request.',
    };
    const cid = String((await call('/admin/connections', 'POST', connection)).body.id);
    const listed = async () =>
      ((await call('/admin/status')).body.connections as { id: string; description: string }[]).find(
        (c) => c.id === cid,
      )?.description;
    expect(await listed()).toBe(connection.description);
    await call(`/admin/connections/${cid}`, 'PUT', { ...connection, description: 'Updated notes.' });
    expect(await listed()).toBe('Updated notes.');
    expect(
      (await call(`/admin/connections/${cid}`, 'PUT', { ...connection, description: 'x'.repeat(2001) })).status,
    ).toBe(400);
  });

  it('lists the field names of the current version without their values', async () => {
    const sid = String(
      (
        await call('/admin/secrets', 'POST', {
          name: 'Two fields',
          values: { username: 'synthetic-user', password: 'synthetic-password' },
        })
      ).body.id,
    );
    await call(`/admin/secrets/${sid}`, 'PUT', {
      name: 'Two fields',
      values: { region: 'synthetic-region' },
      expectedVersion: 1,
    });
    const status = await call('/admin/status');
    const listed = (status.body.secrets as { id: string; fields: string[] }[]).find((s) => s.id === sid);
    expect(listed?.fields.sort()).toEqual(['password', 'region', 'username']);
    expect(JSON.stringify(status.body)).not.toContain('synthetic-password');
  });
});
