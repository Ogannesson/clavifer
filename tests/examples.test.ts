import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { applyMigrations } from '../scripts/migrations.mjs';
import { issueSql, newToken } from '../scripts/bootstrap-token.mjs';
import worker from '../apps/worker/src/index';
import { handleMcp } from '../apps/worker/src/mcp';
import { targetUrl } from '../packages/core/proxy';
import {
  authEndpoints,
  boundSecret,
  decide,
  policyJson,
  requestInput,
  type ConnectionPolicy,
} from '../apps/worker/src/vault';
import { type Bindings, type Principal } from '../apps/worker/src/context';

const example = JSON.parse(readFileSync('docs/examples/gcp.setup.json', 'utf8'));

// docs/examples/gcp.setup.json is a requested.setup draft for users and agents to copy. Submitting it
// checks it as below and runs its tests with decide(), so a draft that passes here is not refused with
// tests_failed, and a change to what the rules mean shows up here first.
describe('the GCP setup example', () => {
  const setup = requestInput.parse({ requested: { setup: example }, reason: 'GCP' }).requested.setup!;

  for (const c of setup.connections)
    it(`${c.name} decides its tests as written`, () => {
      targetUrl(c.origin, '/');
      authEndpoints(c.auth, false);
      const policy = JSON.parse(policyJson(c)) as Required<ConnectionPolicy>;
      const failed = c.tests.flatMap((t) => {
        const { code } = decide(policy, t.method, t.path, t.grant ? [] : null);
        return code === t.expect ? [] : [`${t.method} ${t.path} grant=${t.grant}: expected ${t.expect}, got ${code}`];
      });
      expect(failed).toEqual([]);
    });
});

// The same file through the real routes, on real D1: an installation submits it over MCP, the Owner
// approves it with a service account key as Google issues one (a test RSA key, fictional names), and the
// installation calls a connection. Google's token endpoint is a stub that checks the assertion's
// signature with the key's public half, as Google does, and answers a made-up token.
describe('the GCP setup example, submitted and approved', () => {
  const origin = 'http://localhost:8787';
  const googleToken = 'https://oauth2.googleapis.com/token';
  const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
  const privateKey = readFileSync('tests/fixtures/keys/rsa-pkcs8.pem', 'utf8');
  const values = {
    client_email: 'clavifer-example@example.com',
    private_key: privateKey,
    private_key_id: randomBytes(20).toString('hex'),
  };
  const accessToken = 'ya29.synthetic-access-token';
  let mf: Miniflare,
    env: Bindings,
    cookie = '',
    agent: Principal;

  type Sent = { url: string; headers: Headers; body: string };
  const sent: { token: Sent[]; upstream: Sent[] } = { token: [], upstream: [] };
  // What the stubbed endpoint found wrong with an assertion; empty when it took every one.
  const refusals: string[] = [];
  const decode = (part: string) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  function tokenEndpoint(request: Sent) {
    const body = new URLSearchParams(request.body);
    const [header, payload, signature] = (body.get('assertion') ?? '').split('.');
    const claims = decode(payload);
    const wrong = [
      body.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:jwt-bearer' && 'grant_type',
      !verify(
        'RSA-SHA256',
        Buffer.from(`${header}.${payload}`),
        createPublicKey(privateKey),
        Buffer.from(signature, 'base64url'),
      ) && 'signature',
      decode(header).alg !== 'RS256' && 'alg',
      decode(header).kid !== values.private_key_id && 'kid',
      claims.iss !== values.client_email && 'iss',
      claims.aud !== googleToken && 'aud',
      claims.scope !== 'https://www.googleapis.com/auth/cloud-platform' && 'scope',
      claims.exp - claims.iat !== 3600 && 'lifetime',
    ].filter((x): x is string => !!x);
    refusals.push(...wrong);
    return wrong.length
      ? Response.json({ error: 'invalid_grant', error_description: 'Invalid JWT Signature.' }, { status: 400 })
      : Response.json({ access_token: accessToken, expires_in: 3599, token_type: 'Bearer' });
  }
  const stub = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const request = { url: String(input), headers: new Headers(init?.headers), body: String(init?.body ?? '') };
    if (request.url === googleToken) {
      sent.token.push(request);
      return tokenEndpoint(request);
    }
    sent.upstream.push(request);
    return Response.json({ accounts: [] });
  });

  async function call(path: string, method = 'GET', body?: unknown) {
    const response = await worker.fetch(
      new Request(origin + path, {
        method,
        headers: {
          'cf-connecting-ip': '127.0.0.1',
          origin,
          cookie,
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      }),
      env,
      context,
    );
    const text = await response.text();
    return { status: response.status, body: text ? (JSON.parse(text) as Record<string, any>) : {} };
  }
  // One tools/call through the real MCP handler, as the installation makes it.
  async function tool(name: string, args: object) {
    const response = await handleMcp(
      new Request(`${origin}/v1/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
      }),
      env,
      agent,
    );
    const message = (await response.json()) as { result: { isError?: boolean; content: { text: string }[] } };
    return { isError: !!message.result.isError, ...JSON.parse(message.result.content[0].text) };
  }
  const rows = async (sql: string, ...binds: unknown[]) =>
    (
      await env.DB.prepare(sql)
        .bind(...binds)
        .all<Record<string, any>>()
    ).results;

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
      ROOT_KEY: `1:${Buffer.from('g'.repeat(32)).toString('base64url')}`,
    } as unknown as Bindings;
    const { token, binds } = newToken();
    await db
      .prepare(issueSql)
      .bind(...binds)
      .run();
    const setup = await worker.fetch(
      new Request(origin + '/api/setup/owner', {
        method: 'POST',
        headers: {
          origin,
          'cf-connecting-ip': '127.0.0.1',
          'content-type': 'application/json',
          'x-bootstrap-token': token,
        },
        body: JSON.stringify({
          name: 'Owner',
          email: 'owner@example.com',
          password: 'synthetic-password-for-examples',
          backupRecipient: await identityToRecipient(await generateIdentity()),
        }),
      }),
      env,
      context,
    );
    expect(setup.status).toBe(201);
    cookie = setup.headers
      .getSetCookie()
      .map((value) => value.split(';')[0])
      .join('; ');
    const owner = await db
      .prepare("SELECT value FROM system_state WHERE key='owner_user_id'")
      .first<{ value: string }>();
    const installation = await call('/admin/clients', 'POST', { name: 'GCP agent' });
    agent = {
      userId: owner!.value,
      clientId: String(installation.body.clientId),
      scopes: ['connection:invoke', 'access:request'],
    };
    vi.stubGlobal('fetch', stub);
  });
  afterAll(async () => {
    vi.unstubAllGlobals();
    await mf.dispose();
  });

  it('is accepted, creates the credential and all 20 connections, and gets one token for all of them', async () => {
    const submitted = await tool('access.request', {
      requested: { setup: example },
      reason: 'Read the GCP project example-project',
    });
    expect(submitted).toMatchObject({ isError: false, id: expect.any(String) });
    const rid = submitted.id as string;
    const [{ requested_json }] = await rows('SELECT requested_json FROM access_requests WHERE id=?', rid);
    const { secretId, connectionIds } = JSON.parse(requested_json).ids as { secretId: string; connectionIds: string[] };
    expect(connectionIds).toHaveLength(20);

    expect(await call(`/admin/access-requests/${rid}/approve`, 'POST', { values })).toEqual({
      status: 200,
      body: { ok: true },
    });
    expect(refusals).toEqual([]);
    expect(await boundSecret(env, agent.userId, secretId)).toEqual({ version: 1, values });
    const created = await rows(
      `SELECT id,origin,auth_json FROM connections WHERE status='active' AND id IN (${connectionIds.map(() => '?').join(',')})`,
      ...connectionIds,
    );
    expect(created.map((c) => [c.id, c.origin]).sort()).toEqual(
      connectionIds.map((id, i) => [id, example.connections[i].origin]).sort(),
    );
    expect(created.every((c) => JSON.parse(c.auth_json).secretId === secretId)).toBe(true);
    // The connections are configured alike: one try at approval, and one cached token they share.
    expect(sent.token).toHaveLength(1);
    expect(await rows('SELECT version FROM token_cache WHERE secret_id=?', secretId)).toEqual([{ version: 1 }]);

    expect(
      (
        await call('/admin/grants', 'POST', {
          clientId: agent.clientId,
          grants: [{ resourceType: 'connection', resourceId: connectionIds[0], permission: 'connection:invoke' }],
        })
      ).status,
    ).toBe(200);
    expect(
      await tool('http.request', {
        connection: connectionIds[0],
        method: 'GET',
        path: '/v1/projects/example-project/serviceAccounts',
      }),
    ).toMatchObject({ isError: false, status: 200, body: '{"accounts":[]}' });
    expect(sent.upstream.map((r) => [r.url, r.headers.get('authorization')])).toEqual([
      ['https://iam.googleapis.com/v1/projects/example-project/serviceAccounts', `Bearer ${accessToken}`],
    ]);
    expect(sent.token).toHaveLength(1);

    // A deny rule holds whatever the grant.
    expect(
      await tool('http.request', {
        connection: connectionIds[0],
        method: 'POST',
        path: '/v1/projects/example-project/serviceAccounts/123456789012345678901/keys',
      }),
    ).toMatchObject({
      isError: true,
      error: 'path_denied',
      hint: expect.stringContaining('POST /v1/projects/{p}/serviceAccounts/{sa}/keys'),
    });
    expect(sent.upstream).toHaveLength(1);
    expect(sent.token).toHaveLength(1);
  });
});
