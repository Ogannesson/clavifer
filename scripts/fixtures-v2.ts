// Writes the v2 sample files in tests/fixtures/v2 (see its README): an automatic backup and a full export
// of one synthetic instance whose connections use every kind of authentication, by the Worker's own code
// on miniflare, encrypted to the test identity of tests/fixtures/v1. The token endpoints the connections
// name are answered here, in place of fetch, so that saving a connection runs its test as it does live.
// Run: npx tsx scripts/fixtures-v2.ts. It never overwrites a file; the samples may be regenerated, by
// deleting them first, only until the release that freezes them, and tests/snapshot.test.ts pins their
// SHA-256 then.
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions, Log, LogLevel } from 'miniflare';
import { identityToRecipient } from 'age-encryption';
import { applyMigrations } from './migrations.mjs';
import { issueSql, newToken } from './bootstrap-token.mjs';
import worker from '../apps/worker/src/index';
import { type Bindings } from '../apps/worker/src/context';
import { runAutomaticBackup } from '../apps/worker/src/backup';

const directory = 'tests/fixtures/v2';
const origin = 'http://localhost:8787';
const endpoint = 'https://oauth.example.com';
const context = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
// A test value, recorded in the README like the test identity.
const password = 'synthetic-v2-fixture-password';
const recipient = await identityToRecipient((await readFile('tests/fixtures/v1/test-identity.txt', 'utf8')).trim());

// The token endpoint: a token for every grant, a new refresh token for the one that rotates, and no
// expires_in under /no-expiry, where the connection's ttl stands in.
const live = globalThis.fetch;
globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (url.origin !== endpoint) return live(input, init);
  const body = init?.body;
  const grant =
    body instanceof URLSearchParams ? Object.fromEntries(body) : (JSON.parse(String(body)) as Record<string, string>);
  return Response.json({
    access_token: `synthetic-access-${randomBytes(6).toString('hex')}`,
    token_type: 'Bearer',
    ...(url.pathname !== '/no-expiry' && { expires_in: 3600 }),
    ...(grant.refresh_token === 'synthetic-refresh-1' && { refresh_token: 'synthetic-refresh-2' }),
  });
};
const publicKeyEncoding = { type: 'spki', format: 'pem' } as const;
const rsaKey = () =>
  generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding,
  }).privateKey;
const ecKey = () =>
  generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    privateKeyEncoding: { type: 'sec1', format: 'pem' },
    publicKeyEncoding,
  }).privateKey;

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
  await applyMigrations(env.DB);
  const { token, binds } = newToken();
  await env.DB.prepare(issueSql)
    .bind(...binds)
    .run();
  const setup = await fetchWorker(
    '/api/setup/owner',
    'POST',
    { name: 'Owner', email: 'owner@example.com', password, backupRecipient: recipient },
    { 'x-bootstrap-token': token },
  );
  if (setup.status !== 201) throw new Error(`setup: ${setup.status} ${await setup.text()}`);
  cookie = setup.headers
    .getSetCookie()
    .map((value) => value.split(';')[0])
    .join('; ');
  const owner = (await env.DB.prepare('SELECT id FROM "user"').first<{ id: string }>())!.id;

  const secret = async (name: string, values: Record<string, string>) =>
    String((await call('/admin/secrets', 'POST', { name, values })).id);
  const connection = async (name: string, auth: Record<string, unknown>, more: Record<string, unknown> = {}) =>
    String(
      (
        await call('/admin/connections', 'POST', {
          name,
          origin: `https://${name.toLowerCase().replaceAll(' ', '-')}.example.com`,
          paths: ['/'],
          ...more,
          auth,
        })
      ).id,
    );
  const ref = ($field: string) => ({ $field });

  // The five kinds of v1.
  const plain = await secret('Static', { token: 'synthetic-token', username: 'user', password: 'pass' });
  await connection('None', { type: 'none' });
  await connection('Bearer', { type: 'bearer', secretId: plain, field: 'token' });
  await connection('Header', { type: 'header', secretId: plain, field: 'token', name: 'X-API-Key' });
  await connection('Basic', { type: 'basic', secretId: plain, usernameField: 'username', passwordField: 'password' });
  await connection('Query', { type: 'query', secretId: plain, field: 'token', name: 'api_key' });

  // A JWT signed for every request: RS256 with a kid from the secret, an object and an array claim and no
  // scheme; ES256 with a jti and a SEC1 key; HS256 with a hex key under the scheme "Ghost".
  const signing = await secret('Signing', {
    private_key: rsaKey(),
    key_id: 'synthetic-key-id',
    issuer: 'synthetic-issuer',
    ec_key: ecKey(),
  });
  await connection('Signed', {
    type: 'jwt',
    secretId: signing,
    jwt: {
      alg: 'RS256',
      keyField: 'private_key',
      header: { kid: ref('key_id'), typ: 'JWT' },
      claims: {
        iss: ref('issuer'),
        aud: 'synthetic-audience',
        video: { room: 'synthetic', roomJoin: true },
        scope: ['a', 'b'],
      },
      lifetime: 1200,
    },
    scheme: '',
  });
  await connection('Signed EC', {
    type: 'jwt',
    secretId: signing,
    jwt: {
      alg: 'ES256',
      keyField: 'ec_key',
      claims: { iss: ref('issuer'), aud: 'appstoreconnect-v1' },
      lifetime: 600,
      jti: true,
    },
  });
  const ghost = await secret('Ghost', { id: 'synthetic-ghost-id', key: 'a1b2c3d4e5f60718293a4b5c6d7e8f90' });
  await connection('Ghost', {
    type: 'jwt',
    secretId: ghost,
    jwt: {
      alg: 'HS256',
      keyField: 'key',
      keyEncoding: 'hex',
      header: { kid: ref('id') },
      claims: { aud: '/admin/' },
      lifetime: 300,
    },
    scheme: 'Ghost',
  });

  // client_credentials with each client authentication: Basic; the body with another grant name, extra
  // parameters and a JSON body; and a client assertion (PS256), with the token in a header of its own.
  const client = await secret('Client', {
    client_id: 'synthetic-client',
    client_secret: 'synthetic-client-secret',
    private_key: rsaKey(),
  });
  await connection('Client Basic', {
    type: 'oauth-client',
    secretId: client,
    client: { method: 'basic', id: ref('client_id'), secretField: 'client_secret' },
    tokenUrl: `${endpoint}/token`,
  });
  await connection('Client Post', {
    type: 'oauth-client',
    secretId: client,
    client: { method: 'post', id: 'synthetic-literal-client', secretField: 'client_secret' },
    grantType: 'account_credentials',
    params: { account_id: 'synthetic-account' },
    bodyFormat: 'json',
    tokenUrl: `${endpoint}/token`,
  });
  await connection('Client Assertion', {
    type: 'oauth-client',
    secretId: client,
    client: {
      method: 'jwt',
      id: ref('client_id'),
      jwt: {
        alg: 'PS256',
        keyField: 'private_key',
        claims: { iss: ref('client_id'), sub: ref('client_id'), aud: `${endpoint}/token` },
        lifetime: 300,
      },
    },
    scope: 'https://graph.example.com/.default',
    tokenUrl: `${endpoint}/token`,
    header: 'X-Shopify-Access-Token',
    scheme: '',
  });

  // A JWT bearer assertion: alone, with the rules of the new syntax; and with a client secret in the
  // body, a jti and a ttl for an endpoint without expires_in.
  const account = await secret('Service account', {
    client_email: 'synthetic@project.example.com',
    private_key: rsaKey(),
    private_key_id: 'synthetic-private-key-id',
    client_secret: 'synthetic-assertion-secret',
  });
  await connection(
    'Assertion',
    {
      type: 'oauth-jwt',
      secretId: account,
      jwt: {
        alg: 'RS256',
        keyField: 'private_key',
        header: { kid: ref('private_key_id') },
        claims: {
          iss: ref('client_email'),
          scope: 'https://www.googleapis.com/auth/cloud-platform',
          aud: `${endpoint}/token`,
        },
        lifetime: 3600,
      },
      tokenUrl: `${endpoint}/token`,
    },
    {
      methods: ['GET', 'HEAD'],
      deny: ['POST /v1/projects/{p}/serviceAccounts/{sa}/keys', '* /batch/*'],
      approval: ['* /**/{r}:setIamPolicy', 'PUT /storage/v1/b/**/iam'],
      free: ['GET /compute/{v}/projects/{p}/zones/{z}/instances/{}'],
    },
  );
  await connection('Assertion Post', {
    type: 'oauth-jwt',
    secretId: account,
    jwt: {
      alg: 'RS512',
      keyField: 'private_key',
      claims: { iss: ref('client_email'), box_sub_type: 'enterprise', aud: `${endpoint}/no-expiry` },
      lifetime: 60,
      jti: true,
    },
    client: { method: 'post', id: ref('client_email'), secretField: 'client_secret' },
    tokenUrl: `${endpoint}/no-expiry`,
    ttl: 3600,
  });

  // A refresh token: one the Owner signs in for, which the endpoint rotates when the connection is saved
  // (a second version of its secret); one with Basic, a JSON body and a ttl; one of a public client.
  const user = await secret('User', {
    client_id: 'synthetic-user-client',
    client_secret: 'synthetic-user-secret',
    refresh_token: 'synthetic-refresh-1',
  });
  await connection('Refresh', {
    type: 'oauth-refresh',
    secretId: user,
    refreshField: 'refresh_token',
    client: { method: 'post', id: ref('client_id'), secretField: 'client_secret' },
    authorize: {
      url: `${endpoint}/authorize`,
      scope: 'openid https://www.googleapis.com/auth/gmail.readonly',
      params: { access_type: 'offline', prompt: 'consent' },
    },
    tokenUrl: `${endpoint}/token`,
  });
  const notion = await secret('Notion', {
    client_id: 'synthetic-notion-client',
    client_secret: 'synthetic-notion-secret',
    refresh_token: 'synthetic-notion-refresh',
  });
  await connection('Refresh Basic', {
    type: 'oauth-refresh',
    secretId: notion,
    refreshField: 'refresh_token',
    client: { method: 'basic', id: ref('client_id'), secretField: 'client_secret' },
    bodyFormat: 'json',
    tokenUrl: `${endpoint}/no-expiry`,
    ttl: 3600,
  });
  const publicClient = await secret('Public', { refresh_token: 'synthetic-public-refresh' });
  await connection('Refresh Public', {
    type: 'oauth-refresh',
    secretId: publicClient,
    refreshField: 'refresh_token',
    client: { method: 'none', id: 'synthetic-public-client' },
    scope: 'read',
    tokenUrl: `${endpoint}/token`,
  });
  // Not authorized yet: its secret has no refresh token until the Owner signs in, which saving a
  // connection with authorize allows.
  const pending = await secret('Pending', {
    client_id: 'synthetic-pending-client',
    client_secret: 'synthetic-pending-secret',
  });
  await connection(
    'Pending',
    {
      type: 'oauth-refresh',
      secretId: pending,
      refreshField: 'refresh_token',
      client: { method: 'basic', id: ref('client_id'), secretField: 'client_secret' },
      authorize: { url: `${endpoint}/authorize` },
      tokenUrl: `${endpoint}/token`,
    },
    { methods: ['GET', 'HEAD'] },
  );

  const outcome = await runAutomaticBackup(env, owner, true);
  if (outcome.outcome !== 'saved') throw new Error(`automatic backup: ${outcome.outcome}`);
  const latest = await env.DB.prepare('SELECT object_key FROM backup_state WHERE id=1').first<{ object_key: string }>();
  const files: [string, Uint8Array][] = [
    ['automatic-a.age', new Uint8Array(await (await env.BACKUPS.get(latest!.object_key))!.arrayBuffer())],
  ];
  const id = randomBytes(16).toString('base64url');
  const full = await fetchWorker(`/admin/backup/export?${new URLSearchParams({ recipient, id })}`);
  if (full.status !== 200) throw new Error(`full export: ${full.status} ${await full.text()}`);
  files.push(['full-a.age', new Uint8Array(await full.arrayBuffer())]);
  if ((await call(`/admin/backup/exports/${id}`)).status !== 'complete') throw new Error('full export incomplete');
  for (const [name, bytes] of files) {
    const path = `${directory}/${name}`;
    await writeFile(path, bytes, { flag: 'wx' });
    console.log(`${path}\t${bytes.length} bytes\tsha256 ${createHash('sha256').update(bytes).digest('hex')}`);
  }
} finally {
  await mf.dispose();
}
