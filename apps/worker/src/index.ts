import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { z } from 'zod';
import { isAPIError } from 'better-auth/api';
import { SCOPES } from '../../../packages/auth/policy';
import { encryptSecret, decryptSecret } from '../../../packages/core/crypto';
import { Fault, assert } from '../../../packages/core/errors';
import { targetUrl, matchHost } from '../../../packages/core/proxy';
import {
  type Bindings,
  createAuth,
  requireOwner,
  requireOrigin,
  principal,
  ownerId,
  rootKeys,
  keyState,
  now,
  id,
  audit,
  auditStatement,
  readJson,
  withRequestId,
  issuesHint,
  VERSION,
} from './context';
import {
  metadata,
  readSecret,
  accessRequest,
  accessStatus,
  invoke,
  parseProxyRequest,
  secretInput,
  connectionInput,
  grantInput,
  readInput,
  requestInput,
  resourceId,
  boundSecret,
  validateAuthBinding,
  policyJson,
  liveExtensions,
  requestedExtension,
  valuesSchema,
  withChanges,
  type ConnectionRow,
  type ConnectionPolicy,
  type StoredRequest,
} from './vault';
import { handleMcp } from './mcp';
import { backupStatus, configureBackup, runAutomaticBackup, downloadLatestBackup } from './backup';
import { exportId, fullExport, exportStatus, recipientInput } from './export';
import { sealColdData } from './archive';
import { tokenState, createOwner, resetOwner, ownerInput, resetInput } from './setup';
import { startImport, assertImporting, importChunk, commitImport, startInput, chunkInput, commitInput } from './import';
import { SEGMENT_LINE_LIMIT } from '../../../packages/core/snapshot';

const app = new Hono<{ Bindings: Bindings }>();
const jsonPolicy =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
// A page of the management site loads its own script and stylesheet (and the browser its icon) and
// calls this origin. Nothing on it is inline, embedded or framed, and script submits every form.
const pagePolicy =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
app.use('*', async (c, next) => {
  const requestId = id();
  c.header('x-request-id', requestId);
  c.header('cache-control', 'no-store');
  c.header('x-content-type-options', 'nosniff');
  c.header('referrer-policy', 'no-referrer');
  c.header('content-security-policy', jsonPolicy);
  if (c.req.header('origin') && c.req.header('origin') !== c.env.APP_ORIGIN && c.req.path !== '/api/auth/oauth2/token')
    throw new Fault('origin_not_allowed', 403);
  await withRequestId(requestId, next);
  // A handler that returns its own Response replaces the prepared headers: the site's files, Better
  // Auth and the proxy all do, so every response gets them again here.
  c.header('x-request-id', requestId);
  c.header('x-content-type-options', 'nosniff');
  c.header('referrer-policy', 'no-referrer');
  c.header(
    'content-security-policy',
    c.res.headers.get('content-type')?.startsWith('text/html') ? pagePolicy : jsonPolicy,
  );
});
// Nothing but /healthz runs under a root key the database does not recognize; see keyState.
app.use('*', async (c, next) => {
  if (c.req.path !== '/healthz') assert((await keyState(c.env)) !== 'mismatch', 'root_key_mismatch', 503);
  await next();
});
app.use('/api/auth/*', bodyLimit({ maxSize: 1024 * 1024, onError: (c) => c.json({ error: 'body_too_large' }, 413) }));
// New authorization, plaintext export, backup recipient changes and saving a connection need a
// recent login. A connection decides which upstream receives which credential, and editing one keeps
// its existing grants, so both forms reach the same credentials an export would. The full export is a
// GET, since the browser downloads it through a link (and Hono answers HEAD with the GET handler).
const recentLoginRequired = (method: string, path: string) =>
  (['GET', 'HEAD'].includes(method) && path === '/admin/backup/export') ||
  (method === 'POST' && (path === '/admin/grants' || /^\/admin\/access-requests\/[^/]+\/approve$/.test(path))) ||
  (method === 'PUT' && path === '/admin/backup/config') ||
  (['POST', 'PUT'].includes(method) && /^\/admin\/connections(\/[^/]+)?$/.test(path));
app.use('/admin/*', async (c, next) => {
  const write = !['GET', 'HEAD'].includes(c.req.method);
  if (write) requireOrigin(c.req.raw, c.env);
  await requireOwner(c.req.raw, c.env, recentLoginRequired(c.req.method, c.req.path));
  await next();
});
app.get('/healthz', async (c) => {
  const keys = await keyState(c.env);
  return c.json({
    ok: keys !== 'mismatch',
    service: 'clavifer',
    version: VERSION,
    keys,
    initialized: keys !== 'uninitialized',
  });
});
// The console's /setup page: with the token the deployment issued, create the Owner of an uninitialized
// instance or give the Owner of an initialized one a new password. Whether the instance is initialized
// is in /healthz; checking the token tells the page the email the Owner signs in with.
app.use('/api/setup/*', async (c, next) => {
  requireOrigin(c.req.raw, c.env);
  await next();
});
app.post('/api/setup/token', async (c) => {
  const { owner, email } = await tokenState(c.env, c.req.header('x-bootstrap-token'));
  return c.json(owner ? { initialized: true, email } : { initialized: false });
});
app.post('/api/setup/owner', async (c) => {
  const input = ownerInput.parse(await readJson(c.req.raw));
  for (const cookie of await createOwner(c.env, c.req.header('x-bootstrap-token'), input, c.req.raw.headers))
    c.header('set-cookie', cookie, { append: true });
  return c.json({ ok: true }, 201);
});
app.post('/api/setup/password', async (c) => {
  await resetOwner(c.env, c.req.header('x-bootstrap-token'), resetInput.parse(await readJson(c.req.raw)));
  return c.json({ ok: true });
});
// Importing a snapshot instead of creating the Owner: the token starts it, the import id it returns
// carries the chunks and the commit.
app.post('/api/setup/import', async (c) =>
  c.json(
    {
      importId: await startImport(
        c.env,
        c.req.header('x-bootstrap-token'),
        startInput.parse(await readJson(c.req.raw)),
      ),
    },
    201,
  ),
);
// A chunk holds about 4 MB of records, or one embedded segment, whose line may take up to 8 MiB.
app.post('/api/setup/import/chunk', async (c) => {
  await assertImporting(c.env);
  return c.json(await importChunk(c.env, chunkInput.parse(await readJson(c.req.raw, SEGMENT_LINE_LIMIT + 64 * 1024))));
});
app.post('/api/setup/import/commit', async (c) => {
  await commitImport(c.env, commitInput.parse(await readJson(c.req.raw)));
  return c.json({ ok: true });
});
app.all('/api/auth/*', async (c) => {
  const path = c.req.path.replace(/\/+$/, '');
  const authorize = path === '/api/auth/oauth2/authorize';
  // An authorization request arrives by GET. The form-encoded POST the library also takes would carry
  // max_age in its body, past the limit set below. /admin/clients is the only writer of installations,
  // so a grant or an access request never points at one the library deleted behind its back.
  assert(
    ![
      '/api/auth/sign-up/email',
      '/api/auth/change-email',
      '/api/auth/delete-user',
      '/api/auth/oauth2/create-client',
      '/api/auth/oauth2/update-client',
      '/api/auth/oauth2/delete-client',
    ].includes(path) && !(authorize && c.req.method === 'POST'),
    'endpoint_disabled',
    403,
  );
  // Whatever endpoint a body with oauth_query reaches, the library resumes the authorization that
  // signed query describes once the response sets the session cookie, and a query signed for the
  // consent page no longer holds max_age. So only the steps of an authorization may carry one:
  // signing in, which starts a session, and consent and continue, which take a recent login below.
  // The library reads it from the body alone, parsed as JSON or as a form; a copy is read both ways
  // here whatever the content type, and the handler still gets the body.
  if (
    c.req.raw.body &&
    !['/sign-in/email', '/passkey/verify-authentication', '/oauth2/consent', '/oauth2/continue'].includes(
      path.slice('/api/auth'.length),
    )
  ) {
    const body = await c.req.raw.clone().arrayBuffer();
    const json: unknown = await new Response(body).json().catch(() => null);
    const form = await new Response(body, { headers: { 'content-type': c.req.header('content-type') ?? '' } })
      .formData()
      .catch(() => null);
    assert(!Object.hasOwn(Object(json), 'oauth_query') && !form?.has('oauth_query'), 'oauth_query_not_allowed', 403);
  }
  if (path === '/api/auth/device') await requireOwner(c.req.raw, c.env, true);
  if (
    [
      '/api/auth/oauth2/client/rotate-secret',
      '/api/auth/oauth2/update-consent',
      '/api/auth/oauth2/delete-consent',
    ].includes(path)
  ) {
    requireOrigin(c.req.raw, c.env);
    await requireOwner(c.req.raw, c.env, true);
  }
  if (
    /\/(device\/(approve|deny)|oauth2\/(consent|continue|register|rotate-client-secret)|passkey\/(generate-register-options|verify-registration|delete-passkey|update-passkey))$/.test(
      path,
    )
  ) {
    if (!['GET', 'HEAD'].includes(c.req.method)) requireOrigin(c.req.raw, c.env);
    await requireOwner(c.req.raw, c.env, true);
  }
  const auth = await createAuth(c.env);
  if (!authorize) return auth.handler(c.req.raw);
  // An authorization code is a new authorization, so it takes a login of the last 10 minutes like the
  // others. The browser comes here by navigation, where a JSON error would end the flow, so the limit
  // goes in as max_age: the library sends an older session to the login page as it does a visitor who
  // is not signed in, and the signed query that page comes back with keeps the limit. A client may
  // ask for a shorter one.
  const url = new URL(c.req.url);
  url.searchParams.set('max_age', String(Math.min(600, Number(url.searchParams.get('max_age') ?? 600))));
  return auth.handler(new Request(url, c.req.raw));
});
app.get('/.well-known/oauth-protected-resource/v1', (c) =>
  c.json({
    resource: `${c.env.APP_ORIGIN}/v1`,
    authorization_servers: [`${c.env.APP_ORIGIN}/api/auth`],
    scopes_supported: SCOPES,
    bearer_methods_supported: ['header'],
  }),
);
app.get('/.well-known/oauth-protected-resource', (c) => c.redirect('/.well-known/oauth-protected-resource/v1'));
app.get('/.well-known/oauth-authorization-server/api/auth', async (c) =>
  (await createAuth(c.env)).handler(
    new Request(`${c.env.APP_ORIGIN}/api/auth/.well-known/oauth-authorization-server`, { headers: c.req.raw.headers }),
  ),
);

app.get('/admin/status', async (c) => {
  const oid = await ownerId(c.env);
  const [secrets, connections, pending, clients, grants, events] = await c.env.DB.batch([
    c.env.DB.prepare(
      "SELECT s.id,s.name,s.description,s.current_version,s.status,s.updated_at,v.envelope_json FROM secrets s JOIN secret_versions v ON v.secret_id=s.id AND v.version=s.current_version WHERE s.owner_id=? AND s.status='active' ORDER BY s.name",
    ).bind(oid),
    c.env.DB.prepare(
      "SELECT id,name,origin,description,auth_json,policy_json,status,updated_at FROM connections WHERE owner_id=? AND status='active' ORDER BY name",
    ).bind(oid),
    c.env.DB.prepare(
      "SELECT id,client_id,requested_json,reason,expires_at FROM access_requests WHERE owner_id=? AND status='pending' AND expires_at>? ORDER BY created_at",
    ).bind(oid, now()),
    c.env.DB.prepare(
      'SELECT clientId,name,disabled,createdAt,userId FROM oauthClient WHERE userId=? OR userId IS NULL ORDER BY createdAt DESC',
    ).bind(oid),
    c.env.DB.prepare(
      "SELECT id,client_id,resource_type,resource_id,permission,fields_json,extensions_json,expires_at FROM grants WHERE owner_id=? AND status='active' AND (expires_at IS NULL OR expires_at>?)",
    ).bind(oid, now()),
    c.env.DB.prepare(
      'SELECT action,client_id,resource_id,result,request_id,created_at FROM audit_events WHERE owner_id=? ORDER BY created_at DESC LIMIT 50',
    ).bind(oid),
  ]);
  const grantRows = grants.results as { fields_json: string | null; extensions_json: string | null }[];
  const keys = rootKeys(c.env);
  const secretRows = secrets.results as { id: string; current_version: number; envelope_json: string }[];
  return c.json({
    // Field names live only inside the ciphertext, so the dashboard decrypts each current version and keeps the keys.
    secrets: await Promise.all(
      secretRows.map(async ({ envelope_json, ...s }) => ({
        ...s,
        fields: Object.keys(
          await decryptSecret(
            keys,
            { ownerId: oid, secretId: s.id, version: s.current_version },
            JSON.parse(envelope_json),
          ),
        ),
      })),
    ),
    connections: connections.results,
    // An invocation to another origin than its connection's own comes with where that origin stands
    // under the connection as it is now: the extra host that covers it, if any, and whether the
    // connection reaches any host. The card warns from this, never from anything the Agent wrote.
    pending: (pending.results as { requested_json: string }[]).map((request) => {
      const call = (JSON.parse(request.requested_json) as StoredRequest).invocation;
      if (!call?.origin) return request;
      const policy = (connections.results as { id: string; policy_json: string }[]).find(
        (conn) => conn.id === call.connection,
      )?.policy_json;
      const { hosts, anyHost }: Partial<ConnectionPolicy> = policy ? JSON.parse(policy) : {};
      const { hostname } = new URL(call.origin);
      return { ...request, elsewhere: { hostname, host: matchHost(hosts, hostname) ?? null, anyHost: !!anyHost } };
    }),
    clients: clients.results,
    grants: grantRows.map(({ fields_json, extensions_json, ...g }) => ({
      ...g,
      fields: fields_json ? (JSON.parse(fields_json) as string[]) : null,
      extensions: liveExtensions(extensions_json),
    })),
    events: events.results,
    backup: await backupStatus(c.env),
  });
});
app.post('/admin/clients', async (c) => {
  const body = z
    .object({ name: z.string().min(1).max(100), redirectUris: z.array(z.string().url()).max(10).default([]) })
    .parse(await readJson(c.req.raw));
  const auth = await createAuth(c.env);
  const result = await auth.api.createOAuthClient({
    headers: c.req.raw.headers,
    body: {
      client_name: body.name,
      token_endpoint_auth_method: 'none',
      application_type: body.redirectUris.length ? 'web' : 'native',
      scope: SCOPES.join(' '),
      grant_types: body.redirectUris.length
        ? ['authorization_code', 'refresh_token']
        : ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
      ...(body.redirectUris.length ? { redirect_uris: body.redirectUris } : {}),
    },
  });
  await audit(c.env, 'owner', 'client:create', result.client_id);
  return c.json({ clientId: result.client_id, name: body.name, server: c.env.APP_ORIGIN }, 201);
});
async function revokeClient(env: Bindings, clientId: string, oid: string) {
  await env.DB.batch([
    // Every installation is created by the signed-in Owner and carries the Owner's id. A row without
    // a user is not one this service writes; it has no other owner to protect, so the Owner may revoke it.
    env.DB.prepare('UPDATE oauthClient SET disabled=1 WHERE clientId=? AND (userId=? OR userId IS NULL)').bind(
      clientId,
      oid,
    ),
    env.DB.prepare('UPDATE oauthRefreshToken SET revoked=1 WHERE clientId=? AND (userId=? OR userId IS NULL)').bind(
      clientId,
      oid,
    ),
    // The OAuth provider signs a JWT only for a token request that names a resource. One that omits
    // the parameter gets an opaque access token instead, which the provider stores as a row here.
    env.DB.prepare('DELETE FROM oauthAccessToken WHERE clientId=? AND (userId=? OR userId IS NULL)').bind(
      clientId,
      oid,
    ),
    env.DB.prepare("UPDATE grants SET status='revoked' WHERE client_id=? AND owner_id=?").bind(clientId, oid),
    // What it still had waiting for the Owner is settled with it and leaves the pending list.
    env.DB.prepare(
      "UPDATE access_requests SET status='denied' WHERE client_id=? AND owner_id=? AND status='pending' AND expires_at>?",
    ).bind(clientId, oid, now()),
  ]);
  await audit(env, 'owner', 'client:revoke', clientId);
}
app.delete('/admin/clients/:id', async (c) => {
  await revokeClient(c.env, c.req.param('id'), await ownerId(c.env));
  return c.json({ ok: true });
});
app.post('/v1/logout', async (c) => {
  const p = await principal(c.req.raw, c.env);
  await revokeClient(c.env, p.clientId, p.userId);
  return c.json({ ok: true });
});

// Approving a request writes its resources in the same batch that marks it approved; each write only
// takes effect while the request is still pending, so an approval that lost a race changes nothing.
const pendingRequest = "EXISTS (SELECT 1 FROM access_requests WHERE id=? AND status='pending' AND expires_at>?)";
/** Encrypts a new credential and stores it as version 1, for the Owner's form or an approved setup. */
async function secretStatements(
  env: Bindings,
  oid: string,
  sid: string,
  body: z.infer<typeof secretInput>,
  requestId?: string,
) {
  const envelope = await encryptSecret(rootKeys(env), { ownerId: oid, secretId: sid, version: 1 }, body.values);
  const pending = requestId ? `WHERE ${pendingRequest}` : '';
  const args = requestId ? [requestId, now()] : [];
  return [
    env.DB.prepare(
      `INSERT INTO secrets (id,owner_id,name,description,current_version,created_at,updated_at) SELECT ?,?,?,?,1,?,? ${pending}`,
    ).bind(sid, oid, body.name, body.description, now(), now(), ...args),
    env.DB.prepare(
      `INSERT INTO secret_versions (id,secret_id,version,envelope_json,created_at) SELECT ?,?,1,?,? ${pending}`,
    ).bind(id(), sid, JSON.stringify(envelope), now(), ...args),
  ];
}
app.post('/admin/secrets', async (c) => {
  const body = secretInput.parse(await readJson(c.req.raw));
  const oid = await ownerId(c.env),
    sid = id();
  await c.env.DB.batch(await secretStatements(c.env, oid, sid, body));
  await audit(c.env, 'owner', 'secret:create', sid);
  return c.json({ id: sid, name: body.name, version: 1 }, 201);
});
app.put('/admin/secrets/:id', async (c) => {
  const body = secretInput.extend({ expectedVersion: z.number().int().positive() }).parse(await readJson(c.req.raw));
  const sid = c.req.param('id'),
    oid = await ownerId(c.env);
  const row = await c.env.DB.prepare(
    "SELECT current_version FROM secrets WHERE id=? AND owner_id=? AND status='active'",
  )
    .bind(sid, oid)
    .first<{ current_version: number }>();
  assert(row && row.current_version === body.expectedVersion, 'version_conflict', 409);
  const version = body.expectedVersion + 1;
  const old = await boundSecret(c.env, oid, sid);
  const merged = secretInput.shape.values.parse({ ...old.values, ...body.values });
  const envelope = await encryptSecret(rootKeys(c.env), { ownerId: oid, secretId: sid, version }, merged);
  await c.env.DB.batch([
    c.env.DB.prepare(
      'INSERT INTO secret_versions (id,secret_id,version,envelope_json,created_at) VALUES (?,?,?,?,?)',
    ).bind(id(), sid, version, JSON.stringify(envelope), now()),
    c.env.DB.prepare(
      "UPDATE secrets SET name=?,description=?,current_version=?,updated_at=? WHERE id=? AND owner_id=? AND current_version=? AND status='active'",
    ).bind(body.name, body.description, version, now(), sid, oid, body.expectedVersion),
  ]);
  await audit(c.env, 'owner', 'secret:rotate', sid);
  return c.json({ id: sid, version });
});
app.delete('/admin/secrets/:id', async (c) => {
  const sid = c.req.param('id'),
    oid = await ownerId(c.env);
  const results = await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE secrets SET status='deleted',updated_at=? WHERE id=? AND owner_id=? AND status='active' AND NOT EXISTS (SELECT 1 FROM connections WHERE owner_id=? AND status='active' AND json_extract(auth_json,'$.type')!='none' AND json_extract(auth_json,'$.secretId')=?)",
    ).bind(now(), sid, oid, oid, sid),
    c.env.DB.prepare(
      "UPDATE grants SET status='revoked' WHERE resource_type='secret' AND resource_id=? AND owner_id=? AND EXISTS (SELECT 1 FROM secrets WHERE id=? AND owner_id=? AND status='deleted')",
    ).bind(sid, oid, sid, oid),
    // Deleting a credential removes its ciphertext in the same transaction. The tombstone row stays
    // so a repeated delete still reports success instead of colliding with the name.
    c.env.DB.prepare(
      "DELETE FROM secret_versions WHERE secret_id=? AND EXISTS (SELECT 1 FROM secrets WHERE id=? AND owner_id=? AND status='deleted')",
    ).bind(sid, sid, oid),
  ]);
  if (results[0].meta.changes === 0) {
    const row = await c.env.DB.prepare('SELECT status FROM secrets WHERE id=? AND owner_id=?')
      .bind(sid, oid)
      .first<{ status: string }>();
    assert(row?.status === 'deleted', 'secret_in_use', 409);
  }
  await audit(c.env, 'owner', 'secret:delete', sid);
  return c.json({ ok: true });
});
/** Creates a connection whose binding, if any, names an active secret, for the Owner's form or an
 * approved setup; origin and policy come checked from targetUrl and policyJson. */
function insertConnection(
  env: Bindings,
  oid: string,
  cid: string,
  body: z.infer<typeof connectionInput>,
  origin: string,
  policy: string,
  requestId?: string,
) {
  const bindingId = body.auth.type === 'none' ? null : body.auth.secretId;
  return env.DB.prepare(
    `INSERT INTO connections (id,owner_id,name,origin,description,auth_json,policy_json,created_at,updated_at) SELECT ?,?,?,?,?,?,?,?,? WHERE (? IS NULL OR EXISTS (SELECT 1 FROM secrets WHERE id=? AND owner_id=? AND status='active')) ${requestId ? `AND ${pendingRequest}` : ''}`,
  ).bind(
    cid,
    oid,
    body.name,
    origin,
    body.description,
    JSON.stringify(body.auth),
    policy,
    now(),
    now(),
    bindingId,
    bindingId,
    oid,
    ...(requestId ? [requestId, now()] : []),
  );
}
app.on(['POST', 'PUT'], '/admin/connections/:id?', async (c) => {
  const body = connectionInput.parse(await readJson(c.req.raw));
  const oid = await ownerId(c.env);
  const target = targetUrl(body.origin, '/', c.env.ALLOW_LOCAL_HTTP === 'true');
  const policy = policyJson(body, c.env.ALLOW_LOCAL_HTTP === 'true');
  if (body.auth.type !== 'none')
    validateAuthBinding(body.auth, (await boundSecret(c.env, oid, body.auth.secretId)).values);
  const cid = c.req.param('id') ?? id();
  if (c.req.method === 'PUT') {
    const bindingId = body.auth.type === 'none' ? null : body.auth.secretId;
    const result = await c.env.DB.prepare(
      "UPDATE connections SET name=?,origin=?,description=?,auth_json=?,policy_json=?,updated_at=? WHERE id=? AND owner_id=? AND status='active' AND (? IS NULL OR EXISTS (SELECT 1 FROM secrets WHERE id=? AND owner_id=? AND status='active'))",
    )
      .bind(
        body.name,
        target.origin,
        body.description,
        JSON.stringify(body.auth),
        policy,
        now(),
        cid,
        oid,
        bindingId,
        bindingId,
        oid,
      )
      .run();
    assert(result.meta.changes > 0, 'connection_or_binding_not_found', 404);
  } else {
    const result = await insertConnection(c.env, oid, cid, body, target.origin, policy).run();
    assert(result.meta.changes > 0, 'secret_not_found', 404);
  }
  await audit(c.env, 'owner', 'connection:save', cid);
  return c.json({ id: cid });
});
app.delete('/admin/connections/:id', async (c) => {
  const cid = c.req.param('id'),
    oid = await ownerId(c.env);
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE connections SET status='deleted' WHERE id=? AND owner_id=?").bind(cid, oid),
    c.env.DB.prepare(
      "UPDATE grants SET status='revoked' WHERE resource_type='connection' AND resource_id=? AND owner_id=?",
    ).bind(cid, oid),
  ]);
  await audit(c.env, 'owner', 'connection:delete', cid);
  return c.json({ ok: true });
});
// Order does not distinguish one field subset from another; absent means every field.
const sameFields = (a: string[] | null | undefined, b: string[] | null | undefined) =>
  (a ? JSON.stringify([...a].sort()) : '') === (b ? JSON.stringify([...b].sort()) : '');
export async function grantStatements(
  env: Bindings,
  oid: string,
  clientId: string,
  grants: z.infer<typeof grantInput>[],
  expiresAt: number | null,
  requestId?: string,
) {
  const client = await env.DB.prepare('SELECT 1 FROM oauthClient WHERE clientId=? AND userId=? AND disabled IS NOT 1')
    .bind(clientId, oid)
    .first();
  assert(client, 'client_not_found', 404);
  const statements = [];
  for (const g of grants) {
    const resource = await env.DB.prepare(
      g.resourceType === 'secret'
        ? "SELECT NULL AS policy_json FROM secrets WHERE id=? AND owner_id=? AND status='active'"
        : "SELECT policy_json FROM connections WHERE id=? AND owner_id=? AND status='active'",
    )
      .bind(g.resourceId, oid)
      .first<{ policy_json: string | null }>();
    assert(resource, 'resource_not_found', 404);
    // The field subset in a request is written by the client, so approving one may only revive a
    // grant that is no longer live. Any other subset is a conflict the Owner resolves in the form,
    // never a silent no-op.
    if (requestId) {
      const live = await env.DB.prepare(
        "SELECT fields_json FROM grants WHERE owner_id=? AND client_id=? AND resource_type=? AND resource_id=? AND permission=? AND status='active' AND (expires_at IS NULL OR expires_at>?)",
      )
        .bind(oid, clientId, g.resourceType, g.resourceId, g.permission, now())
        .first<{ fields_json: string | null }>();
      assert(
        !live || sameFields(live.fields_json ? (JSON.parse(live.fields_json) as string[]) : null, g.fields),
        'existing_grant_conflict',
        409,
      );
    }
    // An active grant never loses reach: an unlimited or later expiry survives, while a revoked or
    // already expired one takes the new value. The CASE expressions use the same liveness test.
    // A scope extension carries the expiry chosen for it, so it never inherits a longer one the
    // grant already had. Approving adds it to the grant's live extensions (UNION drops repeats);
    // the Owner's form replaces them, as it does the field subset.
    const live = "grants.status='active' AND (grants.expires_at IS NULL OR grants.expires_at>?)";
    const fields = requestId
      ? `CASE WHEN ${live} THEN grants.fields_json ELSE excluded.fields_json END`
      : 'excluded.fields_json';
    const extensions = requestId
      ? `CASE WHEN ${live} THEN (SELECT NULLIF(json_group_array(json(value)),'[]') FROM (SELECT value FROM json_each(grants.extensions_json) WHERE json_extract(value,'$.expiresAt') IS NULL OR json_extract(value,'$.expiresAt')>? UNION SELECT value FROM json_each(excluded.extensions_json))) ELSE excluded.extensions_json END`
      : 'excluded.extensions_json';
    const extension = requestedExtension(g, resource.policy_json, expiresAt);
    statements.push(
      env.DB.prepare(
        `INSERT INTO grants (id,owner_id,client_id,resource_type,resource_id,permission,fields_json,extensions_json,status,created_at,expires_at) SELECT ?,?,?,?,?,?,?,?,'active',?,? ${requestId ? `WHERE ${pendingRequest}` : ''} ON CONFLICT(client_id,resource_type,resource_id,permission) DO UPDATE SET status='active',fields_json=${fields},extensions_json=${extensions},expires_at=CASE WHEN grants.status='active' AND (grants.expires_at IS NULL OR (excluded.expires_at IS NOT NULL AND grants.expires_at>excluded.expires_at)) THEN grants.expires_at ELSE excluded.expires_at END`,
      ).bind(
        id(),
        oid,
        clientId,
        g.resourceType,
        g.resourceId,
        g.permission,
        g.fields ? JSON.stringify(g.fields) : null,
        extension ? JSON.stringify([extension]) : null,
        now(),
        expiresAt,
        ...(requestId ? [requestId, now(), now(), now(), now()] : []),
      ),
    );
  }
  return statements;
}
// Owner-chosen expiry for a direct grant and for an approval alike; null means until revoked.
const grantExpiry = z
  .number()
  .int()
  .refine((n) => n > now())
  .nullable();
app.post('/admin/grants', async (c) => {
  const body = z
    .object({
      clientId: resourceId,
      grants: z.array(grantInput).min(1).max(20),
      expiresAt: grantExpiry.default(null),
    })
    .parse(await readJson(c.req.raw));
  await c.env.DB.batch(await grantStatements(c.env, await ownerId(c.env), body.clientId, body.grants, body.expiresAt));
  await audit(c.env, 'owner', 'grant:create', body.clientId);
  return c.json({ ok: true });
});
app.delete('/admin/grants/:id', async (c) => {
  await c.env.DB.prepare("UPDATE grants SET status='revoked' WHERE id=? AND owner_id=?")
    .bind(c.req.param('id'), await ownerId(c.env))
    .run();
  await audit(c.env, 'owner', 'grant:revoke', c.req.param('id'));
  return c.json({ ok: true });
});
app.post('/admin/access-requests/:id/:decision', async (c) => {
  const decision = c.req.param('decision');
  assert(['approve', 'deny'].includes(decision), 'invalid_decision');
  const oid = await ownerId(c.env),
    rid = c.req.param('id');
  const row = await c.env.DB.prepare(
    "SELECT client_id,requested_json FROM access_requests WHERE id=? AND owner_id=? AND status='pending' AND expires_at>?",
  )
    .bind(rid, oid, now())
    .first<{ client_id: string; requested_json: string }>();
  assert(row, 'request_not_found', 404);
  // A request without a content-type counts as having no body and keeps the default 24 hours.
  // Only a grant request has an expiry to choose, only a setup with a credential takes values, which
  // the Owner enters here, and only an invocation to another origin has that origin to name back; any
  // other approval ignores the body.
  const requested = JSON.parse(row.requested_json) as StoredRequest;
  const approve = decision === 'approve';
  const elsewhere = approve ? requested.invocation?.origin : undefined;
  const body =
    approve && (requested.grants || requested.setup?.secret || elsewhere) && c.req.header('content-type')
      ? await readJson(c.req.raw)
      : {};
  const expiresAt =
    approve && requested.grants
      ? z.object({ expiresAt: grantExpiry.default(() => now() + 86400000) }).parse(body).expiresAt
      : null;
  const values = approve && requested.setup?.secret ? z.object({ values: valuesSchema }).parse(body).values : undefined;
  // The approval names the origin back, which shows that the Owner was told where the request goes:
  // an approval that names none may come from a client that presented it as a request to the
  // connection's own origin.
  assert(
    !elsewhere || z.object({ origin: z.string().optional() }).parse(body).origin === elsewhere,
    'origin_mismatch',
    409,
    'This request goes to another origin than its connection’s own; the approval has to name that origin as stored. Reload the page and review the request again.',
  );
  await decideRequest(c.env, oid, rid, row, approve, expiresAt, values);
  return c.json({ ok: true });
});
/** Approving a setup creates its credential from the values the Owner entered and every connection,
 * each bound to that credential, under the ids fixed on submission and checked as the Owner's own forms
 * check them. One batch holds them all, so a name taken since submission leaves nothing created. The
 * audit rows of the approval are in that batch under the same condition as the resources, so they are
 * written exactly when the resources are, however many connections there are. */
async function setupStatements(
  env: Bindings,
  oid: string,
  rid: string,
  { setup, ids }: StoredRequest,
  values: Record<string, string> | undefined,
) {
  const { secretId, connectionIds } = ids!;
  const { secret } = setup!;
  const connections = setup!.connections.map((draft) =>
    connectionInput.parse({ ...draft, auth: draft.auth.type === 'none' ? draft.auth : { ...draft.auth, secretId } }),
  );
  const audited = (action: string, resource: string) =>
    auditStatement(env, 'owner', action, resource, { where: `WHERE ${pendingRequest}`, args: [rid, now()] });
  const writes = [
    ...connections.map((connection, i) =>
      insertConnection(
        env,
        oid,
        connectionIds[i],
        connection,
        targetUrl(connection.origin, '/', env.ALLOW_LOCAL_HTTP === 'true').origin,
        policyJson(connection, env.ALLOW_LOCAL_HTTP === 'true'),
        rid,
      ),
    ),
    ...(await Promise.all(connectionIds.map((cid) => audited('connection:save', cid)))),
    await audited('access:approve', rid),
  ];
  if (!secret) return writes;
  assert(
    values && sameFields(Object.keys(values), secret.fields),
    'secret_fields_mismatch',
    400,
    `values holds exactly the fields ${secret.fields.join(', ')}`,
  );
  for (const connection of connections) validateAuthBinding(connection.auth, values);
  // Submission leaves credential names unchecked, since an installation may not learn names it cannot
  // list; a taken one (deleted credentials keep theirs) only surfaces here, to the Owner.
  assert(
    !(await env.DB.prepare('SELECT 1 FROM secrets WHERE owner_id=? AND name=?').bind(oid, secret.name).first()),
    'secret_name_taken',
    409,
    'A credential with this name exists or existed, so this setup cannot be approved. Deny it and ask the Agent to submit again with another name.',
  );
  return [
    ...(await secretStatements(
      env,
      oid,
      secretId!,
      { name: secret.name, description: secret.description, values },
      rid,
    )),
    await audited('secret:create', secretId!),
    ...writes,
  ];
}
/** Approving an update writes the scope and rules it proposes, as long as the connection is as it was
 * on submission: the Agent's tests and the Owner's comparison both read that state. The edit carries
 * stamp as updated_at, which the request's own update checks. */
async function updateStatements(env: Bindings, oid: string, rid: string, requested: StoredRequest, stamp: number) {
  const update = requested.update!;
  const conn = await env.DB.prepare(
    "SELECT name,origin,description,auth_json,policy_json,updated_at FROM connections WHERE id=? AND owner_id=? AND status='active'",
  )
    .bind(update.connection, oid)
    .first<ConnectionRow>();
  assert(
    conn && conn.updated_at === requested.updatedAt,
    'connection_changed',
    409,
    'The connection changed after the Agent submitted this update. Deny it; the Agent can submit again against the connection as it is now.',
  );
  const body = withChanges(conn, update.changes);
  return [
    env.DB.prepare(
      `UPDATE connections SET name=?,description=?,policy_json=?,updated_at=? WHERE id=? AND owner_id=? AND status='active' AND updated_at=? AND ${pendingRequest}`,
    ).bind(
      body.name,
      body.description,
      policyJson(body, env.ALLOW_LOCAL_HTTP === 'true'),
      stamp,
      update.connection,
      oid,
      conn.updated_at,
      rid,
      now(),
    ),
  ];
}
/** Applies a decision to a request read as pending. The request can expire after that read, so the
 * final UPDATE re-checks it and a decision that changed nothing fails without an audit row. */
export async function decideRequest(
  env: Bindings,
  oid: string,
  rid: string,
  row: { client_id: string; requested_json: string },
  approve: boolean,
  expiresAt: number | null,
  values?: Record<string, string>,
) {
  const requested = JSON.parse(row.requested_json) as StoredRequest;
  const stamp = now();
  const statements = !approve
    ? []
    : requested.setup
      ? await setupStatements(env, oid, rid, requested, values)
      : requested.update
        ? await updateStatements(env, oid, rid, requested, stamp)
        : requested.grants
          ? await grantStatements(
              env,
              oid,
              row.client_id,
              requestInput.shape.requested.parse(requested).grants!,
              expiresAt,
              rid,
            )
          : [];
  // An approved update counts only together with its edit, which carries stamp as updated_at.
  const edited = approve && requested.update ? [requested.update.connection, stamp] : null;
  // An approved invocation's expires_at becomes the 10 minute window for its one run.
  statements.push(
    requested.invocation
      ? env.DB.prepare(
          "UPDATE access_requests SET status=?,expires_at=? WHERE id=? AND status='pending' AND expires_at>?",
        ).bind(approve ? 'approved' : 'denied', now() + 600000, rid, now())
      : env.DB.prepare(
          `UPDATE access_requests SET status=? WHERE id=? AND status='pending' AND expires_at>? ${edited ? 'AND EXISTS (SELECT 1 FROM connections WHERE id=? AND updated_at=?)' : ''}`,
        ).bind(approve ? 'approved' : 'denied', rid, now(), ...(edited ?? [])),
  );
  const results = await env.DB.batch(statements);
  // D1 counts the row the backup revision trigger updates as a change too.
  assert(results[results.length - 1].meta.changes > 0, 'request_not_found', 404);
  // What an approval created or changed is audited as the Owner's own forms audit it; an approved
  // setup wrote its rows in the batch.
  if (approve && requested.setup) return;
  if (approve && requested.update) await audit(env, 'owner', 'connection:save', requested.update.connection);
  await audit(env, 'owner', `access:${approve ? 'approve' : 'deny'}`, rid);
}
// The complete state of the instance, streamed; see fullExport for how the console learns it finished.
// The recipient is in the link, so a page of another site could otherwise have the browser download the
// Owner's credentials encrypted to its own key; only the console's own page may start one.
app.get('/admin/backup/export', async (c) => {
  assert(c.req.header('sec-fetch-site') === 'same-origin', 'cross_site_request', 403);
  return fullExport(c.env, await ownerId(c.env), c.req.query('recipient') ?? '', exportId.parse(c.req.query('id')));
});
app.get('/admin/backup/exports/:id', async (c) => c.json(await exportStatus(c.env, exportId.parse(c.req.param('id')))));
app.get('/admin/backup/status', async (c) => c.json(await backupStatus(c.env)));
app.put('/admin/backup/config', async (c) => {
  const body = z.object({ recipient: recipientInput.nullable() }).parse(await readJson(c.req.raw));
  return c.json(await configureBackup(c.env, body.recipient));
});
app.post('/admin/backup/run', async (c) => c.json(await runAutomaticBackup(c.env, await ownerId(c.env), true)));
app.get('/admin/backup/latest', async (c) => downloadLatestBackup(c.env));
app.get('/v1/secrets', async (c) =>
  c.json(await metadata(c.env, await principal(c.req.raw, c.env, ['metadata:list']))),
);
app.post('/v1/secrets/:id/read', async (c) => {
  const p = await principal(c.req.raw, c.env, ['secret:read']);
  const empty = !c.req.raw.body || c.req.header('content-length') === '0';
  const body = empty ? {} : readInput.parse(await readJson(c.req.raw));
  return c.json(await readSecret(c.env, p, resourceId.parse(c.req.param('id')), body.fields));
});
app.post('/v1/access-requests', async (c) =>
  c.json(
    await accessRequest(
      c.env,
      await principal(c.req.raw, c.env, ['access:request']),
      await readJson(c.req.raw),
      c.env.APP_ORIGIN,
    ),
    202,
  ),
);
app.get('/v1/access-requests/:id', async (c) =>
  c.json(await accessStatus(c.env, await principal(c.req.raw, c.env, ['access:request']), c.req.param('id'))),
);
app.all('/v1/proxy/:connection/*', async (c) => {
  const p = await principal(c.req.raw, c.env, ['connection:invoke']);
  const input = await parseProxyRequest(c.req.raw, c.req.param('connection'));
  const result = await invoke(c.env, p, input);
  return new Response(c.req.method === 'HEAD' || [204, 205, 304].includes(result.status) ? null : result.body, {
    status: result.status,
    headers: result.headers,
  });
});
app.all('/v1/mcp', async (c) => handleMcp(c.req.raw, c.env, await principal(c.req.raw, c.env)));
app.notFound((c) => {
  if (/^\/(api|v1|admin|\.well-known)(\/|$)/.test(c.req.path)) return c.json({ error: 'not_found' }, 404);
  return c.env.ASSETS.fetch(c.req.raw);
});
app.onError((e, c) => {
  const authError = isAPIError(e);
  const conflict = e.message.includes('UNIQUE constraint failed');
  const code =
    e instanceof Fault
      ? e.code
      : e instanceof z.ZodError
        ? 'invalid_input'
        : authError
          ? String(e.body?.error ?? e.body?.code ?? 'authentication_error')
          : conflict
            ? 'conflict'
            : 'internal_error';
  const status =
    e instanceof Fault ? e.status : e instanceof z.ZodError ? 400 : authError ? e.statusCode : conflict ? 409 : 500;
  if (status === 401)
    c.header(
      'www-authenticate',
      `Bearer resource_metadata="${c.env.APP_ORIGIN}/.well-known/oauth-protected-resource/v1", error="invalid_token"`,
    );
  if (status === 500)
    console.error(JSON.stringify({ error: 'internal_error', requestId: c.res.headers.get('x-request-id') }));
  const hint =
    e instanceof Fault && e.message !== e.code
      ? { hint: e.message }
      : e instanceof z.ZodError
        ? { hint: issuesHint(e) }
        : {};
  return new Response(JSON.stringify({ error: code, ...hint, request_id: c.res.headers.get('x-request-id') }), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      ...(c.res.headers.get('www-authenticate') ? { 'www-authenticate': c.res.headers.get('www-authenticate')! } : {}),
    },
  });
});
export default {
  fetch: (request: Request, env: Bindings, ctx: ExecutionContext) => app.fetch(request, env, ctx),
  scheduled: (event: ScheduledController, env: Bindings) =>
    withRequestId(String(event.scheduledTime), async () => {
      // An uninitialized instance has nothing to seal or back up, and a mismatched one must not be read or written.
      if ((await keyState(env)) !== 'ok') return;
      const owner = await ownerId(env);
      // Sealing first keeps the hot data, and so the backup, small.
      await sealColdData(env, owner);
      await runAutomaticBackup(env, owner);
    }),
};
