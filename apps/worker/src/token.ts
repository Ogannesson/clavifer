import { Buffer } from 'node:buffer';
import { Fault, assert } from '../../../packages/core/errors';
import {
  decryptSecret,
  decryptToken,
  digest,
  encode,
  encryptSecret,
  encryptToken,
  pkceVerifier,
} from '../../../packages/core/crypto';
import {
  assertFields,
  authorizes,
  recipe as recipeOf,
  type Auth,
  type Client,
  type ExchangeAuth,
} from '../../../packages/core/auth';
import { isRef, signJwt, type Ref } from '../../../packages/core/jwt';
import { type Bindings, auditStatement, boundedBytes, finish, id, now, rootKeys } from './context';

// A token derived from a secret at a token endpoint, cached in token_cache under (secret, recipe) and
// encrypted there. One exchange per secret runs at a time, under its row in token_locks: two recipes
// may share one refresh token, which a rotating endpoint accepts only once.

/** How long getting a token may take, waiting for the lock included; the upstream call has its own. */
export const TIME_LIMIT = 20000;
// A cached token is used only while it has this long left, and a lock outlives every holder's time limit.
const MARGIN = 60000;
const LOCK = 30000;
const POLL = 250;
// A request to the token endpoint is sent only with this long left of the time limit: one cut short may
// have spent a code or a refresh token upstream with no answer to show for it.
const EXCHANGE = 10000;

/** Who asks for a token and until when: actor is the installation, or owner for the console's test. */
export type Asker = { env: Bindings; owner: string; actor: string; deadline: number };
/** A token ready to use; createdAt tells invoke whether an upstream 401 may drop it from the cache. */
export type Issued = { value: string; secretId: string; recipe: string; createdAt: number };
/** What a token endpoint answered: expiresIn in milliseconds, absent when it named none. */
export type Minted = { accessToken: string; expiresIn?: number; refreshToken?: string };

/** A failed exchange. Its hint and result (the audit row's) name the endpoint's host, the HTTP status
 * and the endpoint's error code, never anything sent; upstream holds the host and what the endpoint
 * said for the Owner's eyes (see ownerFault). */
type Said = { status?: number; error?: string; error_description?: string };
export class TokenFault extends Fault {
  constructor(
    code: 'token_exchange_failed' | 'token_unavailable',
    message: string,
    public result: string,
    public upstream: Said & { host?: string } = {},
  ) {
    super(code, code === 'token_unavailable' ? 503 : 502, message);
  }
}
const failed = (host: string, what: string, result: string, upstream?: Said) =>
  new TokenFault(
    'token_exchange_failed',
    `The token endpoint ${host} ${what}, so the request was not sent upstream. Tell the user: the Owner has to fix the connection or authorize it again in the console. Do not retry.`,
    result,
    { host, ...upstream },
  );
const unavailable = (host: string, what: string, upstream?: Said) =>
  new TokenFault(
    'token_unavailable',
    `The token endpoint ${host} ${what}, so the request was not sent upstream and a one-time approval it needs was not spent. Send the identical request again later.`,
    'unavailable',
    { host, ...upstream },
  );
const notAuthorized = () =>
  new TokenFault(
    'token_exchange_failed',
    'This connection has not been authorized yet, so its credential holds no refresh token and the request was not sent upstream. Tell the user: the Owner has to authorize the connection on the connections page of the console. Do not retry.',
    'not_authorized',
  );
/** The error a token endpoint returned as the Owner's routes answer it: with the endpoint's own error
 * and description, and ttl_required for a token without an expiry, which saving refuses. */
export function ownerFault(e: unknown) {
  if (!(e instanceof TokenFault)) return e;
  const details = { token_endpoint: e.upstream };
  return e.result === 'no_expiry'
    ? new Fault(
        'ttl_required',
        400,
        'The token endpoint answered without expires_in; give the connection a ttl in seconds.',
        details,
      )
    : new Fault(e.code, e.status, e.message, details);
}
// Of the endpoint's own error, only a code RFC 6749 §5.2 defines reaches a hint or the audit, so an
// endpoint that echoes what it was sent cannot pass it on.
const ERRORS = [
  'invalid_request',
  'invalid_client',
  'invalid_grant',
  'unauthorized_client',
  'unsupported_grant_type',
  'invalid_scope',
];
const errorCode = (value: unknown) => (ERRORS.includes(value as string) ? (value as string) : 'unrecognized');
const said = (value: unknown) => (typeof value === 'string' ? value.slice(0, 1000) : undefined);

const valueOf = (v: string | Ref | undefined, values: Record<string, string>) =>
  v === undefined ? undefined : isRef(v) ? values[v.$field] : v;
// RFC 6749 §2.3.1: the client id and secret are form-encoded before they are joined for Basic.
const formEncoded = (text: string) => new URLSearchParams({ v: text }).toString().slice(2);
async function authenticate(
  client: Client | undefined,
  values: Record<string, string>,
  headers: Headers,
  body: Record<string, string>,
) {
  if (!client) return;
  const cid = valueOf(client.id, values);
  if (client.method === 'basic') {
    const pair = `${formEncoded(cid!)}:${formEncoded(values[client.secretField])}`;
    headers.set('authorization', `Basic ${Buffer.from(pair, 'utf8').toString('base64')}`);
    return;
  }
  if (cid !== undefined) body.client_id = cid;
  if (client.method === 'post') body.client_secret = values[client.secretField];
  if (client.method === 'jwt') {
    // RFC 7523 §3: a client assertion is used once, so it always carries a jti.
    body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    body.client_assertion = await signJwt({ ...client.jwt, jti: true }, values);
  }
}
/** The grant of the auth's own kind, from the secret's values. */
async function grantOf(auth: ExchangeAuth, values: Record<string, string>): Promise<Record<string, string>> {
  if (auth.type === 'oauth-jwt')
    return { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: await signJwt(auth.jwt, values) };
  const scope: Record<string, string> = auth.scope ? { scope: auth.scope } : {};
  return auth.type === 'oauth-client'
    ? { grant_type: auth.grantType ?? 'client_credentials', ...scope }
    : { grant_type: 'refresh_token', refresh_token: values[auth.refreshField], ...scope };
}
/** One POST of grant to the auth's token endpoint, with its extra parameters and client authentication,
 * answered before deadline. values holds every field the auth reads. */
export async function requestToken(
  auth: ExchangeAuth,
  values: Record<string, string>,
  grant: Record<string, string>,
  deadline: number,
): Promise<Minted> {
  const headers = new Headers({ accept: 'application/json' });
  const body: Record<string, string> = { ...grant, ...auth.params };
  await authenticate(auth.client, values, headers, body);
  const json = auth.bodyFormat === 'json';
  headers.set('content-type', json ? 'application/json' : 'application/x-www-form-urlencoded');
  const host = new URL(auth.tokenUrl).host;
  let response: Response | undefined, bytes: Uint8Array;
  try {
    response = await fetch(auth.tokenUrl, {
      method: 'POST',
      headers,
      body: json ? JSON.stringify(body) : new URLSearchParams(body),
      redirect: 'manual',
      signal: AbortSignal.timeout(Math.max(deadline - now(), 1)),
    });
    bytes = await boundedBytes(response.body, 65536);
  } catch (e) {
    if (e instanceof Fault && e.code === 'body_too_large')
      throw failed(host, `answered HTTP ${response!.status} with more than 64 KiB`, 'response_too_large', {
        status: response!.status,
      });
    throw unavailable(host, response ? 'did not finish its answer in time' : 'did not answer in time');
  }
  const { status } = response;
  let answer: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) answer = parsed as Record<string, unknown>;
  } catch {}
  const upstream = { status, error: said(answer.error), error_description: said(answer.error_description) };
  if (status === 429 || status >= 500) throw unavailable(host, `answered HTTP ${status}`, upstream);
  if (status >= 300 && status < 400) throw failed(host, `answered HTTP ${status}, a redirect`, 'redirect', upstream);
  if (status >= 400) {
    const code = errorCode(answer.error);
    throw failed(host, `refused with HTTP ${status} (${code})`, code, upstream);
  }
  const token = answer.access_token;
  // The token goes into a header as it is.
  if (typeof token !== 'string' || !/^[\x21-\x7e]+$/.test(token))
    throw failed(host, `answered HTTP ${status} without a usable access_token`, 'no_access_token', upstream);
  const refresh = answer.refresh_token;
  if (refresh !== undefined && refresh !== null && (typeof refresh !== 'string' || !refresh || refresh.length > 16384))
    throw failed(host, `answered HTTP ${status} with an unusable refresh_token`, 'invalid_refresh_token', upstream);
  // Microsoft's v1 endpoint writes expires_in as a decimal string.
  const seconds = answer.expires_in;
  const expiresIn =
    typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0
      ? seconds * 1000
      : typeof seconds === 'string' && /^[0-9]{1,10}$/.test(seconds)
        ? Number(seconds) * 1000
        : undefined;
  return { accessToken: token, expiresIn, ...(typeof refresh === 'string' && { refreshToken: refresh }) };
}
/** When a token minted now expires: by the endpoint's expires_in, else the auth's ttl. */
export function expiryOf(auth: ExchangeAuth, minted: Minted) {
  const lasts = minted.expiresIn ?? (auth.ttl === undefined ? undefined : auth.ttl * 1000);
  return lasts === undefined ? undefined : now() + lasts;
}
/** The exchange the console's test of a connection that never rewrites its secret runs: one request,
 * no lock and no cache, audited under the Owner. no_expiry when the token has no expiry. */
async function testExchange(env: Bindings, owner: string, auth: ExchangeAuth, values: Record<string, string>) {
  assertFields(auth, values);
  let minted: Minted;
  try {
    minted = await requestToken(auth, values, await grantOf(auth, values), now() + TIME_LIMIT);
  } catch (e) {
    if (e instanceof TokenFault) await (await exchangeAudit(env, owner, 'owner', auth.secretId, e.result)).run();
    throw e;
  }
  const expiresAt = expiryOf(auth, minted);
  await (await exchangeAudit(env, owner, 'owner', auth.secretId, expiresAt ? 'ok' : 'no_expiry')).run();
  if (!expiresAt) throw failed(new URL(auth.tokenUrl).host, 'answered without expires_in', 'no_expiry');
  return { minted, expiresAt };
}

const exchangeAudit = (
  env: Bindings,
  owner: string,
  actor: string,
  secretId: string,
  result: string,
  where = '',
  args: unknown[] = [],
) => auditStatement(env, actor, 'token:exchange', secretId, { result, where, args, owner });
const currentSecret = (env: Bindings, owner: string, secretId: string) =>
  env.DB.prepare(
    "SELECT s.current_version AS version,v.envelope_json FROM secrets s JOIN secret_versions v ON v.secret_id=s.id AND v.version=s.current_version WHERE s.id=? AND s.owner_id=? AND s.status='active'",
  ).bind(secretId, owner);
type SecretRow = { version: number; envelope_json: string };
const openSecret = (env: Bindings, owner: string, secretId: string, row: SecretRow) =>
  decryptSecret(rootKeys(env), { ownerId: owner, secretId, version: row.version }, JSON.parse(row.envelope_json));
/** A cache row for a token minted from version of the secret; where (with args) writes it only when it holds. */
export async function cacheStatement(
  env: Bindings,
  owner: string,
  secretId: string,
  recipe: string,
  version: number,
  token: string,
  expiresAt: number,
  createdAt = now(),
  where = '',
  args: unknown[] = [],
) {
  const envelope = await encryptToken(rootKeys(env), { ownerId: owner, secretId, recipe }, token);
  return env.DB.prepare(
    `INSERT OR REPLACE INTO token_cache (secret_id,recipe,version,envelope_json,expires_at,created_at) SELECT ?,?,?,?,?,? ${where}`,
  ).bind(secretId, recipe, version, JSON.stringify(envelope), expiresAt, createdAt, ...args);
}
// Each write of the cache drops what has expired.
const expired = (env: Bindings) => env.DB.prepare('DELETE FROM token_cache WHERE expires_at<=?').bind(now());
export const releaseLock = (env: Bindings, secretId: string, holder: string, where = '', args: unknown[] = []) =>
  env.DB.prepare(`DELETE FROM token_locks WHERE secret_id=? AND holder=? ${where}`).bind(secretId, holder, ...args);

/** The secret's current version and the cached token of recipe, if one is good for it now. A row that
 * does not open counts as none. */
async function readState(a: Asker, secretId: string, recipe: string) {
  const [secret, cached] = await a.env.DB.batch([
    currentSecret(a.env, a.owner, secretId),
    a.env.DB.prepare(
      'SELECT version,envelope_json,expires_at,created_at FROM token_cache WHERE secret_id=? AND recipe=?',
    ).bind(secretId, recipe),
  ]);
  const row = secret.results[0] as SecretRow | undefined;
  assert(row, 'secret_not_found', 404);
  const hit = cached.results[0] as
    { version: number; envelope_json: string; expires_at: number; created_at: number } | undefined;
  if (hit && hit.version === row.version && now() < hit.expires_at - MARGIN)
    try {
      const value = await decryptToken(
        rootKeys(a.env),
        { ownerId: a.owner, secretId, recipe },
        JSON.parse(hit.envelope_json),
      );
      return { row, issued: { value, secretId, recipe, createdAt: hit.created_at } };
    } catch {}
  return { row, issued: undefined };
}
/** Takes the secret's exchange lock for holder, true when it did; a lock past its time is taken over.
 * releaseLock gives it back. */
export async function takeLock(env: Bindings, secretId: string, holder: string) {
  const [, taken] = await env.DB.batch([
    env.DB.prepare('DELETE FROM token_locks WHERE secret_id=? AND until<=?').bind(secretId, now()),
    // token_locks has no trigger, so this count is the row's alone.
    env.DB.prepare('INSERT OR IGNORE INTO token_locks (secret_id,holder,until) VALUES (?,?,?)').bind(
      secretId,
      holder,
      now() + LOCK,
    ),
  ]);
  return taken.meta.changes === 1;
}

/** The token of an exchanging auth: the cached one when it is good for the secret's current version,
 * otherwise one exchanged now under the secret's lock. Without the lock it waits for whoever holds it
 * and takes the token that one cached, or the lock once free, until the deadline. fresh exchanges even
 * when a cached token is good (the console's test of a connection). */
export async function derivedToken(a: Asker, auth: ExchangeAuth, fresh = false): Promise<Issued> {
  const recipe = await recipeOf(auth);
  const holder = id();
  for (;;) {
    const { issued } = await readState(a, auth.secretId, recipe);
    if (issued && !fresh) return issued;
    if (await takeLock(a.env, auth.secretId, holder)) {
      // Under the lock the exchange and its writes run to the end even when the client disconnects: a
      // rotated refresh token exists nowhere but in the endpoint's answer until it is written.
      const minted = await finish(
        (async () => {
          try {
            // The previous holder may have cached a token or rotated the secret since the read.
            const state = await readState(a, auth.secretId, recipe);
            if (state.issued && !fresh) {
              await releaseLock(a.env, auth.secretId, holder).run();
              return state.issued;
            }
            return await mint(a, auth, recipe, state.row, holder);
          } catch (e) {
            await releaseLock(a.env, auth.secretId, holder).run();
            throw e;
          }
        })(),
      );
      if (minted) return minted;
    } else {
      if (now() + POLL >= a.deadline)
        throw unavailable(new URL(auth.tokenUrl).host, 'was still being asked by another request when time ran out');
      await new Promise((resolve) => setTimeout(resolve, POLL));
    }
  }
}
/** Exchanges under the lock and caches the token in the batch that releases the lock, with a refresh
 * token the endpoint rotated written as the secret's next version. Undefined when the Owner replaced
 * the refresh token meanwhile: the exchange then starts over with the Owner's. */
async function mint(a: Asker, auth: ExchangeAuth, recipe: string, row: SecretRow, holder: string) {
  const values = await openSecret(a.env, a.owner, auth.secretId, row);
  // Nothing is asked of the endpoint before the Owner authorized the connection.
  if (authorizes(auth) && !Object.hasOwn(values, auth.refreshField)) throw notAuthorized();
  assertFields(auth, values);
  if (a.deadline - now() < EXCHANGE)
    throw unavailable(new URL(auth.tokenUrl).host, 'was still being asked by another request when time ran out');
  const grant = await grantOf(auth, values);
  let minted: Minted;
  try {
    minted = await requestToken(auth, values, grant, a.deadline);
  } catch (e) {
    // derivedToken releases the lock.
    if (e instanceof TokenFault) await (await exchangeAudit(a.env, a.owner, a.actor, auth.secretId, e.result)).run();
    throw e;
  }
  const expiresAt = expiryOf(auth, minted);
  const createdAt = now();
  const result = expiresAt ? 'ok' : 'no_expiry';
  // RFC 6749 §6: a refresh token in the response replaces the one used; none keeps it.
  if (
    auth.type === 'oauth-refresh' &&
    minted.refreshToken !== undefined &&
    minted.refreshToken !== values[auth.refreshField]
  ) {
    const written = await writeRefreshToken(a.env, {
      owner: a.owner,
      secretId: auth.secretId,
      field: auth.refreshField,
      token: minted.refreshToken,
      mode: 'rotation',
      used: values[auth.refreshField],
      base: { version: row.version, values },
      holder,
      exchange: { actor: a.actor, result },
      cache: expiresAt ? { recipe, token: minted.accessToken, expiresAt, createdAt } : undefined,
    });
    if (!written) return undefined;
  } else
    await a.env.DB.batch([
      ...(expiresAt
        ? [
            await cacheStatement(
              a.env,
              a.owner,
              auth.secretId,
              recipe,
              row.version,
              minted.accessToken,
              expiresAt,
              createdAt,
            ),
            expired(a.env),
          ]
        : []),
      releaseLock(a.env, auth.secretId, holder),
      await exchangeAudit(a.env, a.owner, a.actor, auth.secretId, result),
    ]);
  if (!expiresAt) throw failed(new URL(auth.tokenUrl).host, 'answered without expires_in', 'no_expiry');
  return { value: minted.accessToken, secretId: auth.secretId, recipe, createdAt };
}

/** A refresh token to store as the secret's next version, in the batch that ends the exchange it came
 * from: that batch releases holder's lock and writes the token:exchange audit row (exchange), and with
 * cache the access token of the same response, on the version after base only.
 * - rotation: the endpoint replaced used, the refresh token in base. The cached tokens of the secret's
 *   other recipes move to the new version, since their refresh token stays good upstream. The audit
 *   row of the new version is the system's.
 * - authorization: the Owner authorized anew, so every token cached before ends, and the Owner's audit
 *   row records the new version. field may be new to the secret.
 * When the version after base is taken (the Owner saved the secret meanwhile) the token goes on top of
 * the current version, at most three times; a rotation gives up when the Owner replaced used. */
export type RefreshWrite = {
  owner: string;
  secretId: string;
  field: string;
  token: string;
  mode: 'rotation' | 'authorization';
  used?: string;
  base: { version: number; values: Record<string, string> };
  holder: string;
  exchange: { actor: string; result: string };
  cache?: { recipe: string; token: string; expiresAt: number; createdAt: number };
};
/** True when the refresh token was written; false when it was not (see RefreshWrite), with the lock
 * released and the exchange audited all the same. */
export async function writeRefreshToken(env: Bindings, w: RefreshWrite): Promise<boolean> {
  let { version, values } = w.base;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt) {
      const row = await currentSecret(env, w.owner, w.secretId).first<SecretRow>();
      if (!row) break;
      version = row.version;
      values = await openSecret(env, w.owner, w.secretId, row);
    }
    if (w.mode === 'rotation' && values[w.field] !== w.used) break;
    const next = version + 1,
      vid = id();
    const envelope = await encryptSecret(
      rootKeys(env),
      { ownerId: w.owner, secretId: w.secretId, version: next },
      { ...values, [w.field]: w.token },
    );
    // Everything after the version row holds only when that row is this write's.
    const ours = 'WHERE EXISTS (SELECT 1 FROM secret_versions WHERE id=?)';
    const results = await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO secret_versions (id,secret_id,version,envelope_json,created_at) SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM secrets WHERE id=? AND owner_id=? AND current_version=? AND status='active')",
      ).bind(vid, w.secretId, next, JSON.stringify(envelope), now(), w.secretId, w.owner, version),
      env.DB.prepare(
        "UPDATE secrets SET current_version=?,updated_at=? WHERE id=? AND current_version=? AND status='active' AND EXISTS (SELECT 1 FROM secret_versions WHERE id=?)",
      ).bind(next, now(), w.secretId, version, vid),
      ...(w.mode === 'rotation'
        ? [
            env.DB.prepare(
              'UPDATE token_cache SET version=? WHERE secret_id=? AND version=? AND EXISTS (SELECT 1 FROM secret_versions WHERE id=?)',
            ).bind(next, w.secretId, version, vid),
          ]
        : []),
      // A token minted from base goes with the version that follows base, not one the Owner saved.
      ...(w.cache && version === w.base.version
        ? [
            await cacheStatement(
              env,
              w.owner,
              w.secretId,
              w.cache.recipe,
              next,
              w.cache.token,
              w.cache.expiresAt,
              w.cache.createdAt,
              ours,
              [vid],
            ),
            expired(env),
          ]
        : []),
      releaseLock(env, w.secretId, w.holder, `AND EXISTS (SELECT 1 FROM secret_versions WHERE id=?)`, [vid]),
      await exchangeAudit(env, w.owner, w.exchange.actor, w.secretId, w.exchange.result, ours, [vid]),
      await auditStatement(env, w.mode === 'rotation' ? 'system' : 'owner', 'secret:rotate', w.secretId, {
        where: ours,
        args: [vid],
        owner: w.owner,
      }),
    ]);
    // secret_versions has a trigger, so its count is checked against 0.
    if (results[0].meta.changes > 0) return true;
  }
  await env.DB.batch([
    releaseLock(env, w.secretId, w.holder),
    await exchangeAudit(env, w.owner, w.exchange.actor, w.secretId, w.exchange.result),
  ]);
  return false;
}
/** The console's test of a connection's credential with secret's values, as ownerFault answers a
 * failure. A JWT is signed once. A token that never rewrites the secret is exchanged once and its
 * returned statements cache it, to run once the connection is saved. A refresh token takes the path of
 * every request, fresh, so a refresh token the endpoint rotates is written to the secret at once, and
 * the secret has to be stored by then; one the Owner has yet to authorize has none to try. Any other
 * auth needs no test. */
export async function testCredential(
  env: Bindings,
  owner: string,
  auth: Auth,
  secret: { version: number; values: Record<string, string> },
): Promise<D1PreparedStatement[]> {
  try {
    if (auth.type === 'jwt') await signJwt(auth.jwt, secret.values);
    else if (auth.type === 'oauth-refresh') {
      if (Object.hasOwn(secret.values, auth.refreshField))
        await derivedToken({ env, owner, actor: 'owner', deadline: now() + TIME_LIMIT }, auth, true);
    } else if (auth.type === 'oauth-client' || auth.type === 'oauth-jwt') {
      const { minted, expiresAt } = await testExchange(env, owner, auth, secret.values);
      return [
        await cacheStatement(
          env,
          owner,
          auth.secretId,
          await recipeOf(auth),
          secret.version,
          minted.accessToken,
          expiresAt,
        ),
        expired(env),
      ];
    }
    return [];
  } catch (e) {
    throw ownerFault(e);
  }
}
/** Drops a cached token an upstream refused: by its creation as well, so a newer one stays. */
export const dropToken = (env: Bindings, issued: Issued) =>
  env.DB.prepare('DELETE FROM token_cache WHERE secret_id=? AND recipe=? AND created_at=?')
    .bind(issued.secretId, issued.recipe, issued.createdAt)
    .run();

// The authorization code flow (RFC 6749 §4.1, with PKCE) the Owner runs in the console on a saved
// connection whose auth has authorize: the start sends the browser to the upstream's authorization page,
// the console's callback page posts the code back, and the refresh token it is exchanged for becomes the
// secret's next version.

/** Where the upstream sends the browser back: the console's page of one connection. An address per
 * connection keeps the code of one authorization server from another's token endpoint (RFC 9700 §4.4.2). */
export const callbackUrl = (env: Bindings, connection: string) => `${env.APP_ORIGIN}/oauth/callback/${connection}`;
// An authorization is completed within 10 minutes of its start.
const FLOW = 600000;
const authOf = (env: Bindings, owner: string, connection: string) =>
  env.DB.prepare("SELECT auth_json FROM connections WHERE id=? AND owner_id=? AND status='active'")
    .bind(connection, owner)
    .first<{ auth_json: string }>();
/** Starts an authorization of connection by the Owner's session: stores the digest of a new state with
 * the session, the connection and the digest of its auth as it is now, for 10 minutes, and returns the
 * authorization URL and its host. The state goes nowhere but into that URL; the PKCE verifier is derived
 * from it (pkceVerifier) under the current root key, whose id leads the state so that completion derives
 * it under the same key, and neither is stored. */
export async function startAuthorization(env: Bindings, owner: string, session: string, connection: string) {
  const row = await authOf(env, owner, connection);
  assert(row, 'connection_not_found', 404);
  const auth = JSON.parse(row.auth_json) as Auth;
  assert(
    authorizes(auth),
    'authorization_not_configured',
    400,
    'Only a connection of type oauth-refresh with authorize is authorized in the console.',
  );
  const secret = await currentSecret(env, owner, auth.secretId).first<SecretRow>();
  assert(secret, 'secret_not_found', 404);
  const clientId = valueOf(auth.client.id, await openSecret(env, owner, auth.secretId, secret));
  assert(
    clientId !== undefined,
    'client_id_required',
    400,
    'auth.client.id: an authorization request names its client, so the connection needs a client id.',
  );
  const [root] = rootKeys(env);
  const state = `${root.id}.${encode(crypto.getRandomValues(new Uint8Array(32)))}`;
  const url = new URL(auth.authorize.url);
  // RFC 6749 §3.1: an authorization server ignores a parameter it does not know, so the PKCE ones go to
  // every upstream, and the reserved names (refused in params) are always the service's.
  for (const [name, value] of Object.entries({
    ...auth.authorize.params,
    response_type: 'code',
    client_id: clientId,
    redirect_uri: callbackUrl(env, connection),
    ...(auth.authorize.scope !== undefined && { scope: auth.authorize.scope }),
    state,
    code_challenge: await digest(await pkceVerifier(root, state)),
    code_challenge_method: 'S256',
  }))
    url.searchParams.set(name, value);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM oauth_flows WHERE expires_at<=?').bind(now()),
    env.DB.prepare(
      'INSERT INTO oauth_flows (state_hash,session_id,connection_id,auth_hash,expires_at) VALUES (?,?,?,?,?)',
    ).bind(await digest(state), session, connection, await digest(row.auth_json), now() + FLOW),
  ]);
  return { url: url.href, host: url.host };
}
/** A connection authorized in the console whose token endpoint named no expiry: the refresh token is
 * stored, but no request runs until the connection has a ttl. */
export type AuthorizationWarning = { connection: string; error: 'ttl_required'; hint: string };
/** Completes the authorization state started, in the same session and on the same connection, whose auth
 * is still what it was then: spends the state, exchanges code at the token endpoint under the secret's
 * lock, and writes the refresh token it got as the secret's next version, over any version the Owner
 * saved meanwhile, with the access token cached and both audited under the Owner. A failure is answered
 * as ownerFault answers it; an answer without a refresh token writes nothing. */
export async function completeAuthorization(
  env: Bindings,
  owner: string,
  session: string,
  input: { connection: string; state: string; code: string },
): Promise<AuthorizationWarning[]> {
  const flow = await env.DB.prepare(
    'DELETE FROM oauth_flows WHERE state_hash=? AND expires_at>? RETURNING session_id,connection_id,auth_hash',
  )
    .bind(await digest(input.state), now())
    .first<{ session_id: string; connection_id: string; auth_hash: string }>();
  assert(
    flow && flow.session_id === session && flow.connection_id === input.connection,
    'authorization_expired',
    400,
    'This authorization is unknown, more than 10 minutes old, already completed, or was started in another session or for another connection. Start it again from the connection.',
  );
  // The state names the root key its verifier was derived under; the ring may have changed since.
  const root = rootKeys(env).find((k) => k.id === input.state.split('.')[0]);
  assert(
    root,
    'authorization_expired',
    400,
    'The root key this authorization started under has left the service. Start it again from the connection.',
  );
  const row = await authOf(env, owner, input.connection);
  assert(
    row && (await digest(row.auth_json)) === flow.auth_hash,
    'connection_changed',
    409,
    'The connection was changed or deleted after this authorization started. Start it again from the connection.',
  );
  const auth = JSON.parse(row.auth_json) as Extract<Auth, { type: 'oauth-refresh' }>;
  const host = new URL(auth.tokenUrl).host;
  // The state is spent, so the Owner starts over rather than sending this again.
  const tooLate = () =>
    new Fault(
      'token_unavailable',
      503,
      `Another exchange of this credential held it until too little time was left, so nothing was sent to the token endpoint ${host}. This authorization is spent: start it again from the connection.`,
    );
  const deadline = now() + TIME_LIMIT,
    holder = id();
  while (!(await takeLock(env, auth.secretId, holder))) {
    if (now() + POLL >= deadline) throw tooLate();
    await new Promise((resolve) => setTimeout(resolve, POLL));
  }
  // As in derivedToken, the exchange and its writes run to the end for a client that disconnects: the
  // code works once, and the refresh token exists nowhere but in the endpoint's answer until written.
  return finish(
    (async () => {
      try {
        const secret = await currentSecret(env, owner, auth.secretId).first<SecretRow>();
        assert(secret, 'secret_not_found', 404);
        const values = await openSecret(env, owner, auth.secretId, secret);
        assertFields(auth, values);
        if (deadline - now() < EXCHANGE) throw tooLate();
        let minted: Minted;
        try {
          minted = await requestToken(
            auth,
            values,
            {
              grant_type: 'authorization_code',
              code: input.code,
              redirect_uri: callbackUrl(env, input.connection),
              code_verifier: await pkceVerifier(root, input.state),
            },
            deadline,
          );
        } catch (e) {
          if (e instanceof TokenFault) await (await exchangeAudit(env, owner, 'owner', auth.secretId, e.result)).run();
          throw e;
        }
        if (minted.refreshToken === undefined) {
          await (await exchangeAudit(env, owner, 'owner', auth.secretId, 'no_refresh_token')).run();
          throw new Fault(
            'no_refresh_token',
            502,
            `The token endpoint ${host} answered without a refresh_token, so nothing was stored. Check the authorization parameters and scope of the connection: Google needs access_type=offline and prompt=consent, Microsoft the scope offline_access, Atlassian offline_access and prompt=consent, Dropbox token_access_type=offline.`,
          );
        }
        const expiresAt = expiryOf(auth, minted);
        const written = await writeRefreshToken(env, {
          owner,
          secretId: auth.secretId,
          field: auth.refreshField,
          token: minted.refreshToken,
          mode: 'authorization',
          base: { version: secret.version, values },
          holder,
          exchange: { actor: 'owner', result: expiresAt ? 'ok' : 'no_expiry' },
          cache: expiresAt
            ? { recipe: await recipeOf(auth), token: minted.accessToken, expiresAt, createdAt: now() }
            : undefined,
        });
        assert(
          written,
          'version_conflict',
          409,
          'The credential kept changing while the refresh token was being stored. Authorize the connection again.',
        );
        return expiresAt
          ? []
          : [
              {
                connection: input.connection,
                error: 'ttl_required' as const,
                hint: 'The token endpoint answered without expires_in. The refresh token is stored, but no request runs until the connection has a ttl in seconds.',
              },
            ];
      } catch (e) {
        await releaseLock(env, auth.secretId, holder).run();
        throw ownerFault(e);
      }
    })(),
  );
}
