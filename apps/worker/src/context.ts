import { AsyncLocalStorage } from 'node:async_hooks';
import type { ZodError } from 'zod';
import { drizzle } from 'drizzle-orm/d1';
import { drizzleAdapter } from '@better-auth/drizzle-adapter';
import { betterAuth } from 'better-auth/minimal';
import { verifyJwsAccessToken } from 'better-auth/oauth2';
import { authPlugins, emailPassword } from '../../../packages/auth/policy';
import * as schema from '../../../packages/auth/schema';
import { Fault, assert } from '../../../packages/core/errors';
import { parseRootKeys, deriveKey, rootKeyFingerprints, encode } from '../../../packages/core/crypto';

export type Bindings = Env & {
  ROOT_KEY?: string;
};
export type Principal = { clientId: string; userId: string; scopes: string[] };
export const VERSION = '0.5.0';
export const now = () => Date.now();
export const id = () => crypto.randomUUID();
// Every audit row of one invocation carries the request id published in the
// x-request-id response header, including rows written inside MCP tool calls.
const currentRequestId = new AsyncLocalStorage<string>();
export const withRequestId = <T>(value: string, fn: () => T) => currentRequestId.run(value, fn);
// For work that runs after the handler returned, such as the end of a streamed response.
export const requestId = () => currentRequestId.getStore() ?? id();
// The Owner id and the Better Auth instance are immutable once the Owner
// exists, so an isolate resolves them once instead of per request.
let owner = '';
let authInstance: Awaited<ReturnType<typeof buildAuth>> | undefined;
export async function ownerId(env: Bindings) {
  if (owner) return owner;
  return (owner =
    (
      await env.DB.prepare('SELECT value FROM system_state WHERE key=?')
        .bind('owner_user_id')
        .first<{ value: string }>()
    )?.value ?? '');
}
export const rootKeys = (env: Bindings) => parseRootKeys(env.ROOT_KEY ?? '');
// The database records the fingerprint of every root key in the ring when the Owner is created. A
// Worker whose ring no longer matches them (the key was replaced, or the Worker is bound to another
// instance's database) refuses everything but /healthz instead of writing data under a new key. A
// match is final for the isolate; an uninitialized instance is checked again on every request, since
// another isolate may complete the setup at any time.
let keysMatched = false;
export async function keyState(env: Bindings): Promise<'ok' | 'mismatch' | 'uninitialized'> {
  if (keysMatched) return 'ok';
  const rows = await env.DB.prepare(
    "SELECT key,value FROM system_state WHERE key IN ('owner_user_id','root_key_fingerprints')",
  ).all<{ key: string; value: string }>();
  const state = Object.fromEntries(rows.results.map((r) => [r.key, r.value]));
  if (!state.owner_user_id) return 'uninitialized';
  const recorded: Record<string, string> = JSON.parse(state.root_key_fingerprints ?? '{}');
  const ring = rootKeys(env);
  const current = await rootKeyFingerprints(ring);
  keysMatched =
    Object.hasOwn(recorded, ring[0].id) && Object.entries(recorded).every(([kid, value]) => current[kid] === value);
  return keysMatched ? 'ok' : 'mismatch';
}
export async function createAuth(env: Bindings) {
  if (authInstance) return authInstance;
  const oid = await ownerId(env);
  const auth = await buildAuth(env, oid);
  // Every use of an instance awaits its one initialization, so one that failed would fail them all.
  await auth.$context;
  if (oid) authInstance = auth;
  return auth;
}
async function buildAuth(env: Bindings, oid: string) {
  // One Better Auth secret per root key, the version being the key's id: cookies and signed queries use
  // the current one, and the signing keys stay readable under every key still in the ring.
  const secrets = await Promise.all(
    rootKeys(env).map(async ({ id, key }) => ({
      version: Number(id),
      value: encode(await deriveKey(key, 'better-auth')),
    })),
  );
  return betterAuth({
    baseURL: env.APP_ORIGIN,
    secrets,
    trustedOrigins: [env.APP_ORIGIN],
    database: drizzleAdapter(drizzle(env.DB), { provider: 'sqlite', camelCase: true, transaction: false, schema }),
    session: { expiresIn: 86400, updateAge: 3600 },
    // The Owner is written by /api/setup; nobody signs up.
    emailAndPassword: { ...emailPassword, disableSignUp: true },
    // /device is Owner-only at the routing layer. Keep guessing protection on
    // public endpoints while allowing normal multi-device administration.
    rateLimit: {
      enabled: true,
      storage: 'database',
      window: 60,
      max: 100,
      customRules: { '/device': { window: 60, max: 30 } },
    },
    advanced: { ipAddress: { ipAddressHeaders: ['cf-connecting-ip'] } },
    plugins: authPlugins(env.APP_ORIGIN, oid),
  });
}
export async function requireOwner(request: Request, env: Bindings, recent = false) {
  const session = await (await createAuth(env)).api.getSession({ headers: request.headers });
  assert(session?.user.id && session.user.id === (await ownerId(env)), 'owner_auth_required', 401);
  if (recent) assert(now() - new Date(session.session.createdAt).getTime() < 600_000, 'recent_login_required', 403);
  return session.user;
}
export function requireOrigin(request: Request, env: Bindings) {
  assert(request.headers.get('origin') === env.APP_ORIGIN, 'origin_not_allowed', 403);
}
// A stable object lets Better Auth cache the key set of a function source; per
// request closures would otherwise query the jwks table on every verification.
const jwksCacheKey = {};
export async function principal(request: Request, env: Bindings, required: string[] = []): Promise<Principal> {
  const authorization = request.headers.get('authorization') ?? '';
  assert(authorization.startsWith('Bearer '), 'missing_bearer_token', 401);
  let payload;
  try {
    payload = await verifyJwsAccessToken(authorization.slice(7).trim(), {
      jwksFetch: async () => {
        const rows = await env.DB.prepare('SELECT id,publicKey,alg,crv FROM jwks').all<{
          id: string;
          publicKey: string;
          alg?: string;
          crv?: string;
        }>();
        return {
          keys: rows.results.map((k) => ({
            ...JSON.parse(k.publicKey),
            kid: k.id,
            ...(k.alg ? { alg: k.alg } : {}),
            ...(k.crv ? { crv: k.crv } : {}),
          })),
        };
      },
      jwksCacheKey,
      verifyOptions: { audience: `${env.APP_ORIGIN}/v1`, issuer: `${env.APP_ORIGIN}/api/auth` },
    });
  } catch {
    throw new Fault('invalid_token', 401);
  }
  const clientId = String(payload.client_id ?? payload.azp ?? '');
  const userId = String(payload.sub ?? '');
  const row = await env.DB.prepare('SELECT userId,disabled FROM oauthClient WHERE clientId=?')
    .bind(clientId)
    .first<{ userId: string; disabled: number }>();
  assert(row && !row.disabled && row.userId === (await ownerId(env)) && userId === row.userId, 'client_revoked', 401);
  const scopes = String(payload.scope ?? '').split(/\s+/);
  assert(
    required.every((s) => scopes.includes(s)),
    'insufficient_scope',
    403,
  );
  return { clientId, userId, scopes };
}
/** An audit row as a statement, for a batch that writes it together with what it records. where (a
 * WHERE clause and its arguments) writes the row only when it holds, as the batch's other writes do.
 * owner is given only by the batch that creates the Owner, before anything records it. */
export async function auditStatement(
  env: Bindings,
  actor: string,
  action: string,
  resource: string | null,
  {
    result = 'ok',
    where = '',
    args = [],
    owner,
  }: { result?: string; where?: string; args?: unknown[]; owner?: string } = {},
) {
  return env.DB.prepare(
    `INSERT INTO audit_events (id,owner_id,client_id,action,resource_id,result,request_id,created_at) SELECT ?,?,?,?,?,?,?,? ${where}`,
  ).bind(id(), owner ?? (await ownerId(env)), actor, action, resource, result, requestId(), now(), ...args);
}
export async function audit(env: Bindings, actor: string, action: string, resource: string | null, result = 'ok') {
  return (await auditStatement(env, actor, action, resource, { result })).run();
}
export async function boundedBytes(stream: ReadableStream<Uint8Array> | null, max = 1024 * 1024) {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > max) {
        await reader.cancel();
        throw new Fault('body_too_large', 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
/** The hint for invalid input: each offending field and what is wrong with it. */
export const issuesHint = (e: ZodError) =>
  e.issues
    .slice(0, 5)
    .map((issue) => `${issue.path.join('.') || 'input'}: ${issue.message}`)
    .join('; ');
export async function readJson(request: Request, max = 1024 * 1024): Promise<unknown> {
  assert(request.headers.get('content-type')?.split(';')[0] === 'application/json', 'json_required', 415);
  try {
    return JSON.parse(new TextDecoder().decode(await boundedBytes(request.body, max)));
  } catch (e) {
    if (e instanceof Fault) throw e;
    throw new Fault('invalid_json', 400);
  }
}
