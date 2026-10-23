import { z } from 'zod';
import { getTableName } from 'drizzle-orm';
import { hashPassword } from 'better-auth/crypto';
import { generateHybridIdentity } from 'age-encryption';
import * as authTables from '../../../packages/auth/schema';
import { digest, encryptArchiveIdentity, rootKeyFingerprints } from '../../../packages/core/crypto';
import { Fault, assert } from '../../../packages/core/errors';
import { type Bindings, auditStatement, createAuth, id, now, rootKeys } from './context';
import { recipientInput, validateRecipient } from './export';

// Initializing an instance and recovering its Owner both take the one-time token the deployment issues
// into system_state as bootstrap_token: {hash, expiresAt}. The token itself only ever travels in the
// x-bootstrap-token header.

const password = z.string().min(12).max(128);
export const ownerInput = z.object({
  name: z.string().min(1).max(100),
  email: z.email(),
  password,
  backupRecipient: recipientInput,
});
export const resetInput = z.object({ password });
const invalidToken = () =>
  new Fault(
    'invalid_bootstrap_token',
    401,
    'The token is wrong, expired or already used. The deployment issues a new one; it replaces any earlier token.',
  );

/** The instance as a live token sees it: the Owner's id and login email once there is an Owner. Checked
 * before anything else, so a caller without the token never makes the server hash a password. */
export async function tokenState(env: Bindings, token: string | undefined) {
  const row = token
    ? await env.DB.prepare(
        `SELECT o.value AS owner,(SELECT email FROM "user" WHERE id=o.value) AS email FROM system_state t LEFT JOIN system_state o ON o.key='owner_user_id' WHERE t.key='bootstrap_token' AND json_extract(t.value,'$.hash')=? AND json_extract(t.value,'$.expiresAt')>?`,
      )
        .bind(await digest(token), now())
        .first<{ owner: string | null; email: string | null }>()
    : null;
  if (!row) throw invalidToken();
  return row;
}

/** The first statement of a batch that spends the token. It inserts the stored token only when hash
 * names it, it has not expired and the instance is in the state the operation needs; otherwise it
 * inserts NULL, which the column refuses, and the whole batch rolls back. Nothing weaker would do: a
 * statement that matches no row does not abort a batch. The batch ends with deleteToken. */
export const tokenGuard = (env: Bindings, hash: string, initialized: boolean) =>
  env.DB.prepare(
    `INSERT INTO system_state (key,value,updated_at) SELECT 'token_spent',(SELECT value FROM system_state WHERE key='bootstrap_token' AND json_extract(value,'$.hash')=? AND json_extract(value,'$.expiresAt')>? AND ${initialized ? '' : 'NOT '}EXISTS (SELECT 1 FROM system_state WHERE key='owner_user_id')),?`,
  ).bind(hash, now(), now());
export const deleteToken = (env: Bindings) =>
  env.DB.prepare("DELETE FROM system_state WHERE key IN ('bootstrap_token','token_spent')");
/** Runs a batch that starts with tokenGuard. Its guard is the only statement that can fail on NULL. */
export async function consumeToken(env: Bindings, statements: D1PreparedStatement[]) {
  try {
    await env.DB.batch(statements);
  } catch (e) {
    if (e instanceof Error && e.message.includes('NOT NULL constraint failed: system_state.value'))
      throw invalidToken();
    throw e;
  }
}

// An uninitialized instance holds nothing valid: whatever is there was left by an initialization that
// did not complete. Every table of the instance's data and every Better Auth table starts empty;
// a table added later goes in this list.
const cleared = [
  'secrets',
  'secret_versions',
  'connections',
  'grants',
  'access_requests',
  'audit_events',
  'archive_segments',
  'import_chunks',
  ...Object.values(authTables).map((table) => getTableName(table)),
];
/** Empties the instance inside a batch that has spent an uninitialized instance's token, keeping only
 * the token rows; backup_state goes back to the row the migration created, and oauthResource to the one
 * resource of the configuration, as the OAuth provider seeds it. Left to the provider, every Better Auth
 * instance that starts before the row exists inserts it, and the provider does not recognize the
 * duplicate key error of the one that comes second (drizzle wraps it): that request fails, as does every
 * later one of an isolate that kept its instance. */
export function clearOut(env: Bindings) {
  const resource = `${env.APP_ORIGIN}/v1`,
    time = now();
  return [
    ...cleared.map((table) => env.DB.prepare(`DELETE FROM "${table}"`)),
    env.DB.prepare("DELETE FROM system_state WHERE key NOT IN ('bootstrap_token','token_spent')"),
    env.DB.prepare('INSERT OR REPLACE INTO backup_state (id) VALUES (1)'),
    env.DB.prepare(
      'INSERT INTO "oauthResource" (id,identifier,name,dpopBoundAccessTokensRequired,disabled,policyVersion,createdAt,updatedAt) VALUES (?,?,?,0,0,1,?,?)',
    ).bind(id(), resource, resource, time, time),
  ];
}

/** Creates the Owner of an uninitialized instance in one batch and returns the session cookie of its
 * first sign-in. No sign-up runs, so a failure leaves no user behind. The archive identity is stored
 * encrypted in system_state as archive_identity. */
export async function createOwner(
  env: Bindings,
  token: string | undefined,
  input: z.infer<typeof ownerInput>,
  headers: Headers,
) {
  assert(!(await tokenState(env, token)).owner, 'already_initialized', 409);
  validateRecipient(input.backupRecipient);
  const uid = id(),
    time = now(),
    email = input.email.toLowerCase(),
    ring = rootKeys(env);
  const state = (key: string, value: string) =>
    env.DB.prepare('INSERT INTO system_state (key,value,updated_at) VALUES (?,?,?)').bind(key, value, time);
  await consumeToken(env, [
    tokenGuard(env, await digest(token!), false),
    ...clearOut(env),
    env.DB.prepare(
      'INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt) VALUES (?,?,?,0,NULL,?,?)',
    ).bind(uid, input.name, email, time, time),
    // Better Auth signs in a password only through this row: provider credential, account id = user id.
    env.DB.prepare(
      "INSERT INTO account (id,accountId,providerId,userId,password,createdAt,updatedAt) VALUES (?,?,'credential',?,?,?,?)",
    ).bind(id(), uid, uid, await hashPassword(input.password), time, time),
    state('owner_user_id', uid),
    state('root_key_fingerprints', JSON.stringify(await rootKeyFingerprints(ring))),
    state('archive_identity', JSON.stringify(await encryptArchiveIdentity(ring, uid, await generateHybridIdentity()))),
    env.DB.prepare('UPDATE backup_state SET recipient=? WHERE id=1').bind(input.backupRecipient),
    await auditStatement(env, 'owner', 'owner:create', uid, { owner: uid }),
    deleteToken(env),
  ]);
  const { headers: response } = await (
    await createAuth(env)
  ).api.signInEmail({ body: { email, password: input.password }, headers, returnHeaders: true });
  return response.getSetCookie();
}

/** Gives the Owner a new password and signs every browser out: Passkeys and sessions go, while
 * installations, grants and their refresh tokens stay. */
export async function resetOwner(env: Bindings, token: string | undefined, input: z.infer<typeof resetInput>) {
  const { owner } = await tokenState(env, token);
  assert(owner, 'not_initialized', 409);
  await consumeToken(env, [
    tokenGuard(env, await digest(token!), true),
    env.DB.prepare("UPDATE account SET password=?,updatedAt=? WHERE userId=? AND providerId='credential'").bind(
      await hashPassword(input.password),
      now(),
      owner,
    ),
    env.DB.prepare('DELETE FROM passkey WHERE userId=?').bind(owner),
    env.DB.prepare('DELETE FROM session WHERE userId=?').bind(owner),
    await auditStatement(env, 'owner', 'owner:recover', owner),
    deleteToken(env),
  ]);
}
