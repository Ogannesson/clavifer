// The one-time token for the console's /setup page. The deployment issues it into the instance's
// database; the token itself goes only to a file. Running issueSql replaces any earlier token.
import { randomBytes, createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';

// D1's own clock sets the expiry, in the same statement that decides it: 24 hours to create the Owner
// of an uninitialized instance, 1 hour to recover the Owner of an initialized one.
export const issueSql =
  "INSERT OR REPLACE INTO system_state (key,value,updated_at) VALUES ('bootstrap_token',json_object('hash',?,'expiresAt',CAST(strftime('%s','now') AS INTEGER)*1000+CASE WHEN EXISTS (SELECT 1 FROM system_state WHERE key='owner_user_id') THEN 3600000 ELSE 86400000 END),CAST(strftime('%s','now') AS INTEGER)*1000)";

/** A new token and the binds of issueSql that make it the instance's token. */
export function newToken() {
  const token = randomBytes(32).toString('base64url');
  return { token, binds: [createHash('sha256').update(token).digest('base64url')] };
}

/** Writes a new token to path, a file that must not exist yet and only its owner may read, and returns
 * the path with the statement that makes it valid. Nothing returned contains the token. */
export async function issueToken(path) {
  const { token, binds } = newToken();
  await writeFile(path, token, { mode: 0o600, flag: 'wx' });
  return { path, sql: issueSql, binds };
}
