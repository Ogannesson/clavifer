import { Buffer } from 'node:buffer';
import { Fault, assert } from '../../../packages/core/errors';
import { type Bindings, id, now, audit } from './context';
import { serialized, snapshot, validateRecipient } from './export';

// The columns a snapshot carries from each table of migratable data. Their size as stored bounds the
// automatic backup and decides when sealing moves rows out. length() of a text counts characters, so
// every column is measured as a blob.
export const CARRIED = {
  user: 'id,name,email,emailVerified,image,createdAt,updatedAt',
  account: 'password,createdAt,updatedAt',
  passkey: 'id,name,publicKey,credentialID,counter,deviceType,backedUp,transports,createdAt,aaguid',
  secrets: 'id,name,description,status,current_version,created_at,updated_at',
  secret_versions: 'secret_id,version,envelope_json,created_at',
  connections: 'id,name,origin,description,auth_json,policy_json,status,created_at,updated_at',
  oauthClient: 'clientId,name,applicationType,redirectUris,scopes,grantTypes,disabled,createdAt,updatedAt',
  grants: 'id,client_id,resource_type,resource_id,permission,fields_json,extensions_json,status,expires_at,created_at',
  access_requests: 'id,client_id,requested_json,reason,status,fingerprint,consumed_at,created_at,expires_at',
  audit_events: 'id,client_id,action,resource_id,result,request_id,created_at',
  archive_segments: 'kind,seq,object_key,sha256,first_at,first_id,last_at,last_id,rows,created_at',
};
/** The bytes of one row of table, as an SQL expression over its carried columns. */
export const rowBytes = (table: keyof typeof CARRIED) =>
  CARRIED[table]
    .split(',')
    .map((column) => `IFNULL(length(CAST("${column}" AS BLOB)),0)`)
    .join('+');
type Table = keyof typeof CARRIED;
/** The bytes of every row of tables, as one statement. */
const bytesOf = (env: Bindings, tables: Table[]) =>
  env.DB.prepare(
    `SELECT ${tables.map((table) => `(SELECT IFNULL(SUM(${rowBytes(table)}),0) FROM "${table}")`).join('+')} AS bytes`,
  ).first<{ bytes: number }>();
// About 12 MB of JSON Lines, which an isolate assembles and encrypts within its 128 MB.
const HOT_LIMIT = 9_000_000;
// What sealing never moves out: the Owner's own data, and the manifest of what it sealed. Above
// HOT_LIMIT on its own it stops every automatic backup, so the console warns as it grows.
const UNSEALED = (Object.keys(CARRIED) as Table[]).filter(
  (table) => table !== 'audit_events' && table !== 'access_requests',
);
type BackupState = {
  recipient: string | null;
  config_version: number;
  revision: number;
  success_revision: number;
  success_config_version: number;
  success_at: number | null;
  attempt_at: number | null;
  last_error: string | null;
  retention_error: string | null;
  archive_error: string | null;
  object_key: string | null;
  sha256: string | null;
  lease_until: number;
};
async function backupState(env: Bindings) {
  const state = await env.DB.prepare('SELECT * FROM backup_state WHERE id=1').first<BackupState>();
  assert(state, 'backup_state_unavailable', 503);
  return state;
}
const RETENTION = { daily: 30, monthly: 12 };
export async function backupStatus(env: Bindings) {
  const s = await backupState(env);
  return {
    configured: !!s.recipient,
    recipient: s.recipient,
    revision: s.revision,
    savedRevision: s.success_revision,
    lastSuccessAt: s.success_at,
    lastAttemptAt: s.attempt_at,
    lastError: s.last_error,
    pending: !!s.recipient && (s.revision !== s.success_revision || s.config_version !== s.success_config_version),
    running: s.lease_until > now(),
    downloadAvailable: !!s.object_key,
    sha256: s.sha256,
    scheduleMinutes: 15,
    storage: 'R2',
    independentCopy: false,
    retention: RETENTION,
    retentionError: s.retention_error,
    archiveError: s.archive_error,
    unsealedBytes: (await bytesOf(env, UNSEALED))!.bytes,
  };
}
// Keep the newest object of every recent day, then of every month in the year before that.
export async function pruneBackups(env: Bindings, current: string) {
  const time = now(),
    dailyCutoff = time - RETENTION.daily * 86400000;
  const monthlyStart = new Date(dailyCutoff);
  monthlyStart.setUTCMonth(monthlyStart.getUTCMonth() - RETENTION.monthly);
  const newest = new Map<string, { key: string; uploaded: number }>();
  const stale: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.BACKUPS.list({ prefix: 'vault/', cursor });
    for (const object of page.objects) {
      const uploaded = object.uploaded.getTime(),
        iso = object.uploaded.toISOString();
      const bucket =
        uploaded >= dailyCutoff ? iso.slice(0, 10) : uploaded >= monthlyStart.getTime() ? iso.slice(0, 7) : null;
      const kept = bucket ? newest.get(bucket) : undefined;
      if (!bucket) stale.push(object.key);
      else if (!kept) newest.set(bucket, { key: object.key, uploaded });
      else if (uploaded > kept.uploaded) {
        stale.push(kept.key);
        newest.set(bucket, { key: object.key, uploaded });
      } else stale.push(object.key);
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  const removable = stale.filter((key) => key !== current);
  for (let i = 0; i < removable.length; i += 1000) await env.BACKUPS.delete(removable.slice(i, i + 1000));
  return removable.length;
}
export async function configureBackup(env: Bindings, recipient: string | null) {
  if (recipient !== null) validateRecipient(recipient);
  // Invalidate any overlapping exporter; its object is retained but never advertised as current.
  await env.DB.prepare(
    'UPDATE backup_state SET recipient=?,config_version=config_version+1,last_error=NULL,lease_token=NULL,lease_until=0 WHERE id=1',
  )
    .bind(recipient)
    .run();
  await audit(env, 'owner', recipient ? 'backup:configure' : 'backup:disable', null);
  return backupStatus(env);
}
export async function runAutomaticBackup(env: Bindings, owner: string, force = false) {
  const s = await backupState(env);
  if (!s.recipient) return { outcome: 'not_configured' };
  const time = now(),
    token = id();
  const lease = await env.DB.prepare(
    `UPDATE backup_state SET lease_token=?,lease_until=?,attempt_at=? WHERE id=1 AND config_version=? AND lease_until<=? AND (?=1 OR success_revision<revision OR success_config_version!=config_version OR success_at IS NULL OR success_at<=?)`,
  )
    .bind(token, time + 300000, time, s.config_version, time, force ? 1 : 0, time - 86400000)
    .run();
  if (lease.meta.changes !== 1) return { outcome: s.lease_until > time ? 'running' : 'up_to_date' };
  try {
    // Above the limit this backup is skipped and reports why; it runs again once sealing has moved
    // enough rows out.
    const hot = await bytesOf(env, Object.keys(CARRIED) as Table[]);
    assert(hot!.bytes <= HOT_LIMIT, 'hot_data_over_limit', 413);
    // Assembled whole in memory: the hot data is bounded, and a segment is carried by its key only.
    const { records, revision } = await snapshot(env, owner);
    const encrypted = new Uint8Array(await validateRecipient(s.recipient).encrypt(serialized(records)));
    const hash = Buffer.from(await crypto.subtle.digest('SHA-256', encrypted)).toString('hex');
    const key = `vault/${new Date(time).toISOString().slice(0, 10)}/${time}-${token}.age`;
    // R2 checks the upload against sha256 and keeps it for head().
    const object = await env.BACKUPS.put(key, encrypted, {
      httpMetadata: { contentType: 'application/octet-stream' },
      sha256: hash,
    });
    assert(object, 'backup_storage_failed', 503);
    const saved = await env.DB.prepare(
      'UPDATE backup_state SET success_revision=?,success_config_version=?,success_at=?,object_key=?,sha256=?,last_error=NULL,lease_token=NULL,lease_until=0 WHERE id=1 AND lease_token=? AND config_version=?',
    )
      .bind(revision, s.config_version, now(), key, hash, token, s.config_version)
      .run();
    if (saved.meta.changes !== 1) return { outcome: 'superseded' };
    await audit(env, 'system', 'backup:automatic', null);
    // The new copy is already published; failing to delete older ones does not undo it.
    let retention = null;
    try {
      await pruneBackups(env, key);
    } catch {
      retention = 'backup_retention_failed';
    }
    await env.DB.prepare('UPDATE backup_state SET retention_error=? WHERE id=1').bind(retention).run();
    return { outcome: 'saved', revision, sha256: hash };
  } catch (e) {
    const code = e instanceof Fault ? e.code : 'backup_failed';
    await env.DB.prepare(
      'UPDATE backup_state SET last_error=?,lease_token=NULL,lease_until=0 WHERE id=1 AND lease_token=?',
    )
      .bind(code, token)
      .run();
    // Do not log upstream messages, snapshot values, credentials or signed URLs.
    await audit(env, 'system', 'backup:automatic', null, code);
    throw new Fault(
      code,
      e instanceof Fault ? e.status : 503,
      e instanceof Fault ? e.message : 'Automatic backup failed.',
    );
  }
}
export async function downloadLatestBackup(env: Bindings) {
  const s = await backupState(env);
  assert(s.object_key, 'backup_not_found', 404);
  const object = await env.BACKUPS.get(s.object_key);
  assert(object, 'backup_not_found', 404);
  return new Response(object.body, {
    headers: {
      'content-type': 'application/octet-stream',
      'content-disposition': 'attachment; filename="clavifer-latest.age"',
      'cache-control': 'no-store',
      'x-backup-sha256': s.sha256 ?? '',
      'x-backup-revision': String(s.success_revision),
    },
  });
}
