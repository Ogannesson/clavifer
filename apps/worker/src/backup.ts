import { z } from 'zod';
import { Buffer } from 'node:buffer';
import { Encrypter } from 'age-encryption';
import { encryptSecret, decryptSecret } from '../../../packages/core/crypto';
import { Fault, assert } from '../../../packages/core/errors';
import { type Bindings, id, now, parseKeys, audit } from './context';
import { secretInput, connectionInput, resourceId, authFields, policyJson } from './vault';
import { targetUrl } from '../../../packages/core/proxy';

export const backupSchema = z.object({
  format: z.literal('agent-credentials-backup-v1'),
  createdAt: z.string(),
  secrets: z.array(secretInput.extend({ id: resourceId })).max(500),
  connections: z.array(connectionInput.extend({ id: resourceId })).max(500),
});
export function validateRecipient(recipient: string) {
  try {
    const e = new Encrypter();
    e.addRecipient(recipient);
    return e;
  } catch {
    throw new Fault('invalid_backup_recipient', 400);
  }
}
export async function exportBackup(env: Bindings, owner: string, recipient: string) {
  return (await exportSnapshot(env, owner, recipient)).encrypted;
}
async function exportSnapshot(env: Bindings, owner: string, recipient: string) {
  const e = validateRecipient(recipient);
  // Bound the encrypted snapshot in SQL before bringing rows into Worker memory.
  const sizeSql =
    "SELECT COALESCE(SUM(length(v.envelope_json)),0) FROM secrets s JOIN secret_versions v ON s.id=v.secret_id AND s.current_version=v.version WHERE s.owner_id=? AND s.status='active'";
  const data = await env.DB.batch([
    env.DB.prepare(
      `SELECT s.id,s.name,s.description,s.current_version,v.envelope_json FROM secrets s JOIN secret_versions v ON s.id=v.secret_id AND s.current_version=v.version WHERE s.owner_id=? AND s.status='active' AND (${sizeSql})<=? LIMIT 501`,
    ).bind(owner, owner, 12 * 1024 * 1024),
    env.DB.prepare(
      "SELECT id,name,origin,description,auth_json,policy_json FROM connections WHERE owner_id=? AND status='active' LIMIT 501",
    ).bind(owner),
    env.DB.prepare(`SELECT (${sizeSql}) AS bytes`).bind(owner),
    env.DB.prepare('SELECT revision FROM backup_state WHERE id=1'),
  ]);
  assert(
    Number((data[2].results[0] as { bytes: number } | undefined)?.bytes) <= 12 * 1024 * 1024,
    'backup_limit_exceeded',
    413,
  );
  assert(data[0].results.length <= 500 && data[1].results.length <= 500, 'backup_limit_exceeded', 413);
  const secrets = [];
  for (const row of data[0].results as {
    id: string;
    name: string;
    description: string | null;
    current_version: number;
    envelope_json: string;
  }[]) {
    secrets.push({
      id: row.id,
      name: row.name,
      description: row.description ?? '',
      values: await decryptSecret(
        parseKeys(env),
        { ownerId: owner, secretId: row.id, version: row.current_version },
        JSON.parse(row.envelope_json),
      ),
    });
  }
  const connections = (
    data[1].results as {
      id: string;
      name: string;
      origin: string;
      description: string;
      auth_json: string;
      policy_json: string;
    }[]
  ).map((r) => ({
    id: r.id,
    name: r.name,
    origin: r.origin,
    description: r.description,
    auth: JSON.parse(r.auth_json),
    ...JSON.parse(r.policy_json),
  }));
  const snapshot = backupSchema.parse({
    format: 'agent-credentials-backup-v1',
    createdAt: new Date().toISOString(),
    secrets,
    connections,
  });
  for (const connection of snapshot.connections) {
    const auth = connection.auth;
    if (auth.type !== 'none') {
      const secret = snapshot.secrets.find((s) => s.id === auth.secretId);
      assert(secret, 'backup_has_broken_connection', 409);
      assert(
        authFields(auth).every((field) => Object.hasOwn(secret.values, field)),
        'backup_has_broken_connection',
        409,
      );
    }
  }
  const serialized = JSON.stringify(snapshot);
  assert(new TextEncoder().encode(serialized).length <= 8 * 1024 * 1024, 'backup_limit_exceeded', 413);
  await audit(env, 'owner', 'backup:export', null, 'authorized');
  return {
    encrypted: await e.encrypt(serialized),
    revision: Number((data[3].results[0] as { revision: number }).revision),
  };
}
export async function restoreBackup(env: Bindings, owner: string, input: unknown) {
  const data = backupSchema.parse(input);
  const existing = await env.DB.prepare(
    'SELECT (SELECT COUNT(*) FROM secrets)+(SELECT COUNT(*) FROM connections)+(SELECT COUNT(*) FROM oauthClient) AS n',
  ).first<{ n: number }>();
  assert(existing?.n === 0, 'restore_requires_empty_vault', 409);
  assert(new Set(data.secrets.map((s) => s.id)).size === data.secrets.length, 'duplicate_secret');
  const statements = [
    env.DB.prepare(
      "INSERT INTO system_state (key,value,updated_at) SELECT 'restore_completed',CASE WHEN (SELECT COUNT(*) FROM secrets)+(SELECT COUNT(*) FROM connections)+(SELECT COUNT(*) FROM oauthClient)=0 THEN '1' ELSE NULL END,?",
    ).bind(now()),
  ];
  for (const secret of data.secrets) {
    const envelope = await encryptSecret(
      parseKeys(env),
      env.ACTIVE_KEK_ID ?? 'v1',
      { ownerId: owner, secretId: secret.id, version: 1 },
      secret.values,
    );
    statements.push(
      env.DB.prepare(
        'INSERT INTO secrets (id,owner_id,name,description,current_version,created_at,updated_at) VALUES (?,?,?,?,1,?,?)',
      ).bind(secret.id, owner, secret.name, secret.description, now(), now()),
    );
    statements.push(
      env.DB.prepare(
        'INSERT INTO secret_versions (id,secret_id,version,envelope_json,created_at) VALUES (?,?,1,?,?)',
      ).bind(id(), secret.id, JSON.stringify(envelope), now()),
    );
  }
  for (const conn of data.connections) {
    targetUrl(conn.origin, '/', env.ALLOW_LOCAL_HTTP === 'true');
    const policy = policyJson(conn, env.ALLOW_LOCAL_HTTP === 'true');
    if (conn.auth.type !== 'none') {
      const a = conn.auth;
      const secret = data.secrets.find((s) => s.id === a.secretId);
      assert(secret && authFields(a).every((field) => Object.hasOwn(secret.values, field)), 'invalid_secret_binding');
    }
    statements.push(
      env.DB.prepare(
        "INSERT INTO connections (id,owner_id,name,origin,description,auth_json,policy_json,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'active',?,?)",
      ).bind(conn.id, owner, conn.name, conn.origin, conn.description, JSON.stringify(conn.auth), policy, now(), now()),
    );
  }
  await env.DB.batch(statements);
  await audit(env, 'owner', 'backup:restore', null);
  return { secrets: data.secrets.length, connections: data.connections.length, requiresNewGrants: true };
}

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
    const snapshot = await exportSnapshot(env, owner, s.recipient);
    const hash = Buffer.from(await crypto.subtle.digest('SHA-256', new Uint8Array(snapshot.encrypted))).toString('hex');
    const key = `vault/${new Date(time).toISOString().slice(0, 10)}/${time}-${token}.age`;
    const object = await env.BACKUPS.put(key, snapshot.encrypted, {
      httpMetadata: { contentType: 'application/octet-stream' },
      customMetadata: { format: 'agent-credentials-backup-v1', revision: String(snapshot.revision), sha256: hash },
    });
    assert(object, 'backup_storage_failed', 503);
    const saved = await env.DB.prepare(
      'UPDATE backup_state SET success_revision=?,success_config_version=?,success_at=?,object_key=?,sha256=?,last_error=NULL,lease_token=NULL,lease_until=0 WHERE id=1 AND lease_token=? AND config_version=?',
    )
      .bind(snapshot.revision, s.config_version, now(), key, hash, token, s.config_version)
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
    return { outcome: 'saved', revision: snapshot.revision, sha256: hash };
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
