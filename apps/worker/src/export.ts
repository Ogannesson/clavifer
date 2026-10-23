import { z } from 'zod';
import { Buffer } from 'node:buffer';
import { Encrypter } from 'age-encryption';
import { decryptArchiveIdentity, decryptSecret, type Envelope } from '../../../packages/core/crypto';
import { Fault, assert } from '../../../packages/core/errors';
import {
  COUNTED_TYPES,
  SCRYPT,
  SNAPSHOT_FORMAT,
  SnapshotValidator,
  checkReferences,
  serializeRecord,
  type ArchiveHeader,
  type RecordOf,
  type SnapshotRecord,
} from '../../../packages/core/snapshot';
import { type Bindings, VERSION, now, rootKeys, audit, requestId, withRequestId } from './context';

// Long enough for a post-quantum recipient (age1pq1…, about 1960 characters).
export const recipientInput = z.string().trim().min(10).max(4096);
export function validateRecipient(recipient: string) {
  try {
    const e = new Encrypter();
    e.addRecipient(recipient);
    return e;
  } catch {
    throw new Fault('invalid_backup_recipient', 400);
  }
}
// The console names each full export with at least 128 random bits, so its audit rows can be found.
export const exportId = z.string().regex(/^[A-Za-z0-9_-]{22,64}$/);

type Raw = { type: string } & Record<string, unknown>;
const unrepresentable = (what: string) => new Fault('backup_unrepresentable', 409, what);
function json(text: unknown, what: string): unknown {
  try {
    return JSON.parse(text as string);
  } catch {
    throw unrepresentable(`${what} is not JSON`);
  }
}

// A row of access_requests and of audit_events as its record, in a snapshot and in a sealed segment alike.
export const requestRecord = (r: Record<string, unknown>): Raw => ({
  type: 'access-request',
  id: r.id,
  clientId: r.client_id,
  requested: json(r.requested_json, `access request ${r.id}`),
  reason: r.reason,
  status: r.status,
  fingerprint: r.fingerprint,
  consumedAt: r.consumed_at,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
});
export const auditRecord = (e: Record<string, unknown>): Raw => ({
  type: 'audit',
  id: e.id,
  clientId: e.client_id,
  action: e.action,
  resourceId: e.resource_id,
  result: e.result,
  requestId: e.request_id,
  createdAt: e.created_at,
});
/** Records as the bytes of their file, before encryption. */
export function serialized(records: (SnapshotRecord | ArchiveHeader)[]) {
  const lines = records.map(serializeRecord);
  const bytes = new Uint8Array(lines.reduce((n, line) => n + line.length, 0));
  let offset = 0;
  for (const line of lines) {
    bytes.set(line, offset);
    offset += line.length;
  }
  return bytes;
}

/** The snapshot of this instance as the automatic backup carries it: every record, read in one batch,
 * checked against the v1 schemas and for the references an import requires, with each sealed segment
 * named by its key in the bucket. A full export is the same snapshot with each segment's file in place
 * of its key. revision is the backup revision as of the same read. A failed check refuses the snapshot
 * whole, so neither an export nor a backup is ever written from an inconsistent instance. */
export async function snapshot(env: Bindings, owner: string) {
  // D1 reads within one batch see one state; separate batches could see a rotation half done or a segment
  // sealed between reading the manifest and its rows. The snapshot is dated once that read returned, so
  // nothing in it is newer than its header says.
  const [
    user,
    account,
    passkeys,
    secrets,
    versions,
    connections,
    clients,
    grants,
    requests,
    events,
    segments,
    state,
    identity,
  ] = (
    await env.DB.batch([
      env.DB.prepare('SELECT id,email,name,emailVerified,image,createdAt,updatedAt FROM "user" WHERE id=?').bind(owner),
      env.DB.prepare(
        "SELECT password,createdAt,updatedAt FROM account WHERE userId=? AND providerId='credential'",
      ).bind(owner),
      env.DB.prepare(
        'SELECT id,name,publicKey,credentialID,counter,deviceType,backedUp,transports,createdAt,aaguid FROM passkey WHERE userId=? ORDER BY createdAt,id',
      ).bind(owner),
      env.DB.prepare(
        'SELECT id,name,description,status,current_version,created_at,updated_at FROM secrets ORDER BY created_at,id',
      ),
      // An active credential carries its versions up to the current one; a deleted one has none left.
      env.DB.prepare(
        "SELECT v.secret_id,v.version,v.envelope_json,v.created_at FROM secret_versions v JOIN secrets s ON s.id=v.secret_id AND s.status='active' AND v.version<=s.current_version ORDER BY v.secret_id,v.version",
      ),
      env.DB.prepare(
        'SELECT id,name,origin,description,auth_json,policy_json,status,created_at,updated_at FROM connections ORDER BY created_at,id',
      ),
      env.DB.prepare(
        'SELECT clientId,name,applicationType,redirectUris,scopes,grantTypes,disabled,createdAt,updatedAt FROM oauthClient ORDER BY createdAt,clientId',
      ),
      env.DB.prepare(
        'SELECT id,client_id,resource_type,resource_id,permission,fields_json,extensions_json,status,expires_at,created_at FROM grants ORDER BY created_at,id',
      ),
      env.DB.prepare(
        'SELECT id,client_id,requested_json,reason,status,fingerprint,consumed_at,created_at,expires_at FROM access_requests ORDER BY created_at,id',
      ),
      env.DB.prepare(
        'SELECT id,client_id,action,resource_id,result,request_id,created_at FROM audit_events ORDER BY created_at,id',
      ),
      env.DB.prepare(
        'SELECT kind,seq,object_key,sha256,first_at,first_id,last_at,last_id,rows,created_at FROM archive_segments ORDER BY kind,seq',
      ),
      env.DB.prepare('SELECT recipient,revision FROM backup_state WHERE id=1'),
      env.DB.prepare("SELECT value FROM system_state WHERE key='archive_identity'"),
    ])
  ).map((r) => r.results as Record<string, unknown>[]);
  const createdAt = now();
  const u = user[0];
  assert(u && account.length === 1, 'backup_unrepresentable', 409, 'the Owner has no single password account');
  const hash = String(account[0].password).split(':');
  assert(hash.length === 2, 'backup_unrepresentable', 409, 'the Owner password is not stored as salt:key');
  // Creating the Owner stores it; without it the sealed segments could never be read again.
  assert(identity[0], 'archive_identity_missing', 503);
  const keys = rootKeys(env);
  const raw: Raw[] = [
    {
      type: 'header',
      format: SNAPSHOT_FORMAT,
      kind: 'automatic',
      createdAt,
      source: { origin: env.APP_ORIGIN, rpId: new URL(env.APP_ORIGIN).hostname, version: VERSION },
    },
    {
      type: 'owner',
      id: u.id,
      email: u.email,
      name: u.name,
      emailVerified: !!u.emailVerified,
      image: u.image,
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,
      password: {
        ...SCRYPT,
        salt: hash[0],
        key: hash[1],
        createdAt: account[0].createdAt,
        updatedAt: account[0].updatedAt,
      },
      passkeys: passkeys.map((p) => ({ ...(p as object), backedUp: !!p.backedUp })),
    },
    { type: 'settings', backupRecipient: state[0].recipient },
    // The identity is decrypted only here, while the snapshot is assembled.
    {
      type: 'archive-identity',
      identity: await decryptArchiveIdentity(keys, owner, json(identity[0].value, 'the archive identity') as Envelope),
    },
    ...secrets.map((s) => ({
      type: 'secret',
      id: s.id,
      name: s.name,
      description: s.description ?? '',
      status: s.status,
      currentVersion: s.current_version,
      createdAt: s.created_at,
      updatedAt: s.updated_at,
    })),
  ];
  for (const v of versions) {
    const what = `secret ${v.secret_id} version ${v.version}`;
    const values = await decryptSecret(
      keys,
      { ownerId: owner, secretId: v.secret_id as string, version: v.version as number },
      json(v.envelope_json, what) as Envelope,
    ).catch((e: unknown) => {
      throw e instanceof Fault ? e : unrepresentable(`${what} cannot be decrypted`);
    });
    raw.push({ type: 'secret-version', secretId: v.secret_id, version: v.version, values, createdAt: v.created_at });
  }
  raw.push(
    ...connections.map((c) => ({
      type: 'connection',
      id: c.id,
      name: c.name,
      origin: c.origin,
      description: c.description,
      auth: json(c.auth_json, `connection ${c.id} auth`),
      // A key an older row lacks takes the value the proxy reads in its absence (see decide in vault.ts).
      policy: {
        methods: ['GET', 'HEAD'],
        deny: [],
        approval: [],
        free: [],
        hosts: [],
        anyHost: false,
        ...(json(c.policy_json, `connection ${c.id} policy`) as object),
      },
      status: c.status,
      createdAt: c.created_at,
      updatedAt: c.updated_at,
    })),
    ...clients.map((c) => ({
      type: 'installation',
      clientId: c.clientId,
      name: c.name,
      applicationType: c.applicationType,
      redirectUris: json(c.redirectUris, `installation ${c.clientId} redirectUris`),
      scopes: c.scopes === null ? null : json(c.scopes, `installation ${c.clientId} scopes`),
      grantTypes: c.grantTypes === null ? null : json(c.grantTypes, `installation ${c.clientId} grantTypes`),
      disabled: !!c.disabled,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
    })),
    ...grants.map((g) => ({
      type: 'grant',
      id: g.id,
      clientId: g.client_id,
      resourceType: g.resource_type,
      resourceId: g.resource_id,
      permission: g.permission,
      fields: g.fields_json === null ? null : json(g.fields_json, `grant ${g.id} fields`),
      extensions: g.extensions_json === null ? null : json(g.extensions_json, `grant ${g.id} extensions`),
      status: g.status,
      expiresAt: g.expires_at,
      createdAt: g.created_at,
    })),
    ...requests.map(requestRecord),
    ...events.map(auditRecord),
    ...segments.map((s) => ({
      type: 'segment',
      kind: s.kind,
      seq: s.seq,
      first: [s.first_at, s.first_id],
      last: [s.last_at, s.last_id],
      rows: s.rows,
      createdAt: s.created_at,
      sha256: s.sha256,
      key: s.object_key,
      data: null,
    })),
  );
  raw.push({
    type: 'end',
    counts: Object.fromEntries(COUNTED_TYPES.map((type) => [type, raw.filter((r) => r.type === type).length])),
  });
  const validator = new SnapshotValidator();
  const records = raw.map((r) => {
    try {
      return validator.push(r);
    } catch (e) {
      throw unrepresentable(
        `${r.type} ${String(r.id ?? r.clientId ?? r.secretId ?? r.key ?? '')}: ${(e as Error).message}`,
      );
    }
  });
  validator.finish();
  checkReferences(records);
  return { records, revision: Number(state[0].revision) };
}

/** Streams the complete state of this instance as a v1 full snapshot, age-encrypted to recipient: the
 * snapshot of the automatic backup with every sealed segment's file embedded. Nothing is written before
 * every record passed its checks and every segment was found in the bucket with the checksum its
 * manifest row recorded; a refusal is audited under the export id, since a download link gives the
 * console no response to read. */
export async function fullExport(env: Bindings, owner: string, recipient: string, id: string) {
  let records: SnapshotRecord[], encrypter: Encrypter;
  try {
    encrypter = validateRecipient(recipient);
    ({ records } = await snapshot(env, owner));
    for (const r of records) {
      if (r.type !== 'segment') continue;
      const object = await env.BACKUPS.head(r.key!);
      assert(object, 'archive_segment_unavailable', 409, `${r.key} is missing`);
      const sha256 = object.checksums.sha256;
      assert(
        sha256 && Buffer.from(sha256).toString('hex') === r.sha256,
        'archive_segment_unavailable',
        409,
        `${r.key} does not have the checksum its manifest row recorded`,
      );
    }
  } catch (e) {
    await audit(env, 'owner', 'backup:export', id, e instanceof Fault ? e.code : 'internal_error');
    throw e;
  }
  await audit(env, 'owner', 'backup:export', id, 'started');
  records[0] = { ...(records[0] as RecordOf<'header'>), kind: 'full' };
  const rid = requestId();
  let next = 0;
  const lines = new ReadableStream<Uint8Array>({
    // One record at a time, so at most one segment's file is held. Segments are immutable and were all
    // there a moment ago; the server never decrypts one. Standard base64 with padding is what the format
    // asks of data, so the embedded record is as valid as the checked one it replaces.
    async pull(controller) {
      if (next === records.length) return controller.close();
      const record = records[next++];
      if (record.type !== 'segment') return controller.enqueue(serializeRecord(record));
      const file = await (await env.BACKUPS.get(record.key!))!.arrayBuffer();
      controller.enqueue(serializeRecord({ ...record, key: null, data: Buffer.from(file).toString('base64') }));
    },
  });
  // A stream that fails midway still reaches the browser as a 200 with a clean end, so the file counts as
  // whole only once this row exists: it is written after the last encrypted byte was passed on.
  const body = (await encrypter.encrypt(lines)).pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      async flush() {
        await withRequestId(rid, () => audit(env, 'owner', 'backup:export', id, 'complete'));
      },
    }),
  );
  return new Response(body, {
    headers: {
      'content-type': 'application/octet-stream',
      'content-disposition': `attachment; filename="clavifer-full-${new Date().toISOString().slice(0, 10)}.age"`,
      'cache-control': 'no-store',
    },
  });
}

/** How far the full export with this id got: complete only after its last byte, failed with the code of
 * a refusal, started while it runs or after it broke off, unknown when it never reached the handler. */
export async function exportStatus(env: Bindings, id: string) {
  const results = (
    await env.DB.prepare("SELECT result FROM audit_events WHERE action='backup:export' AND resource_id=?")
      .bind(id)
      .all<{ result: string }>()
  ).results.map((r) => r.result);
  const failed = results.find((r) => r !== 'started' && r !== 'complete');
  return results.includes('complete')
    ? { status: 'complete' }
    : failed
      ? { status: 'failed', error: failed }
      : { status: results.includes('started') ? 'started' : 'unknown' };
}
