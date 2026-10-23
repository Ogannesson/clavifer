import { z } from 'zod';
import { Buffer } from 'node:buffer';
import { generateHybridIdentity } from 'age-encryption';
import {
  decryptSecret,
  digest,
  encode,
  encryptArchiveIdentity,
  encryptSecret,
  rootKeyFingerprints,
  type Envelope,
} from '../../../packages/core/crypto';
import { Fault, assert } from '../../../packages/core/errors';
import {
  COUNTED_TYPES,
  SCRYPT,
  snapshotRecord,
  type RecordOf,
  type SnapshotRecord,
} from '../../../packages/core/snapshot';
import { type Bindings, auditStatement, id, issuesHint, now, rootKeys } from './context';
import { clearOut, consumeToken, deleteToken, tokenGuard, tokenState } from './setup';
import { segmentKey, segmentPrefix } from './archive';

// Importing a snapshot is the other way to initialize an instance, for a migration and a disaster
// recovery alike. The browser decrypts the file and sends it in three steps: the start spends the token
// and empties the instance, chunks write the records, and the commit checks what was written and creates
// the Owner. Until the commit the instance stays uninitialized, so nobody can sign in to half an import.
// Only the structure of the records and the references between them are checked, never the business rules
// of this version (an access request over today's size limit imports as it was stored): a version that
// tightens a rule converts the stored rows and imported ones alike.

// The import in progress is system_state import_id: {id, owner, header}, the whole owner record kept for
// the commit. Like the token, its id is a bearer credential: 128 random bits, only ever in request and
// response bodies.
export const importId = z.string().regex(/^[A-Za-z0-9_-]{22}$/);
export const startInput = z.object({ header: z.unknown(), owner: z.unknown() });
export const chunkInput = z.object({
  importId,
  seq: z.int().nonnegative(),
  records: z.array(z.unknown()).min(1),
  // Referenced segments of this chunk the Owner chose to import without, after this chunk named them missing.
  skip: z.array(z.object({ kind: z.enum(['audit', 'access-request']), seq: z.int().nonnegative() })).default([]),
});
export const commitInput = z.object({
  importId,
  settings: z.unknown(),
  archiveIdentity: z.unknown(),
  end: z.unknown(),
});
type Import = { id: string; owner: RecordOf<'owner'>; header: RecordOf<'header'> };

function parse<T extends SnapshotRecord['type']>(value: unknown, types: readonly T[], what: string) {
  const parsed = snapshotRecord.safeParse(value);
  if (!parsed.success) throw new Fault('invalid_snapshot', 400, `${what}: ${issuesHint(parsed.error)}`);
  assert(
    (types as readonly string[]).includes(parsed.data.type),
    'invalid_snapshot',
    400,
    `${what}: a ${parsed.data.type} record does not belong here`,
  );
  return parsed.data as RecordOf<T>;
}
const superseded = () =>
  new Fault(
    'import_superseded',
    409,
    'This import is no longer the one in progress: the instance was initialized, a start with a new token replaced it, or a chunk arrived while it was being committed.',
  );
// An import is in progress while its id is in import_id and nobody initialized the instance.
const UNINITIALIZED = "NOT EXISTS (SELECT 1 FROM system_state WHERE key='owner_user_id')";
const CURRENT = `key='import_id' AND json_extract(value,'$.id')=? AND ${UNINITIALIZED}`;
/** Refuses a chunk before its body is read when no import is in progress at all, so that nobody makes an
 * instance buffer megabytes for nothing. */
export async function assertImporting(env: Bindings) {
  if (!(await env.DB.prepare(`SELECT 1 FROM system_state WHERE key='import_id' AND ${UNINITIALIZED}`).first()))
    throw superseded();
}
/** Runs statements in a batch that starts with the import guard. Like tokenGuard, it inserts the import
 * record while the import is in progress, and otherwise NULL, which the column refuses, so the whole batch
 * rolls back: a stale import's writes that merely matched nothing would report success. With chunks, the
 * import must also still hold exactly that many chunks, the ones its commit checked. */
async function guarded(env: Bindings, importId: string, statements: D1PreparedStatement[], chunks?: number) {
  const checked = chunks === undefined ? [] : [chunks];
  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO system_state (key,value,updated_at) SELECT 'import_guard',(SELECT value FROM system_state WHERE ${CURRENT}${checked.length ? ' AND (SELECT COUNT(*) FROM import_chunks)=?' : ''}),?`,
      ).bind(importId, ...checked, now()),
      ...statements,
      env.DB.prepare("DELETE FROM system_state WHERE key='import_guard'"),
    ]);
  } catch (e) {
    if (e instanceof Error && e.message.includes('NOT NULL constraint failed: system_state.value')) throw superseded();
    throw e;
  }
}

/** Spends the token of an uninitialized instance, empties it and opens an import of the snapshot whose
 * header and owner records these are. Returns the import id. */
export async function startImport(env: Bindings, token: string | undefined, input: z.infer<typeof startInput>) {
  assert(!(await tokenState(env, token)).owner, 'already_initialized', 409);
  const header = parse(input.header, ['header'], 'header');
  const owner = parse(input.owner, ['owner'], 'owner');
  // The stored key verifies only under the parameters it was derived with, and the library has its own.
  assert(
    Object.entries(SCRYPT).every(([name, value]) => owner.password[name as keyof typeof SCRYPT] === value),
    'invalid_snapshot',
    400,
    'owner: the password was derived with other parameters than this version uses',
  );
  const imported = encode(crypto.getRandomValues(new Uint8Array(16)));
  await consumeToken(env, [
    tokenGuard(env, await digest(token!), false),
    ...clearOut(env),
    env.DB.prepare("INSERT INTO system_state (key,value,updated_at) VALUES ('import_id',?,?)").bind(
      JSON.stringify({ id: imported, owner, header } satisfies Import),
      now(),
    ),
    deleteToken(env),
  ]);
  return imported;
}

// Each record type is written to its table as a row of these columns. The Owner id goes into every
// owner_id; an installation gets the columns the OAuth provider fills when the console creates one: a
// public client of the Owner, without secret.
const COLUMNS = {
  secrets: 'id,owner_id,name,description,status,current_version,created_at,updated_at',
  secret_versions: 'id,secret_id,version,envelope_json,created_at',
  connections: 'id,owner_id,name,origin,description,auth_json,policy_json,status,created_at,updated_at',
  oauthClient:
    'id,clientId,name,applicationType,redirectUris,scopes,grantTypes,disabled,createdAt,updatedAt,userId,tokenEndpointAuthMethod,responseTypes,clientCredentialsScopes,dpopBoundAccessTokens',
  grants:
    'id,owner_id,client_id,resource_type,resource_id,permission,fields_json,extensions_json,status,expires_at,created_at',
  access_requests: 'id,owner_id,client_id,requested_json,reason,status,fingerprint,consumed_at,created_at,expires_at',
  audit_events: 'id,owner_id,client_id,action,resource_id,result,request_id,created_at',
  archive_segments: 'kind,seq,object_key,sha256,first_at,first_id,last_at,last_id,rows,created_at',
};
type Table = keyof typeof COLUMNS;
const BULK = [
  'secret',
  'secret-version',
  'connection',
  'installation',
  'grant',
  'access-request',
  'audit',
  'segment',
] as const;
const nullable = (value: unknown) => (value === null ? null : JSON.stringify(value));
// D1 takes at most 100 bound parameters a statement and 2 MB a value, so the rows of a table go in as JSON
// arrays of up to PACK bytes through json_each. A row larger than that (a credential version or an access
// request near D1's 2 MB row limit) gets a plain INSERT of its own.
const PACK = 1_000_000;
const encoder = new TextEncoder();
function inserts(env: Bindings, table: Table, rows: unknown[][]) {
  const columns = COLUMNS[table].split(',');
  const names = columns.map((column) => `"${column}"`).join(',');
  const statements: D1PreparedStatement[] = [];
  let pack: string[] = [],
    size = 2;
  const flush = () => {
    if (!pack.length) return;
    statements.push(
      env.DB.prepare(
        `INSERT INTO "${table}" (${names}) SELECT ${columns.map((_, i) => `json_extract(value,'$[${i}]')`).join(',')} FROM json_each(?)`,
      ).bind(`[${pack.join(',')}]`),
    );
    pack = [];
    size = 2;
  };
  for (const row of rows) {
    const text = JSON.stringify(row),
      bytes = encoder.encode(text).length;
    if (bytes + 2 > PACK) {
      statements.push(
        env.DB.prepare(`INSERT INTO "${table}" (${names}) VALUES (${columns.map(() => '?').join(',')})`).bind(...row),
      );
      continue;
    }
    if (size + bytes + 1 > PACK) flush();
    pack.push(text);
    size += bytes + 1;
  }
  flush();
  return statements;
}

/** Writes one chunk of records of the import in progress, with the chunk's seq in the same batch, so a
 * chunk sent again succeeds without writing twice. A credential version is encrypted under this instance's
 * root key for the imported Owner. An embedded segment goes to a new key of its own in the bucket; a
 * referenced one must be in this bucket already with its checksum, and the chunk writes nothing while one
 * is not and the Owner has not chosen to go without it: the answer names those instead. */
export async function importChunk(env: Bindings, input: z.infer<typeof chunkInput>) {
  const current = await env.DB.prepare(
    `SELECT value,EXISTS (SELECT 1 FROM import_chunks WHERE seq=?) AS written FROM system_state WHERE ${CURRENT}`,
  )
    .bind(input.seq, input.importId)
    .first<{ value: string; written: number }>();
  if (!current) throw superseded();
  // Sent again, say after the response was lost: the first one wrote it.
  if (current.written) return { written: true };
  const { owner, header } = JSON.parse(current.value) as Import;
  const ring = rootKeys(env);
  const skip = new Set(input.skip.map((s) => `${s.kind}/${s.seq}`));
  // At the index of their record, so that both lists keep the order of the file.
  const skipping: RecordOf<'segment'>[] = [];
  const absent: { kind: string; seq: number }[] = [];
  const rows = Object.fromEntries(Object.keys(COLUMNS).map((table) => [table, [] as unknown[][]])) as Record<
    Table,
    unknown[][]
  >;
  const records = input.records.map((value, i) => parse(value, BULK, `record ${i + 1}`));
  await Promise.all(
    records.map(async (r, i): Promise<void> => {
      if (r.type === 'secret')
        rows.secrets.push([
          r.id,
          owner.id,
          r.name,
          r.description,
          r.status,
          r.currentVersion,
          r.createdAt,
          r.updatedAt,
        ]);
      else if (r.type === 'secret-version') {
        const envelope = await encryptSecret(
          ring,
          { ownerId: owner.id, secretId: r.secretId, version: r.version },
          r.values,
        );
        rows.secret_versions.push([id(), r.secretId, r.version, JSON.stringify(envelope), r.createdAt]);
      } else if (r.type === 'connection')
        rows.connections.push([
          r.id,
          owner.id,
          r.name,
          r.origin,
          r.description,
          JSON.stringify(r.auth),
          JSON.stringify(r.policy),
          r.status,
          r.createdAt,
          r.updatedAt,
        ]);
      else if (r.type === 'installation')
        rows.oauthClient.push([
          id(),
          r.clientId,
          r.name,
          r.applicationType,
          JSON.stringify(r.redirectUris),
          nullable(r.scopes),
          nullable(r.grantTypes),
          r.disabled ? 1 : 0,
          r.createdAt,
          r.updatedAt,
          owner.id,
          'none',
          r.grantTypes?.includes('authorization_code') ? '["code"]' : null,
          '[]',
          0,
        ]);
      else if (r.type === 'grant')
        rows.grants.push([
          r.id,
          owner.id,
          r.clientId,
          r.resourceType,
          r.resourceId,
          r.permission,
          nullable(r.fields),
          nullable(r.extensions),
          r.status,
          r.expiresAt,
          r.createdAt,
        ]);
      else if (r.type === 'access-request')
        rows.access_requests.push([
          r.id,
          owner.id,
          r.clientId,
          JSON.stringify(r.requested),
          r.reason,
          r.status,
          r.fingerprint,
          r.consumedAt,
          r.createdAt,
          r.expiresAt,
        ]);
      else if (r.type === 'audit')
        rows.audit_events.push([
          r.id,
          owner.id,
          r.clientId,
          r.action,
          r.resourceId,
          r.result,
          r.requestId,
          r.createdAt,
        ]);
      else {
        const what = `record ${i + 1}: segment ${r.kind} ${r.seq}`;
        let key: string;
        if (header.kind === 'full') {
          assert(r.data !== null && r.key === null, 'invalid_snapshot', 400, `${what} of a full snapshot has no data`);
          const file = Buffer.from(r.data, 'base64');
          const sha256 = Buffer.from(await crypto.subtle.digest('SHA-256', file)).toString('hex');
          assert(sha256 === r.sha256, 'invalid_snapshot', 400, `${what} does not have the checksum it names`);
          key = segmentKey(r.kind, r.seq);
          // R2 checks the upload against sha256 and keeps it for head().
          await env.BACKUPS.put(key, file, { sha256 });
        } else {
          assert(
            r.key !== null && r.data === null,
            'invalid_snapshot',
            400,
            `${what} of an automatic snapshot has no key`,
          );
          // The pattern keeps the key under archive/, never at a backup that retention deletes.
          assert(r.key.startsWith(segmentPrefix(r.kind, r.seq)), 'invalid_snapshot', 400, `${what} has another's key`);
          if (skip.has(`${r.kind}/${r.seq}`)) return void (skipping[i] = r);
          // Found as it was sealed, by the checksum R2 verified on upload; never read.
          const sha256 = (await env.BACKUPS.head(r.key))?.checksums.sha256;
          if (!sha256 || Buffer.from(sha256).toString('hex') !== r.sha256)
            return void (absent[i] = { kind: r.kind, seq: r.seq });
          key = r.key;
        }
        rows.archive_segments.push([
          r.kind,
          r.seq,
          key,
          r.sha256,
          r.first[0],
          r.first[1],
          r.last[0],
          r.last[1],
          r.rows,
          r.createdAt,
        ]);
      }
    }),
  );
  const skipped = Object.values(skipping),
    missing = Object.values(absent);
  assert(
    skipped.length === input.skip.length,
    'invalid_input',
    400,
    'skip names a segment this chunk does not refer to',
  );
  if (missing.length) return { written: false, missing };
  try {
    await guarded(env, input.importId, [
      env.DB.prepare('INSERT INTO import_chunks (seq,skipped) VALUES (?,?)').bind(input.seq, JSON.stringify(skipped)),
      ...(Object.keys(COLUMNS) as Table[]).flatMap((table) => inserts(env, table, rows[table])),
    ]);
  } catch (e) {
    // The same chunk sent again while the first was still being written: one of them wrote it.
    if (e instanceof Error && e.message.includes('UNIQUE constraint failed: import_chunks.seq'))
      return { written: true };
    throw e;
  }
  return { written: true };
}

const inconsistent = (message: string) => new Fault('snapshot_inconsistent', 409, message);
/** Completes the import in progress: once the chunks hold exactly what end counts, every reference between
 * the written rows holds and the sealed ranges line up, one batch creates the Owner (Passkeys only on the
 * hostname they were registered for), its archive identity (a new one for a snapshot without), the root
 * key fingerprints and the backup recipient, and the instance is initialized. */
export async function commitImport(env: Bindings, input: z.infer<typeof commitInput>) {
  const current = await env.DB.prepare(`SELECT value FROM system_state WHERE ${CURRENT}`)
    .bind(input.importId)
    .first<{ value: string }>();
  if (!current) throw superseded();
  const { owner, header } = JSON.parse(current.value) as Import;
  const settings = parse(input.settings, ['settings'], 'settings');
  const identity =
    input.archiveIdentity === null ? null : parse(input.archiveIdentity, ['archive-identity'], 'archive-identity');
  const end = parse(input.end, ['end'], 'end');

  // Read in one batch, which the final one repeats only in its guard: these checks hold for what is written
  // as long as no chunk arrived since, so the guard requires the chunks counted here.
  const [counts, skippedRows, grant, request, versions, bound, ranges] = (
    await env.DB.batch([
      env.DB.prepare(
        'SELECT (SELECT COUNT(*) FROM import_chunks) AS chunks,(SELECT COUNT(*) FROM secrets) AS "secret",(SELECT COUNT(*) FROM secret_versions) AS "secret-version",(SELECT COUNT(*) FROM connections) AS "connection",(SELECT COUNT(*) FROM "oauthClient") AS "installation",(SELECT COUNT(*) FROM grants) AS "grant",(SELECT COUNT(*) FROM access_requests) AS "access-request",(SELECT COUNT(*) FROM audit_events) AS "audit",(SELECT COUNT(*) FROM archive_segments) AS "segment"',
      ),
      env.DB.prepare('SELECT j.value FROM import_chunks c,json_each(c.skipped) j ORDER BY c.seq,j.key'),
      env.DB.prepare(
        `SELECT id FROM grants g WHERE NOT EXISTS (SELECT 1 FROM "oauthClient" WHERE clientId=g.client_id) OR NOT EXISTS (SELECT 1 FROM secrets WHERE g.resource_type='secret' AND id=g.resource_id UNION ALL SELECT 1 FROM connections WHERE g.resource_type='connection' AND id=g.resource_id) LIMIT 1`,
      ),
      env.DB.prepare(
        'SELECT id FROM access_requests r WHERE NOT EXISTS (SELECT 1 FROM "oauthClient" WHERE clientId=r.client_id) LIMIT 1',
      ),
      // With (secret_id, version) unique and versions from 1, these two leave an active credential exactly
      // its versions 1 to current_version, at least one, and every other credential none.
      env.DB.prepare(
        "SELECT id FROM secrets s WHERE status='active' AND (current_version<1 OR current_version<>(SELECT COUNT(*) FROM secret_versions WHERE secret_id=s.id)) UNION ALL SELECT secret_id FROM secret_versions v WHERE NOT EXISTS (SELECT 1 FROM secrets WHERE id=v.secret_id AND status='active' AND v.version<=current_version) LIMIT 1",
      ),
      env.DB.prepare(
        "SELECT c.id,c.auth_json,s.id AS secret_id,s.current_version,v.envelope_json FROM connections c LEFT JOIN secrets s ON s.id=json_extract(c.auth_json,'$.secretId') AND s.status='active' LEFT JOIN secret_versions v ON v.secret_id=s.id AND v.version=s.current_version WHERE c.status='active' AND json_extract(c.auth_json,'$.type')<>'none'",
      ),
      // Each kind's segments, those skipped included, cover ranges in (created_at, id) order that do not
      // overlap, and every row still in its table comes after the last of them.
      env.DB.prepare(
        `WITH s AS (SELECT kind,first_at,first_id,last_at,last_id FROM archive_segments UNION ALL SELECT json_extract(j.value,'$.kind'),json_extract(j.value,'$.first[0]'),json_extract(j.value,'$.first[1]'),json_extract(j.value,'$.last[0]'),json_extract(j.value,'$.last[1]') FROM import_chunks c,json_each(c.skipped) j),
o AS (SELECT *,LAG(last_at) OVER w AS before_at,LAG(last_id) OVER w AS before_id FROM s WINDOW w AS (PARTITION BY kind ORDER BY first_at,first_id))
SELECT kind FROM o WHERE (first_at,first_id)>(last_at,last_id) OR (before_at,before_id)>=(first_at,first_id)
UNION ALL SELECT 'audit' FROM audit_events WHERE (created_at,id)<=(SELECT last_at,last_id FROM s WHERE kind='audit' ORDER BY last_at DESC,last_id DESC LIMIT 1)
UNION ALL SELECT 'access-request' FROM access_requests WHERE (created_at,id)<=(SELECT last_at,last_id FROM s WHERE kind='access-request' ORDER BY last_at DESC,last_id DESC LIMIT 1)
LIMIT 1`,
      ),
    ])
  ).map((r) => r.results as Record<string, unknown>[]);
  const skipped = skippedRows.map((r) => JSON.parse(r.value as string) as RecordOf<'segment'>);
  const { chunks, ...tables } = counts[0] as Record<string, number>;
  const written: Record<string, number> = {
    owner: 1,
    settings: 1,
    'archive-identity': identity ? 1 : 0,
    ...tables,
  };
  written.segment += skipped.length;
  // A chunk that never arrived shows here.
  for (const type of COUNTED_TYPES)
    assert(
      written[type] === end.counts[type],
      'import_incomplete',
      409,
      `${type}: ${written[type]} imported, the snapshot has ${end.counts[type]}`,
    );
  assert(!written.segment || identity, 'invalid_snapshot', 400, 'the snapshot has segments but no archive-identity');
  if (grant.length) throw inconsistent(`grant ${grant[0].id} names an installation or resource the snapshot lacks`);
  if (request.length) throw inconsistent(`access request ${request[0].id} names an installation the snapshot lacks`);
  if (versions.length) throw inconsistent(`secret ${versions[0].id} does not have exactly its versions`);
  const ring = rootKeys(env);
  for (const c of bound) {
    const auth = JSON.parse(c.auth_json as string) as {
      type: string;
      field?: string;
      usernameField?: string;
      passwordField?: string;
    };
    const values = c.envelope_json
      ? await decryptSecret(
          ring,
          { ownerId: owner.id, secretId: c.secret_id as string, version: c.current_version as number },
          JSON.parse(c.envelope_json as string) as Envelope,
        )
      : null;
    const fields = auth.type === 'basic' ? [auth.usernameField!, auth.passwordField!] : [auth.field!];
    if (!values || !fields.every((field) => Object.hasOwn(values, field)))
      throw inconsistent(`connection ${c.id} injects a credential or field the snapshot lacks`);
  }
  if (ranges.length) throw inconsistent(`the ${ranges[0].kind} segments and rows are not in order`);

  const time = now();
  const state = (key: string, value: string) =>
    env.DB.prepare('INSERT INTO system_state (key,value,updated_at) VALUES (?,?,?)').bind(key, value, time);
  const { password } = owner;
  // A Passkey works only on the hostname it was registered for (its RP id); elsewhere the Owner registers again.
  const passkeys = header.source.rpId === new URL(env.APP_ORIGIN).hostname ? owner.passkeys : [];
  await guarded(
    env,
    input.importId,
    [
      env.DB.prepare(
        'INSERT INTO "user" (id,name,email,emailVerified,image,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?)',
      ).bind(
        owner.id,
        owner.name,
        owner.email,
        owner.emailVerified ? 1 : 0,
        owner.image,
        owner.createdAt,
        owner.updatedAt,
      ),
      // Better Auth signs in a password only through this row: provider credential, account id = user id.
      env.DB.prepare(
        "INSERT INTO account (id,accountId,providerId,userId,password,createdAt,updatedAt) VALUES (?,?,'credential',?,?,?,?)",
      ).bind(id(), owner.id, owner.id, `${password.salt}:${password.key}`, password.createdAt, password.updatedAt),
      ...passkeys.map((p) =>
        env.DB.prepare(
          'INSERT INTO passkey (id,name,publicKey,userId,credentialID,counter,deviceType,backedUp,transports,createdAt,aaguid) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
        ).bind(
          p.id,
          p.name,
          p.publicKey,
          owner.id,
          p.credentialID,
          p.counter,
          p.deviceType,
          p.backedUp ? 1 : 0,
          p.transports,
          p.createdAt,
          p.aaguid,
        ),
      ),
      state('owner_user_id', owner.id),
      state('root_key_fingerprints', JSON.stringify(await rootKeyFingerprints(ring))),
      state(
        'archive_identity',
        JSON.stringify(
          await encryptArchiveIdentity(ring, owner.id, identity?.identity ?? (await generateHybridIdentity())),
        ),
      ),
      env.DB.prepare('UPDATE backup_state SET recipient=? WHERE id=1').bind(settings.backupRecipient),
      await auditStatement(
        env,
        'owner',
        'instance:import',
        JSON.stringify({
          origin: header.source.origin,
          createdAt: header.createdAt,
          skipped: skipped.map((s) => ({ kind: s.kind, seq: s.seq })),
        }),
        { owner: owner.id },
      ),
      env.DB.prepare("DELETE FROM system_state WHERE key='import_id'"),
      env.DB.prepare('DELETE FROM import_chunks'),
      // A token issued while the import ran would otherwise outlive it with the 24 hours of a setup token,
      // where recovering an initialized instance gives 1.
      deleteToken(env),
    ],
    chunks,
  );
}
