/**
 * The snapshot format "clavifer-backup-v1". This comment is the normative specification and the
 * schemas below implement it. v1 is frozen: files in it are read by every later version, so its
 * meaning never changes; a change of the format is a new version (v2) with a conversion from v1.
 * The module is shared by the Worker and the console, so it imports nothing platform-specific.
 *
 * A snapshot is a logical export, not a copy of the tables: the dozens of internal columns of the
 * Better Auth plugin tables are not carried, so the file is not tied to a plugin version, and an
 * importer fills them as its own code does.
 *
 * File
 * - An age-encrypted UTF-8 text without a byte order mark and without a compression layer.
 * - Every record is one JSON object written on one line terminated by LF (0x0A). Writers escape
 *   U+2028, U+2029 and U+0085 as \u2028, \u2029 and \u0085 (JSON.stringify leaves them as they are,
 *   and some readers take them for line breaks). Readers split lines on the byte 0x0A only.
 * - A line is exactly one JSON value with nothing outside it: no whitespace before or after it and no
 *   CR before the LF. Readers refuse such a line.
 * - No object contains the same member name twice; writers never emit one (JSON parsers differ in
 *   which of the two they keep).
 * - Integers (times, versions, counts, seq) are written in plain decimal, without fraction or
 *   exponent.
 * - A segment line is at most 8 MiB and every other line at most 4 MiB, counted in bytes without the
 *   LF. The bounds on single rows guarantee these: a D1 row is at most 2 MB, an access request at most
 *   256 KiB, a sealed segment about 1 MB.
 * - The format is closed: an unknown record type or an unknown field is rejected. Every field is
 *   present; a nullable field (marked ? below) is written as null when it has no value.
 * - Records come in this normative order: header, owner, settings, archive-identity (optional), every
 *   secret, every secret-version, every connection, every installation, every grant, every
 *   access-request, every audit, every segment, end. owner follows header, so an importer has the
 *   Owner id from the start. header, owner, settings and end occur exactly once, archive-identity at
 *   most once.
 * - Times are integers, UTC milliseconds since the epoch. Ids are strings, kept as stored.
 *
 * Records. Every record carries "type", its record type, and these fields:
 * - header: format "clavifer-backup-v1"; kind "automatic" or "full"; createdAt, the time of the one
 *   consistent read the snapshot was taken from; source {origin, rpId, version}: the exporting
 *   instance's origin, its WebAuthn RP id (the hostname of the origin) and the service version.
 * - owner: id, email (lowercase), name, emailVerified (boolean), image?, createdAt, updatedAt,
 *   password, passkeys.
 *   - password: algorithm "scrypt"; N, r, p, dkLen (integers); normalization "NFKC"; salt; key;
 *     createdAt, updatedAt (those of the credential account). The key is
 *     scrypt(password normalized to NFKC, salt, N, r, p, dkLen). salt is a string of 32 hexadecimal
 *     characters that is used as it is, as its UTF-8 bytes, as the scrypt salt: it is NOT hex-decoded.
 *     key is the lowercase hexadecimal of the dkLen (64) byte result. An importer refuses parameters
 *     that differ from its own. Writers of this version use SCRYPT below.
 *   - passkeys: an array of {id, name?, publicKey (standard base64 with padding, as stored),
 *     credentialID (base64url without padding), counter (integer), deviceType, backedUp (boolean),
 *     transports? (comma-separated, as stored), createdAt?, aaguid?}.
 * - settings: backupRecipient? (null while the Owner has paused backups).
 * - archive-identity: identity, the post-quantum age identity of the cold-data segments
 *   ("AGE-SECRET-KEY-PQ-1" followed by its uppercase Bech32 data). A snapshot with segments must
 *   carry it. (The snapshots the first 0.5.0 exporter wrote from instances of the earlier structure
 *   have neither segments nor this record.)
 * - secret: id, name, description ("" where the database holds NULL), status "active" or "deleted",
 *   currentVersion, createdAt, updatedAt.
 * - secret-version: secretId, version, values (an object from field name to plaintext), createdAt.
 *   One record per version, never nested in the secret, so that a credential rotated many times
 *   does not become one unbounded line. An active secret has exactly its versions 1 to
 *   currentVersion; a deleted secret has none (its versions were deleted with it).
 * - connection: id, name, origin, description, auth, policy, status "active" or "deleted", createdAt,
 *   updatedAt.
 *   - auth: one of {type: "none"}, {type: "bearer", secretId, field}, {type: "header", secretId,
 *     field, name}, {type: "basic", secretId, usernameField, passwordField}, {type: "query", secretId,
 *     field, name}.
 *   - policy: the full normalized shape {paths, methods, deny, approval, free, hosts, anyHost}.
 *     paths and methods are non-empty; deny, approval, free and hosts are arrays (the rules as stored,
 *     "METHOD /path"); anyHost is a boolean. Writers fill keys an older stored policy lacks with their
 *     defaults: methods ["GET", "HEAD"], empty lists, anyHost false.
 * - installation: clientId, name?, applicationType? ("native" or "web"), redirectUris (an array of
 *   strings), scopes? and grantTypes? (arrays of strings; null where the database holds NULL, written
 *   back as they are on import), disabled (boolean; NULL in the database means false, as some
 *   early installations hold it), createdAt?, updatedAt?.
 * - grant: id, clientId, resourceType "secret" or "connection", resourceId, permission "secret:read"
 *   or "connection:invoke", fields? (a non-empty array of field names, or null for every field),
 *   extensions? (an array of temporary scope extensions {paths, methods, expiresAt?} with non-empty
 *   paths and methods), status "active" or "revoked", expiresAt?, createdAt.
 * - access-request: id, clientId, requested (an object, carried as it is; an importer does not
 *   interpret it), reason?, status "pending", "approved" or "denied", fingerprint?, consumedAt?,
 *   createdAt, expiresAt.
 * - audit: id, clientId?, action, resourceId?, result, requestId, createdAt.
 * - segment: kind "audit" or "access-request"; seq (an integer from 0 to 9999999999, the ten digits of
 *   the key); first and last, each [createdAt, id] of the first and last row in the segment, ordered
 *   as SQLite's BINARY collation orders them; rows (count); createdAt (when the segment was sealed);
 *   sha256 (lowercase hexadecimal of the bytes of the segment's age file); key and data, both present:
 *   in a snapshot whose header.kind is "automatic", key is the R2 key of the segment and data is null;
 *   in a "full" snapshot, data is the bytes of the age file in standard base64 with padding, and key
 *   is null. A key matches ^archive/(audit|access-request)/[0-9]{10}-[A-Za-z0-9_-]{22}\.age$ and is
 *   archive/<kind>/<seq padded with zeros to 10 digits>-<22 random characters>.age for its own record's
 *   kind and seq.
 * - end: counts, an object giving, for every record type except header and end, the number of its
 *   records in this file; types with no records are listed with 0.
 *
 * Why nested objects are in their full normalized shape: an empty path list means "every path" to the
 * proxy (checkPath(path, []) is true), and an importer checks structure and references only, not the
 * business rules of its version; so an empty paths or methods list in a policy or an extension is
 * excluded by the format itself.
 *
 * Not in a snapshot: the owner_id of the business tables (an importer writes owner.id), sessions,
 * access and refresh tokens, device codes, signing keys (jwks), rate limits, verifications, OAuth
 * consents, oauthResource and oauthClientResource rows (rebuilt for the origin), setup tokens, import
 * records, backup bookkeeping other than the recipient, secret_versions.id (regenerated on import) and
 * the manifest's own timestamps (a segment's seal time is segment.createdAt). An importer writes every
 * installation with the Owner as its user, tokenEndpointAuthMethod "none" and no client secret.
 *
 * Versions: an importer accepts its own format and earlier ones and rejects later ones. The segment
 * format "clavifer-archive-v1" is always accepted. A closed format is deliberate: a reader that
 * ignored unknown fields would silently drop data when an older version imports a newer file.
 *
 * Segment files ("clavifer-archive-v1"), age-encrypted to the archive identity, follow the same file
 * grammar. The first line is {"type": "header", "format": "clavifer-archive-v1", kind, seq, first,
 * last, rows, createdAt} with the meanings of the segment record; each following line is one audit or
 * access-request record of the header's kind, in the same shape as in a snapshot.
 */
import { z } from 'zod';
import { Fault, assert } from './errors';

export const SNAPSHOT_FORMAT = 'clavifer-backup-v1';
export const ARCHIVE_FORMAT = 'clavifer-archive-v1';
const MiB = 1024 * 1024;
export const LINE_LIMIT = 4 * MiB;
export const SEGMENT_LINE_LIMIT = 8 * MiB;
// Better Auth stores a password as "<salt>:<key>" and keeps these scrypt parameters as constants in
// @better-auth/utils/password, so a snapshot carries them next to the hash.
export const SCRYPT = { algorithm: 'scrypt', N: 16384, r: 16, p: 1, dkLen: 64, normalization: 'NFKC' } as const;

const time = z.int().nonnegative();
const id = z.string().min(1);
const strings = z.array(z.string());
const method = z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const segmentKind = z.enum(['audit', 'access-request']);
const bound = z.tuple([time, id]);
const seq = z.int().nonnegative().max(9_999_999_999);
const rows = z.int().positive();

const header = z.strictObject({
  type: z.literal('header'),
  format: z.literal(SNAPSHOT_FORMAT),
  kind: z.enum(['automatic', 'full']),
  createdAt: time,
  source: z.strictObject({ origin: z.string(), rpId: z.string(), version: z.string() }),
});
const password = z
  .strictObject({
    algorithm: z.literal('scrypt'),
    N: z.int().positive(),
    r: z.int().positive(),
    p: z.int().positive(),
    dkLen: z.int().positive(),
    normalization: z.literal('NFKC'),
    salt: z.string().regex(/^[0-9a-fA-F]{32}$/),
    key: z.string().regex(/^[0-9a-f]+$/),
    createdAt: time,
    updatedAt: time,
  })
  .refine((p) => p.key.length === p.dkLen * 2, { message: 'key is the hexadecimal of dkLen bytes', path: ['key'] });
const passkey = z.strictObject({
  id,
  name: z.string().nullable(),
  publicKey: z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/),
  credentialID: z.string().regex(/^[A-Za-z0-9_-]+$/),
  counter: z.int().nonnegative(),
  deviceType: z.string(),
  backedUp: z.boolean(),
  transports: z.string().nullable(),
  createdAt: time.nullable(),
  aaguid: z.string().nullable(),
});
const owner = z.strictObject({
  type: z.literal('owner'),
  id,
  email: z.string().refine((e) => e === e.toLowerCase(), { message: 'email is lowercase' }),
  name: z.string(),
  emailVerified: z.boolean(),
  image: z.string().nullable(),
  createdAt: time,
  updatedAt: time,
  password,
  passkeys: z.array(passkey),
});
const settings = z.strictObject({ type: z.literal('settings'), backupRecipient: z.string().nullable() });
const archiveIdentity = z.strictObject({
  type: z.literal('archive-identity'),
  identity: z.string().regex(/^AGE-SECRET-KEY-PQ-1[0-9A-Z]+$/),
});
const secret = z.strictObject({
  type: z.literal('secret'),
  id,
  name: z.string(),
  description: z.string(),
  status: z.enum(['active', 'deleted']),
  currentVersion: z.int().nonnegative(),
  createdAt: time,
  updatedAt: time,
});
const secretVersion = z.strictObject({
  type: z.literal('secret-version'),
  secretId: id,
  version: z.int().positive(),
  values: z.record(z.string(), z.string()),
  createdAt: time,
});
const field = z.string().min(1);
const auth = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('none') }),
  z.strictObject({ type: z.literal('bearer'), secretId: id, field }),
  z.strictObject({ type: z.literal('header'), secretId: id, field, name: z.string().min(1) }),
  z.strictObject({ type: z.literal('basic'), secretId: id, usernameField: field, passwordField: field }),
  z.strictObject({ type: z.literal('query'), secretId: id, field, name: z.string().min(1) }),
]);
const policy = z.strictObject({
  paths: strings.min(1),
  methods: z.array(method).min(1),
  deny: strings,
  approval: strings,
  free: strings,
  hosts: strings,
  anyHost: z.boolean(),
});
const connection = z.strictObject({
  type: z.literal('connection'),
  id,
  name: z.string(),
  origin: z.string(),
  description: z.string(),
  auth,
  policy,
  status: z.enum(['active', 'deleted']),
  createdAt: time,
  updatedAt: time,
});
const installation = z.strictObject({
  type: z.literal('installation'),
  clientId: id,
  name: z.string().nullable(),
  applicationType: z.enum(['native', 'web']).nullable(),
  redirectUris: strings,
  scopes: strings.nullable(),
  grantTypes: strings.nullable(),
  disabled: z.boolean(),
  createdAt: time.nullable(),
  updatedAt: time.nullable(),
});
const extension = z.strictObject({
  paths: strings.min(1),
  methods: z.array(method).min(1),
  expiresAt: time.nullable(),
});
const grant = z.strictObject({
  type: z.literal('grant'),
  id,
  clientId: id,
  resourceType: z.enum(['secret', 'connection']),
  resourceId: id,
  permission: z.enum(['secret:read', 'connection:invoke']),
  fields: strings.min(1).nullable(),
  extensions: z.array(extension).nullable(),
  status: z.enum(['active', 'revoked']),
  expiresAt: time.nullable(),
  createdAt: time,
});
const accessRequest = z.strictObject({
  type: z.literal('access-request'),
  id,
  clientId: id,
  requested: z.record(z.string(), z.unknown()),
  reason: z.string().nullable(),
  status: z.enum(['pending', 'approved', 'denied']),
  fingerprint: z.string().nullable(),
  consumedAt: time.nullable(),
  createdAt: time,
  expiresAt: time,
});
const audit = z.strictObject({
  type: z.literal('audit'),
  id,
  clientId: z.string().nullable(),
  action: z.string(),
  resourceId: z.string().nullable(),
  result: z.string(),
  requestId: z.string(),
  createdAt: time,
});
const segment = z.strictObject({
  type: z.literal('segment'),
  kind: segmentKind,
  seq,
  first: bound,
  last: bound,
  rows,
  createdAt: time,
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  key: z
    .string()
    .regex(/^archive\/(audit|access-request)\/[0-9]{10}-[A-Za-z0-9_-]{22}\.age$/)
    .nullable(),
  // Checked as a character class and a length rather than one pattern of 4-character groups, which
  // would backtrack over a line of megabytes.
  data: z
    .string()
    .regex(/^[A-Za-z0-9+/]+={0,2}$/)
    .refine((d) => d.length % 4 === 0, { message: 'data is padded base64' })
    .nullable(),
});
/** The record types in their normative order. */
export const RECORD_TYPES = [
  'header',
  'owner',
  'settings',
  'archive-identity',
  'secret',
  'secret-version',
  'connection',
  'installation',
  'grant',
  'access-request',
  'audit',
  'segment',
  'end',
] as const;
/** The types end.counts lists: every type but header and end. */
export const COUNTED_TYPES = RECORD_TYPES.slice(1, -1) as Exclude<(typeof RECORD_TYPES)[number], 'header' | 'end'>[];
const count = z.int().nonnegative();
const end = z.strictObject({
  type: z.literal('end'),
  counts: z.strictObject({
    owner: count,
    settings: count,
    'archive-identity': count,
    secret: count,
    'secret-version': count,
    connection: count,
    installation: count,
    grant: count,
    'access-request': count,
    audit: count,
    segment: count,
  }),
});
export const snapshotRecord = z.discriminatedUnion('type', [
  header,
  owner,
  settings,
  archiveIdentity,
  secret,
  secretVersion,
  connection,
  installation,
  grant,
  accessRequest,
  audit,
  segment,
  end,
]);
export const archiveHeader = z.strictObject({
  type: z.literal('header'),
  format: z.literal(ARCHIVE_FORMAT),
  kind: segmentKind,
  seq,
  first: bound,
  last: bound,
  rows,
  createdAt: time,
});
export type SnapshotRecord = z.infer<typeof snapshotRecord>;
export type RecordOf<T extends SnapshotRecord['type']> = Extract<SnapshotRecord, { type: T }>;
export type ArchiveHeader = z.infer<typeof archiveHeader>;

const invalid = (message: string) => new Fault('invalid_snapshot', 400, message);
const issues = (e: z.ZodError) =>
  e.issues
    .slice(0, 5)
    .map((issue) => `${issue.path.join('.') || 'record'}: ${issue.message}`)
    .join('; ');
const lineLimit = (type: unknown) => (type === 'segment' ? SEGMENT_LINE_LIMIT : LINE_LIMIT);

const encoder = new TextEncoder();
/** One record as its line: JSON with U+2028, U+2029 and U+0085 escaped, terminated by LF, in UTF-8.
 * The three characters only occur inside JSON strings, where the escape means the same character. */
export function serializeRecord(record: SnapshotRecord | ArchiveHeader) {
  const line = encoder.encode(
    JSON.stringify(record).replace(
      /[\u2028\u2029\u0085]/g,
      (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`,
    ) + '\n',
  );
  if (line.length - 1 > lineLimit(record.type))
    throw new Fault('snapshot_line_too_long', 413, `a ${record.type} line exceeds its length limit`);
  return line;
}

/** Reads the lines of a decrypted snapshot or segment file and yields each parsed as JSON. It splits
 * on 0x0A only, refuses a byte order mark, invalid UTF-8, a line over its limit and a last line
 * without LF (a truncated file), and never holds more than one line. */
export async function* readRecords(stream: ReadableStream<Uint8Array>): AsyncGenerator<unknown> {
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  const reader = stream.getReader();
  let parts: Uint8Array[] = [],
    size = 0,
    line = 0;
  const parse = (bytes: Uint8Array) => {
    line++;
    if (line === 1 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
      throw invalid('line 1: the file starts with a byte order mark');
    // JSON.parse would accept them; the format does not.
    if ([bytes[0], bytes[bytes.length - 1]].some((b) => b === 0x20 || b === 0x09 || b === 0x0d))
      throw invalid(`line ${line}: whitespace or a CR around the JSON value`);
    let value: unknown;
    try {
      value = JSON.parse(decoder.decode(bytes));
    } catch {
      throw invalid(`line ${line}: not a JSON value in UTF-8`);
    }
    if (bytes.length > lineLimit((value as { type?: unknown } | null)?.type))
      throw invalid(`line ${line}: longer than its limit`);
    return value;
  };
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      let start = 0;
      for (let at = value.indexOf(0x0a); at !== -1; at = value.indexOf(0x0a, start)) {
        const piece = value.subarray(start, at);
        let bytes = piece;
        if (parts.length) {
          bytes = new Uint8Array(size + piece.length);
          let offset = 0;
          for (const part of [...parts, piece]) {
            bytes.set(part, offset);
            offset += part.length;
          }
          parts = [];
          size = 0;
        }
        if (bytes.length > SEGMENT_LINE_LIMIT) throw invalid(`line ${line + 1}: longer than its limit`);
        yield parse(bytes);
        start = at + 1;
      }
      if (start < value.length) {
        parts.push(value.slice(start));
        size += value.length - start;
        if (size > SEGMENT_LINE_LIMIT) throw invalid(`line ${line + 1}: longer than its limit`);
      }
    }
    if (size) throw invalid(`line ${line + 1}: the last line has no LF, so the file is truncated`);
  } catch (e) {
    await reader.cancel();
    throw e;
  } finally {
    reader.releaseLock();
  }
}

const SINGLE = new Set<string>(['header', 'owner', 'settings', 'archive-identity', 'end']);
/** Checks a snapshot record by record, in file order: each against its schema, the normative order, a
 * segment's key or data against header.kind, and at the end the counts against end.counts. push
 * returns the parsed record; finish confirms that the end record came. */
export class SnapshotValidator {
  private kind: RecordOf<'header'>['kind'] | null = null;
  private position = -1;
  private line = 0;
  private ended = false;
  private counts = Object.fromEntries(COUNTED_TYPES.map((type) => [type, 0])) as Record<
    (typeof COUNTED_TYPES)[number],
    number
  >;
  push(value: unknown): SnapshotRecord {
    this.line++;
    const fail = (message: string) => invalid(`line ${this.line}: ${message}`);
    if (this.ended) throw fail('a record after end');
    const parsed = snapshotRecord.safeParse(value);
    if (!parsed.success) throw fail(issues(parsed.error));
    const record = parsed.data;
    const at = RECORD_TYPES.indexOf(record.type);
    // header, owner and settings open the file in this order; after them a type may repeat its
    // predecessor unless it occurs once, and never goes back.
    if (
      this.position < 2
        ? at !== this.position + 1
        : at < this.position || (at === this.position && SINGLE.has(record.type))
    )
      throw fail(`${record.type} is out of order`);
    this.position = at;
    if (record.type === 'header') this.kind = record.kind;
    else if (record.type === 'segment') {
      const embedded = this.kind === 'full';
      if (embedded ? record.data === null || record.key !== null : record.key === null || record.data !== null)
        throw fail(`a segment in a ${this.kind} snapshot has ${embedded ? 'data and no key' : 'a key and no data'}`);
      if (
        record.key !== null &&
        !record.key.startsWith(`archive/${record.kind}/${String(record.seq).padStart(10, '0')}-`)
      )
        throw fail("a segment key does not name the segment's own kind and seq");
    }
    if (record.type === 'end') {
      this.ended = true;
      for (const type of COUNTED_TYPES)
        if (record.counts[type] !== this.counts[type])
          throw fail(`end.counts.${type} is ${record.counts[type]}, the file has ${this.counts[type]}`);
      if (this.counts.segment && !this.counts['archive-identity'])
        throw fail('the snapshot has segments but no archive-identity');
    } else if (record.type !== 'header') this.counts[record.type]++;
    return record;
  }
  finish() {
    if (!this.ended) throw invalid(`line ${this.line + 1}: no end record, so the file is truncated`);
  }
}

/** What a snapshot needs besides its structure to be imported: every active credential has all its
 * versions, every active connection's credential exists with the fields it injects, every grant and
 * access request names an installation of the file and every grant a resource of the file. */
export function checkReferences(records: SnapshotRecord[]) {
  const of = <T extends SnapshotRecord['type']>(type: T) => records.filter((r): r is RecordOf<T> => r.type === type);
  const held = new Map<string, RecordOf<'secret-version'>[]>();
  for (const v of of('secret-version')) held.set(v.secretId, [...(held.get(v.secretId) ?? []), v]);
  const current = new Map<string, Record<string, string>>();
  for (const s of of('secret')) {
    if (s.status !== 'active') continue;
    const versions = held.get(s.id) ?? [];
    assert(
      versions.length === s.currentVersion && versions.every((v, i) => v.version === i + 1),
      'backup_has_missing_versions',
      409,
      `secret ${s.id}`,
    );
    current.set(s.id, versions[versions.length - 1].values);
  }
  for (const c of of('connection')) {
    if (c.status !== 'active' || c.auth.type === 'none') continue;
    const values = current.get(c.auth.secretId);
    const fields = c.auth.type === 'basic' ? [c.auth.usernameField, c.auth.passwordField] : [c.auth.field];
    assert(
      values && fields.every((field) => Object.hasOwn(values, field)),
      'backup_has_broken_connection',
      409,
      `connection ${c.id}`,
    );
  }
  const clients = new Set(of('installation').map((i) => i.clientId));
  const resources = {
    secret: new Set(of('secret').map((s) => s.id)),
    connection: new Set(of('connection').map((c) => c.id)),
  };
  for (const g of of('grant'))
    assert(
      clients.has(g.clientId) && resources[g.resourceType].has(g.resourceId),
      'backup_has_dangling_reference',
      409,
      `grant ${g.id}`,
    );
  for (const r of of('access-request'))
    assert(clients.has(r.clientId), 'backup_has_dangling_reference', 409, `access request ${r.id}`);
}
