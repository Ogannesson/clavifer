import { Buffer } from 'node:buffer';
import { Encrypter, identityToRecipient } from 'age-encryption';
import { decryptArchiveIdentity, encode } from '../../../packages/core/crypto';
import { Fault, assert } from '../../../packages/core/errors';
import { ARCHIVE_FORMAT, archiveHeader, snapshotRecord } from '../../../packages/core/snapshot';
import { type Bindings, audit, auditStatement, now, rootKeys } from './context';
import { CARRIED, rowBytes } from './backup';
import { auditRecord, requestRecord, serialized } from './export';

// Cold data: audit rows and access requests leave the hot tables in sealed segments, immutable age files
// under archive/ encrypted to the archive identity, and never come back. Nothing under archive/ is ever
// overwritten or deleted: an object no manifest row names may be the only copy of an earlier instance's
// rows. A row is sealable once nothing changes it any more: an audit row 5 minutes after it was written
// (a request may write it a little after it took the time), an access request 25 hours after it was
// created (expired after 24 hours, or run within 10 minutes of approval). Both horizons hold only while
// created_at is always the time of the INSERT.
const KINDS = {
  audit: { table: 'audit_events', age: 5 * 60_000, record: auditRecord },
  'access-request': { table: 'access_requests', age: 25 * 3_600_000, record: requestRecord },
} as const;
// A kind is sealed while its sealable rows take more than KEEP bytes, a segment of about SEGMENT bytes at a
// time from the oldest, so the hot tables keep the most recent history for the console.
const KEEP = 1_500_000;
const SEGMENT = 1_000_000;
// One run stops after about 20 seconds or 600 D1 queries, leaving the backup that follows it in the same
// invocation the rest of the 30 seconds and of the 1000 queries. A segment takes at most 6 queries.
const TIME_BUDGET = 20_000;
const QUERY_BUDGET = 600;
const SEGMENT_QUERIES = 6;

/** What every key of segment seq of kind starts with: archive/<kind>/<seq padded to ten digits>-. */
export const segmentPrefix = (kind: string, seq: number) => `archive/${kind}/${String(seq).padStart(10, '0')}-`;
/** A key no object has had: the prefix and 22 random characters. */
export const segmentKey = (kind: string, seq: number) =>
  `${segmentPrefix(kind, seq)}${encode(crypto.getRandomValues(new Uint8Array(16)))}.age`;

// Sealing needs only the public recipient. The isolate derives it once, after the self-check passed;
// the identity itself is decrypted again only to assemble a snapshot.
let recipient = '';
async function archiveRecipient(env: Bindings, owner: string) {
  if (recipient) return recipient;
  const row = await env.DB.prepare("SELECT value FROM system_state WHERE key='archive_identity'").first<{
    value: string;
  }>();
  assert(row, 'archive_identity_missing', 503);
  return (recipient = await identityToRecipient(
    await decryptArchiveIdentity(rootKeys(env), owner, JSON.parse(row.value)),
  ));
}

/** Seals the oldest sealable rows of each kind into segments, while there are enough of them and the run
 * has budget left. It stops at the first failure and records its code in backup_state.archive_error for
 * the console, without retrying: every attempt leaves an object behind for good. A run that lost the race
 * to an overlapping one stops without an error. */
export async function sealColdData(env: Bindings, owner: string) {
  const started = now();
  let queries = 0;
  try {
    for (const kind of Object.keys(KINDS) as (keyof typeof KINDS)[])
      while (now() - started < TIME_BUDGET && queries + SEGMENT_QUERIES <= QUERY_BUDGET) {
        queries += SEGMENT_QUERIES;
        const outcome = await sealSegment(env, owner, kind);
        if (outcome === 'superseded') return;
        if (outcome === 'none') break;
      }
  } catch (e) {
    const code = e instanceof Fault ? e.code : 'archive_failed';
    await env.DB.prepare('UPDATE backup_state SET archive_error=? WHERE id=1').bind(code).run();
    await audit(env, 'system', 'archive:seal', null, code);
    return;
  }
  await env.DB.prepare('UPDATE backup_state SET archive_error=NULL WHERE id=1 AND archive_error IS NOT NULL').run();
}

/** Seals the next segment of kind, if its sealable rows take more than KEEP bytes. Returns none when they
 * do not, superseded when an overlapping run committed the same segment first. */
async function sealSegment(env: Bindings, owner: string, kind: keyof typeof KINDS) {
  const { table, age, record } = KINDS[kind];
  const columns = CARRIED[table];
  // seq is fixed by this read: it is in the object's key and header, and the commit inserts exactly it.
  // The segment is the oldest rows up to the one that reaches SEGMENT bytes, read in one page; the
  // window sums run in the database, so only the segment's own rows come back.
  const [last, page] = await env.DB.batch([
    env.DB.prepare('SELECT IFNULL(MAX(seq),0) AS seq FROM archive_segments WHERE kind=?').bind(kind),
    env.DB.prepare(
      `SELECT ${columns} FROM (SELECT *,SUM(bytes) OVER (ORDER BY created_at,id ROWS UNBOUNDED PRECEDING)-bytes AS before,SUM(bytes) OVER () AS total FROM (SELECT ${columns},${rowBytes(table)} AS bytes FROM ${table} WHERE created_at<?)) WHERE total>? AND before<? ORDER BY created_at,id`,
    ).bind(now() - age, KEEP, SEGMENT),
  ]);
  const rows = page.results as Record<string, unknown>[];
  if (!rows.length) return 'none';
  const seq = (last.results[0] as { seq: number }).seq + 1,
    sealedAt = now();
  const first = rows[0],
    end = rows[rows.length - 1];
  const bounds = [first.created_at, first.id, end.created_at, end.id];
  const plain = serialized([
    archiveHeader.parse({
      type: 'header',
      format: ARCHIVE_FORMAT,
      kind,
      seq,
      first: bounds.slice(0, 2),
      last: bounds.slice(2),
      rows: rows.length,
      createdAt: sealedAt,
    }),
    ...rows.map((row) => snapshotRecord.parse(record(row))),
  ]);
  const encrypter = new Encrypter();
  encrypter.addRecipient(await archiveRecipient(env, owner));
  const file = new Uint8Array(await encrypter.encrypt(plain));
  const sha256 = Buffer.from(await crypto.subtle.digest('SHA-256', file)).toString('hex');
  const key = segmentKey(kind, seq);
  // R2 checks the upload against sha256 and keeps it for head().
  await env.BACKUPS.put(key, file, { sha256 });
  const range = `FROM ${table} WHERE (created_at,id)>=(?,?) AND (created_at,id)<=(?,?)`;
  // The manifest row is the guard: its object_key is NULL, which the column refuses, unless the range
  // still holds exactly the rows read, and its key (kind, seq) is taken if an overlapping run committed
  // first. Either way the whole batch rolls back. A DELETE that matches nothing would not.
  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO archive_segments (kind,seq,object_key,sha256,first_at,first_id,last_at,last_id,rows,created_at) SELECT ?,?,CASE WHEN (SELECT COUNT(*) ${range})=? THEN ? END,?,?,?,?,?,?,?`,
      ).bind(kind, seq, ...bounds, rows.length, key, sha256, ...bounds, rows.length, sealedAt),
      env.DB.prepare(`DELETE ${range}`).bind(...bounds),
      await auditStatement(env, 'system', 'archive:seal', key),
    ]);
  } catch (e) {
    // Only a segment committed under this seq means another run sealed these rows. Without one, the range
    // changed while nobody sealed it, which the created_at invariant rules out: that is an error, or every
    // run would leave another object behind without a word.
    if (await env.DB.prepare('SELECT 1 FROM archive_segments WHERE kind=? AND seq=?').bind(kind, seq).first())
      return 'superseded';
    if (e instanceof Error && /constraint failed: archive_segments\./.test(e.message))
      throw new Fault('archive_conflict', 409);
    throw e;
  }
  return 'sealed';
}
