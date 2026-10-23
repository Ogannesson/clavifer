import { Decrypter } from 'age-encryption';
import { SnapshotValidator, readRecords, type RecordOf, type SnapshotRecord } from '../../../packages/core/snapshot';

/** Posts a JSON body to a path of the service and resolves with its JSON answer; throws on an error. */
export type Send = (path: string, body: unknown, headers?: Record<string, string>) => Promise<Record<string, unknown>>;
export type Segment = { kind: 'audit' | 'access-request'; seq: number };

// About 4 MB of records go in one chunk, which the service writes in one batch; an embedded segment goes
// alone. The service looks up each referenced segment in its bucket, a subrequest each, so a chunk names
// at most this many.
const CHUNK = 4_000_000;
const REFERENCES = 1000;
const encoder = new TextEncoder();

/**
 * Imports an age-encrypted snapshot file into the uninitialized instance the token was issued for. The
 * file is decrypted with identity and read record by record as it streams, each checked against the v1
 * format, and sent in chunks: no more than one chunk is held. When the service does not find referenced
 * segments in its bucket, missing decides whether to go on without them; declining stops the import and
 * resolves null, leaving the instance uninitialized. Resolves the snapshot's header once imported.
 */
export async function importSnapshot({
  file,
  identity,
  token,
  send,
  missing,
}: {
  file: ReadableStream<Uint8Array>;
  identity: string;
  token: string;
  send: Send;
  missing: (segments: Segment[]) => Promise<boolean>;
}) {
  const decrypter = new Decrypter();
  decrypter.addIdentity(identity);
  const validator = new SnapshotValidator();
  let header: RecordOf<'header'> | undefined,
    importId = '',
    settings: RecordOf<'settings'> | undefined,
    archiveIdentity: RecordOf<'archive-identity'> | null = null,
    end: RecordOf<'end'> | undefined;
  let chunk: SnapshotRecord[] = [],
    size = 0,
    references = 0,
    seq = 0;
  // A chunk the service wrote is written once however often it arrives, so one lost on the way is sent again.
  const post = async (body: unknown) => {
    for (let attempt = 1; ; attempt++)
      try {
        return await send('/api/setup/import/chunk', body);
      } catch (e) {
        if (attempt === 3 || (e as { code?: unknown }).code !== 'network_error') throw e;
      }
  };
  const flush = async () => {
    if (!chunk.length) return true;
    let skip: Segment[] = [];
    for (;;) {
      const answer = await post({ importId, seq, records: chunk, skip });
      if (answer.written) break;
      skip = answer.missing as Segment[];
      if (!(await missing(skip))) return false;
    }
    seq++;
    chunk = [];
    size = 0;
    references = 0;
    return true;
  };
  for await (const value of readRecords(await decrypter.decrypt(file))) {
    const record = validator.push(value);
    if (record.type === 'header') header = record;
    else if (record.type === 'owner')
      importId = String(
        (await send('/api/setup/import', { header, owner: record }, { 'x-bootstrap-token': token })).importId,
      );
    else if (record.type === 'settings') settings = record;
    else if (record.type === 'archive-identity') archiveIdentity = record;
    else if (record.type === 'end') end = record;
    else {
      const bytes = encoder.encode(JSON.stringify(record)).length;
      const embedded = record.type === 'segment' && record.data !== null;
      if ((size + bytes > CHUNK || embedded || references === REFERENCES) && !(await flush())) return null;
      chunk.push(record);
      size += bytes;
      if (record.type === 'segment') references++;
    }
  }
  validator.finish();
  if (!(await flush())) return null;
  await send('/api/setup/import/commit', { importId, settings, archiveIdentity, end });
  return header!;
}
