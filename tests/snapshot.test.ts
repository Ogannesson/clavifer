import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { createHash, scryptSync } from 'node:crypto';
import { Decrypter } from 'age-encryption';
import {
  ARCHIVE_FORMAT,
  LINE_LIMIT,
  RECORD_TYPES,
  SEGMENT_LINE_LIMIT,
  SnapshotValidator,
  archiveHeader,
  checkReferences,
  readRecords,
  serializeRecord,
  snapshotRecord,
  type RecordOf,
  type SnapshotRecord,
} from '../packages/core/snapshot';

const header = (kind = 'full') => ({
  type: 'header',
  format: 'clavifer-backup-v1',
  kind,
  createdAt: 1,
  source: { origin: 'https://vault.example.com', rpId: 'vault.example.com', version: '0.5.0' },
});
const owner = {
  type: 'owner',
  id: 'owner',
  email: 'owner@example.com',
  name: 'Owner',
  emailVerified: false,
  image: null,
  createdAt: 1,
  updatedAt: 2,
  password: {
    algorithm: 'scrypt',
    N: 16384,
    r: 16,
    p: 1,
    dkLen: 64,
    normalization: 'NFKC',
    salt: '0123456789abcdef0123456789abcdef',
    key: 'a'.repeat(128),
    createdAt: 1,
    updatedAt: 2,
  },
  passkeys: [
    {
      id: 'passkey',
      name: null,
      publicKey: 'pQECAyYgASFYIA==',
      credentialID: 'Y3JlZGVudGlhbA',
      counter: 0,
      deviceType: 'multiDevice',
      backedUp: true,
      transports: 'internal,hybrid',
      createdAt: null,
      aaguid: null,
    },
  ],
};
const settings = { type: 'settings', backupRecipient: null };
const identity = { type: 'archive-identity', identity: 'AGE-SECRET-KEY-PQ-1ABC' };
const secret = {
  type: 'secret',
  id: 'secret',
  name: 'Synthetic',
  description: '',
  status: 'active',
  currentVersion: 1,
  createdAt: 1,
  updatedAt: 1,
};
const version = {
  type: 'secret-version',
  secretId: 'secret',
  version: 1,
  values: { token: 'synthetic' },
  createdAt: 1,
};
const policy = { paths: ['/v1'], methods: ['GET'], deny: [], approval: [], free: [], hosts: [], anyHost: false };
const connection = {
  type: 'connection',
  id: 'connection',
  name: 'Synthetic',
  origin: 'https://api.example.com',
  description: '',
  auth: { type: 'bearer', secretId: 'secret', field: 'token' },
  policy,
  status: 'active',
  createdAt: 1,
  updatedAt: 1,
};
const installation = {
  type: 'installation',
  clientId: 'client',
  name: 'CLI',
  applicationType: 'native',
  redirectUris: [],
  scopes: ['secret:read'],
  grantTypes: null,
  disabled: false,
  createdAt: 1,
  updatedAt: null,
};
const grant = {
  type: 'grant',
  id: 'grant',
  clientId: 'client',
  resourceType: 'connection',
  resourceId: 'connection',
  permission: 'connection:invoke',
  fields: null,
  extensions: [{ paths: ['/v2'], methods: ['POST'], expiresAt: null }],
  status: 'active',
  expiresAt: null,
  createdAt: 1,
};
const request = {
  type: 'access-request',
  id: 'request',
  clientId: 'client',
  requested: { grants: [{ resourceId: 'connection' }] },
  reason: null,
  status: 'pending',
  fingerprint: null,
  consumedAt: null,
  createdAt: 1,
  expiresAt: 2,
};
const audit = {
  type: 'audit',
  id: 'audit',
  clientId: null,
  action: 'secret:create',
  resourceId: null,
  result: 'ok',
  requestId: 'request-id',
  createdAt: 1,
};
const segment = (embedded: boolean) => ({
  type: 'segment',
  kind: 'audit',
  seq: 1,
  first: [1, 'a'],
  last: [2, 'b'],
  rows: 2,
  createdAt: 3,
  sha256: 'e'.repeat(64),
  key: embedded ? null : `archive/audit/0000000001-${'A'.repeat(22)}.age`,
  data: embedded ? 'YWdlLWVuY3J5cHRpb24=' : null,
});
const counts = (over: Record<string, number> = {}) => ({
  owner: 1,
  settings: 1,
  'archive-identity': 0,
  secret: 0,
  'secret-version': 0,
  connection: 0,
  installation: 0,
  grant: 0,
  'access-request': 0,
  audit: 0,
  segment: 0,
  ...over,
});
const end = (over: Record<string, number> = {}) => ({ type: 'end', counts: counts(over) });
const complete = () => [
  header(),
  owner,
  settings,
  secret,
  version,
  connection,
  installation,
  grant,
  request,
  audit,
  end({ secret: 1, 'secret-version': 1, connection: 1, installation: 1, grant: 1, 'access-request': 1, audit: 1 }),
];

function validate(records: unknown[]) {
  const validator = new SnapshotValidator();
  for (const record of records) validator.push(record);
  validator.finish();
}
const utf8 = new TextEncoder();
const chunks = (...parts: (string | Uint8Array)[]) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      for (const part of parts) controller.enqueue(typeof part === 'string' ? utf8.encode(part) : part);
      controller.close();
    },
  });
async function read(stream: ReadableStream<Uint8Array>) {
  const out: unknown[] = [];
  for await (const record of readRecords(stream)) out.push(record);
  return out;
}
const concat = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  parts.reduce((offset, p) => (out.set(p, offset), offset + p.length), 0);
  return out;
};
// Built from code points so this file holds none of the characters raw.
const [LS, PS, NEL] = [0x2028, 0x2029, 0x85].map((c) => String.fromCharCode(c));
const escaped = (c: string) => '\\' + 'u' + c.charCodeAt(0).toString(16).padStart(4, '0');

describe('snapshot lines', () => {
  it('escapes U+2028, U+2029 and U+0085 so the line splits back only on LF', () => {
    const value = `a${LS}b${PS}c${NEL}d`;
    const line = serializeRecord({ ...audit, action: value } as SnapshotRecord);
    expect(line.filter((b) => b === 0x0a)).toHaveLength(1);
    expect(line[line.length - 1]).toBe(0x0a);
    const text = new TextDecoder().decode(line);
    for (const c of [LS, PS, NEL]) {
      expect(text).not.toContain(c);
      expect(text).toContain(escaped(c));
    }
    // A reader that also broke lines at these characters still sees one line.
    expect(text.split(new RegExp(`\r\n|\n|${LS}|${PS}|${NEL}`))).toEqual([text.slice(0, -1), '']);
    expect(JSON.parse(text)).toEqual({ ...audit, action: value });
  });

  it('reads records whose lines and characters are split across chunks', async () => {
    const records = complete().map((r) => ({ ...r }));
    (records[3] as typeof secret).name = '中文凭据';
    const bytes = concat(records.map((r) => serializeRecord(r as SnapshotRecord)));
    const cut = bytes.indexOf(0xe4) + 1; // inside the first Chinese character
    expect(await read(chunks(bytes.subarray(0, 3), bytes.subarray(3, cut), bytes.subarray(cut)))).toEqual(records);
    expect(await read(chunks(...[...bytes].map((b) => Uint8Array.of(b))))).toEqual(records);
  });

  it('holds a line to exactly 4 MiB, or 8 MiB for a segment, in bytes without the LF', async () => {
    expect([LINE_LIMIT, SEGMENT_LINE_LIMIT]).toEqual([4 * 1024 * 1024, 8 * 1024 * 1024]);
    // Records padded to the limit, and one byte past it.
    const sized = <T extends object>(record: T, key: keyof T, bytes: number) => {
      const bare = JSON.stringify({ ...record, [key]: '' }).length;
      return { ...record, [key]: 'A'.repeat(bytes - bare) } as unknown as SnapshotRecord;
    };
    for (const [record, key, limit] of [
      [audit, 'action', LINE_LIMIT],
      [segment(true), 'data', SEGMENT_LINE_LIMIT],
    ] as const) {
      const fits = sized(record, key as never, limit),
        over = sized(record, key as never, limit + 1);
      expect(serializeRecord(fits)).toHaveLength(limit + 1);
      expect(() => serializeRecord(over)).toThrow(expect.objectContaining({ code: 'snapshot_line_too_long' }));
      expect(await read(chunks(JSON.stringify(fits) + '\n'))).toHaveLength(1);
      await expect(read(chunks(JSON.stringify(over) + '\n'))).rejects.toThrow('longer than its limit');
    }
  });

  it('refuses whitespace or a CR around the value', async () => {
    const line = JSON.stringify(header());
    for (const bad of [`${line}\r\n`, ` ${line}\n`, `${line} \n`, `\t${line}\n`])
      await expect(read(chunks(bad))).rejects.toThrow('whitespace or a CR');
    expect(await read(chunks(`${line}\n`))).toEqual([header()]);
  });

  it('refuses lines over their limit, a truncated last line, a byte order mark and invalid UTF-8', async () => {
    // A line is refused once it grows past the segment limit, before its end arrives.
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(1024 * 1024).fill(0x61));
      },
    });
    await expect(read(endless)).rejects.toThrow(`longer than its limit`);
    await expect(read(chunks(JSON.stringify(header()) + '\n' + JSON.stringify(owner)))).rejects.toThrow('truncated');
    await expect(read(chunks(Uint8Array.of(0xef, 0xbb, 0xbf), JSON.stringify(header()) + '\n'))).rejects.toThrow(
      'byte order mark',
    );
    await expect(read(chunks(Uint8Array.of(0x22, 0xff, 0x22, 0x0a)))).rejects.toMatchObject({
      code: 'invalid_snapshot',
    });
    await expect(read(chunks('\n'))).rejects.toMatchObject({ code: 'invalid_snapshot' });
  });
});

describe('snapshot records', () => {
  const accepts = (record: unknown) => snapshotRecord.safeParse(record).success;

  it('accepts every record type in its specified shape', () => {
    for (const record of [...complete(), identity, segment(true), segment(false)]) expect(accepts(record)).toBe(true);
    expect(
      archiveHeader.safeParse({
        type: 'header',
        format: 'clavifer-archive-v1',
        kind: 'access-request',
        seq: 0,
        first: [1, 'a'],
        last: [1, 'a'],
        rows: 1,
        createdAt: 2,
      }).success,
    ).toBe(true);
  });

  it('rejects unknown types and unknown fields, also inside nested objects', () => {
    expect(accepts({ type: 'session', id: 'x' })).toBe(false);
    expect(accepts({ ...header(), extra: 1 })).toBe(false);
    expect(accepts({ ...owner, password: { ...owner.password, iterations: 1 } })).toBe(false);
    expect(accepts({ ...connection, policy: { ...policy, scope: [] } })).toBe(false);
    expect(accepts({ ...connection, auth: { ...connection.auth, value: 'x' } })).toBe(false);
    expect(accepts({ ...grant, extensions: [{ ...grant.extensions[0], note: '' }] })).toBe(false);
    expect(accepts({ ...segment(true), first: [1, 'a', 'b'] })).toBe(false);
    expect(accepts({ ...header(), format: 'clavifer-backup-v2' })).toBe(false);
  });

  it('tells null from a missing field', () => {
    const { image: _, ...withoutImage } = owner;
    expect(accepts(withoutImage)).toBe(false);
    expect(accepts({ ...owner, image: 'https://example.com/a.png' })).toBe(true);
    const { reason: __, ...withoutReason } = request;
    expect(accepts(withoutReason)).toBe(false);
    // Fields that are not nullable refuse null.
    const { fingerprint: ____, ...withoutFingerprint } = request;
    expect(accepts(withoutFingerprint)).toBe(false);
    expect(accepts({ ...grant, extensions: [{ paths: ['/v2'], methods: ['POST'] }] })).toBe(false);
    expect(accepts({ ...installation, disabled: null })).toBe(false);
    expect(accepts({ ...installation, redirectUris: null })).toBe(false);
    expect(accepts({ ...secret, description: null })).toBe(false);
    expect(accepts({ ...audit, requestId: null })).toBe(false);
  });

  it('holds enumerations and the normalized shapes', () => {
    expect(accepts({ ...secret, status: 'archived' })).toBe(false);
    expect(accepts({ ...connection, status: 'revoked' })).toBe(false);
    expect(accepts({ ...grant, permission: 'secret:write' })).toBe(false);
    expect(accepts({ ...grant, status: 'deleted' })).toBe(false);
    expect(accepts({ ...request, status: 'expired' })).toBe(false);
    expect(accepts({ ...installation, applicationType: 'browser' })).toBe(false);
    expect(accepts({ ...header(), kind: 'partial' })).toBe(false);
    expect(accepts({ ...segment(true), kind: 'grant' })).toBe(false);
    // An empty list would read as "every path" or "every method".
    expect(accepts({ ...connection, policy: { ...policy, paths: [] } })).toBe(false);
    expect(accepts({ ...connection, policy: { ...policy, methods: [] } })).toBe(false);
    expect(accepts({ ...connection, policy: { ...policy, methods: ['TRACE'] } })).toBe(false);
    const { anyHost: ___, ...partial } = policy;
    expect(accepts({ ...connection, policy: partial })).toBe(false);
    expect(accepts({ ...grant, extensions: [{ paths: [], methods: ['GET'], expiresAt: 1 }] })).toBe(false);
    expect(accepts({ ...grant, extensions: [{ paths: ['/'], methods: [], expiresAt: 1 }] })).toBe(false);
    expect(accepts({ ...grant, fields: [] })).toBe(false);
    expect(accepts({ ...grant, fields: ['token'] })).toBe(true);
    expect(accepts({ ...owner, email: 'Owner@example.com' })).toBe(false);
    expect(accepts({ ...owner, password: { ...owner.password, salt: 'ab'.repeat(32) } })).toBe(false);
    expect(accepts({ ...owner, password: { ...owner.password, key: 'a'.repeat(64) } })).toBe(false);
    expect(accepts({ ...owner, password: { ...owner.password, normalization: 'NFC' } })).toBe(false);
    expect(accepts({ ...request, requested: 'grants' })).toBe(false);
    expect(accepts({ ...audit, createdAt: 1.5 })).toBe(false);
    expect(accepts({ ...segment(true), data: 'YWdl=' })).toBe(false);
  });

  it('pins every encoding exactly', () => {
    const password = (over: object) => ({ ...owner, password: { ...owner.password, ...over } });
    const passkey = (over: object) => ({ ...owner, passkeys: [{ ...owner.passkeys[0], ...over }] });
    expect(accepts(password({ key: 'A'.repeat(128) }))).toBe(false);
    expect(accepts(password({ salt: '0'.repeat(31) }))).toBe(false);
    expect(accepts(password({ salt: '0'.repeat(33) }))).toBe(false);
    expect(accepts(password({ salt: '0123456789ABCDEF0123456789abcdef' }))).toBe(true);
    for (const credentialID of ['Y3Jl+ZA', 'Y3Jl/ZA', 'Y3JlZA=='])
      expect(accepts(passkey({ credentialID }))).toBe(false);
    for (const publicKey of ['pQEC-yYg', 'pQEC_yYg']) expect(accepts(passkey({ publicKey }))).toBe(false);
    for (const value of [
      'AGE-SECRET-KEY-1ABC',
      'AGE-SECRET-KEY-PQ-1abc',
      'AGE-SECRET-KEY-PQ-ABC',
      ' AGE-SECRET-KEY-PQ-1ABC',
    ])
      expect(accepts({ ...identity, identity: value })).toBe(false);
    expect(accepts({ ...segment(true), sha256: 'E'.repeat(64) })).toBe(false);
    expect(accepts({ ...segment(true), sha256: 'e'.repeat(63) })).toBe(false);
    const name = 'A'.repeat(22);
    for (const key of [
      'archive/x',
      'vault/2026-10-21/1.age',
      `archive/grant/0000000001-${name}.age`,
      `archive/audit/1-${name}.age`,
      `archive/audit/00000000001-${name}.age`,
      `archive/audit/0000000001-${'A'.repeat(21)}.age`,
      `archive/audit/0000000001-${name}.txt`,
      `archive/audit/0000000001-${name}.age/x`,
    ])
      expect(accepts({ ...segment(false), key })).toBe(false);
    expect(accepts({ ...segment(false), seq: 9_999_999_999 })).toBe(true);
    expect(accepts({ ...segment(false), seq: 10_000_000_000 })).toBe(false);
  });
});

describe('snapshot order and counts', () => {
  it('accepts a complete snapshot and refuses one cut short', () => {
    expect(() => validate(complete())).not.toThrow();
    expect(() => validate(complete().slice(0, -1))).toThrow('no end record');
  });

  it('refuses records out of the normative order', () => {
    const records = complete();
    const swap = (i: number, j: number) => {
      const copy = [...records];
      [copy[i], copy[j]] = [copy[j], copy[i]];
      return copy;
    };
    expect(() => validate(swap(0, 1))).toThrow('out of order');
    expect(() => validate(swap(1, 2))).toThrow('out of order');
    expect(() => validate(swap(4, 5))).toThrow('out of order');
    expect(() => validate(swap(8, 9))).toThrow('out of order');
    expect(() => validate([header(), settings])).toThrow('out of order');
    expect(() => validate([header(), owner, owner])).toThrow('out of order');
    expect(() => validate([header(), owner, settings, identity, identity])).toThrow('out of order');
    expect(() => validate([header(), owner, settings, end(), audit])).toThrow('a record after end');
    expect(() => validate([header(), owner, settings, end(), end()])).toThrow('a record after end');
    // Repeated types may follow one another.
    expect(() =>
      validate([header(), owner, settings, secret, { ...secret, id: 'b' }, end({ secret: 2 })]),
    ).not.toThrow();
  });

  it('checks end.counts, zero counts included', () => {
    expect(() => validate([header(), owner, settings, secret, end()])).toThrow('end.counts.secret is 0');
    for (const type of Object.keys(counts())) {
      const missing: Record<string, number> = counts();
      delete missing[type];
      // Refused by the record's own shape, not only by the count comparison.
      expect(snapshotRecord.safeParse({ type: 'end', counts: missing }).success).toBe(false);
    }
    expect(() => validate([header(), owner, settings, end()])).not.toThrow();
  });

  it('ties a segment to header.kind and to the archive identity', () => {
    const tail = [end({ 'archive-identity': 1, segment: 1 })];
    expect(() => validate([header('full'), owner, settings, identity, segment(true), ...tail])).not.toThrow();
    expect(() => validate([header('full'), owner, settings, identity, segment(false), ...tail])).toThrow(
      'has data and no key',
    );
    expect(() => validate([header('automatic'), owner, settings, identity, segment(false), ...tail])).not.toThrow();
    expect(() => validate([header('automatic'), owner, settings, identity, segment(true), ...tail])).toThrow(
      'has a key and no data',
    );
    expect(() =>
      validate([header('full'), owner, settings, { ...segment(true), key: segment(false).key }, ...tail]),
    ).toThrow();
    expect(() => validate([header('full'), owner, settings, segment(true), end({ segment: 1 })])).toThrow(
      'no archive-identity',
    );
  });

  it("requires a segment key to name the segment's own kind and seq", () => {
    const automatic = (s: object) => () =>
      validate([header('automatic'), owner, settings, identity, s, end({ 'archive-identity': 1, segment: 1 })]);
    const name = 'A'.repeat(22);
    expect(automatic(segment(false))).not.toThrow();
    expect(automatic({ ...segment(false), kind: 'access-request' })).toThrow('own kind and seq');
    expect(automatic({ ...segment(false), seq: 2 })).toThrow('own kind and seq');
    expect(automatic({ ...segment(false), seq: 12, key: `archive/audit/0000000012-${name}.age` })).not.toThrow();
  });
});

describe('snapshot references', () => {
  const check = (records: unknown[]) => () => checkReferences(records as SnapshotRecord[]);
  it('requires what an import needs besides the structure', () => {
    expect(check(complete())).not.toThrow();
    expect(check(complete().filter((r) => r !== version))).toThrow(
      expect.objectContaining({ code: 'backup_has_missing_versions' }),
    );
    expect(check([...complete(), { ...version, version: 2 }])).toThrow(
      expect.objectContaining({ code: 'backup_has_missing_versions' }),
    );
    expect(check([...complete().filter((r) => r !== version), { ...version, values: { other: 'x' } }])).toThrow(
      expect.objectContaining({ code: 'backup_has_broken_connection' }),
    );
    expect(check(complete().filter((r) => r !== installation))).toThrow(
      expect.objectContaining({ code: 'backup_has_dangling_reference' }),
    );
    expect(check([...complete().filter((r) => r !== request), { ...request, clientId: 'gone' }])).toThrow(
      expect.objectContaining({ code: 'backup_has_dangling_reference', message: 'access request request' }),
    );
    expect(check([...complete().filter((r) => r !== grant), { ...grant, resourceId: 'gone' }])).toThrow(
      expect.objectContaining({ code: 'backup_has_dangling_reference', message: 'grant grant' }),
    );
    // A deleted credential has no versions, and a deleted connection binds nothing.
    expect(
      check([
        ...complete().filter((r) => r !== secret && r !== version && r !== connection),
        { ...secret, status: 'deleted' },
        { ...connection, status: 'deleted' },
      ]),
    ).not.toThrow();
  });
});

describe('v1 sample files', () => {
  // Written once by the first exporter from synthetic data and never modified: every later version
  // must still read them.
  it('decrypts and validates the full export sample', async () => {
    const decrypter = new Decrypter();
    decrypter.addIdentity((await readFile('tests/fixtures/v1/test-identity.txt', 'utf8')).trim());
    const file = new Uint8Array(await readFile('tests/fixtures/v1/full-a.age'));
    // A regenerated or altered sample fails here; the file itself is the promise.
    expect(createHash('sha256').update(file).digest('hex')).toBe(
      '892aa4a088720b0e4e05a43daa2953708fb037f56eea04ec6b7b500991dc941e',
    );
    const plain = await decrypter.decrypt(chunks(file));
    const validator = new SnapshotValidator();
    const records: SnapshotRecord[] = [];
    for await (const value of readRecords(plain)) records.push(validator.push(value));
    validator.finish();
    expect(records[0]).toMatchObject({ type: 'header', format: 'clavifer-backup-v1', kind: 'full' });
    const types = new Set(records.map((r) => r.type));
    for (const type of ['secret', 'secret-version', 'connection', 'installation', 'grant', 'access-request', 'audit'])
      expect(types).toContain(type);
  });

  // Written by the 0.5.0 release code (scripts/fixtures-v1.ts) from one synthetic instance: frozen from the release on.
  const sample = (name: string) => readFile(`tests/fixtures/v1/${name}`).then((b) => new Uint8Array(b));
  const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
  async function snapshotSample(name: string, digest: string) {
    const file = await sample(name);
    expect(sha256(file), name).toBe(digest);
    const decrypter = new Decrypter();
    decrypter.addIdentity((await readFile('tests/fixtures/v1/test-identity.txt', 'utf8')).trim());
    const validator = new SnapshotValidator();
    const records: SnapshotRecord[] = [];
    for await (const value of readRecords(await decrypter.decrypt(chunks(file)))) records.push(validator.push(value));
    validator.finish();
    checkReferences(records);
    const of = <T extends SnapshotRecord['type']>(type: T) => records.filter((r): r is RecordOf<T> => r.type === type);
    return { records, of };
  }
  const automatic = () =>
    snapshotSample('automatic-b.age', 'ea371c55e54e8db65989db59512f6ea3637b6e9eaeb2fcbba91d39933679816b');
  const full = () => snapshotSample('full-b.age', 'cbad6737bcded090a5f73a44342925fcc838d2e49c6073feac59fcab00edf5f8');
  /** The lines of a segment file, readable with the archive identity a snapshot carries and nothing else
   * of this project. */
  async function segmentLines(identity: string, file: Uint8Array) {
    const decrypter = new Decrypter();
    decrypter.addIdentity(identity);
    return read(await decrypter.decrypt(chunks(file)));
  }

  it('decrypts and validates the automatic backup sample, and every segment file it names', async () => {
    const { records, of } = await automatic();
    expect(records[0]).toMatchObject({ type: 'header', kind: 'automatic' });
    const segments = of('segment');
    expect(segments.map((s) => [s.kind, s.seq])).toEqual([
      ['access-request', 1],
      ['audit', 1],
      ['audit', 2],
    ]);
    for (const segment of segments) {
      const file = await sample(segment.key!);
      expect(sha256(file)).toBe(segment.sha256);
      const [header, ...rows] = await segmentLines(of('archive-identity')[0].identity, file);
      expect(archiveHeader.parse(header)).toEqual({
        type: 'header',
        format: ARCHIVE_FORMAT,
        kind: segment.kind,
        seq: segment.seq,
        first: segment.first,
        last: segment.last,
        rows: segment.rows,
        createdAt: segment.createdAt,
      });
      const parsed = rows.map((row) => snapshotRecord.parse(row) as RecordOf<'audit' | 'access-request'>);
      expect(parsed.length).toBe(segment.rows);
      expect(parsed.every((row) => row.type === segment.kind)).toBe(true);
      expect([parsed[0].createdAt, parsed[0].id]).toEqual(segment.first);
      expect([parsed.at(-1)!.createdAt, parsed.at(-1)!.id]).toEqual(segment.last);
      // The hot rows of a kind all come after its last segment.
      const hot = of(segment.kind).map((r) => r.createdAt);
      expect(Math.min(...hot)).toBeGreaterThan(segment.last[0]);
    }
  });

  it('decrypts and validates the full export sample, whose segments are those files embedded', async () => {
    const { records, of } = await full();
    expect(records[0]).toMatchObject({ type: 'header', kind: 'full' });
    const named = (await automatic()).of('segment');
    expect(of('segment').map(({ data, key, ...rest }) => rest)).toEqual(named.map(({ data, key, ...rest }) => rest));
    for (const [i, segment] of of('segment').entries())
      expect(Buffer.from(segment.data!, 'base64').equals(await sample(named[i].key!))).toBe(true);
    expect(of('archive-identity')).toEqual((await automatic()).of('archive-identity'));
  });

  it('hold every record type, in every state, across the samples', async () => {
    const named = await automatic();
    const sealed: SnapshotRecord[] = [];
    for (const segment of named.of('segment'))
      sealed.push(
        ...(await segmentLines(named.of('archive-identity')[0].identity, await sample(segment.key!)))
          .slice(1)
          .map((line) => snapshotRecord.parse(line)),
      );
    const records = [...named.records, ...(await full()).records, ...sealed];
    const of = <T extends SnapshotRecord['type']>(type: T) => records.filter((r): r is RecordOf<T> => r.type === type);
    expect(new Set(records.map((r) => r.type))).toEqual(new Set(RECORD_TYPES));
    const states = <T extends SnapshotRecord['type']>(type: T, state: (r: RecordOf<T>) => unknown) =>
      new Set(of(type).map(state));
    expect(states('secret', (s) => s.status)).toEqual(new Set(['active', 'deleted']));
    expect(states('connection', (c) => c.status)).toEqual(new Set(['active', 'deleted']));
    expect(states('connection', (c) => c.auth.type)).toEqual(new Set(['bearer', 'basic', 'header', 'query', 'none']));
    expect(states('connection', (c) => c.policy.anyHost)).toEqual(new Set([true, false]));
    expect(states('installation', (i) => i.disabled)).toEqual(new Set([true, false]));
    expect(states('installation', (i) => i.scopes === null)).toEqual(new Set([true, false]));
    expect(states('grant', (g) => g.status)).toEqual(new Set(['active', 'revoked']));
    expect(states('grant', (g) => g.extensions === null)).toEqual(new Set([true, false]));
    expect(states('grant', (g) => g.fields === null)).toEqual(new Set([true, false]));
    expect(states('access-request', (r) => r.status)).toEqual(new Set(['pending', 'approved', 'denied']));
    expect(states('audit', (a) => a.clientId === null)).toEqual(new Set([true, false]));
    expect(states('segment', (s) => s.kind)).toEqual(new Set(['audit', 'access-request']));
    expect(states('owner', (o) => o.emailVerified)).toEqual(new Set([true]));
    const passkeys = of('owner').flatMap((o) => o.passkeys);
    const shapes = (state: (p: (typeof passkeys)[number]) => unknown) => new Set(passkeys.map(state));
    expect(shapes((p) => p.backedUp)).toEqual(new Set([true, false]));
    expect(shapes((p) => p.transports)).toEqual(new Set(['internal,hybrid', '']));
    for (const field of ['name', 'createdAt', 'aaguid'] as const)
      expect(shapes((p) => p[field] === null)).toEqual(new Set([true, false]));
  });

  // Recorded in README.md: NFKC turns its "ﬁ" ligature into "fi".
  const PASSWORD = 'synthetic-ﬁxture-password';
  it('carry the password as scrypt of its NFKC form, salted with the salt as text', async () => {
    expect(PASSWORD.normalize('NFKC')).not.toBe(PASSWORD);
    for (const sample of [automatic, full]) {
      const { salt, key, N, r, p, dkLen } = (await sample()).of('owner')[0].password;
      const hash = (password: string, saltBytes: Buffer) =>
        scryptSync(password, saltBytes, dkLen, { N, r, p, maxmem: 64 * 1024 * 1024 }).toString('hex');
      expect(hash(PASSWORD.normalize('NFKC'), Buffer.from(salt, 'utf8'))).toBe(key);
      // What an importer that skipped NFKC or hex-decoded the salt would compute.
      expect(hash(PASSWORD, Buffer.from(salt, 'utf8'))).not.toBe(key);
      expect(hash(PASSWORD.normalize('NFKC'), Buffer.from(salt, 'hex'))).not.toBe(key);
    }
  });
});
