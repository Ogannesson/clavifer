# v1 sample files

Never modify, regenerate or delete these files. The tests that read them (`tests/snapshot.test.ts`) also check their SHA-256. The only exception is the samples written by the 0.5.0 release code, listed below: until the release of 0.5.0 they may be regenerated, by deleting them and running `npx tsx scripts/fixtures-v1.ts`, which never overwrites a file; the tests then take the new SHA-256 values. From the release on they are frozen like `full-a.age`.

They are the only checkable promise that every later version can still read the snapshot format `clavifer-backup-v1` (specified in `packages/core/snapshot.ts`). Tests decrypt them and validate every record, and the import tests (`tests/import.test.ts`) import them in full. A version that cannot read them is broken, not the files.

- `full-a.age`: a full export written by the first exporter of the format (before the 0.5.0 release) from synthetic data. It holds every record type of that export:
  - an Owner with an image, a password and a passkey, and a backup recipient;
  - a credential with three versions (one value contains U+2028), a deleted credential, and one whose description was NULL;
  - a bound connection with deny rules and extra hosts, one whose stored policy predates the optional keys, and a deleted one;
  - installations as the console creates them (native and web), a revoked one, and one without user, scopes or grant types;
  - active and revoked grants, with a field subset and with scope extensions with and without an expiry;
  - access requests pending, denied and approved (an invocation with fingerprint and consumption), a setup draft with its fixed ids and an update draft;
  - audit rows, including one without client or resource.

  It has no `archive-identity` and no `segment` records.

- Written by the 0.5.0 release code (`scripts/fixtures-v1.ts`) from one synthetic instance. The two snapshots are written by the Worker's own code. The segment files are not: the script seals a few rows per segment with its own copy of the sealing logic of `apps/worker/src/archive.ts`, because the service seals only above about 1.5 MB and writes about 1 MB per segment, which would make the samples large. Together they hold every record type and every state, the rows inside the segments included:
  - `automatic-b.age`: an automatic backup. Besides what `full-a.age` holds, it has an `archive-identity` record and three `segment` records that name their files by key: two audit segments and one of access requests. Its Owner has a verified email and two passkeys, one with every field and one without a name, a time or an authenticator id, not backed up, with empty transports (what Better Auth writes when the browser reports none). Its connections cover all five kinds of authentication, and one reaches any host.
  - `archive/audit/…`, `archive/access-request/…`: the segment files those keys name, age-encrypted to the archive identity that the snapshot carries, laid out as the keys say so that a test can serve this directory as the bucket.
  - `full-b.age`: a full export of the same instance a moment later (one audit row more), with those segment files embedded.
- `test-identity.txt`: the age identity the snapshots are encrypted to. It exists only for these tests and protects nothing else.
- The Owner password of the samples written by the 0.5.0 release code is `synthetic-ﬁxture-password`, with the "ﬁ" ligature (U+FB01). NFKC turns it into "fi", so the stored key verifies only as scrypt over the NFKC form, salted with the salt's characters as UTF-8. Like the test identity it is a test value and protects nothing else.

New samples are added as new files next to these.
