# v2 sample files

Never modify, regenerate or delete these files once the version that first writes the format `clavifer-backup-v2` is released. The tests that read them (`tests/snapshot.test.ts`) also check their SHA-256. Until that release they may be regenerated, by deleting them and running `npx tsx scripts/fixtures-v2.ts`, which never overwrites a file; the tests then take the new SHA-256 values.

They are the only checkable promise that every later version can still read the snapshot format `clavifer-backup-v2` (specified in `packages/core/snapshot.ts`). Tests decrypt them and validate every record, and the import tests (`tests/import.test.ts`) import them in full. A version that cannot read them is broken, not the files.

Both are written by the Worker's own code (`scripts/fixtures-v2.ts`) from one synthetic instance, whose connections were saved through the console's route, each tried against a stand-in token endpoint as saving does. They hold what v2 adds to v1:

- `automatic-a.age`: an automatic backup. Its connections cover all nine kinds of authentication:
  - the five of v1 (`none`, `bearer`, `header`, `basic`, `query`);
  - `jwt` with RS256 (a `kid` from the credential, an object and an array claim, the empty scheme), ES256 (a SEC1 key, a `jti`) and HS256 (a hex key, the scheme `Ghost`);
  - `oauth-client` with a Basic client, with a client in the body (another grant name, extra parameters, a JSON body) and with a client assertion (PS256), whose token goes into a header of its own;
  - `oauth-jwt` alone and with a client in the body, a `jti` and a `ttl`;
  - `oauth-refresh` with `authorize`, whose refresh token the endpoint rotated when the connection was saved (its credential has a second version), with a Basic client, a JSON body and a `ttl`, with a public client, and one with `authorize` that is not authorized yet, saved as the route saves such a connection: its credential has no refresh token.

  One connection has rules in the new syntax: `{name}` and `{}` segments, `**`, and the trailing `/*`. It has an `archive-identity` record and no segments: the segment format did not change.
- `full-a.age`: a full export of the same instance a moment later.
- Neither carries the tokens derived from the credentials (`token_cache`), although saving the connections cached some.
- The age identity they are encrypted to is `tests/fixtures/v1/test-identity.txt`. The Owner password is `synthetic-v2-fixture-password`. The private keys and every other credential value are generated or written for these samples only and protect nothing else.

New samples are added as new files next to these.
