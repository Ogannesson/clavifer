# Security model

Clavifer keeps credentials on a server so that AI agents can use them without holding them. This page states what that protects, what it does not, where the trust boundaries are, and how the mechanisms work. Each section names the source files and tests that back it. [Known limits and non-goals](#known-limits-and-non-goals) lists what the project does not do.

Clavifer has had no third-party security audit.

## What it protects

- **Stored secret values.** Values are encrypted before they reach the database. The key that decrypts them is derived from a Worker secret and is not in the database. A copy of the database alone does not reveal a value.
- **Credentials used through connections.** An installation that calls a connection never receives the credential. The server injects it into the outgoing request, removes any `Authorization` or `Cookie` header the caller sent, and returns only five response headers from the upstream.
- **Where a credential can go.** A connection sends its credential to its own fixed origin. It reaches another origin only when the Owner listed that hostname or turned on any host, and then only for one request the Owner approved.
- **What each installation can do.** An installation can use only what the Owner granted or approved. Revoking a grant or an installation takes effect on its next request.
- **Sensitive Owner operations.** Granting access, approving requests, editing connections, downloading a full export, and changing the backup recipient need a sign-in within the last 10 minutes, so an older stolen session cannot perform them.

## What it does not protect

- **A secret granted for reading.** A `secret:read` grant delivers the plaintext to the installation's machine.
- **A credential the upstream echoes.** Clavifer does not inspect upstream responses.
- **What an allowed request does.** A grant lets an installation send any request inside the connection's regular scope that no deny rule or approval rule matches. Clavifer does not judge whether a request is what the user wanted.
- **A compromised Owner.** Whoever holds the Owner's password or a Passkey, or controls the Owner's browser during a fresh session, has the Owner's full power.
- **A compromised Cloudflare account.** Whoever controls the account controls the Worker and its secrets.
- **A hostile upstream or hostile DNS.** The upstream receives the credential. The server trusts the hostname's resolution.

## Trust boundaries

### The server is the boundary

Every decision is made on the server, for every request:

- The server verifies the access token's signature, audience, issuer, and expiry, and then reads the installation's record. See [authentication.md](authentication.md#tokens).
- OAuth scopes are not the boundary. Every installation is created with all five scopes. A scope only lets an installation call a kind of endpoint; which secret or connection it may use is decided by the grants table, read on each request.
- A `connection:invoke` grant and a `secret:read` grant are separate permissions on separate resources. The first never allows reading a secret.
- MCP has no tool that returns a secret value. Reading one takes `POST /v1/secrets/{id}/read` and a `secret:read` grant.

Source: `principal()` in `apps/worker/src/context.ts`; `assertGrant()`, `readSecret()`, and `invoke()` in `apps/worker/src/vault.ts`. Tests: `tests/security.test.ts`, `tests/proxy.test.ts`, `tests/grants.test.ts`.

### The agent host and the local machine

The `clavifer` command keeps an installation's tokens in the operating system's credential store. Any program that runs as the same operating system user can use that login. Profiles separate grants and revocation between agent hosts; they are not a security boundary between programs of one user.

`clavifer run` reads a granted secret and places it in the environment of a child process. That process can print it, write it to disk, or send it anywhere. Grant `secret:read` only for secrets you accept having on that machine, and prefer connections for everything an API call can do.

The local MCP bridge removes any `waitCommand` field from server responses and writes its own, so the command an agent is told to run always comes from the local binary.

Source: `cmd/clavifer/main.go` (`cmdRun`, `withWaitCommand`). Tests: `cmd/clavifer/main_test.go`.

### Cloudflare is trusted

Clavifer runs on Cloudflare Workers with a D1 database and an R2 bucket. The Worker decrypts secrets in memory to inject them. The root key is a Worker secret. TLS ends at Cloudflare. The design assumes the platform and the account that deploys to it are trustworthy.

### The upstream must be trusted

A connection's origin receives the credential on every request that runs. Its response body is passed back as it is. Point a connection only at a service whose operator you trust.

The server accepts only public HTTPS hostnames as origins and extra hosts: no IP addresses, no single-label names, and no names ending in `localhost`, `local`, `internal`, `lan`, `home`, `test`, or `invalid`. It does not pin DNS and does not detect a public hostname that resolves to a private address.

Source: `targetUrl()` and `validHost()` in `packages/core/proxy.ts`. Tests: `tests/security.test.ts`, `tests/policy.test.ts`.

## How secrets are stored

A secret is a set of named fields. Each saved version of a secret is encrypted as one envelope.

| Element            | Value                                                                |
| ------------------ | -------------------------------------------------------------------- |
| Cipher             | AES-256-GCM through the Web Crypto API, with its default 128-bit tag |
| Nonce              | 12 random bytes, new for every encryption                            |
| Data key           | 32 random bytes, new for every version of every secret               |
| Key-encryption key | 32 bytes, derived from the current root key with HKDF-SHA256          |

Encryption of one version:

1. The server generates a data key.
2. It encrypts the JSON object of field names and values with the data key. The additional authenticated data is the JSON array `["clavifer", 1, ownerId, secretId, version]`.
3. It encrypts the data key with the key-encryption key. The additional authenticated data is `dek:`, the same JSON array, `:`, and the root key's ID.
4. It stores `{"format": 1, "kekId", "wrappedDek", "ciphertext"}`, where `kekId` is the root key's ID. Each encrypted part is `base64url(nonce).base64url(ciphertext and tag)`.

The additional authenticated data binds an envelope to its owner, secret, and version. An envelope copied onto another secret or another version does not decrypt.

Updating a secret writes a new version with a new data key under the current root key. Earlier versions stay in the database, encrypted, until the secret is deleted.

What is and is not encrypted:

| Stored encrypted                                                                | Stored in the clear                                                               |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Field names and values of every secret version                                  | Secret names and descriptions                                                     |
| The archive identity, in an envelope of the same kind                           | Connections: origin, policy, description, and which secret and fields they inject |
| Sealed [segments](#cold-data) of old audit rows and access requests, in R2       | Grants, access requests with their full content, and the audit log                |

A pending or decided access request keeps the request an agent submitted, including the headers and body of an invocation. Do not put a secret into a request submitted for approval.

Deleting a secret removes the ciphertext of all its versions in the same database batch. A secret that a connection still uses cannot be deleted (`secret_in_use`).

### The root key

The service has one secret of its own, the Worker secret `ROOT_KEY`. It is a comma-separated ring of `<id>:<key>` entries, each key 32 bytes in base64url, the current key first; `parseRootKeys()` accepts nothing else. HKDF-SHA256 derives three keys from each root key, each for one use: the key-encryption key, the auth library's secret, and a fingerprint. The deploy entry `npm run deploy` generates the root key and hands it to wrangler without writing or printing it. A Worker secret cannot be read back once it is set.

Self-check. Creating the Owner, or completing an import, records the fingerprint of every key in the ring in the database. A Worker whose ring does not match them, because the key was replaced or the Worker is bound to another instance's database, answers `503 root_key_mismatch` on every route except `/healthz` and skips its scheduled work. It never writes data under a key the database does not know. On an initialized instance, a `ROOT_KEY` that cannot be parsed makes every route answer `503 invalid_root_key`, `/healthz` included. `/healthz` reports the state in `keys` and `initialized`, and `clavifer doctor` explains each state.

Outside the Worker (and `.dev.vars` for a local trial), no copy of the root key exists, by design: nobody is asked to keep one, so there is none to leak. The cost is that a lost or overwritten key makes every stored secret undecryptable. Recovery goes through the automatic backup instead. `npm run deploy -- --rebuild` gives the Worker a new key and a new, empty database, and refuses unless `/healthz` reports the key lost or every database the Worker is bound to was deleted. The latest automatic backup is then [imported](#backups) into the new database; changes made after that backup are lost. Creating the Owner therefore requires a backup recipient, and the Owner keeps the matching age private key outside the service. [deploy.md](deploy.md) has the steps.

Source: `packages/core/crypto.ts`; `rootKeys()` and `keyState()` in `apps/worker/src/context.ts`; the secret routes in `apps/worker/src/index.ts`; `scripts/deploy.mjs`. Tests: `tests/core.test.ts`, `tests/secrets.test.ts`, `tests/root-key-check.test.ts`, `tests/deploy.test.ts`.

## Backups

The automatic backup and the full export are the same snapshot of the instance. A snapshot is a file in the format `clavifer-backup-v1`, one JSON record per line, encrypted with [age](https://age-encryption.org) to a recipient, which is an age public key the Owner supplies. The server never holds the matching private key. The format is frozen: every later version reads it. The header comment of `packages/core/snapshot.ts` specifies it.

Contents:

| In a snapshot                                                      | Not in a snapshot                                      |
| ------------------------------------------------------------------ | ------------------------------------------------------ |
| The Owner: name, email address, password hash, and Passkeys        | Sessions, access and refresh tokens, and device codes   |
| Every secret, and every version of an active one, with its values  | The keys that sign access tokens                        |
| Connections, installations with their client IDs, and grants       | OAuth consents and rate limit counters                  |
| Access requests and the audit log, sealed segments included        | The bootstrap token                                     |
| The backup recipient and the archive identity                      | Backup bookkeeping other than the recipient             |

A snapshot is taken from one consistent read of the database and checked against the format and for the references an import needs. If the instance is inconsistent, the snapshot is refused whole and the console shows why; the last good backup stays.

Three operations:

- **Automatic backup.** Once the Owner has set a recipient, a scheduled run every 15 minutes writes a new file to the R2 bucket when the data a snapshot carries changed, when the recipient changed, or when the last successful backup is 24 hours old. Sign-ins and the service's own audit rows do not count as changes. It names each [sealed segment](#cold-data) by its key in the same bucket instead of copying it. The server keeps the newest file of each day for 30 days and the newest file of each month for the 12 months before that, and deletes the rest. It never deletes the latest backup. A failed cleanup is reported separately and does not mark the backup as failed. While the data outside sealed segments takes more than about 9 MB, the backup is skipped (`hot_data_over_limit`); the console warns before that.
- **Full export.** The Owner gives a recipient and downloads the whole instance, with every sealed segment embedded. `GET /admin/backup/export` runs only when the browser reports `Sec-Fetch-Site: same-origin`, because the recipient is part of the link. A segment missing from the bucket, or without the checksum recorded when it was sealed, refuses the export before the first byte (`archive_segment_unavailable`). A download that breaks off can still end cleanly in the browser, so an export counts as whole only after the server wrote a `backup:export` audit row with the result `complete`. The console checks this with `GET /admin/backup/exports/{id}`.
- **Import.** On the `/setup` page, an uninitialized instance can be initialized from a snapshot instead of creating a new Owner. This serves a migration to a new instance and a recovery after a lost root key alike. The Owner's browser decrypts the file locally with the age private key and sends the records over HTTPS in chunks; the private key is not sent. The server encrypts every secret version again under its own root key. Everything in the snapshot comes across, and installations keep their client IDs. Passkeys come across only when the new instance has the hostname of the old one. No token travels, so every installation logs in again. A segment that an automatic backup names must already be in the new instance's bucket with its checksum; the Owner can choose to go on without a missing one, and the import's audit row lists those skipped. The import checks structure and references only. The instance stays uninitialized, and nobody can sign in, until a final batch completes it.

The full export and changing the recipient need a recent sign-in. Changing the recipient decides who can read all future backups.

The R2 bucket belongs to the same Cloudflare account as the Worker. Automatic backups are not an independent copy. Copy them elsewhere yourself.

Source: `snapshot()` and `fullExport()` in `apps/worker/src/export.ts`; `apps/worker/src/backup.ts`; `apps/worker/src/import.ts`; `packages/core/snapshot.ts`; the importer in `apps/web/src/import.ts`. Tests: `tests/automatic-backup.test.ts`, `tests/full-export.test.ts`, `tests/import.test.ts`, `tests/snapshot.test.ts`, with the frozen samples in `tests/fixtures/v1/`.

## Audit log

The server writes a row to the `audit_events` table for each of the events below. A row holds the actor (`owner`, `system`, or an installation's client ID), the action, the ID of the resource, a result, the time, and a request ID. The request ID equals the `x-request-id` header of the response that caused the row.

| Action                                                                  | Written when                                                                 | Result                                               |
| ----------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------- |
| `connection:invoke`                                                     | A request is about to be sent upstream, and again when it ends               | `started`, then `http_<status>` or `outcome_unknown` |
| `access:consume`                                                        | A one-time approval is spent; the resource is the access request's ID        | `ok`                                                 |
| `secret:read`                                                           | An installation reads a secret                                               | `authorized`                                         |
| `access:approve`, `access:deny`                                         | The Owner decides an access request                                          | `ok`                                                 |
| `grant:create`, `grant:revoke`                                          | The Owner creates or revokes a grant                                         | `ok`                                                 |
| `secret:create`, `secret:rotate`, `secret:delete`                       | The Owner creates, updates, or deletes a secret                              | `ok`                                                 |
| `connection:save`, `connection:delete`                                  | The Owner creates, edits, or deletes a connection, also by approving a draft | `ok`                                                 |
| `client:create`, `client:revoke`                                        | An installation is created or revoked                                        | `ok`                                                 |
| `backup:export`                                                         | A full export starts, and again after its last byte; the resource is the export's ID | `started`, then `complete`; or an error code |
| `backup:configure`, `backup:disable`                                    | The Owner sets or clears the backup recipient                                | `ok`                                                 |
| `backup:automatic`                                                      | An automatic backup run saves a file or fails                                | `ok` or an error code                                |
| `archive:seal`                                                          | A segment is sealed, or sealing fails; the resource is the segment's key     | `ok` or an error code                                |
| `owner:create`, `owner:recover`, `instance:import`                      | On `/setup`: the Owner is created, its password is reset, or an import completes | `ok`                                             |

Not recorded:

- The method, path, query, headers, or body of a request sent through a connection, and nothing of the response except its status code.
- The address a request to another origin went to. It is found through the `access:consume` row, which points to the access request that stores the whole approved request.
- Requests the server refused, and access requests at the time they are submitted.
- Owner sign-ins and device code approvals.
- Any secret value.

The web console shows the latest 50 rows. The server never deletes audit rows; old ones move to sealed segments, as the next section describes. The table is an ordinary table in the same database, and the segments are files in the same account's bucket, so neither is tamper-proof against someone with access to the account.

When a request fails with an internal error, the Worker logs the error code and the request ID and nothing else.

Source: `audit()` in `apps/worker/src/context.ts` and its callers in `apps/worker/src/index.ts`, `vault.ts`, `backup.ts`, `export.ts`, `archive.ts`, `setup.ts`, and `import.ts`. Tests: `tests/policy.test.ts`, `tests/proposals.test.ts`.

### Cold data

Audit rows and access requests leave the database in sealed segments and are never deleted:

- An audit row can be sealed once it is 5 minutes old, and an access request once it is 25 hours old. By then nothing changes either of them any more.
- On every scheduled run, before the automatic backup, the server seals the oldest of these rows, about 1 MB per segment, while they take more than about 1.5 MB. The most recent history therefore stays in the tables for the console.
- A segment is an immutable file under `archive/` in the R2 bucket, encrypted with age to the archive identity. Nothing under `archive/` is ever overwritten or deleted.
- The archive identity is a hybrid post-quantum age identity created with the Owner. The database holds it encrypted under the root key, and every snapshot carries it, so whoever can decrypt a snapshot can also read its segments. The segments are therefore protected no better than the backup recipient. The key pair the console generates for backups is X25519, which is not post-quantum; for post-quantum protection, use an `age1pq1…` recipient. The service itself never reads a segment again.
- An archived access request is gone from `access.status`, which answers `request_not_found`.

Source: `apps/worker/src/archive.ts`. Tests: `tests/archive.test.ts`.

## Response headers

Every response carries:

| Header                    | Value                         |
| ------------------------- | ----------------------------- |
| `X-Content-Type-Options`  | `nosniff`                     |
| `Referrer-Policy`         | `no-referrer`                 |
| `X-Request-Id`            | A new ID for each request     |
| `Content-Security-Policy` | One of the two policies below |

For HTML pages:

```text
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
```

For every other response:

```text
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```

The console therefore runs only its own scripts and styles, nothing inline, and cannot be framed. An edge feature that injects a third-party script into HTML pages, such as an analytics snippet added automatically, is blocked by this policy. Turn such features off for the service's domain.

Further rules:

- A request that carries an `Origin` header different from the service's own origin is refused with `origin_not_allowed`. The OAuth token endpoint is the only exception. The Worker's own routes set no CORS headers.
- JSON responses of the API, error responses, and responses relayed from an upstream carry `Cache-Control: no-store`.
- A `401` response carries a `WWW-Authenticate` header that points to the protected resource metadata.

Source: the first middleware and `onError` in `apps/worker/src/index.ts`.

## What an approval binds

Approving any access request needs a sign-in within the last 10 minutes.

### One-time approvals

The server stores a SHA-256 fingerprint of the request the agent submitted, and runs a request only when its fingerprint is identical. The fingerprint covers the connection, the method, the path exactly as sent, the query parameters, the headers that are forwarded upstream, the SHA-256 of the body, and the other origin if the request names one. The exact matching rules are in [connections.md](connections.md#one-time-approvals).

| Property                                   | Mechanism                                                                                                                                                                                           |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The request cannot be changed after review | Any difference changes the fingerprint, and the request is decided as if no approval existed.                                                                                                       |
| Limited time                               | An approval is valid for 10 minutes from the moment the Owner approves.                                                                                                                             |
| Single use                                 | One database statement marks the approval spent and returns it. The request is sent only if that statement succeeded. It runs before the upstream is called, so a lost response cannot be replayed. |
| Bound to the installation                  | The lookup includes the installation that submitted the request.                                                                                                                                    |
| Bound to the destination                   | A request to another origin has that origin in its fingerprint. It does not run on any other origin, the connection's own included.                                                                 |
| The Owner saw the destination              | To approve a request to another origin, the approval call must name that origin back as stored (`origin_mismatch` otherwise). A page that does not show the origin cannot approve it.               |
| Deny rules still win                       | Deny rules are checked on submission and again when the request runs.                                                                                                                               |
| Extra hosts are checked twice              | Coverage of another origin is checked on submission and again when the request runs. Removing the entry stops an approved request.                                                                  |

The path a reviewer reads is the path that routes. Paths with control characters, format characters such as bidirectional overrides, `;`, or dot segments are refused, in any encoding. The review page shows non-ASCII and control characters in bodies and paths as marked `\uXXXX` escapes.

For a request to another origin that only any host covers, the console also asks the Owner to tick a confirmation that names the hostname. This is a step of the page; the server does not check it.

### Grants and scope extensions

- Approving a request never changes the field subset of a live `secret:read` grant (`existing_grant_conflict`).
- A scope extension carries the expiry the Owner chose for it and ends with its grant.
- A path or method list that an extension leaves out is fixed from the connection at approval. Later edits of the connection do not widen it.

### Drafts

- A setup draft cannot reference an existing secret, so an agent cannot route a stored credential to an origin it chose.
- An update draft cannot change a connection's origin, injection, extra hosts, or any host setting.
- A draft cannot turn on any host.
- A draft's tests are decided by the same function as real requests, and a mismatch refuses the submission.
- The review card states which field goes to which origin and how. That text is built from the draft's own `origin` and `auth` fields, not from anything the agent wrote, and stands above the agent's reason.
- Submission does not reveal whether a secret name is taken, because an installation must not learn the names of secrets it cannot list.
- Approval writes the secret, all connections, and the request's status in one batch. If one write fails, none takes effect.
- An update is applied only if the connection is unchanged since submission (`connection_changed`).

One request takes at most 256 KiB as stored, and one installation can hold at most 20 pending requests and 1 MiB of them, which bounds what the Owner has to read.

Source: `requestFingerprint()`, `consumeApproval()`, `accessRequest()`, and `decide()` in `apps/worker/src/vault.ts`; `decideRequest()` and the approval route in `apps/worker/src/index.ts`; `canonicalPath()` in `packages/core/proxy.ts`; the review cards in `apps/web/src/pages/access.tsx`. Tests: `tests/policy.test.ts`, `tests/proposals.test.ts`.

## Known limits and non-goals

These are properties of the design or gaps the project has not closed. They are not vulnerabilities to report.

- **No detection of echoed credentials.** If an upstream returns the credential in a response, the caller receives it. No general proxy can recognize a credential that was transformed, split, or partly echoed, so the project does not try. Connect only upstreams that do not echo credentials.
- **`secret:read` puts plaintext on the local machine.** After such a grant, the value reaches the installation's machine and the environment of the process `clavifer run` starts.
- **Single Owner.** There is one administrator account. There are no roles, no delegation, and no second approver.
- **Cloudflare only.** The server depends on Workers, D1, and R2. There is no self-hosted variant.
- **The console is in Chinese only.**
- **macOS and Linux command line builds are not verified on real machines.** The command is cross-compiled for both. Its use of Keychain and Secret Service has not been tested on a real machine; only Windows has.
- **No third-party security audit.**
- **Profiles are not isolation.** Programs running as the same operating system user can use each other's stored logins.
- **No DNS pinning.** A connection's hostname is checked by name only.
- **No key rotation procedure.** `ROOT_KEY` is read as a ring and every envelope names the key that wrapped it, but no command adds a key, and the self-check refuses a current key that was not recorded at initialization. The way to a new key is a full export imported into a new instance.
- **No copy of the root key.** A lost key loses the changes made since the last automatic backup. See [The root key](#the-root-key).
- **Backups stay in the same Cloudflare account** unless you copy them out. So do the sealed segments.
- **The audit log does not record request contents** and is not tamper-proof.
- **No account recovery by email.** Recovering a lost password and Passkeys takes a token that only the deployment can issue.
- **Revocation cannot recall a request** that was already sent to an upstream.
- **The REST proxy does not limit response size.** It streams until the upstream ends or 20 seconds pass.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
