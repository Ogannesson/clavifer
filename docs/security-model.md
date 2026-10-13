# Security model

Clavifer keeps credentials on a server so that AI agents can use them without holding them. This page states what that protects, what it does not, where the trust boundaries are, and how the mechanisms work. Each section names the source files and tests that back it. [Known limits and non-goals](#known-limits-and-non-goals) lists what the project does not do.

Clavifer has had no third-party security audit.

## What it protects

- **Stored secret values.** Values are encrypted before they reach the database. The key that decrypts them is a Worker secret and is not in the database. A copy of the database alone does not reveal a value.
- **Credentials used through connections.** An installation that calls a connection never receives the credential. The server injects it into the outgoing request, removes any `Authorization` or `Cookie` header the caller sent, and returns only five response headers from the upstream.
- **Where a credential can go.** A connection sends its credential to its own fixed origin. It reaches another origin only when the Owner listed that hostname or turned on any host, and then only for one request the Owner approved.
- **What each installation can do.** An installation can use only what the Owner granted or approved. Revoking a grant or an installation takes effect on its next request.
- **Sensitive Owner operations.** Granting access, approving requests, editing connections, exporting, restoring, and changing the backup recipient need a sign-in within the last 10 minutes, so an older stolen session cannot perform them.

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

Clavifer runs on Cloudflare Workers with a D1 database and an R2 bucket. The Worker decrypts secrets in memory to inject them. The key ring is a Worker secret. TLS ends at Cloudflare. The design assumes the platform and the account that deploys to it are trustworthy.

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
| Key-encryption key | 32 bytes, taken from `KEK_RING`                                      |

Encryption of one version:

1. The server generates a data key.
2. It encrypts the JSON object of field names and values with the data key. The additional authenticated data is the JSON array `["agent-credentials", 1, ownerId, secretId, version]`.
3. It encrypts the data key with the active key-encryption key. The additional authenticated data is `dek:`, the same JSON array, `:`, and the key's ID.
4. It stores `{"format": 1, "kekId", "wrappedDek", "ciphertext"}`. Each encrypted part is `base64url(nonce).base64url(ciphertext and tag)`.

The additional authenticated data binds an envelope to its owner, secret, and version. An envelope copied onto another secret or another version does not decrypt.

The `agent-credentials` prefix is the project's former name. It is part of every stored envelope and never changes.

Keys:

- `KEK_RING` is a comma-separated list of `id:key` pairs, each key 32 bytes in base64url. `ACTIVE_KEK_ID` names the key that encrypts new envelopes. Decryption uses the key the envelope names, so a key must stay in the ring as long as any envelope uses it.
- Both are Worker secrets. They cannot be read back after they are set. Without `KEK_RING` no stored secret can be decrypted, so keep a copy somewhere safe before the first deployment, as [deploy.md](deploy.md#step-210-save-the-secrets-before-deploying) describes.
- Updating a secret writes a new version with a new data key under the active key. Earlier versions stay in the database, encrypted, until the secret is deleted.

What is and is not encrypted:

| Stored encrypted                               | Stored in the clear                                                               |
| ---------------------------------------------- | --------------------------------------------------------------------------------- |
| Field names and values of every secret version | Secret names and descriptions                                                     |
|                                                | Connections: origin, policy, description, and which secret and fields they inject |
|                                                | Grants, access requests with their full content, and the audit log                |

A pending or decided access request keeps the request an agent submitted, including the headers and body of an invocation. Do not put a secret into a request submitted for approval.

Deleting a secret removes the ciphertext of all its versions in the same database batch. A secret that a connection still uses cannot be deleted (`secret_in_use`).

Source: `packages/core/crypto.ts`; `parseKeys()` in `apps/worker/src/context.ts`; the secret routes in `apps/worker/src/index.ts`. Tests: `tests/core.test.ts`, `tests/secrets.test.ts`.

## Backups

A backup is one file encrypted with [age](https://age-encryption.org) to a recipient, which is an age public key the Owner supplies. The server never holds the matching private key.

Contents:

| In a backup                                          | Not in a backup                                           |
| ---------------------------------------------------- | --------------------------------------------------------- |
| The current version of every secret, with its values | Earlier versions of secrets                               |
| Every connection with its policy and description     | The Owner account, sessions, and Passkeys                 |
|                                                      | Installations, grants, access requests, and the audit log |

The snapshot inside the file is JSON with the format identifier `agent-credentials-backup-v1`. The identifier keeps the project's former name and never changes. A snapshot holds at most 500 secrets and 500 connections and at most 8 MiB.

Three operations:

- **Manual export.** The Owner gives a recipient and downloads the encrypted file. The Worker decrypts the current secret values, builds the snapshot, and encrypts it to the recipient.
- **Automatic backup.** Once the Owner has set a recipient, a scheduled run every 15 minutes writes a new encrypted file to the R2 bucket when a secret or connection changed, when the recipient changed, or when the last successful backup is 24 hours old. The server keeps the newest file of each day for 30 days and the newest file of each month for the 12 months before that, and deletes the rest. It never deletes the latest backup. A failed cleanup is reported separately and does not mark the backup as failed.
- **Restore.** The Owner's browser decrypts the file locally with the age private key and sends the snapshot to the server over HTTPS. The private key is not sent. The server accepts a restore only when no secret, connection, or installation has ever been created in the deployment (`restore_requires_empty_vault`), and encrypts every value again under the active key. Grants are not restored and must be issued again.

Export, restore, and changing the recipient need a recent sign-in. Changing the recipient decides who can read all future backups.

The R2 bucket belongs to the same Cloudflare account as the Worker. Automatic backups are not an independent copy. Copy them elsewhere yourself.

Source: `apps/worker/src/backup.ts`; the restore form in `apps/web/src/pages/backup.tsx`. Tests: `tests/automatic-backup.test.ts`, `tests/backup-bindings.test.ts`.

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
| `backup:export`, `backup:restore`, `backup:configure`, `backup:disable` | The Owner uses the backup functions                                          | `authorized` or `ok`                                 |
| `backup:automatic`                                                      | An automatic backup run saves a file or fails                                | `ok` or an error code                                |

Not recorded:

- The method, path, query, headers, or body of a request sent through a connection, and nothing of the response except its status code.
- The address a request to another origin went to. It is found through the `access:consume` row, which points to the access request that stores the whole approved request.
- Requests the server refused, and access requests at the time they are submitted.
- Owner sign-ins and device code approvals.
- Any secret value.

The web console shows the latest 50 rows. The server never deletes audit rows. The table is an ordinary table in the same database, so it is not tamper-proof against someone with database access.

When a request fails with an internal error, the Worker logs the error code and the request ID and nothing else.

Source: `audit()` in `apps/worker/src/context.ts` and its callers in `apps/worker/src/index.ts`, `vault.ts`, and `backup.ts`. Tests: `tests/policy.test.ts`, `tests/proposals.test.ts`.

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

One installation can hold at most 20 pending requests, which bounds what the Owner has to read.

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
- **No key rotation procedure.** The code reads a ring of keys and encrypts new versions with the active one, but no command adds a key or re-encrypts existing envelopes, and changing the ring on a deployment that holds data is untested. See [deploy.md](deploy.md#server-keys).
- **Backups stay in the same Cloudflare account** unless you copy them out.
- **The audit log does not record request contents** and is not tamper-proof.
- **No account recovery in the console.** There is no email reset.
- **Revocation cannot recall a request** that was already sent to an upstream.
- **The REST proxy does not limit response size.** It streams until the upstream ends or 20 seconds pass.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
