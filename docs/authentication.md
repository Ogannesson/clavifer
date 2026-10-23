# Authentication

Clavifer authenticates two kinds of callers, and they never share credentials. The Owner signs in to the web console with a password or a Passkey and gets a browser session. Each installation logs in through OAuth and gets tokens that are valid only for this server's `/v1` API. This page covers both, the one-time bootstrap token that creates the Owner or resets its password, where the command line keeps its tokens, and what to redo after the service moves to another domain.

| Caller       | Proves identity with                                  | Used for                                      |
| ------------ | ----------------------------------------------------- | --------------------------------------------- |
| Owner        | Session cookie, set after password or Passkey sign-in | The console and `/admin/*`                    |
| Installation | OAuth access token (Bearer)                           | `/v1/*`, including the MCP endpoint `/v1/mcp` |

There is no third-party single sign-on, and there is exactly one Owner account.

## Bootstrap token

A new deployment has no Owner. The deployment issues a one-time bootstrap token and writes it to a file. The console's `/setup` page takes the token and sends it in the `x-bootstrap-token` header, and nowhere else. What the token does depends on the instance:

| Instance      | Token valid for | What `/setup` does with it                                                                                                                                                                                           |
| ------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Uninitialized | 24 hours        | Creates the Owner from a name, an email address, a password (12 to 128 characters), and the age recipient for automatic backups. Or [imports a snapshot](security-model.md#backups) instead.                         |
| Initialized   | 1 hour          | Sets a new Owner password. Every Passkey and every session of the Owner is removed. Installations, grants, and their logins stay.                                                                                   |

- The database stores only the SHA-256 hash of the token and its expiry. The token itself exists only in the file the deployment wrote.
- The token works once: the first statement of the batch that does the work spends it. Issuing a new token replaces any earlier one.
- A wrong, expired, or spent token fails with `invalid_bootstrap_token`. Creating an Owner on an initialized instance fails with `already_initialized`, and resetting the password on an uninitialized one with `not_initialized`.
- `/setup` is the only way to create an account. The auth library's sign-up endpoint is closed (`endpoint_disabled`), as are its endpoints for changing the email address and deleting the account, and its endpoints for creating, updating, and deleting OAuth clients: `/admin/clients` is the only way to create or revoke an installation.

Treat the token like a password until it is spent. Do not paste it into an agent conversation or a log. [deploy.md](deploy.md) issues the token as part of a deployment, and issues a new one when the Owner needs to recover.

## Owner sign-in

The Owner signs in with email and password, or with a Passkey.

- **Password.** At least 12 characters. Changing it in the console signs the browser out and revokes the Owner's other sessions.
- **Passkey.** A WebAuthn credential bound to the service's hostname. The Owner can register several, name them, rename them, and delete them. Deleting one does not affect password sign-in.
- **Session.** A session lasts 24 hours and is extended while it is in use.
- **Rate limit.** The auth endpoints under `/api/auth` are limited to 100 requests per 60 seconds, and the device code lookup to 30, counted by client IP address.

There is no email recovery. Keep at least one working way to sign in, and register more than one Passkey. If the password and every Passkey are lost, whoever can deploy the service issues a new bootstrap token, and `/setup` sets a new password with it, as described [above](#bootstrap-token).

## Operations that need a recent sign-in

Some operations require that the Owner signed in within the last 10 minutes. The server compares against the time the session was created; activity that extends a session does not count. When the sign-in is older, the server answers `recent_login_required`, the console asks for the password or a Passkey in place, and then repeats the operation.

| Operation                                                                        | Route                                                                                                                                                          |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Create a grant                                                                   | `POST /admin/grants`                                                                                                                                           |
| Approve an access request                                                        | `POST /admin/access-requests/{id}/approve`                                                                                                                     |
| Create or edit a connection                                                      | `POST /admin/connections`, `PUT /admin/connections/{id}`                                                                                                       |
| Download a full export                                                           | `GET /admin/backup/export`                                                                                                                                     |
| Set or clear the backup recipient                                                | `PUT /admin/backup/config`                                                                                                                                     |
| Look up, approve, or deny a device code                                          | `/api/auth/device`, `/api/auth/device/approve`, `/api/auth/device/deny`                                                                                        |
| Issue an OAuth authorization code                                                | `/api/auth/oauth2/authorize`, `/api/auth/oauth2/consent`, `/api/auth/oauth2/continue`                                                                          |
| Register, rename, or delete a Passkey                                            | `/api/auth/passkey/generate-register-options`, `/api/auth/passkey/verify-registration`, `/api/auth/passkey/update-passkey`, `/api/auth/passkey/delete-passkey` |
| Rotate a client secret or change a stored consent through the auth library's own routes | `/api/auth/oauth2/client/rotate-secret`, `/api/auth/oauth2/update-consent`, `/api/auth/oauth2/delete-consent`                                            |

Every other write under `/admin/*` needs a signed-in Owner and a request from the service's own origin. That includes creating an installation, revoking an installation or a grant, creating, rotating, or deleting a secret, deleting a connection, denying an access request, and starting a backup run.

Every write under `/admin/*` must carry an `Origin` header equal to the service's origin (`origin_not_allowed` otherwise). A request without a valid Owner session fails with `owner_auth_required`.

## Installations

An installation is the record the Owner creates in the console for one agent client. It is an OAuth public client: it has a client ID and no client secret. Dynamic client registration is disabled, so an installation exists only when the Owner created it.

Create one installation per agent host. Grants belong to the installation, not to a device: any device that logs in with an installation's client ID has all of that installation's grants at once.

The Owner chooses the kind of installation by leaving the redirect addresses empty or filling them in:

| Kind               | Redirect addresses | Logs in with             |
| ------------------ | ------------------ | ------------------------ |
| Local command line | None               | OAuth device code        |
| Remote MCP client  | 1 to 10            | OAuth authorization code |

### Device code login

The `clavifer` command logs in with the device code flow:

```text
clavifer --profile codex login --server https://credentials.example.com --client-id INSTALLATION_CLIENT_ID
```

1. The command asks the server for a device code and prints a verification address and a short code. It refuses a verification address that is not on the server's own origin.
2. The Owner opens the address, signs in, and enters the code. The page shows the installation's name, the code, the requested scopes, and how many live grants the installation already holds.
3. The Owner approves or denies. Approval needs a recent sign-in.
4. The command polls for the result, no faster than every 5 seconds, and stores the tokens.

Logging in grants nothing by itself. Access to secrets and connections comes from [grants](connections.md#grants). [clients.md](clients.md#step-4-log-in) walks through the whole setup for an agent host.

### Authorization code login

A remote MCP client discovers the server from the MCP endpoint `https://credentials.example.com/v1/mcp`:

- A request without a valid token gets `401` with a `WWW-Authenticate` header that points to `/.well-known/oauth-protected-resource/v1`.
- That document names the authorization server, whose metadata is at `/.well-known/oauth-authorization-server/api/auth`.
- The client sends the browser to the authorization endpoint. The Owner signs in and confirms on the consent page.

The authorization endpoint accepts `GET` only. Issuing a code needs a sign-in within the last 10 minutes: the server caps `max_age` at 600 seconds, and an older session is sent to the sign-in page first. An authorization code is valid for 120 seconds.

The signed parameter that carries an authorization across the sign-in page, `oauth_query`, is accepted only by the sign-in, consent, and continue endpoints. Any other auth endpoint that receives it answers `oauth_query_not_allowed`.

### Tokens

| Property            | Value                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------- |
| Access token        | A signed JWT, valid for 10 minutes                                                          |
| Refresh token       | Lifetime 90 days                                                                            |
| Audience            | `https://credentials.example.com/v1`, the service origin plus `/v1`. REST and MCP share it. |
| Issuer              | `https://credentials.example.com/api/auth`                                                  |
| Server-side storage | Tokens the server stores are kept as SHA-256 hashes                                         |

The server checks all of the following on every `/v1` request:

1. The token's signature, expiry, audience, and issuer (`invalid_token` otherwise; `missing_bearer_token` when there is none).
2. The token's client is an installation that exists, is not revoked, and belongs to the Owner (`client_revoked` otherwise).
3. The token carries the OAuth scope the call needs (`insufficient_scope` otherwise).
4. The grant or approval the call needs, as described in [connections.md](connections.md#how-a-request-is-decided).

The scopes:

| Scope               | Allows calling                           |
| ------------------- | ---------------------------------------- |
| `metadata:list`     | `credentials.list` and `GET /v1/secrets` |
| `connection:invoke` | `http.request` and the REST proxy        |
| `secret:read`       | `POST /v1/secrets/{id}/read`             |
| `access:request`    | `access.request` and `access.status`     |
| `offline_access`    | Receiving a refresh token                |

Every installation is created with all five scopes, and the `clavifer` command asks for all five. A scope only lets the installation call a kind of endpoint. Which secret or connection it may use is decided by grants on the server, never by scopes.

### Revocation

The Owner revokes an installation in the console. An installation can also revoke itself with `clavifer logout`. Both do the same, in one database batch:

- the installation is marked disabled;
- its refresh tokens are revoked and its stored access tokens deleted;
- all its grants are revoked;
- its pending access requests are denied.

Revocation takes effect on the next request. Step 2 of the token check reads the installation's record every time, so an access token that has not expired yet stops working at once. A request already sent to an upstream cannot be recalled.

A revoked installation is not re-enabled. Create a new one to connect the same agent host again.

Revoking a single grant works the same way: the next request no longer finds it.

## Where the command line keeps tokens

The `clavifer` command stores the access and refresh token in the operating system's credential store:

| System  | Store                                         |
| ------- | --------------------------------------------- |
| Windows | Credential Manager                            |
| macOS   | Keychain                                      |
| Linux   | Secret Service, over the user's D-Bus session |

The entry's service name is `clavifer` and its account name is the server address followed by `/` and the client ID. There is no plain-text fallback: when the store is unavailable, the command fails with `system credential store unavailable`.

A profile is the local name of one login. Its file holds only the server address and the client ID:

| Profile                 | File                                       |
| ----------------------- | ------------------------------------------ |
| Named, `--profile NAME` | `<config dir>/clavifer/profiles/NAME.json` |
| Default                 | `<config dir>/clavifer/profile.json`       |

`<config dir>` is `%AppData%` on Windows, `~/Library/Application Support` on macOS, and `$XDG_CONFIG_HOME` or `~/.config` on Linux.

The command refreshes an access token shortly before it expires, under a lock shared by all processes of the same installation. If a refreshed token cannot be written back to the store, the command asks for a new login, because the old refresh token is already used up.

`clavifer logout` revokes the installation on the server, deletes the stored tokens, and renames the profile file to an archive beside it. `clavifer logout --local` only clears the local login; revoke the installation in the console first.

Only Windows has been verified on a real machine. See [security-model.md](security-model.md#known-limits-and-non-goals).

## After changing the domain

The service's origin is part of every token's audience, of each stored login, and of every Passkey. After the service moves to another domain:

1. **Log each profile in again** against the new address, with the same client ID:

   ```text
   clavifer --profile codex login --server https://new-credentials.example.com --client-id INSTALLATION_CLIENT_ID
   ```

   Installations and their grants stay in the database and keep working. Tokens issued under the old origin fail with `invalid_token`. If the old domain still reaches the service, a login that names it fails with `invalid_target`.

2. **Register every Passkey again.** A Passkey is bound to the hostname it was registered on. Sign in with the password on the new domain, then register the Passkeys anew.

3. **Authorize remote MCP clients again** at the new address.

The server-side steps of the move are in [deploy.md](deploy.md#changing-the-hostname).

The same holds after a snapshot is imported into a new instance. Installations keep their client IDs and grants, but no token travels in a snapshot: every profile logs in again, and remote MCP clients authorize again. Passkeys come across only when the new instance has the same hostname.
