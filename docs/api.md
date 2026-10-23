# API

Clavifer has two interfaces for installations, a REST API and an MCP server, and one REST interface for the Owner's web console. This page gives an overview of the routes, describes the four MCP tools with their inputs and outputs, and says where the machine-readable contract is. The exact schemas are in the generated OpenAPI document and in the tool list the MCP server publishes; this page does not repeat them.

| Interface             | Path                          | Caller              | Authentication                             |
| --------------------- | ----------------------------- | ------------------- | ------------------------------------------ |
| MCP server            | `/v1/mcp`                     | Installation        | OAuth access token (Bearer)                |
| Installation REST API | `/v1/*`                       | Installation        | OAuth access token (Bearer)                |
| Owner REST API        | `/admin/*`                    | The console         | Owner session cookie, same origin          |
| Authentication        | `/api/auth/*`, `/api/setup/*` | Browser, `clavifer` | See [authentication.md](authentication.md) |

All timestamps are milliseconds since the Unix epoch. `null` in an expiry field means no expiry.

## OpenAPI document

The REST contract is [`packages/contracts/openapi.json`](../packages/contracts/openapi.json), an OpenAPI 3.1 document. `scripts/generate-openapi.mjs` generates it from the same schemas the Worker validates requests with.

```text
npm run openapi:generate   # write the document again after changing a route or a schema
npm run openapi:check      # fail if the committed document differs from the generated one
```

What the document leaves out:

- **MCP tools.** They are JSON-RPC calls, not REST operations. See [MCP tools](#mcp-tools).
- **OAuth endpoints.** They are described by the metadata documents at `/.well-known/oauth-protected-resource/v1` and `/.well-known/oauth-authorization-server/api/auth`.
- **Most proxy methods.** The proxy operation lists `GET`, `HEAD`, and `POST` as examples. The proxy accepts every method the connection's policy allows.

The document's server URL is the placeholder `https://YOUR-APP-ORIGIN`. Replace it with your deployment's origin.

## Errors

A failed REST call returns an HTTP error status and this body:

```json
{ "error": "grant_required", "hint": "No grant covers this request. Call access.request with ...", "request_id": "..." }
```

`error` is a stable code. `hint` is present when there is a next step. `request_id` equals the `x-request-id` response header and the request ID in the audit log.

A failed MCP tool call returns a normal JSON-RPC result with `isError: true`. Its text content is the JSON object `{"error", "hint"}`.

The codes for connection requests and access requests, with the next step for each, are in [connections.md](connections.md#error-codes). Codes that apply to every route:

| Code                                                      | Status | Meaning                                                                          |
| --------------------------------------------------------- | ------ | -------------------------------------------------------------------------------- |
| `invalid_input` (REST), `invalid_arguments` (MCP)         | 400    | The input does not match the schema. The hint names up to five offending fields. |
| `json_required`                                           | 415    | The request body is not sent as `application/json`.                              |
| `invalid_json`                                            | 400    | The request body is not valid JSON.                                              |
| `missing_bearer_token`, `invalid_token`, `client_revoked` | 401    | See [authentication.md](authentication.md#tokens).                               |
| `insufficient_scope`                                      | 403    | The token lacks an OAuth scope, or a secret read is not covered by a grant.      |
| `origin_not_allowed`                                      | 403    | The request carries an `Origin` header that is not the service's own origin.     |
| `not_found`                                               | 404    | No such route.                                                                   |
| `conflict`                                                | 409    | A unique value, such as a name, is already in use.                               |
| `internal_error`                                          | 500    | Unexpected failure. Quote the `request_id` when reporting it.                    |
| `root_key_mismatch`                                       | 503    | The Worker's root key is not the one the database recorded. Every route but `/healthz` answers this. See [security-model.md](security-model.md#the-root-key). |
| `invalid_root_key`                                        | 503    | The Worker's `ROOT_KEY` cannot be parsed. On an initialized instance every route answers this, `/healthz` included. |

## Installation REST API

| Route                                                                                            | OAuth scope         | Purpose                                                                                                                   |
| ------------------------------------------------------------------------------------------------ | ------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `GET /v1/secrets`                                                                                | `metadata:list`     | Lists every connection and the secrets granted to this installation. Same result as the tool `credentials.list`.          |
| `POST /v1/secrets/{id}/read`                                                                     | `secret:read`       | Returns the values of a granted secret.                                                                                   |
| `POST /v1/access-requests`                                                                       | `access:request`    | Submits an access request. Same input as the tool `access.request`. Returns `202`.                                        |
| `GET /v1/access-requests/{id}`                                                                   | `access:request`    | Reads an access request's status. Same result as the tool `access.status`.                                                |
| `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, or `OPTIONS` on `/v1/proxy/{connection}/{path}` | `connection:invoke` | Sends a request through a connection. See [connections.md](connections.md#limits) for how it differs from `http.request`. |
| `POST /v1/logout`                                                                                | None                | Revokes this installation. See [authentication.md](authentication.md#revocation).                                         |

### Reading a secret

`POST /v1/secrets/{id}/read` is the only way a stored value leaves the server in plain form. No MCP tool reads a secret. The `clavifer run` command uses this route.

- The installation needs a live `secret:read` grant on the secret.
- The optional body `{"fields": ["token"]}` asks for some fields. Without it the response holds every field the grant covers.
- Asking for a field outside the grant fails with `insufficient_scope`. Asking for a field the secret does not have fails with `secret_field_not_found`.
- The response is `{"id", "version", "values"}` and is never cacheable.

An agent asks for such a grant with `access.request`:

```json
{
  "requested": {
    "grants": [
      { "resourceType": "secret", "resourceId": "SECRET_ID", "permission": "secret:read", "fields": ["token"] }
    ]
  },
  "reason": "The deploy script reads the registry token from its environment."
}
```

Leave out `fields` to ask for the whole secret.

## MCP tools

The MCP server speaks Streamable HTTP at `/v1/mcp`. It handles each `POST` on its own, keeps no session, and answers with JSON. A message holds at most 8 MiB. The server's name is `clavifer`.

The usual way to reach it is the local bridge `clavifer mcp`, which an agent host starts as a stdio MCP server. See [clients.md](clients.md). Some agent hosts rewrite the dots in tool names; Claude Code shows `credentials.list` as `mcp__clavifer__credentials_list`.

The server publishes four tools. `tools/list` returns their exact input schemas, and the `initialize` result carries instructions that tell an agent what to do after each error.

| Tool                                   | Purpose                                                        | Changes state                  |
| -------------------------------------- | -------------------------------------------------------------- | ------------------------------ |
| [`credentials.list`](#credentialslist) | See which connections exist and what this installation may use | No                             |
| [`http.request`](#httprequest)         | Send a request through a connection                            | Yes, at the upstream           |
| [`access.request`](#accessrequest)     | Ask the Owner for access                                       | Yes, creates a pending request |
| [`access.status`](#accessstatus)       | Read the state of an access request                            | No                             |

Every tool returns one text content item that holds a JSON object. The examples below show that object.

### `credentials.list`

Takes no arguments. Call it first.

```json
{
  "items": [
    {
      "id": "SECRET_ID",
      "name": "Registry token",
      "description": "",
      "current_version": 3,
      "expires_at": null,
      "fields": ["token"]
    }
  ],
  "connections": [
    {
      "id": "CONNECTION_ID",
      "name": "Example API",
      "origin": "https://api.example.com",
      "description": "Send Accept: application/json on every request.",
      "policy_json": "{\"paths\":[\"/v1\"],\"methods\":[\"GET\",\"POST\"],\"deny\":[\"* /v1/admin/*\"],\"approval\":[\"POST /v1/payments/*\"],\"free\":[\"GET /v1/status\"],\"hosts\":[],\"anyHost\":false}",
      "granted": true,
      "expires_at": 1798761600000,
      "extensions": [{ "paths": ["/v2/tokens"], "methods": ["DELETE"], "expiresAt": 1798761600000 }]
    }
  ]
}
```

- `items` holds only the secrets this installation has a live `secret:read` grant on. `fields` is the granted subset, or `null` when the grant covers every field. `expires_at` is the grant's expiry.
- `connections` holds every connection, granted or not, so that an agent can ask for one. It never shows which secret a connection uses or what other installations were granted.
- `policy_json` is a JSON string. Parse it to read the policy. Its fields are defined in [connections.md](connections.md#policy).
- `granted` says whether this installation holds a live `connection:invoke` grant. `expires_at` is that grant's expiry, and `extensions` its live [scope extensions](connections.md#scope-extensions).
- Follow the notes in `description`.

### `http.request`

Sends one request through a connection. Send the request directly first; if it is refused, the error says what to ask for.

| Argument     | Required | Content                                                                                                    |
| ------------ | -------- | ---------------------------------------------------------------------------------------------------------- |
| `connection` | Yes      | The connection's ID from `credentials.list`                                                                |
| `method`     | No       | Default `GET`                                                                                              |
| `path`       | No       | Default `/`. No query string.                                                                              |
| `query`      | No       | An object of string values                                                                                 |
| `headers`    | No       | An object of string values                                                                                 |
| `body`       | No       | A UTF-8 string. Serialize JSON yourself and set `content-type`.                                            |
| `origin`     | No       | Another origin than the connection's own. See [connections.md](connections.md#requests-to-another-origin). |

Arguments:

```json
{ "connection": "CONNECTION_ID", "method": "GET", "path": "/v1/items", "query": { "limit": "10" } }
```

Result:

```json
{
  "status": 200,
  "headers": { "content-type": "application/json", "cache-control": "no-store" },
  "body": "{\"items\":[]}"
}
```

`status` is the upstream's HTTP status. An upstream error such as `404` or `500` is a successful tool call with that status. A refusal by Clavifer is a tool error:

```json
{
  "error": "path_not_allowed",
  "hint": "This path is outside the connection’s regular scope; that is not a prohibition. ..."
}
```

The decision order is in [connections.md](connections.md#how-a-request-is-decided), and the limits are in [connections.md](connections.md#limits).

### `access.request`

Submits a request for the Owner to decide. Arguments:

| Argument    | Required     | Content                                                                       |
| ----------- | ------------ | ----------------------------------------------------------------------------- |
| `requested` | Yes          | An object with exactly one of `grants`, `invocation`, `setup`, `update`       |
| `reason`    | Yes          | Up to 500 characters for the Owner. Required in the MCP tool schema; when it is missing, the server stores an empty string. |

What each of the four holds, with a complete example of each, is in [connections.md](connections.md#access-requests). The example for a secret grant is [above](#reading-a-secret).

Result:

```json
{
  "id": "REQUEST_ID",
  "status": "pending",
  "approveUrl": "https://credentials.example.com/?tab=access",
  "waitCommand": "/path/to/clavifer --profile codex status REQUEST_ID --wait"
}
```

- `approveUrl` is the page where the Owner decides. Show it to the user.
- `waitCommand` is present only through the local bridge, which adds it. It is a shell command that exits once the Owner has decided and prints the final status. Run it instead of polling. It exits with `124` when the Owner has not decided within its timeout, 25 minutes by default; run it again or ask the user.

Do not call `access.request` after `path_denied`.

### `access.status`

Takes `{"id": "REQUEST_ID"}`. An installation can read only its own requests.

| `status`   | Meaning                                                                            | Other fields                                                                                                                        |
| ---------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `pending`  | The Owner has not decided.                                                         | `expires_at`: when the request expires undecided                                                                                    |
| `approved` | Approved. For an invocation: not sent yet.                                         | Invocation: `expires_at`, the deadline to send it. Grants: `grants`. Setup: `connectionIds`, and `secretId` if it created a secret. |
| `executed` | An approved invocation was sent.                                                   | `expires_at`                                                                                                                        |
| `denied`   | The Owner denied it, or the installation was revoked.                              | None                                                                                                                                |
| `expired`  | Not decided within 24 hours, or an approved invocation not sent within 10 minutes. | `expires_at`                                                                                                                        |

A request more than about 25 hours old may have been moved to the [archive](security-model.md#cold-data); `access.status` then answers `request_not_found`.

An approved grant request lists the grants as they stand now, not as they were approved:

```json
{
  "id": "REQUEST_ID",
  "status": "approved",
  "grants": [
    {
      "resource_type": "connection",
      "resource_id": "CONNECTION_ID",
      "permission": "connection:invoke",
      "expires_at": 1798761600000,
      "extensions": [{ "paths": ["/v2/tokens"], "methods": ["DELETE"], "expiresAt": 1796083200000 }]
    }
  ]
}
```

`expires_at` can be later than the period just approved, because an approval never shortens a live grant. Each extension has its own `expiresAt`. A grant that has ended since is left out.

### A typical sequence

1. Call `credentials.list` and pick the connection.
2. Call `http.request`.
3. On a tool error, read `error` and `hint`. If the code is `path_denied`, stop and tell the user.
4. Otherwise call `access.request` with what the hint names, and a `reason` the Owner can check.
5. Run `waitCommand`, or call `access.status` now and then. Never poll in a tight loop.
6. On `approved`: resend the identical request with `http.request` for an invocation, or start the granted work. On `denied` or `expired`: stop and tell the user.

## Owner REST API

The console is the only intended client of `/admin/*`. Every route needs the Owner's session cookie. Every write needs an `Origin` header equal to the service's origin, and some writes need a recent sign-in; see [authentication.md](authentication.md#operations-that-need-a-recent-sign-in).

| Routes                                                                                                                                                                  | Purpose                                                                                                                                                                                   |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /admin/status`                                                                                                                                                     | Everything the console shows: secrets with their field names and no values, connections, pending access requests, installations, live grants, the latest 50 audit rows, and backup status |
| `POST /admin/clients`, `DELETE /admin/clients/{id}`                                                                                                                     | Create and revoke an installation                                                                                                                                                         |
| `POST /admin/secrets`, `PUT /admin/secrets/{id}`, `DELETE /admin/secrets/{id}`                                                                                          | Create a secret, write a new version, delete                                                                                                                                              |
| `POST /admin/connections`, `PUT /admin/connections/{id}`, `DELETE /admin/connections/{id}`                                                                              | Create, edit, and delete a connection                                                                                                                                                     |
| `POST /admin/grants`, `DELETE /admin/grants/{id}`                                                                                                                       | Create and revoke grants                                                                                                                                                                  |
| `POST /admin/access-requests/{id}/approve`, `POST /admin/access-requests/{id}/deny`                                                                                     | Decide an access request                                                                                                                                                                  |
| `GET /admin/backup/export`, `GET /admin/backup/exports/{id}`, `PUT /admin/backup/config`, `GET /admin/backup/status`, `POST /admin/backup/run`, `GET /admin/backup/latest` | Full export and its completion status, the backup recipient, automatic backups. See [security-model.md](security-model.md#backups).                                                     |

No route returns a stored secret value to the Owner. The values leave the server only through `POST /v1/secrets/{id}/read` and inside an encrypted snapshot: an automatic backup or a full export.

The console's `/setup` page calls `/api/setup/*` with the one-time bootstrap token, to create the Owner, import a snapshot, or reset the Owner's password. See [authentication.md](authentication.md#bootstrap-token).

`GET /healthz` needs no authentication. It returns `{"ok", "service", "version", "keys", "initialized"}`: `keys` is `ok`, `mismatch` (the root key is not the one the database recorded; `ok` is then `false`), or `uninitialized` (no Owner yet).
