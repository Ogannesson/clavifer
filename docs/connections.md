# Connections

A connection lets an agent call one upstream API without holding its credential. The installation sends a request to Clavifer; Clavifer decides whether the request may run, adds the credential on the server, and forwards it. This page defines what a connection holds, how a request is decided, what every refusal means, and how an agent asks the Owner for more access.

An installation calls a connection through the MCP tool `http.request` or through the REST proxy `/v1/proxy/{connection}/{path}`. Both go through the same decision. Tool inputs and outputs are in [api.md](api.md).

All timestamps on this page (`expires_at`, `expiresAt`) are milliseconds since the Unix epoch.

## What a connection holds

| Field                      | Content                                                                                                                                                                                                                                                            |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                     | 1 to 120 characters. Unique among the Owner's connections, deleted ones included.                                                                                                                                                                                  |
| `origin`                   | The fixed upstream origin, such as `https://api.example.com`. HTTPS only; no path, query, or user info. The hostname must be public: not an IP address, at least one dot, and not ending in `localhost`, `local`, `internal`, `lan`, `home`, `test`, or `invalid`. |
| `description`              | Up to 2000 characters of usage notes for agents, such as a non-secret header every request needs. Every installation can read it. Never put a secret in it.                                                                                                        |
| `auth`                     | How the credential is injected. See [Credential injection](#credential-injection).                                                                                                                                                                                 |
| `paths`, `methods`         | The regular scope. See [Policy](#policy).                                                                                                                                                                                                                          |
| `deny`, `approval`, `free` | Three lists of rules. See [Rule syntax](#rule-syntax).                                                                                                                                                                                                             |
| `hosts`, `anyHost`         | Where else a one-time approval may send a request. See [Requests to another origin](#requests-to-another-origin).                                                                                                                                                  |

Only the Owner creates or edits a connection, in the web console or by approving a [draft](#drafts) an agent submitted. Deleting a connection revokes every grant on it.

A local deployment (`ALLOW_LOCAL_HTTP` set to `true`) also accepts `http://localhost` and the IPv4 loopback address as an origin.

## Credential injection

`auth` names fields of one stored secret. The connection stores the secret's ID and the field names, never a value.

| Type   | `auth`                                                                                          | What the upstream receives                                  |
| ------ | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| None   | `{"type":"none"}`                                                                               | No credential.                                              |
| Bearer | `{"type":"bearer","secretId":"SECRET_ID","field":"token"}`                                      | `Authorization: Bearer <value>`                             |
| Header | `{"type":"header","secretId":"SECRET_ID","field":"token","name":"X-API-Key"}`                   | The named header with the value.                            |
| Basic  | `{"type":"basic","secretId":"SECRET_ID","usernameField":"username","passwordField":"password"}` | `Authorization: Basic <base64 of username:password, UTF-8>` |
| Query  | `{"type":"query","secretId":"SECRET_ID","field":"token","name":"api_key"}`                      | The URL parameter `api_key=<value>`, URL-encoded.           |

The server checks the stored values when the connection is saved and again on every request:

- Bearer and header values are printable ASCII without leading or trailing spaces (`invalid_header_credential` otherwise).
- A Basic username holds no colon, and neither Basic field holds a control character (`invalid_basic_credential` otherwise).
- A header name is 1 to 64 letters, digits, or hyphens, and is not one of the [stripped request headers](#limits), except `Authorization`.
- A query parameter name starts with a letter or underscore and continues with letters, digits, `_`, `.`, `~`, or `-`, up to 64 characters.

A caller cannot override the injected credential. The server drops the caller's `Authorization` and `Cookie` headers before it injects. For query injection it removes every caller parameter with the same name, in any letter case, and then sets the one credential value.

Query injection puts the credential in the URL, which the upstream may write to its logs. Choose it only when the upstream offers nothing else.

## Policy

The policy is stored as JSON. `credentials.list` returns it as the string `policy_json`:

```json
{
  "paths": ["/v1"],
  "methods": ["GET", "POST"],
  "deny": ["* /v1/admin/*"],
  "approval": ["POST /v1/payments/*"],
  "free": ["GET /v1/status"],
  "hosts": ["files.example.com", "*.cdn.example.com"],
  "anyHost": false
}
```

A field that is missing from `policy_json` counts as empty (`deny`, `approval`, `free`, `hosts`) or `false` (`anyHost`).

### Regular scope

`paths` and `methods` together form the regular scope. A request is inside the regular scope when its path lies under one of `paths` and its method is listed in `methods`.

- `paths` holds 1 to 30 literal prefixes of up to 300 characters each. A prefix matches by whole segments and is case-sensitive: `/v1` covers `/v1`, `/v1/`, and `/v1/items`, and does not cover `/v10` or `/V1`. The prefix `/` covers every path. A prefix cannot contain `*` (`use_path_prefix_not_glob`).
- `methods` holds 1 to 7 of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`. The default is `["GET", "HEAD"]`. Each method counts only when listed: `GET` in `methods` does not put `HEAD` in the regular scope.

A request outside the regular scope is not forbidden. It needs a [scope extension](#scope-extensions) or a [one-time approval](#one-time-approvals).

### Rule syntax

`deny`, `approval`, and `free` each hold up to 50 rules. A rule is one line of at most 320 characters: `METHOD /path`.

- `METHOD` is one of the seven methods above or `*` for any method. Letter case is ignored on input.
- The path starts with `/` and matches exactly. A trailing `/*` makes the rule cover that path and everything below it. `*` is allowed nowhere else in the path.
- A rule written as a bare path gets a default method: `GET` in `free`, `*` in `deny` and `approval`.
- A `GET` rule also covers `HEAD`. A `HEAD` rule does not cover `GET`.

The server saves each rule in its normal form, `METHOD /path` with the method in upper case, and that is what `policy_json` shows.

What each list does:

| List       | Effect on a matching request                                                                                                                                                                                |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `deny`     | Always refused with `path_denied`. Nothing overrides a deny rule: no grant, no scope extension, no one-time approval. Only the Owner lifts it, by editing the connection.                                   |
| `approval` | Needs a one-time approval of this exact request, even when the installation holds a grant. Applies inside and outside the regular scope.                                                                    |
| `free`     | Runs without any grant, when the request is also inside the regular scope. A free rule has no effect outside the regular scope. It applies to every installation, including one that holds no grant at all. |

A rule matches on the decoded path (see [Path handling](#path-handling)). Matching ignores the case of ASCII letters and one trailing slash, and never looks at the query string.

| Rule                | Request               | Matches |
| ------------------- | --------------------- | ------- |
| `GET /v1/items`     | `GET /v1/items`       | Yes     |
| `GET /v1/items`     | `HEAD /v1/items`      | Yes     |
| `GET /v1/items`     | `GET /v1/items/1`     | No      |
| `GET /v1/items`     | `POST /v1/items`      | No      |
| `HEAD /v1/items`    | `GET /v1/items`       | No      |
| `GET /v1/items/*`   | `GET /v1/items`       | Yes     |
| `GET /v1/items/*`   | `GET /v1/items/1/sub` | Yes     |
| `GET /v1/items/*`   | `GET /v1/itemsx`      | No      |
| `* /v1/items`       | `DELETE /v1/items`    | Yes     |
| `DELETE /zones/abc` | `DELETE /ZONES/abc/`  | Yes     |
| `DELETE /x/*`       | `DELETE /x/a%2Fb`     | Yes     |

Rules ignore letter case and allowed paths do not. Both choices err on the side of refusing: a deny rule catches every spelling of a route, and an allowed path admits only the spelling the Owner wrote.

Saving a malformed rule fails with `invalid_rule` and a hint that names the list and the line, such as `deny line 3`. More than 50 rules in one list fails with `too_many_rules`.

### Path handling

A path starts with `/`, holds at most 2048 characters, and carries no query string. Send query parameters in `query`.

The upstream receives the path exactly as the caller sent it. Every policy decision reads the percent-decoded path.

| Path as sent                                           | Result                                                                                              |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| `/x/a%2Fb`                                             | Accepted. Policy reads `/x/a/b`.                                                                    |
| `/x/my%20key`                                          | Accepted. Policy reads `/x/my key`.                                                                 |
| `/x/my key`                                            | `invalid_path`: literal space. Send `%20`.                                                          |
| `/v1/secret;x`, `/v1/secret%3Bx`                       | `invalid_path`: `;` in any spelling.                                                                |
| `/v1?x=1`, `/v1/#x`, `/v1\admin`                       | `invalid_path`: `?`, `#`, or `\`.                                                                   |
| `/x/a%2F%2Fb`, `//host/x`                              | `invalid_path`: empty segment.                                                                      |
| `/v1/../admin`, `/x/%2e%2e/admin`, `/x/a%2F..%2Fadmin` | `invalid_path`: `.` or `..` segment in any spelling.                                                |
| `/x/a%252Fb`                                           | `invalid_path`: decodes to a path that still holds `%`.                                             |
| `/v1/%00`, `/v1/a%E2%80%AEb`                           | `invalid_path`: control or format character, such as a bidirectional override or a zero-width mark. |
| `/v1/%`                                                | `invalid_path`: malformed percent-encoding.                                                         |

Two consequences of reading the decoded path:

- A deny or approval rule cannot be bypassed with `%2F`. The rule `* /x/a/secret/*` matches `/x/a%2Fsecret`, `/x%2Fa/secret`, and `/X/A%2FSECRET/`.
- An allowed path, a free rule, or a scope extension that names `/x/a` also covers `/x/a%2Fb`. In a key-value store that is the key `a/b`.

The same checks apply to allowed paths, rule paths, and scope extension paths when they are saved.

## How a request is decided

The server takes these steps in order, for MCP and REST alike. A step that produces an error ends the decision. A grant or a scope extension is live when it has not been revoked and has not expired.

1. **Check the request itself.** A body over 1 MiB fails with `body_too_large`. A body on `GET` or `HEAD` fails with `body_not_allowed`. A token without the `connection:invoke` scope fails with `insufficient_scope`. An unknown or deleted connection fails with `connection_not_found`.
2. **Check another origin.** If the request names an `origin` that differs from the connection's own, the connection's `hosts` or `anyHost` must cover its hostname. Otherwise the request fails with `host_not_allowed`.
3. **Read the path and apply deny rules.** A path that [Path handling](#path-handling) refuses fails with `invalid_path`. If a deny rule matches, the request fails with `path_denied`. The hint quotes the rule.
4. **Apply the policy.** The first line that matches gives the outcome. An outcome of "refuse" becomes final only in step 5.
   1. The request names another origin: refuse with `approval_required`. Nothing in the policy runs such a request.
   2. An approval rule matches: refuse with `approval_required`.
   3. The request is inside the regular scope and a free rule matches: run.
   4. The request is inside the regular scope and the installation holds a live grant on the connection: run.
   5. The request is outside the regular scope and the installation's live grant carries a live scope extension that covers both its path and its method: run.
   6. The path lies under none of `paths`: refuse with `path_not_allowed`.
   7. The path is allowed and the method is not in `methods`: refuse with `method_not_allowed`.
   8. Otherwise: refuse with `grant_required`.
5. **Look for a one-time approval.** If the outcome of step 4 is "refuse", the server looks for an approved, unspent, unexpired one-time approval that this installation holds for exactly this request. If one exists, the server marks it spent and the request runs. If none exists, the request fails with the code from step 4.
6. **Inject and send.** The server injects the credential, sends the request, and returns the upstream's status and body.

Under the example policy above, the decisions are:

| Request                  | Without a grant      | With a grant and no extension |
| ------------------------ | -------------------- | ----------------------------- |
| `GET /v1/status`         | Runs                 | Runs                          |
| `GET /v1/items`          | `grant_required`     | Runs                          |
| `DELETE /v1/admin/users` | `path_denied`        | `path_denied`                 |
| `POST /v1/payments/1`    | `approval_required`  | `approval_required`           |
| `GET /v2/x`              | `path_not_allowed`   | `path_not_allowed`            |
| `PUT /v1/items`          | `method_not_allowed` | `method_not_allowed`          |
| `HEAD /v1/status`        | `method_not_allowed` | `method_not_allowed`          |

The last row shows that a free `GET` rule runs `HEAD` only when `HEAD` is also listed in `methods`.

## Error codes

Every refusal carries `error` and, when there is a next step, `hint`. Over REST the body is `{"error", "hint", "request_id"}` with the HTTP status below. Over MCP the tool result has `isError: true` and its text is `{"error", "hint"}`.

Errors from sending a request:

| Code                                                                                                                            | Status                  | Meaning                                                                                                                                                    | Next step for an agent                                                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `path_denied`                                                                                                                   | 403                     | A deny rule, quoted in the hint, forbids this request.                                                                                                     | Stop. Tell the user which rule blocked it. Do not call `access.request`: no approval lifts a deny rule.                                                      |
| `approval_required`                                                                                                             | 403                     | An approval rule matches, or the request names another origin. No grant covers it.                                                                         | Call `access.request` with `requested.invocation` set to this exact request, including `origin` if it has one. After approval, resend it unchanged.          |
| `path_not_allowed`                                                                                                              | 403                     | The path is outside `paths` and no scope extension covers it.                                                                                              | One operation: `requested.invocation`. Several operations: `requested.grants` for this connection with `paths` (and `methods` if needed).                    |
| `method_not_allowed`                                                                                                            | 403                     | The path is allowed, the method is outside `methods`, and no scope extension covers it.                                                                    | One operation: `requested.invocation`. Several operations: `requested.grants` with `methods` (and `paths` if needed).                                        |
| `grant_required`                                                                                                                | 403                     | The request is inside the regular scope, no free rule matches, and the installation holds no live grant.                                                   | Several operations: `requested.grants`. One operation: `requested.invocation`.                                                                               |
| `host_not_allowed`                                                                                                              | 403                     | The request names an `origin` whose hostname the connection's `hosts` do not cover, and `anyHost` is off.                                                  | Tell the user which hostname is needed and why. The Owner can add it to the connection. Do not retry with another spelling of the address.                   |
| `origin_must_be_https`, `origin_must_not_contain_path`, `public_origin_required`                                                | 400                     | The `origin` named is not a public HTTPS origin.                                                                                                           | Send `https://hostname` with no path, and no IP address or local name.                                                                                       |
| `invalid_path`                                                                                                                  | 400                     | The path holds something [Path handling](#path-handling) refuses. The hint says what.                                                                      | Do not try another encoding. Use an endpoint that takes the name or key in the request body, or ask the user to do the operation by hand.                    |
| `connection_not_found`                                                                                                          | 404                     | No active connection has this ID.                                                                                                                          | Check `credentials.list`. If the API is not configured, tell the user what connection is needed. Submit a [setup draft](#drafts) only after the user agrees. |
| `insufficient_scope`                                                                                                            | 403                     | The access token lacks the OAuth scope this call needs.                                                                                                    | Tell the user. The installation has to log in again with the full scope list.                                                                                |
| `body_too_large`                                                                                                                | 413                     | The request body exceeds 1 MiB.                                                                                                                            | Split the work into smaller requests. Upload large files with the agent host's own tools.                                                                    |
| `body_not_allowed`                                                                                                              | 400                     | A `GET` or `HEAD` request carries a body.                                                                                                                  | Remove the body or change the method.                                                                                                                        |
| `invalid_query`, `query_too_large`                                                                                              | 400, 413                | The query breaks a [limit](#limits).                                                                                                                       | Send fewer or shorter parameters, paginate, or use an endpoint that takes the filter in the body.                                                            |
| `invalid_headers`                                                                                                               | 400                     | A header name or value is not valid HTTP.                                                                                                                  | Fix the header.                                                                                                                                              |
| `response_too_large`                                                                                                            | 413                     | MCP only. The response exceeded 1 MiB. The upstream request already ran.                                                                                   | Do not resend a write. Paginate or narrow the query.                                                                                                         |
| `upstream_outcome_unknown`                                                                                                      | 502                     | The request to the upstream failed before a response arrived, by timeout or network error. The request may have run. A one-time approval it used is spent. | Read the upstream state first. Never retry a write automatically.                                                                                            |
| `secret_not_found`, `secret_field_not_found`, `invalid_header_credential`, `invalid_basic_credential`, `encryption_key_missing` | 404, 404, 400, 400, 503 | The connection's credential binding is broken or the server cannot decrypt.                                                                                | Tell the user. Only the Owner can repair it.                                                                                                                 |
| `invalid_arguments` (MCP), `invalid_input` (REST)                                                                               | 400                     | The input does not match the schema. The hint names each offending field.                                                                                  | Fix the named field.                                                                                                                                         |

Errors from `access.request` and `access.status`:

| Code                                                                         | Status | Meaning                                                                                           | Next step for an agent                                                    |
| ---------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `path_denied`                                                                | 403    | The invocation matches a deny rule.                                                               | Same as above: stop and tell the user.                                    |
| `host_not_allowed`                                                           | 403    | The invocation names an origin the connection does not cover.                                     | Same as above.                                                            |
| `connection_not_found`, `secret_not_found`                                   | 404    | A grant, invocation, or update names a resource that does not exist.                              | Check `credentials.list`, or ask the user which resource the task needs.  |
| `body_too_large`                                                             | 413    | The invocation body exceeds 64 KiB.                                                               | Split the work, or upload large files with the agent host's own tools.    |
| `headers_too_large`                                                          | 413    | The invocation headers exceed 16 KiB in total.                                                    | Send only the headers the upstream needs.                                 |
| `too_many_pending`                                                           | 429    | This installation already has 20 requests waiting for the Owner.                                  | Tell the user and wait. Do not submit again until the Owner decides some. |
| `tests_failed`                                                               | 400    | A draft's tests do not match its policy. The hint lists each mismatch.                            | Fix the draft or the expectation and submit again.                        |
| `name_taken`                                                                 | 409    | A draft uses a connection name that exists or existed.                                            | Choose another name.                                                      |
| `invalid_rule`, `too_many_rules`, `invalid_host`, `use_path_prefix_not_glob` | 400    | A draft or a scope extension is malformed. The hint names the connection, the list, and the line. | Fix that line.                                                            |
| `request_not_found`                                                          | 404    | This installation has no access request with this ID.                                             | Use the ID `access.request` returned.                                     |

Errors only the Owner sees, when approving a request:

| Code                      | Status | Meaning                                                                                                                                     |
| ------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `recent_login_required`   | 403    | Approval needs a sign-in within the last 10 minutes. See [authentication.md](authentication.md#operations-that-need-a-recent-sign-in).      |
| `existing_grant_conflict` | 409    | The request asks for a different field subset than a live grant on the same secret. The Owner changes that grant in the grant form instead. |
| `secret_name_taken`       | 409    | A setup draft's secret name exists or existed. The Owner denies the draft; the agent submits again under another name.                      |
| `secret_fields_mismatch`  | 400    | The values entered for a setup do not match the draft's field names.                                                                        |
| `connection_changed`      | 409    | The connection changed after the agent submitted an update draft. The Owner denies it; the agent submits again.                             |
| `origin_mismatch`         | 409    | The approval did not name back the other origin the request goes to. Reloading the page fixes it.                                           |
| `request_not_found`       | 404    | The request is no longer pending.                                                                                                           |

## Access requests

An agent asks for access with `access.request`. `requested` holds exactly one of four things:

| Key          | Asks for                                         | Approved result                                                                         |
| ------------ | ------------------------------------------------ | --------------------------------------------------------------------------------------- |
| `grants`     | 1 to 20 grants, each on a secret or a connection | [Grants](#grants), and [scope extensions](#scope-extensions) if the request carried any |
| `invocation` | One exact request                                | A [one-time approval](#one-time-approvals)                                              |
| `setup`      | A new secret and the connections that use it     | The secret and connections exist. See [Drafts](#drafts).                                |
| `update`     | A change to an existing connection               | The connection is changed. See [Drafts](#drafts).                                       |

Rules common to all four:

- `reason` holds up to 500 characters and is what the Owner reads first. Name the target the way a person knows it (name, account, creation date) and the expected effect. When acting on an opaque ID, say how you identified it.
- A request stays `pending` for 24 hours. After that its status is `expired`.
- Submitting the same `requested` content again while the first request is pending returns the first request's ID.
- One installation holds at most 20 pending requests (`too_many_pending`). Expired ones do not count.
- Revoking an installation denies its pending requests.
- The Owner needs a recent sign-in to approve. Denying does not need one.

`access.status` reports `pending`, `approved`, `denied`, `expired`, or `executed`. `executed` means an approved one-time approval has been spent.

### Grants

A grant gives one installation one permission on one resource: `connection:invoke` on a connection, or `secret:read` on a secret. There is at most one grant per installation, resource, and permission.

A request for a connection grant:

```json
{
  "requested": {
    "grants": [{ "resourceType": "connection", "resourceId": "CONNECTION_ID", "permission": "connection:invoke" }]
  },
  "reason": "List and update items in the example account for the nightly sync."
}
```

Lifecycle:

- **Start.** The Owner creates a grant directly in the console, or approves a `grants` request.
- **Expiry.** The Owner chooses it on approval: a time, or none, which means until revoked. An approval that names no expiry lasts 24 hours.
- **Renewal.** A new grant or approval never shortens a live grant. If the live grant has no expiry or a later one, it keeps it. A revoked or expired grant takes the new expiry.
- **End.** A grant ends when it expires, when the Owner revokes it, when its connection or secret is deleted, or when its installation is revoked. The server reads the grant on every request, so the end takes effect on the next request.

A `connection:invoke` grant runs requests inside the regular scope. It does not run a request that a deny or approval rule matches, a request outside the regular scope, or a request to another origin. It never allows reading the secret.

A `secret:read` grant may carry `fields` to cover only part of a secret. Approving a request never changes the field subset of a live grant (`existing_grant_conflict`).

### Scope extensions

A scope extension lets one installation send requests outside a connection's regular scope for a limited time. It lives on the installation's grant and never changes the connection.

An agent asks for one by adding `paths`, `methods`, or both to a connection grant:

```json
{
  "requested": {
    "grants": [
      {
        "resourceType": "connection",
        "resourceId": "CONNECTION_ID",
        "permission": "connection:invoke",
        "paths": ["/v2/tokens"],
        "methods": ["DELETE"]
      }
    ]
  },
  "reason": "Revoke the token \"ci-deploy\" created 2026-09-01, found by name in GET /v2/tokens."
}
```

- `paths` are literal prefixes with the same syntax as allowed paths. `methods` are listed one by one.
- An extension covers a request when the path lies under one of its `paths` and the method is one of its `methods`. Two extensions are never combined: `{paths: ["/v2/tokens"], methods: ["DELETE"]}` and `{paths: ["/v2/keys"], methods: ["PATCH"]}` do not cover `PATCH /v2/tokens/abc`.
- A list left out is copied from the connection at the moment of approval. Editing the connection later does not widen an approved extension.
- Each extension carries the expiry the Owner chose for that approval, even when the grant itself lasts longer.
- An extension ends with its grant. A later grant does not bring it back.
- Approving a request adds its extension to the grant's live ones. A grant the Owner creates directly replaces them.
- Deny rules and approval rules still apply to a request an extension covers.

`credentials.list` shows a grant's live extensions as `extensions`, each `{paths, methods, expiresAt}`.

### One-time approvals

A one-time approval lets one installation send one exact request once. It runs a request that an approval rule matches, a request outside the regular scope, a request without a grant, and a request to another origin. It does not run a request that a deny rule matches.

The request for one names the method and the path explicitly:

```json
{
  "requested": {
    "invocation": {
      "connection": "CONNECTION_ID",
      "method": "POST",
      "path": "/v1/payments/1",
      "query": { "notify": "false" },
      "headers": { "content-type": "application/json" },
      "body": "{\"amount\":1200,\"currency\":\"EUR\"}"
    }
  },
  "reason": "Pay invoice 2026-104 to Example Supplies, 12.00 EUR, as the user asked in this session."
}
```

Lifecycle:

1. **Submit.** The server checks the input, that the connection exists, the deny rules, and the coverage of `origin` if one is named. It does not check the regular scope. The body holds at most 64 KiB and the headers 16 KiB in total.
2. **Review.** The Owner sees the whole request and approves or denies it. The request stays pending for at most 24 hours.
3. **Run.** From the moment of approval the installation has 10 minutes to send the identical request through `http.request`. `access.status` shows `approved` with `expires_at` as the deadline.
4. **Spent.** The approval is marked spent when the request is sent, before the upstream answers. `access.status` then shows `executed`. After `upstream_outcome_unknown` the approval is spent as well.
5. **Expired.** An approval not used within 10 minutes shows `expired`.

The resent request must match the approved one in all of these:

- the connection, and the `origin` if the request names another one;
- the method;
- the path exactly as sent, so `/v1/items/%61` and `/v1/items/a` need separate approvals;
- the query parameters and their values, in any order;
- the headers that are forwarded upstream, with names compared in lower case ([stripped headers](#limits) do not count);
- the body, byte for byte.

A request that differs in any of them is decided as if no approval existed.

Further rules:

- Only the installation that submitted the request can use the approval.
- A deny rule or a removed extra host that applies at run time still refuses the request. The approval stays unspent until its 10 minutes pass.
- If the request would run anyway when it is resent, through a free rule, a grant, or an extension, it runs that way and the approval stays unspent.
- One-time approvals work through MCP only. An HTTP client adds headers of its own, such as `user-agent` and `accept`, so a request sent through the REST proxy does not match the approved one.

## Requests to another origin

A request goes to the connection's own origin. Some APIs point to a second hostname, such as a download host. The Owner can let a connection's credential go there, one approved request at a time.

Two policy fields control it:

- `hosts` (extra hosts): up to 20 entries. An entry is an exact hostname (`files.example.com`) or `*.suffix` (`*.cdn.example.com`), which covers every hostname below the suffix at any depth and not the suffix itself. Write it in lower-case ASCII, with punycode for an internationalized name, and without scheme, port, or path. The suffix after `*.` has at least two labels, so `*.com` is refused (`invalid_host`). The Owner sets `hosts` in the console, or approves a setup draft that lists them.
- `anyHost` (any host): when `true`, any public HTTPS origin is covered. Only the Owner sets it, in the console.

| Entry               | Hostname                          | Covered |
| ------------------- | --------------------------------- | ------- |
| `files.example.com` | `files.example.com`               | Yes     |
| `files.example.com` | `x.files.example.com`             | No      |
| `*.cdn.example.com` | `a.cdn.example.com`               | Yes     |
| `*.cdn.example.com` | `a.b.cdn.example.com`             | Yes     |
| `*.cdn.example.com` | `cdn.example.com`                 | No      |
| `*.cdn.example.com` | `xcdn.example.com`                | No      |
| `*.cdn.example.com` | `a.cdn.example.com.other.example` | No      |

To use it, put `origin` in `requested.invocation`, wait for approval, and resend through `http.request` with the same `origin`:

```json
{
  "requested": {
    "invocation": {
      "connection": "CONNECTION_ID",
      "origin": "https://eu.cdn.example.com",
      "method": "GET",
      "path": "/v1/exports/2026-10.csv"
    }
  },
  "reason": "Download the October export the API returned as a link on eu.cdn.example.com."
}
```

Rules for such a request:

- `origin` is `https://hostname` with an optional port and no path. It passes the same checks as a connection's origin.
- Coverage compares the hostname only and ignores the port. The approval binds the whole origin, port included: an approval for `https://files.example.com:8443` does not run on `https://files.example.com`.
- Only a one-time approval runs it. Free rules, grants, and scope extensions do not count on another origin. Deny rules still apply.
- Coverage is checked on submission and again when the request runs (`host_not_allowed`). If the Owner removes the entry or turns `anyHost` off in between, the approved request does not run.
- An approval for another origin does not run on the connection's own origin, and the reverse.
- Naming the connection's own origin in `origin` is the same as naming none.
- The credential is injected the same way as on the connection's own origin.
- The REST proxy has no way to name an origin.

An update draft can change neither field.

Do not list a suffix under which anyone can register a hostname, such as the shared domain of a hosting or object storage service. Every hostname below it would be covered.

## Drafts

An agent can propose a new connection or a change to one. The Owner reviews and approves the whole draft or denies it. A secret's values never pass through the agent: the draft names the fields, and the Owner types the values when approving.

Ask the user before submitting a `setup`. Never submit one unprompted.

### Setup

A `setup` creates one new secret and 1 to 20 connections that use it. One secret serves several connections when an API key is valid on several hostnames.

```json
{
  "requested": {
    "setup": {
      "secret": {
        "name": "Example API key",
        "description": "Read and write key of the example account",
        "fields": ["token"]
      },
      "connections": [
        {
          "name": "Example API",
          "origin": "https://api.example.com",
          "description": "Send Accept: application/json on every request.",
          "paths": ["/v1"],
          "methods": ["GET", "POST"],
          "deny": ["/v1/admin/*"],
          "approval": ["POST /v1/payments/*"],
          "free": ["/v1/status"],
          "auth": { "type": "bearer", "field": "token" },
          "tests": [
            { "method": "GET", "path": "/v1/status", "expect": "run" },
            { "method": "GET", "path": "/v1/items", "expect": "grant_required" },
            { "method": "GET", "path": "/v1/items", "grant": true, "expect": "run" },
            { "method": "DELETE", "path": "/v1/admin/users", "grant": true, "expect": "path_denied" },
            { "method": "POST", "path": "/v1/payments/1", "grant": true, "expect": "approval_required" },
            { "method": "GET", "path": "/v2/x", "grant": true, "expect": "path_not_allowed" },
            { "method": "PUT", "path": "/v1/items", "grant": true, "expect": "method_not_allowed" }
          ]
        },
        {
          "name": "Example API files",
          "origin": "https://files.example.com",
          "paths": ["/v1"],
          "methods": ["GET"],
          "hosts": ["*.cdn.example.com"],
          "auth": { "type": "header", "field": "token", "name": "X-Example-Key" },
          "tests": [{ "method": "GET", "path": "/v1/files", "grant": true, "expect": "run" }]
        }
      ]
    }
  },
  "reason": "The user asked to connect the Example API so the nightly sync can read and create items."
}
```

- `secret` has `name`, optional `description`, and `fields` (1 to 20 unique field names). It has no `values`.
- Each connection takes the fields listed in [What a connection holds](#what-a-connection-holds), plus its own `tests`. Connection names are unique within the draft. Two connections may share an origin.
- `auth` names fields from `secret.fields` and has no `secretId`. A draft cannot use a secret that already exists.
- With `secret`, every connection injects it: none has `auth` type `none`. Without `secret`, every connection has `auth` type `none`.
- A connection may list `hosts`. It may not set `anyHost`.

### Update

An `update` changes an existing connection.

```json
{
  "requested": {
    "update": {
      "connection": "CONNECTION_ID",
      "changes": { "deny": ["DELETE /v1/items/*"], "free": ["/v1/status"] },
      "tests": [
        { "method": "DELETE", "path": "/v1/items/1", "grant": true, "expect": "path_denied" },
        { "method": "GET", "path": "/v1/status", "expect": "run" }
      ]
    }
  },
  "reason": "Block item deletion and let the status check run without a grant, as the user asked."
}
```

- `changes` holds at least one of `name`, `description`, `paths`, `methods`, `deny`, `approval`, `free`.
- A list in `changes` replaces the connection's whole list. To add one rule, send the existing rules plus the new one.
- `changes` cannot hold `origin`, `auth`, `hosts`, or `anyHost`. These decide where a credential goes, and an update leaves them as they are.

### Test tables

Every draft carries tests: 1 to 100 per connection in a setup, 1 to 100 in an update. Each test is `{method, path, grant, expect}`:

- `grant` defaults to `false`: the installation holds no grant. `true` means it holds a grant without a scope extension.
- `expect` is `run` or one of `path_denied`, `approval_required`, `path_not_allowed`, `method_not_allowed`, `grant_required`.

On submission the server decides each test with the same function that decides real requests (step 3 and step 4 of [How a request is decided](#how-a-request-is-decided)). One-time approvals and other origins are not part of a test. If any result differs from `expect`, the whole submission fails with `tests_failed` and a hint like this:

```text
1 of 8 tests do not match the draft policy; fix the draft or the expectation and submit again. connections.0 "Example API" tests.1 GET /v1/items without a grant: expected run, got grant_required
```

For an update the server also records each test's result under the connection's current policy, so the Owner sees both side by side.

### Submission and approval

On submission the server checks a draft the way it checks the Owner's own connection form. An error names the connection by index and name, the list, and the line, such as `connections.1 "Example API files": deny line 2`. A connection name that exists or existed fails with `name_taken`. The secret's name is not checked until approval, because an installation must not learn the names of secrets it cannot list.

On approval:

- **Setup.** The Owner enters a value for each field once. The secret, every connection, and the request's new status are written together. If one of them cannot be written, none is. `access.status` then returns `connectionIds`, in the order of `connections`, and `secretId`.
- **Update.** The change is applied only if the connection is still as it was on submission. Otherwise approval fails with `connection_changed`.

A draft carries no grant. After approval the agent asks for a grant as usual. Requests that a free rule matches run for every installation without any grant.

## Limits

These limits apply to both ways of calling a connection:

| Limit            | Value                                                                                                                                           |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Request body     | 1 MiB, counted in bytes after UTF-8 encoding                                                                                                    |
| Upstream timeout | 20 seconds. The timeout also cuts off a response stream that is still being read.                                                               |
| Redirects        | Not followed. A 3xx response is returned as it is, without its `Location` header.                                                               |
| Retries          | None                                                                                                                                            |
| Query parameters | At most 100. A name is 1 to 256 characters without spaces or control characters. A value is at most 8192 characters without control characters. |
| Target URL       | 16 KiB before injection, 32 KiB after a query credential is injected                                                                            |
| Request headers  | At most 100, each value at most 8192 characters                                                                                                 |
| Path             | 2048 characters                                                                                                                                 |

Request headers the server removes before forwarding: `authorization`, `cookie`, `host`, `connection` and every header it names, `keep-alive`, `content-length`, `transfer-encoding`, `upgrade`, `te`, `trailer`, `expect`, `forwarded`, `origin`, `referer`, `x-real-ip`, `x-request-id`, `x-original-url`, `x-original-uri`, `x-original-host`, `x-rewrite-url`, `x-http-method`, `x-http-method-override`, `x-method-override`, and every header that starts with `proxy-`, `sec-`, `cf-`, or `x-forwarded-`.

Response headers the server passes back: `content-type`, `content-length`, `retry-after`, `etag`, `last-modified`. It adds `cache-control: no-store`. Upstream cookies are not returned.

The two ways of calling differ as follows:

|                      | MCP `http.request`                                                | REST proxy `/v1/proxy/{connection}/{path}` |
| -------------------- | ----------------------------------------------------------------- | ------------------------------------------ |
| Request body         | UTF-8 string                                                      | Raw bytes                                  |
| Default content type | `text/plain;charset=UTF-8`. Set `content-type` yourself for JSON. | Whatever the client sends                  |
| Query                | An object of string values, one value per name                    | As sent. Repeated names keep their order.  |
| Response body        | Decoded as text, at most 1 MiB (`response_too_large` beyond that) | Streamed as received, no size limit        |
| One-time approval    | Supported                                                         | Not supported                              |
| `origin`             | Supported                                                         | Not supported                              |
| Errors               | Tool result with `isError: true`                                  | HTTP status and JSON body                  |

The REST proxy is for programs that hold an installation token of their own. The `clavifer` command has no subcommand for it.

## Upstreams that cannot be connected

- **Upstreams that block Cloudflare Workers.** Requests leave from Cloudflare's network. Some upstreams refuse them by egress IP address or by the `Cf-Ray` request header. Such an upstream answers with its own error, which Clavifer returns as the response status. No connection setting changes this, and Clavifer has no outbound proxy setting. Reaching such an upstream takes a relay you run on another network, with the connection's origin pointing at the relay. The relay then sees the credential, so it needs the same trust as the upstream.
- **Upstreams without a public HTTPS hostname.** IP addresses, single-label names, and private suffixes are refused as origins.
- **Upstreams that need more than a static credential.** The five injection types send a stored value as it is. Per-request signatures, token exchange, and client certificates are not supported.
- **Upstreams that echo the credential.** Clavifer does not inspect responses. See [security-model.md](security-model.md#known-limits-and-non-goals).
- **Long-running or upgraded connections.** A request ends after 20 seconds, and the `upgrade` header is removed, so WebSocket and long streams do not work.
