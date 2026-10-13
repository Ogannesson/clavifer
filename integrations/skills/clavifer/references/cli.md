# CLI

```text
clavifer --profile codex login --server https://vault.example.com --client-id OWNER_CREATED_INSTALLATION_ID
clavifer profiles list
clavifer --profile codex doctor
clavifer --profile codex list
clavifer --profile codex run --bind MY_API_TOKEN=SECRET_ID.token -- python task.py
clavifer --profile codex request --connection CONNECTION_ID --reason "Task requires this API"
clavifer --profile codex request --secret SECRET_ID --fields token,api-key --reason "Task requires these fields"
clavifer --profile codex status REQUEST_ID
clavifer --profile codex status REQUEST_ID --wait
```

`status --wait` checks every 5 seconds (longer when the server asks it to slow down) until the request is no longer `pending`, then prints the final status JSON and exits 0. After `--timeout` (default `25m`) it exits 124: the Owner has not decided yet, so run it again or ask the user. An interrupt exits 130. Run it in the background where the host wakes the session when a background command exits (Claude Code), otherwise in the foreground (Codex); in the foreground set the host's command timeout no shorter than `--timeout`, or pass a shorter `--timeout` and run it again after 124.

The client stores refresh credentials in the operating system credential store. The binding reference is metadata and never includes a value. Pass the executable and arguments directly; do not compose a shell string.

These examples use the standard Codex profile; use `--profile claude` for the standard Claude Code installation. The global `--profile` option must precede the command. Find the executable's absolute path in the current host's MCP configuration if `clavifer` is not on PATH.

Use `clavifer help` to discover commands. `profiles list` inspects local profile metadata without opening the system credential store; it does not confirm login or grants. `doctor` reports the CLI/service versions, selected profile, login accessibility, authorized resource counts, and MCP protocol/tool compatibility as redacted JSON. It never reads a stored business secret, calls an upstream connection, creates an access request, or invokes an MCP tool. It may rotate an expired login token through the normal refresh flow. Resource names, IDs, login tokens and raw server errors are omitted. Exit code 1 means at least one check failed; zero authorized resources is a valid configured state.

Use `doctor --offline` to inspect the local profile and system-store login without network requests or token refresh. An available refresh token is not proof that the server still accepts the login. The diagnostic does not prove that the host has reloaded its MCP configuration; after installation or configuration changes, restart or reconnect the host and verify tool discovery there. Never silently switch to another profile when diagnosis fails.

Access tokens refresh automatically with a per-installation operating-system lock. `--bind` is repeatable. Child exit codes are preserved, and an interrupted child is given ten seconds to shut down itself before it is killed. A run ended by an interrupt exits 130 even when the child cleaned up and exited zero. `clavifer --profile NAME logout` revokes that installation, removes its login tokens from the system credential store, and renames its non-secret profile metadata to a unique `.json.logged-out-*` archive in the same directory. Existing archives are never overwritten and are omitted from `profiles list`. `logout --local` only clears the local login after the Owner separately revokes remote access; it is not remote revocation. Profiles support independent grants and revocation but are not a security boundary against other programs running as the same OS user.

All bindings are checked before reading any secret. When several bindings reference fields of one secret, `run` fetches that secret once so the child receives a consistent version, and it asks the service only for the fields those bindings name. A field outside the grant fails with an insufficient permission error.

`request --secret` accepts an optional `--fields a,b` to ask for a subset of a secret. Omit it to request every field. Request the narrowest set the task needs, and list every field the task uses in one request: approval never changes an existing active grant, and a request whose fields differ from an existing grant is rejected at approval with `existing_grant_conflict` until the Owner adjusts that grant in the management page. The Owner may resolve it by changing the grant and then rejecting the now-redundant request, so a rejected request does not prove the access is missing; confirm with `list` before giving up. Credentials are not written into the profile or copied into diagnostic output.

Windows uses Credential Manager, macOS uses Keychain, and Linux uses an unlocked Secret Service over the user's D-Bus session. Headless Linux servers without such a service are not supported by a plaintext-file fallback. Cross-compilation alone does not establish that a platform's credential store works; verify `doctor` and an authorized login on that platform before relying on it.

Only authorized metadata is visible. Ask the Owner for a resource ID or explicit grant if it is missing; never enumerate guessed IDs. Login and resource grants are separate. Never request or print the Owner password, bootstrap token, bearer token, or raw stored API key.
