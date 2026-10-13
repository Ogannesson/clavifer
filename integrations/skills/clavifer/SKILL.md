---
name: clavifer
description: Use the configured Clavifer service when a task needs an API key or other credential for a CLI, SDK, HTTP connection, or MCP tool. Do not activate for ordinary networking that needs no stored credential.
---

# Clavifer

Use the configured credential service without placing secret values in prompts, files, command arguments, logs, or tool output.

- Discover the actual available `clavifer` commands or connected MCP tools before acting; names and namespaces may vary by host.
- `clavifer` below stands for the installed executable. The setup does not put it on `PATH`: when the bare name is not found, use the absolute path that this host's MCP configuration gives as the command of the `clavifer` server.
- Diagnose a configured CLI with `clavifer --profile NAME doctor`; it inspects login and metadata without reading business secret values. `profiles list` lists local metadata only and never grants access.
- Use the installation profile configured for this host. The standard setup uses `clavifer --profile codex` in Codex and `clavifer --profile claude` in Claude Code. MCP already selects its configured profile. Never silently switch profiles to obtain more permissions.
- For local programs, use CLI `run` with an explicit `ENV=secret-id.field` binding. Keep the existing SDK or command unchanged.
- For remote or invoke-only access, use the configured HTTP connection or MCP `http.request`. Never escalate invoke-only access to raw secret reading.
- Use metadata listing to find references. Request access only when the current grant is insufficient; an existing grant does not need repeated approval.
- For MCP `http.request`, try the request first and follow the error's `hint`. Only `path_denied` (a deny rule, quoted in the hint) is an absolute refusal: stop, tell the user which rule, and do not request access. Everything else has a way through the Owner: `path_not_allowed` / `method_not_allowed` mean outside the connection's regular scope, so request a one-time `invocation` for one operation or a connection grant with `paths` / `methods` (a temporary scope extension) for multi-step work; `grant_required` takes a grant or an `invocation`; `approval_required` takes an `invocation`. A request goes to the connection's own origin; when its `policy_json` lists `hosts` (or `anyHost`), one request may name another `origin` there, which always takes an approved `invocation` carrying the same `origin`, and `host_not_allowed` means the connection does not list that host: tell the user which host is needed. See the decision table in [references/mcp.md](references/mcp.md).
- Write `reason` for the Owner: the target the way a person knows it (name, account, creation date), the expected effect, and for an opaque id how you identified it, so the Owner can check it in the upstream console.
- After submitting a request, wait for the Owner with the `waitCommand` the MCP result carries (or `clavifer --profile NAME status REQUEST_ID --wait`): Claude Code runs it as a background command and ends the turn, since its exit wakes the session; Codex runs it in the foreground, with the host's command timeout no shorter than `--timeout` (default 25 minutes), or with a shorter `--timeout` and a rerun after 124. It exits with the decision: continue on `approved`, stop and tell the user on `denied` / `expired`; exit code 124 means still pending, so run it again or ask the user.
- After an invocation approval, resend the identical request once through MCP `http.request`; the approval is used even if the outcome is unknown, so check upstream state before requesting again.
- Treat pending approvals, revoked access, upstream errors, and unknown write results as separate states. Never blindly retry a side-effecting request.
- Secret values belong only in the authorized process environment or the service's upstream request. Never print them for diagnosis.

Read [references/cli.md](references/cli.md) for local execution and [references/mcp.md](references/mcp.md) for MCP/remote invocation.
