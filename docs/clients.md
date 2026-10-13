# Connecting an agent host

This document connects an agent host, such as Claude Code or Codex, to a running Clavifer service. The agent host starts the local command `clavifer` as an MCP server; `clavifer` holds the login for one installation and forwards MCP messages to the service.

Like [deploy.md](deploy.md), it is written to be executed by a coding agent on behalf of a person, and it follows the same conventions. The service must already run: either the local instance of [Part A](deploy.md#part-a-local-trial) or a deployment from [Part B](deploy.md#part-b-production-deployment).

## Platform status

The command line client is built for Windows first and has been verified on Windows 11 with Claude Code and Codex. It compiles for macOS and Linux, but has not been run on a real machine of either, and there are no install scripts for them. The macOS and Linux commands in this document are unverified.

The login is kept in the credential store of the operating system: Credential Manager on Windows, Keychain on macOS, and an unlocked Secret Service on the D-Bus session on Linux. There is no fallback to a plain file, so a Linux machine without such a service is not supported.

## Conventions

- Every step has a `Who` line that names who performs it: `Agent`, the coding agent executing this document, or `Human`, the Owner of the service. In a Human step the agent sends the quoted message, waits for the reply, and runs the check under `Verify`.
- Any result that differs from `Verify` and is not covered under `If it fails` means: stop and ask the human.
- Run every command from the repository root.
- Commands that start the client are written as `"<CLAVIFER>" …`. In PowerShell, put the call operator in front: `& "<CLAVIFER>" …`. In POSIX shells, including Git Bash on Windows, use the line as written.
- The web console, the Owner's management site, is in Chinese only. Labels are quoted as they appear in the console, followed by their meaning in parentheses.
- The agent never asks for the Owner's password, a bootstrap token or an access token, and never reads them. The values this document passes through the conversation, `<CLIENT_ID>` and the short code of a login, are not secrets: neither gives access until the Owner approves the login in the browser. The short code is the code that `clavifer login` prints and the human types into the console, where it is labelled 设备短码.

## Stop and ask the human

1. The agent host already has an MCP server named `clavifer` with a different command (Step 6).
2. A profile with the chosen name already exists (Step 4).
3. The Skill installer reports local changes (Step 7).
4. A command's result differs from what `Verify` describes, and no `If it fails` entry covers it.

## Placeholders

| Placeholder   | What it is                                                                  | Where it comes from                                                                                     | Used in          |
| ------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------- |
| `<SERVER>`    | The origin of the service: `https://<HOSTNAME>`, or `http://localhost:8787` | The deployment, or the local instance                                                                   | Steps 3, 4       |
| `<PROFILE>`   | The local name of this login                                                | `claude` for Claude Code, `codex` for Codex; another name for a further environment, as described below | Steps 4, 5, 6    |
| `<CLAVIFER>`  | The absolute path of the installed `clavifer` executable                    | The output of Step 2                                                                                    | Steps 2, 4, 5, 6 |
| `<CLIENT_ID>` | The public identifier of one installation                                   | The human, Step 3                                                                                       | Step 4           |

An installation is the record the Owner creates in the console for one agent client. Grants and revocation apply per installation, so each agent host gets its own. To connect a second agent host, repeat Steps 3 to 8 with its own `<PROFILE>` and `<CLIENT_ID>`.

A profile name has 1 to 64 letters, digits, `_` or `-`, and starts with a letter or digit.

### Connecting a second environment

The steps register the MCP server under the name `clavifer` and log in under the profile `claude` or `codex`. An agent host holds one server per name, and a profile holds one login. Keep these default names for the production deployment.

Every further environment needs names of its own. This covers a staging environment next to production, and also the local instance of Part A: connect it under its own names, so that the default names stay free for a deployment. To connect the same agent host on the same machine to a further environment, perform Steps 3, 4, 5, 6 and 8 again with that environment's `<SERVER>` and with two changes:

- Use a different `<PROFILE>`, such as `staging-claude` or `local-claude`.
- Use a different MCP server name, such as `clavifer-staging` or `clavifer-local`, wherever Step 6 and Step 8 have `clavifer` as the server name.

Steps 1, 2 and 7 are not performed again: every environment uses the same executable and the same Skill. The agent host shows each tool under the name of its server, so the tool names of a further environment differ from those in Step 8.

## Step 1: Build the client

Who: Agent

Building needs Go. `go.mod` names the toolchain `go1.26.9`. Inside this repository, `go version` always reports that toolchain, not the version installed on the machine: when the installed Go is older, Go downloads the named toolchain on first use, which needs network access, and prints a line such as `go: downloading go1.26.9`. Nobody has to upgrade Go by hand.

Run `go version` from the repository root and decide by the result:

- The command succeeds: continue. The first build may download the toolchain.
- The command fails: Go is not installed, is too old to switch toolchains, or cannot download the toolchain. Stop and show the human the message as printed.

Run:

Windows:

```
npm run build:cli
```

macOS or Linux (unverified):

```sh
go build -trimpath -o dist/clavifer ./cmd/clavifer
```

Verify: The command exits with status 0, and `dist/clavifer.exe` exists on Windows, `dist/clavifer` on macOS or Linux.

Rerun: Safe. It replaces the file in `dist/` and does not touch an installed copy.

## Step 2: Install the client to a stable path

Who: Agent

Agent hosts must start a copy outside the build directory. Otherwise the next build would replace the executable that a running agent host uses.

Run:

Windows. The script needs PowerShell 7 (`pwsh`); the line works from PowerShell and from Git Bash:

```
pwsh -NoProfile -File ./integrations/adapters/install-cli.ps1
```

The script copies the executable to `%LOCALAPPDATA%\clavifer\bin\clavifer.exe` and prints `Point each host's MCP command at this absolute path: ` followed by the path. That path is `<CLAVIFER>`. The script changes no agent host configuration.

macOS or Linux (unverified; there is no install script):

```sh
mkdir -p "$HOME/.local/bin"
cp dist/clavifer "$HOME/.local/bin/clavifer"
printf '%s\n' "$HOME/.local/bin/clavifer"
```

The last line prints `<CLAVIFER>`.

Verify:

```
"<CLAVIFER>" version
```

It prints `clavifer 0.5.0`. The number is the version of the client that was built; this release is 0.5.0.

Rerun: Safe.

If it fails:

- `Cannot replace … Close the hosts still running it, then retry.`: an agent host is running the installed copy. Ask the human to close the agent hosts that use Clavifer, then run the script again.
- `clavifer.exe not found.`: Step 1 has not been done.

## Step 3: Create an installation

Who: Human

Say to the human:

> Please create an installation for this agent host.
>
> 1. Open `<SERVER>` in your browser and sign in.
> 2. Open 安装实例 (installations) and press 创建实例 (create an installation).
> 3. In 实例名称 (installation name), enter a name that tells the machine and the agent host apart from others, such as "Laptop · Claude Code". Leave 回调地址 (callback addresses) empty.
> 4. Press 创建实例 (create an installation). A panel titled with the name and 已创建 (created) shows a command of the form `clavifer login --server … --client-id …`.
>
> Send me the value after `--client-id`. It is an identifier, not a secret.

Verify: The human has given `<CLIENT_ID>`. Step 4 proves that it is valid.

Rerun: Each run creates another installation. An unused one can be revoked on the same page with 撤销 (revoke).

## Step 4: Log in

Who: Agent starts the login; Human approves it in the browser

First list the profiles that exist:

```
"<CLAVIFER>" profiles list
```

It prints a JSON object with a `profiles` array. If an entry has `"name": "<PROFILE>"`, stop and ask the human whether to replace that login.

Run: The command blocks until the human approves or the short code expires. A short code is valid for 30 minutes; tell the human so. Start it so that you can read its output while it is still running, for example as a background process.

```
"<CLAVIFER>" --profile <PROFILE> login --server <SERVER> --client-id <CLIENT_ID>
```

`--profile` must come before `login`. The command printed in the console in Step 3 has no `--profile`; use the form above.

The command prints one line on standard error:

```
Open <SERVER>/device and enter code <CODE>. Approve only this installation.
```

`<CODE>` is the short code. Say to the human, with the address and the short code from that line:

> Please approve this login.
>
> 1. Open `<SERVER>/device` in your browser. Sign in if the page asks; it can also ask you to verify your identity again, because approving needs a sign-in from the last 10 minutes.
> 2. The page shows the heading 批准设备登录 (approve a device login). Enter the short code `<CODE>` under 设备短码 (short code) and press 查看请求 (review the request).
> 3. Check that 安装实例 (installation) shows the name you created in Step 3 and that 设备短码 (short code) shows the same code. Then press 批准此设备 (approve this device).

Verify: The login command prints `Logged in. Resource grants are managed separately in the web page.` and exits with status 0.

The login token is now in the credential store of the operating system. The profile file holds only the server address and the client ID. It is `%APPDATA%\clavifer\profiles\<PROFILE>.json` on Windows, and `clavifer/profiles/<PROFILE>.json` under the user configuration directory on macOS and Linux.

Rerun: Safe. A new login replaces the stored login of the profile.

If it fails:

- `device code expired; start login again`: the short code ran out before the human approved. Run the command again; it prints a new short code.
- `server must be an HTTPS origin (HTTP only on localhost)`: `<SERVER>` must be an origin only, with no path, such as `https://vault.example.org`.
- `server returned … (invalid_target)`: the address is not the one the service is configured for. Compare `<SERVER>` with the address in the human's browser.
- `service unavailable; check the server address and network connection`: the service does not answer. Check `curl -sS <SERVER>/healthz`; when `<SERVER>` is the local instance, add `--noproxy localhost`, because curl otherwise sends the request to a configured proxy.
- `system credential store unavailable`: the credential store of the operating system is locked or missing. Ask the human to unlock it, then run the command again.

## Step 5: Check the login

Who: Agent

Run:

```
"<CLAVIFER>" --profile <PROFILE> doctor
```

The command takes the login token of this profile from the credential store of the operating system and uses it to call the service. It does not read the value of any credential stored in the service, and it calls no MCP tool.

Verify: The command exits with status 0 and prints a JSON report with `"ok": true`. Its `checks` array has five entries, `profile`, `login`, `server`, `metadata` and `mcp`, each with `"status": "pass"`. Its `tools` array lists `access.request`, `access.status`, `credentials.list` and `http.request`. The numbers under `metadata` count the connections this installation can see and the secrets granted to it. Any numbers are valid, zero included.

Rerun: Safe.

If it fails: The command exits with status 1 and the failing check carries a `detail` that names the next action. Follow it.

## Step 6: Register the MCP server in the agent host

Who: Agent

This step changes the user-level configuration of the agent host.

First list the MCP servers that are registered: `claude mcp list` for Claude Code, `codex mcp list --json` for Codex. If there is an entry named `clavifer` whose command is `"<CLAVIFER>" --profile <PROFILE> mcp`, this step is done. If there is one with a different command, stop and ask the human; after the human agrees to replace it, remove it with `claude mcp remove --scope user clavifer` or `codex mcp remove clavifer` and continue.

Run:

Claude Code:

```
claude mcp add --transport stdio --scope user clavifer '--' "<CLAVIFER>" --profile <PROFILE> mcp
```

Codex:

```
codex mcp add clavifer '--' "<CLAVIFER>" --profile <PROFILE> mcp
```

Keep the single quotes around `--`. In PowerShell, `claude` and `codex` installed through npm start through a script wrapper, and PowerShell removes an unquoted `--` on the way. The `--profile` after it would then be read as an option of the agent host itself. The quoted form passes through unchanged in PowerShell and in POSIX shells.

Verify: The registered command must contain `--profile <PROFILE> mcp`.

- Claude Code: `claude mcp list` prints a line for `clavifer` that contains `<CLAVIFER>`, `--profile <PROFILE> mcp` and `Connected`.
- Codex: `codex mcp list --json` prints a JSON array. It has an entry with `"name": "clavifer"` whose `transport.command` is `<CLAVIFER>` and whose `transport.args` is `["--profile", "<PROFILE>", "mcp"]`.

Rerun: Run the list command first, as described above.

If it fails:

- The entry exists, but its command lacks `--profile <PROFILE>`: the `--` was dropped. Remove the entry with `claude mcp remove --scope user clavifer` or `codex mcp remove clavifer`, and run the add command again exactly as written.

## Step 7: Install the Skill

Who: Agent

The Skill is a set of instructions that tells the agent how to use Clavifer: when to request access, how to wait for the Owner, what never to print. It grants no access.

Run:

Windows, Claude Code:

```
pwsh -NoProfile -File ./integrations/adapters/install-skill.ps1 -Target '.claude\skills\clavifer'
```

Windows, Codex:

```
pwsh -NoProfile -File ./integrations/adapters/install-skill.ps1 -Target '.agents\skills\clavifer'
```

The script copies `integrations/skills/clavifer/` to the target under the user's home directory.

macOS or Linux, Claude Code (unverified; there is no install script):

```sh
mkdir -p "$HOME/.claude/skills"
cp -R integrations/skills/clavifer "$HOME/.claude/skills/"
```

macOS or Linux, Codex (unverified):

```sh
mkdir -p "$HOME/.agents/skills"
cp -R integrations/skills/clavifer "$HOME/.agents/skills/"
```

Verify: On Windows the script prints `Installed clavifer Skill at ` followed by the directory. On every platform, `SKILL.md` exists in that directory.

Rerun: Safe on Windows: the script replaces files it installed earlier and refuses to overwrite a file that was changed afterwards.

If it fails:

- `Local changes preserved: … Review them before using -Force.`: someone edited the installed Skill. Stop and ask the human. Do not add `-Force` on your own.

## Step 8: Restart the agent host and confirm the tools

Who: Human restarts; the Agent in the new session confirms

An agent host loads MCP servers and Skills when a session starts, so the session that ran Steps 1 to 7 does not see the new tools.

Say to the human:

> Please close the agent host and open it again. In the new session, give this instruction: "Continue docs/clients.md at Step 8: list the tools of the clavifer MCP server, then call credentials.list."

Verify: In the new session, the MCP server `clavifer` offers four tools: `credentials.list`, `access.request`, `access.status` and `http.request`. Each agent host shows them under names of its own; go by the names the agent host actually shows, also when you set a tool allowlist. Claude Code puts underscores in place of dots: `mcp__clavifer__credentials_list`, `mcp__clavifer__access_request`, `mcp__clavifer__access_status` and `mcp__clavifer__http_request`. The form Codex uses has not been verified.

Then call `credentials.list`. It returns a result, not an error. On a new deployment the result lists no connections and no secrets.

If it fails:

- The tools are missing: run Step 5 again, and compare the command in the agent host's MCP configuration with `<CLAVIFER>`.

## Giving the installation access

Step 8 completes the connection. What the installation may do is a separate matter.

A new installation has no grants. It can list every connection. Without a grant, it can send only the requests that a connection's free rules cover; every other request, and reading any secret, needs the Owner.

The Owner creates secrets and connections and grants access on the 凭据 (secrets), API 连接 (connections) and 授权 (grants) pages of the console. The agent can also ask: it submits an access request through the MCP tool `access.request`, and the Owner approves it in the console. [connections.md](connections.md) describes connections, rules, grants and requests.

## Command reference

`--profile <PROFILE>` goes before the command. Without it, the profile `default` is used.

| Command                                              | Effect                                                                        |
| ---------------------------------------------------- | ----------------------------------------------------------------------------- |
| `login --server <SERVER> --client-id <CLIENT_ID>`    | Signs in to one installation                                                  |
| `doctor`                                             | Checks profile, login, service and MCP; prints a JSON report without secrets  |
| `doctor --offline`                                   | Checks the profile and the stored login without any network request           |
| `profiles list`                                      | Lists local profiles without opening the credential store                     |
| `list`                                               | Prints the connections and the secrets this installation may see              |
| `request --connection <ID> --reason <TEXT>`          | Asks the Owner for a grant on a connection                                    |
| `request --secret <ID> --fields a,b --reason <TEXT>` | Asks the Owner for a grant to read fields of a secret                         |
| `status <REQUEST_ID>`                                | Prints the state of an access request                                         |
| `status <REQUEST_ID> --wait`                         | Blocks until the Owner decides, then prints the final state                   |
| `run --bind ENV=<SECRET_ID>.<FIELD> -- <command>`    | Starts a program with granted secret fields in its environment                |
| `mcp`                                                | Serves the MCP bridge on standard input and output; started by the agent host |
| `logout`                                             | Revokes the installation and clears its local login                           |
| `logout --local`                                     | Clears the local login only                                                   |
| `version`                                            | Prints the version                                                            |

`status --wait` asks every 5 seconds. It exits with status 0 once the request is no longer pending, with 124 when `--timeout` (default 25 minutes) runs out first, and with 130 on an interrupt. When a request is submitted through the MCP bridge, the result of `access.request` carries `waitCommand`, this same command in full. Run it in the background where the agent host wakes the session when a background command exits, as Claude Code does. Otherwise run it in the foreground with a command timeout no shorter than `--timeout`.

`request --secret` without `--fields` asks for every field. `--bind` can be repeated, and `run` asks the service only for the fields it binds.

`run` hands the secret values to the program it starts. That program can read and print them, which is the one way a credential leaves the service in plain form. It needs a grant to read the secret, which is separate from a grant on a connection. With `http.request` through MCP, the service itself never puts the credential into the result; an upstream that echoes the credential in its response still delivers it to the caller.

One-time approval of a single request works only through MCP, not through this command. See [connections.md](connections.md).

Profiles let installations be granted and revoked separately. They do not isolate programs that run as the same operating system user: any of them can use any profile.

## Updating the client

Who: Agent builds and verifies; Human installs

While an agent host is open, its MCP process keeps the installed executable in use, and the install script cannot replace it. The agent that reads this runs inside such an agent host, so it cannot perform the installation. The human does, with the agent hosts closed. Logins, profiles and the MCP registration stay valid.

First, the agent performs Step 1 and then Step 7. The build writes only to `dist/` and does not touch the installed copy. The Skill files are not held open by a running agent host, and an agent host reads the Skill when it starts, so installing the Skill now lets one restart bring in both the new client and the new Skill.

Then say to the human:

> The new client is built and the Skill is updated. Installing the client needs every agent host that uses Clavifer closed, this one included, so please do it yourself.
>
> 1. Close all agent hosts that use Clavifer.
> 2. In an ordinary PowerShell 7 terminal, in this repository, run `pwsh -NoProfile -File ./integrations/adapters/install-cli.ps1`. It prints a line that starts with `Installed`.
> 3. Open the agent host again and say in the new session: "Continue docs/clients.md at Updating the client: verify the new client."

On macOS or Linux, the command in point 2 is the `cp` line of Step 2 (unverified).

In the new session, the agent verifies. `<CLAVIFER>` is the same path as before; it is the command of the `clavifer` entry that `claude mcp list` or `codex mcp list --json` prints.

Verify: `"<CLAVIFER>" version` prints the version this update goes to, which is the topmost entry of [CHANGELOG.md](../CHANGELOG.md), and `"<CLAVIFER>" --profile <PROFILE> doctor` reports `"ok": true`.

If it fails:

- The script prints `Cannot replace … Close the hosts still running it, then retry.`: an agent host is still open. The human closes it and runs the script again.

## Disconnecting

```
"<CLAVIFER>" --profile <PROFILE> logout
```

This revokes the installation on the service, deletes its login from the credential store, and renames the profile file to an archive beside it. Other installations are not affected. To connect again, create a new installation.

If the service cannot be reached or the login is no longer valid, the command fails. In that case the Owner revokes the installation on the 安装实例 (installations) page, and `"<CLAVIFER>" --profile <PROFILE> logout --local` clears the local login. `--local` alone revokes nothing on the service.

Removing the MCP server from the agent host is `claude mcp remove --scope user clavifer` or `codex mcp remove clavifer`.

## Remote MCP clients

The console can also create an installation for an MCP client that connects to the service directly and signs in with OAuth, without the local command: enter the client's callback addresses under 回调地址 (callback addresses) in Step 3. [authentication.md](authentication.md) describes that flow. The local bridge described here is the recommended way, because the access token then never appears in an agent host's configuration.

## Troubleshooting

- `profile not found; run clavifer --profile NAME login`: the profile named in the command has no login on this machine. Check the name, or perform Step 4.
- `not logged in; run login`: the profile exists, but the credential store holds no login for it. Perform Step 4.
- `stored login is unreadable; run login again`: the stored login is damaged. Perform Step 4; it replaces the entry.
- `refreshed login could not be saved to the system credential store; run login again`: the service has already issued a new token, and the stored one is no longer valid. Perform Step 4.
- `system credential store unavailable`: the credential store cannot be opened. Unlock it and repeat the command; logging in again does not help.
- `doctor` reports `Login expired or installation revoked`: the Owner checks the installation on the 安装实例 (installations) page. A revoked installation cannot be restored; perform Steps 3 and 4.
- After the hostname of the service has changed, every profile must log in again with the new address (Step 4). The client ID stays the same.
- An error from `http.request` or `access.request`, such as `grant_required` or `path_denied`: it carries a `hint` that names the next action. [connections.md](connections.md) lists these codes.
