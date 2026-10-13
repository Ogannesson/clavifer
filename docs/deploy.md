# Deploying Clavifer

This document is written to be executed by a coding agent on behalf of a person. The person says "deploy this by following docs/deploy.md"; the agent runs the commands and stops wherever a step belongs to the human. A person deploying by hand follows the same steps and performs the Agent steps too.

The document has two parts, and where to start depends on what was asked:

- Asked to deploy to Cloudflare: read the sections before Part A, then start at [Part B](#part-b-production-deployment). Do not perform Part A.
- Asked to try Clavifer locally, or the human wants to look at it before deciding: read the sections before Part A, then perform [Part A](#part-a-local-trial). It is optional and needs no Cloudflare account.
- Asked to try it first and deploy if the trial goes well: read the sections before Part A and perform Part A. When it is finished, ask the human whether to continue with the deployment. If the human agrees, start at Part B.
- If it is not clear which of these was asked, ask the human.

Cloudflare Workers with D1 and R2 is the only supported platform.

The agent must run on the human's own machine: the human opens files in the checkout and, in Part A, browses to `localhost`.

## Conventions

- Every step has a `Who` line that names who performs it. `Agent` is the coding agent executing this document. `Human` is the person who owns the Cloudflare account and becomes the Owner, the single administrator of the service.
- In a Human step, the agent sends the quoted message, waits for the reply, and then runs the check under `Verify`. The agent does not perform a Human step itself.
- `Verify` states what to run and what counts as success. `Rerun` states whether the step can be repeated. `If it fails` lists the failures the maintainer has met or looked up. Any failure that is not listed falls under [Stop and ask the human](#stop-and-ask-the-human).
- Run every command from the repository root.
- A command shown once is the same in PowerShell 7 and in POSIX shells. Where the two differ, both are given.
- `curl` means the curl program. In Windows PowerShell 5.1 (`$PSVersionTable.PSVersion.Major` prints `5`), type `curl.exe` instead.
- Every `curl` request to the local instance carries `--noproxy localhost`. When `HTTP_PROXY` is set, curl sends requests for `localhost` to the proxy too, and the proxy can answer with success while the service is not running.
- An existence check is used throughout. To learn whether a file exists without reading it, run `Test-Path <path>` in PowerShell, or `test -e <path> && echo True || echo False` in a POSIX shell. Both print `True` or `False`.
- wrangler does not wait for input when it has no terminal. It answers its own questions and prints `🤖 Using fallback value in non-interactive context`. These lines are expected.
- A wrangler command with `--json` prints pure JSON on standard output. Its other lines go to standard error: a warning about proxy environment variables when such variables are set, and the `npm notice` lines that `npx` adds. Read the JSON from standard output only and do not merge the two streams; merged, the warning line `[WARNING]` comes before the JSON and itself starts with `[`. Commands without `--json` start with a banner that can mention a newer wrangler. All of this is expected.
- Where a step tells a failure by the exit status, it means any non-zero status. On Windows, wrangler can exit with 127 instead of 1 after it has printed an API error.
- The web console, the Owner's management site, is in Chinese only. This document quotes each label as it appears in the console, followed by its meaning in parentheses.

## Secrets never pass through the agent

Clavifer exists so that agents work without seeing credentials. The deployment follows the same rule.

The agent must not open, print, copy, summarize or quote any of these, and must not write a value taken from them into a command:

- `.dev.vars`
- every file under `work/`
- any `*.agekey` file
- everything under `.wrangler/`, which holds the local database with sessions and password hashes
- the value of the environment variable `CLOUDFLARE_API_TOKEN`

The agent may run an existence check on these files, and may pass their paths to the commands in this document. The scripts used here write secret values to files and print only the file paths.

What is forbidden is the value: writing it into a command, printing it, or reading it. Referring to the token by the name of its variable is allowed. In `$env:CLOUDFLARE_API_TOKEN` (PowerShell) or `$CLOUDFLARE_API_TOKEN` (POSIX), the shell fills in the value when the command runs, and the value does not enter the conversation. Step 2.14 uses the token this way.

Do not run a command that prints the whole environment (`env`, `printenv`, `Get-ChildItem Env:`), because the output would include the API token. To learn whether a variable is set, run `[bool]$env:CLOUDFLARE_API_TOKEN` in PowerShell, or `test -n "$CLOUDFLARE_API_TOKEN" && echo True || echo False` in a POSIX shell.

When `npm run dev` starts, wrangler tells an agent about a local data interface under the path `/cdn-cgi/local/explorer`. It reads the local database. Do not call it.

The human never pastes a secret into the conversation. If a secret value appears in command output anyway, stop and tell the human which one.

## Stop and ask the human

Stop, report what you found, and wait for a decision in each of these cases:

1. A step would cost money: enabling R2, changing the Workers plan, buying a domain.
2. A step would delete or overwrite data. This includes a D1 database, an R2 bucket or a Worker that already exists under a name this document uses, and an existing `.dev.vars` or file under `work/`.
3. The chosen hostname already resolves, which is what Step 2.6 checks: it has an address record or an alias, or another Worker serves it.
4. Anything about key material that a step does not spell out: generating secrets a second time, deleting, moving or backing up a secrets file or key.
5. A command's result differs from what `Verify` describes, and no `If it fails` entry covers it.

## Names and placeholders

These names are fixed by `wrangler.jsonc`. Part B uses the `production` column. The `staging` column belongs to the optional second environment described under [Staging environment](#staging-environment).

| Thing                    | `production`                      | `staging`                         |
| ------------------------ | --------------------------------- | --------------------------------- |
| wrangler environment     | `production`                      | `staging`                         |
| Worker                   | `clavifer-production`             | `clavifer-staging`                |
| D1 database              | `clavifer`                        | `clavifer-staging`                |
| R2 bucket                | `clavifer-backups`                | `clavifer-staging-backups`        |
| Hostname in the template | `credentials.example.com`         | `credentials-staging.example.com` |
| Secrets file             | `work/production.secrets.json`    | `work/staging.secrets.json`       |
| Bootstrap token file     | `work/production-bootstrap.token` | `work/staging-bootstrap.token`    |

Replace each placeholder below with its value before running a command.

| Placeholder       | What it is                                                          | Where it comes from                       | Used in                               |
| ----------------- | ------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------- |
| `<HOSTNAME>`      | The hostname that serves the service, such as `vault.example.org`   | The human, Step 1.4                       | Steps 2.5, 2.6, 2.11, 2.13, 2.14, 3.2 |
| `<ZONE_ID>`       | The ID of the Cloudflare zone that contains `<HOSTNAME>`            | The human, Step 1.4                       | Step 2.14                             |
| `<ACCOUNT_ID>`    | The ID of the Cloudflare account to deploy into                     | Step 2.1, confirmed by the human          | Step 2.2                              |
| `<DATABASE_ID>`   | The `uuid` of the D1 database `clavifer`                            | The output of `d1 list --json`, Step 2.3  | Step 2.5                              |
| `<RULESET_ID>`    | The ID of the zone's configuration ruleset                          | The output of the list request, Step 2.14 | Step 2.14                             |
| `<AGE_RECIPIENT>` | The public key that backups are encrypted to; it starts with `age1` | The human, or the output of Step 3.4      | Step 3.4                              |

`<HOSTNAME>`, `<ZONE_ID>`, `<ACCOUNT_ID>`, `<DATABASE_ID>`, `<RULESET_ID>` and `<AGE_RECIPIENT>` are identifiers, not secrets. They may appear in the conversation.

## Part A: Local trial

Part A is optional. It needs Node.js and git, and it creates no Cloudflare resource. The instance and its data stay in this checkout. npm and wrangler write caches under the user's home directory, and wrangler contacts the network to check for updates and, by default, to report usage statistics. Setting the environment variable `WRANGLER_SEND_METRICS=false` turns the statistics off.

### Step A1: Check the tools

Who: Agent

Run:

```
node --version
git --version
```

Verify: Node.js is 22.12 or later. wrangler 4.149.0 requires Node.js 22, and vite 8 requires 22.12. The maintainer uses Node.js 26.5. Any git version works.

Rerun: Safe.

### Step A2: Install dependencies

Who: Agent

Run:

```
npm ci
```

Verify: The command exits with status 0.

Recent npm versions block the install scripts of `esbuild` and `workerd` and print a warning that starts with `npm warn install-scripts`. This is expected, and every later step works without those scripts. Do not approve them.

Rerun: Safe. It replaces `node_modules`.

### Step A3: Build the console

Who: Agent

Run:

```
npm run build:web
```

Verify: The command exits with status 0, and an existence check on `apps/web/dist/index.html` prints `True`.

Rerun: Safe.

### Step A4: Generate the local secrets

Who: Agent

First run an existence check on `.dev.vars`. If it prints `True`, this checkout is already set up: skip to Step A5 and do not delete the file. The local database can only be decrypted with the keys in it.

Run:

```
node scripts/init-secrets.mjs
```

Verify: The command prints a line that starts with `Created .dev.vars.` and prints no secret value. Existence checks on `.dev.vars` and `work/local-bootstrap.token` both print `True`.

Rerun: Not possible. The script refuses with `.dev.vars already exists; refusing to overwrite`.

If it fails:

- `EEXIST` naming `work/local-bootstrap.token`: a token file from an earlier setup is left over while `.dev.vars` is gone. Stop and ask the human.

### Step A5: Create the local database

Who: Agent

Run:

```
npm run db:local
npx wrangler d1 migrations list clavifer --local
```

Verify: The second command prints `No migrations to apply!`.

Rerun: Safe. Migrations that are already applied are skipped.

If it fails:

- On Windows, `npm run db:local` prints only `internal error; reference = …`: the checkout path is too long. The path of the local database file is 136 characters longer than the path of the checkout, and Windows limits a path to 260 characters, so the full path of the checkout directory must be at most 120 characters. Stop and tell the human that the checkout has to move to a shorter path.

### Step A6: Start the service

Who: Agent

First run `curl -sS --noproxy localhost http://localhost:8787/healthz`. If it already answers as described under Verify, the service is running: skip to Step A7.

Run: Start this command as a background process and leave it running. Record the process ID of the process you started; stopping the service later needs it.

```
npm run dev
```

Verify: Within 60 seconds, both requests answer as shown.

```
curl -sS --noproxy localhost http://localhost:8787/healthz
curl -sS --noproxy localhost http://localhost:8787/setup
```

The first prints `{"ok":true,"service":"clavifer","version":"0.5.0"}`. `version` is the version of the code that is running; this release is 0.5.0. The second prints `{"initialized":false}` in a new checkout. In a checkout that already has an Owner it prints `{"initialized":true}`, and Step A7 is then skipped.

The local configuration fixes the origin to `http://localhost:8787`. The console works only at exactly this address: not at the numeric loopback address, and not on another port. The `Ready on` line in wrangler's startup log shows the numeric loopback address; do not copy the address from the log when you tell the human where to go.

The startup log also announces the local data interface named under [Secrets never pass through the agent](#secrets-never-pass-through-the-agent). Do not call it.

Rerun: Do not start a second copy while the first one runs.

### Step A7: Create the Owner

Who: Human

First run `curl -sS --noproxy localhost http://localhost:8787/setup`. If it prints `{"initialized":true}`, the Owner already exists: skip this step. The token works only once, so do not send the human to the form again.

Say to the human:

> The local instance is running. Please do the following yourself.
>
> 1. Open `work/local-bootstrap.token` in your own editor and copy its content. Do not paste it into this conversation.
> 2. Open `http://localhost:8787` in your browser. The page shows the heading 创建管理员 (create the administrator).
> 3. Fill in 初始化令牌 (bootstrap token) with the copied value, 姓名 (name), 邮箱 (email) and 新密码 (new password, at least 12 characters). The email is your sign-in name; nothing is sent to it, and there is no password recovery by email. Save the password in your password manager.
> 4. Press 创建管理员 (create the administrator). The page signs you in and shows the console.
> 5. Delete `work/local-bootstrap.token`. The token cannot be used again.
>
> Tell me when the console is showing and the file is deleted.

Verify:

```
curl -sS --noproxy localhost http://localhost:8787/setup
```

It prints `{"initialized":true}`. An existence check on `work/local-bootstrap.token` prints `False`.

Rerun: Not possible. After the Owner exists, the token is rejected with `bootstrap_already_used`.

### After the trial

If the human also wants a deployment, ask now whether to continue. If the human agrees, start at [Part B](#part-b-production-deployment).

To connect an agent host to the local instance, follow [clients.md](clients.md) with `http://localhost:8787` as `<SERVER>`. Do not use the default names for it: they would be taken when a deployment is connected later. Use a profile name such as `local-claude` and an MCP server name such as `clavifer-local`, as described under [Connecting a second environment](clients.md#connecting-a-second-environment).

To stop the service, end the process recorded in Step A6 together with its child processes. Use the process ID only, never a process name.

Windows:

```
taskkill /PID <PID> /T /F
```

POSIX (unverified):

```sh
kill <PID>
```

On POSIX, npm passes the signal on to wrangler, which stops its own child processes. Then confirm that the port no longer answers:

```
curl -sS --noproxy localhost http://localhost:8787/healthz
```

The command must fail with a connection error. If it still prints a response, stop and ask the human. If this session did not start the service and has no process ID, ask the human to stop it.

The local database stays in `.wrangler/` and is used again the next time the service starts. Discarding the local instance means deleting `.wrangler/` and `.dev.vars`; that is the human's decision.

## Part B: Production deployment

### Phase 1: Prerequisites

Authentication comes first among the steps that need the human, because one of its two options makes the human restart the agent host, and at that point there is nothing yet to carry over. Steps 1.3 to 1.5 are Human steps; the agent may send their messages together and wait for all the answers.

#### Step 1.1: Check the tools and install dependencies

Who: Agent

If the local instance of Part A is running from this checkout, stop it first: `npm ci` replaces `node_modules` while the service is using it. To find out, run `curl -sS --noproxy localhost http://localhost:8787/healthz`. If it answers, stop the service as described under [After the trial](#after-the-trial).

Then perform Steps A1 and A2 of Part A. If this session has just performed them in Part A, they need not be repeated.

Phase 4 builds the command line client on this machine. Check its tools now, so that a missing tool does not surface after the cloud resources exist. Skip this only if the human has said that no agent host will be connected from this machine.

```
go version
pwsh --version
claude --version
codex --version
```

`go version` must succeed, as described in Step 1 of [clients.md](clients.md). `pwsh --version` is needed on Windows only and must print PowerShell 7 or later. Of the last two, run the one for the agent host that will be connected: `claude` for Claude Code, `codex` for Codex. If a command that is needed fails, stop and ask the human to install the tool.

#### Step 1.2: Authentication for wrangler

Who: Agent checks; Human decides and authenticates

wrangler is Cloudflare's command line tool. It may already hold a login on this machine, and that login can belong to another account than the one the human means, such as an employer's. So look first, and never continue with an existing login without asking.

Run:

```
npx wrangler whoami --json
```

If the command exits with status 0 and prints `"loggedIn": true`, say to the human, filling in `authType`, `email` if present, and the `name` and `id` of every entry in `accounts`:

> wrangler is already logged in on this machine: `<authType>`, `<email>`. It can act on these Cloudflare accounts: `<name>` (`<id>`), … Do you want me to deploy with this login, and into which of these accounts? Or do you want to set up a different login?

When the check for `CLOUDFLARE_API_TOKEN` from [Secrets never pass through the agent](#secrets-never-pass-through-the-agent) prints `False`, the login is a browser login. Then add to the message:

> If we keep this browser login and Step 2.14 finds that your domain injects Web Analytics into the pages, you will have to create one rule by hand in the Cloudflare dashboard to turn that off. With an API token I could create it myself.

If the human keeps this login, the step is done. Note whether the human named an account; Step 2.1 uses that.

If the human wants a different one, or if the command exited with a non-zero status because wrangler is not logged in, send the message below. Its Option B has two forms, because wrangler refuses a browser login while `CLOUDFLARE_API_TOKEN` is set and prefers the token over an existing browser login. Send the first form when the check for the variable prints `False`, the second when it prints `True`.

> I need wrangler, Cloudflare's command line tool, to act on your account. Please choose one of two ways. In both, do not paste any token into this conversation.
>
> Option A is an API token. With it I can also create the rule myself that Step 2.14 may need.
>
> 1. In the Cloudflare dashboard, open My Profile > API Tokens > Create Token and start from the template "Edit Cloudflare Workers".
> 2. Add two permissions: Account · D1 · Edit, and Zone · Config Rules · Edit.
> 3. Under Zone Resources select the one domain that will serve Clavifer. Under Account Resources select the one account.
> 4. Open a terminal, set the variable below, and start your agent host from that same terminal, so that my commands inherit it. A session that is already running does not see the variable.
> 5. In the new session, say: "Continue docs/deploy.md at Step 1.2. I have set CLOUDFLARE_API_TOKEN in this terminal."
>
> PowerShell 7:
>
> ```powershell
> $env:CLOUDFLARE_API_TOKEN = Read-Host -MaskInput 'Cloudflare API token'
> ```
>
> bash or zsh:
>
> ```sh
> read -rs CLOUDFLARE_API_TOKEN && export CLOUDFLARE_API_TOKEN
> ```
>
> Option B is a browser login. If Step 2.14 finds that a rule is needed, you will have to create it by hand.
>
> First form: In your own terminal, in this repository, run `npx wrangler login` and approve the request in the browser. You do not need to restart anything.
>
> Second form: An API token is set in the terminal that started this session, and wrangler uses it in preference to a browser login. Start your agent host again from a terminal in which `CLOUDFLARE_API_TOKEN` is not set. In this repository, run `npx wrangler login` and approve the request in the browser. In the new session, say: "Continue docs/deploy.md at Step 1.2. I have logged in to wrangler with the browser."
>
> Tell me which option you used.

The permission names above are the ones Cloudflare's documentation gives for the dashboard. Whether the token page currently shows these names or Cloudflare's newer Workers role names is unverified.

Verify: This check is for a login that the human set up during this session, which is the first form of Option B. A login the human chose to keep is already confirmed, and a session that continues after a restart confirms it with the question at the top of this step. Run `npx wrangler whoami --json` again. It must exit with status 0 and print `"loggedIn": true`, but that alone does not complete the step. Show the human `authType`, `email` if present, and the `name` and `id` of every entry in `accounts`, and ask whether this is the login they meant. The step is done when the human confirms. Step 2.1 then settles the account.

Rerun: Safe. A session that continues here after a restart starts this step from the top. Its first command shows the new login, and the question that follows it is this confirmation.

#### Step 1.3: Cloudflare account and plan

Who: Human

Say to the human:

> You need a Cloudflare account. The maintainer has run and verified Clavifer only on the Workers Paid plan. The Workers Free plan limits every request to 10 ms of CPU time, which is probably not enough for password hashing and encryption; this has not been tested. Workers Paid has a monthly fee. Which plan is the account on, and do you want to continue with it?
>
> The database and the backup bucket are created in Cloudflare's default location. If the data must stay in a particular region or jurisdiction, tell me now.

Verify: The agent cannot check the plan. Continue when the human has named the plan and agreed. If the plan is Workers Free, repeat to the human that this path is unverified before continuing. If the human names a region or jurisdiction, Steps 2.3 and 2.4 use it.

#### Step 1.4: Zone and hostname

Who: Human

Say to the human:

> Clavifer is served on a hostname of your own. You need a domain that is in the same Cloudflare account, uses Cloudflare for DNS, and shows as Active in the dashboard. Choose a hostname under it that is not in use, such as `vault.` followed by your domain. Do not create a DNS record for it; the deployment creates the record and the certificate.
>
> Please tell me the hostname, and the Zone ID of the domain. The Zone ID is on the domain's Overview page in the Cloudflare dashboard.

Verify: The human has given `<HOSTNAME>` and `<ZONE_ID>`. Step 2.6 checks that the hostname is free.

#### Step 1.5: Enable R2

Who: Human

Say to the human:

> Encrypted backups are stored in Cloudflare R2. R2 must be enabled once per account, in the dashboard, by you: open Storage & databases > R2 > Overview and complete the checkout. R2 has a free allowance and bills for use beyond it. Tell me when R2 is enabled.

Verify: Step 2.4 checks this.

### Phase 2: Provision and deploy

The steps in this phase are Agent steps, with three exceptions. Step 2.1 needs the human's confirmation. Step 2.10 is a Human step. In Step 2.14, creating the rule goes to the human when no API token is set in your shell, or when the token lacks the permission.

#### Step 2.1: Confirm the account

Who: Agent, with the human's confirmation

Run:

```
npx wrangler whoami --json
```

Verify: The command exits with status 0 and prints a JSON object with `"loggedIn": true` and an `accounts` array of `id` and `name`.

If the human already named the account in Step 1.2, by name or by ID, check that `accounts` still contains it. If it does, its `id` is `<ACCOUNT_ID>`, and there is no need to ask again. If it does not, stop and ask the human.

If the human has not named an account, then, whatever the number of entries, say to the human, with the `name` and `id` of every entry in `accounts`:

> wrangler can act on these Cloudflare accounts: `<name>` (`<id>`), … Which one should Clavifer be deployed into? Please confirm even if there is only one.

Wait for the answer. The `id` of the account the human names is `<ACCOUNT_ID>`. If `accounts` has no entry, stop and ask the human.

The top-level keys of the object are `loggedIn`, `authType`, `email`, `accounts` and `tokenPermissions`. For a browser login, `authType` is `"OAuth Token"`.

Rerun: Safe.

If it fails:

- Non-zero exit status, or a message that `CLOUDFLARE_API_TOKEN` is necessary in a non-interactive environment: wrangler is not authenticated in your shell. Return to Step 1.2.

#### Step 2.2: Write the account into the configuration

Who: Agent

Every later command must act on the same account. wrangler takes the account from `account_id` in `wrangler.jsonc` first, then from the environment variable `CLOUDFLARE_ACCOUNT_ID`, then from its cached login. If the check in Step 2.9 and the deployment in Step 2.11 reached different accounts, the check would protect nothing, and the deployment could replace the keys of a Worker with the same name in the other account. Writing the account into the configuration before anything is created rules this out. From this step on, the configuration decides the account for every command this document uses, whatever `CLOUDFLARE_ACCOUNT_ID` is set to. A few wrangler commands ignore `account_id`; one of them is `d1 migrations list --remote`, which is why Step 2.8 does not use it.

The deployment keeps its own values in `wrangler.jsonc`, as commits on a local branch named `deploy`.

Run: Create the branch.

```
git switch -c deploy
```

If git answers that the branch `deploy` already exists, run `git switch deploy` instead.

Then add one line to the top level of `wrangler.jsonc`, directly below the line `"name": "clavifer",`:

```jsonc
  "account_id": "<ACCOUNT_ID>",
```

A value at the top level is inherited by every environment, and also applies to commands that take no `--env`, such as `d1 create` and `r2 bucket create`. The account ID is an identifier, not a secret.

Verify:

```
git diff -- wrangler.jsonc
```

The diff shows exactly one added line, above the `env` block. Then commit:

```
git commit -m "Deployment account" -- wrangler.jsonc
```

Do not push this branch yourself. It holds identifiers, not secrets, so the human may push it to a private remote of their own to keep it safe. It must not go to a public fork.

Rerun: If `git diff main -- wrangler.jsonc` already shows this line with `<ACCOUNT_ID>`, the step is done. If it shows the line with a different ID, stop and ask the human.

If it fails:

- The commit fails because git has no author identity: ask the human to set `user.name` and `user.email`, or to run the commit command themselves.
- The commit waits for or fails on a signature that needs the human, such as a hardware key: ask the human to run the commit command themselves.

The same two entries apply to the commit in Step 2.5.

#### Step 2.3: Create the D1 database

Who: Agent

Run: First list the databases that exist.

```
npx wrangler d1 list --json
```

If the JSON array already contains an entry with `"name": "clavifer"`, stop and ask the human whether that database belongs to this deployment. Otherwise create it:

```
npx wrangler d1 create clavifer
```

The command creates the database in Cloudflare's default location. If the human named a region or jurisdiction in Step 1.3, do not run it as written: `npx wrangler d1 create --help` lists the `--location` and `--jurisdiction` values, and the human chooses the one to add.

wrangler prints a configuration snippet and asks whether to add it to the configuration file; without a terminal it answers no. Do not pass `--update-config` or `--binding`: they add a second binding instead of filling in the existing one.

Verify: Run the list command again.

```
npx wrangler d1 list --json
```

The array contains an entry with `"name": "clavifer"`. Its `uuid` is `<DATABASE_ID>`.

Rerun: Run only the list command. A second `d1 create clavifer` fails with `A database with that name already exists`.

If it fails:

- A Cloudflare API error with code 7403: run the same command again. If it fails three times in a row, stop.

#### Step 2.4: Create the R2 bucket

Who: Agent

Run:

```
npx wrangler r2 bucket create clavifer-backups
```

The command creates the bucket in Cloudflare's default location. If the human named a region or jurisdiction in Step 1.3, do not run it as written: `npx wrangler r2 bucket create --help` lists the `--location` and `--jurisdiction` values, and the human chooses the one to add.

Like `d1 create`, the command asks whether to add a snippet to the configuration file and answers no without a terminal.

Verify: The command exits with status 0, and its output contains `Created bucket 'clavifer-backups'`. Then this command also exits with status 0:

```
npx wrangler r2 bucket info clavifer-backups --json
```

Rerun: Do not run `create` again. Run only the `info` command. Exit status 0 means the bucket is there; for a bucket that does not exist it fails with `The specified bucket does not exist. [code: 10006]`.

If it fails:

- `Please enable R2 through the Cloudflare Dashboard. [code: 10042]`: R2 is not enabled on the account. Return to Step 1.5. Right after R2 is enabled, the error can persist for a short time; wait one minute and run the command again.
- `The bucket you tried to create already exists, and you own it. [code: 10004]`: stop and ask the human. The bucket may hold someone's data, and the service deletes old backup objects under the prefix `vault/` in this bucket.
- The create command fails with anything else: stop and show the human the message as printed.

#### Step 2.5: Write the deployment configuration

Who: Agent

Run: Confirm that `git branch --show-current` prints `deploy`, the branch from Step 2.2. Then edit `wrangler.jsonc`. Change exactly three values, all inside the `env.production` block, and nothing else:

| Key                           | Value in the template                  | New value            |
| ----------------------------- | -------------------------------------- | -------------------- |
| `routes[0].pattern`           | `credentials.example.com`              | `<HOSTNAME>`         |
| `vars.APP_ORIGIN`             | `https://credentials.example.com`      | `https://<HOSTNAME>` |
| `d1_databases[0].database_id` | `00000000-0000-0000-0000-000000000000` | `<DATABASE_ID>`      |

`APP_ORIGIN` has no trailing slash and no path.

Verify:

```
git diff -- wrangler.jsonc
```

The diff shows three changed lines, all between `"production": {` and the end of the file. The `staging` block and the top level are unchanged. When this step is repeated only because Step 2.6 led to a new hostname, the diff shows the two hostname lines.

Then commit:

```
git commit -m "Deployment configuration" -- wrangler.jsonc
```

Rerun: If `git diff main -- wrangler.jsonc` already shows these three changes next to the line from Step 2.2, the step is done.

#### Step 2.6: Confirm that the hostname is free

Who: Agent

Without a terminal, `wrangler deploy` does not ask before it takes a hostname. It detaches the hostname from any other Worker and overwrites conflicting DNS records. This check is the only safeguard.

Run:

```
curl -sS -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=<HOSTNAME>&type=A"
curl -sS -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=<HOSTNAME>&type=AAAA"
```

The two requests ask for address records. An alias (CNAME) at the hostname appears in both answers, and so does a wildcard record of the domain. Other record types are not checked.

Verify: First make sure that both queries worked: each response is JSON and its `Status` is `0` or `3`. A response that is not JSON, or that has another `Status`, means the query itself failed. Run that request again; if it fails a second time, stop.

Then: neither JSON response has an `Answer` field. The hostname is free. A hostname that was never used answers with `"Status":0` and an `Authority` field in place of `Answer`.

If either response has an `Answer` field, the hostname resolves already. Stop, show the human the `Answer` entries, and ask which of two ways to go:

- Another hostname: the human names it. Change the two hostname values of Step 2.5 to it, commit as in Step 2.5, and repeat this step.
- This hostname, replacing what is there: only the human can decide this. Repeat back the records that the deployment will replace, as listed in `Answer`, and that a Worker serving the hostname now will lose it. Continue only after the human confirms in so many words.

Rerun: Safe until Step 2.11 has succeeded. After that the hostname resolves because this Worker serves it, and the check no longer applies.

#### Step 2.7: Build the console

Who: Agent

Perform Step A3 of Part A. If this session has just performed it in Part A and the code has not changed since, it need not be repeated.

#### Step 2.8: Apply the database migrations

Who: Agent

Run:

```
npx wrangler d1 migrations apply clavifer --env production --remote
```

Then run the same command a second time. The second run is the check.

The command needs `--remote`. Without it, it acts on a local database and reports success. On the first run it lists the migrations, asks whether to continue, and answers yes without a terminal.

Verify: The second run exits with status 0 and prints `No migrations to apply!`. Do not rely on the output of the first run: the command has reported success without applying anything.

Do not use `npx wrangler d1 migrations list --remote` as the check. It ignores `account_id` in the configuration, and when the login can act on more than one account it fails with `More than one account available but unable to select one in non-interactive mode.`

Rerun: Safe.

If it fails:

- A Cloudflare API error with code 7403: run the same command again. If it fails three times in a row, stop.
- `Couldn't find a D1 DB with the name or binding 'clavifer'`: Step 2.5 is incomplete, or the command lacks `--env production`.
- The second run still prints `Migrations to be applied:` and a table: run it once more. If the table is still there, stop.

#### Step 2.9: Generate the Worker secrets

Who: Agent

The Worker needs four secrets: `AUTH_SECRET`, `KEK_RING`, `ACTIVE_KEK_ID` and `BOOTSTRAP_HASH`. `KEK_RING` holds the key that encrypts every stored credential. A secret cannot be read back from a Worker. If `KEK_RING` is replaced or lost, every credential stored in this environment becomes impossible to decrypt.

First run existence checks on `work/production.secrets.json` and `work/production-bootstrap.token`. Decide by the two results:

- Both print `False`: run the command below.
- Both print `True`: an earlier run of this step created the files. Do not delete them and do not run the command below. Run `npx wrangler secret list --env production` and decide by its result:
  - It fails with `Worker "clavifer-production" (env: production) not found.`: the first deployment has not happened. Continue with Step 2.10 and the existing files.
  - It prints a list that contains all four names, `ACTIVE_KEK_ID`, `AUTH_SECRET`, `BOOTSTRAP_HASH` and `KEK_RING`: the first deployment has happened. Continue with Step 2.12.
  - It prints a list that is empty or lacks any of the four names: a Worker with this name exists without these secrets. Follow [A Worker that already exists](#a-worker-that-already-exists) below.
- One prints `True` and the other `False`: stop and ask the human. Half of an earlier run is missing, and nothing may continue with the half that is left.

Run:

```
node scripts/init-secrets.mjs --env production
```

The script checks for the secrets file, then for the token file, and refuses if either exists. It then asks Cloudflare which of the four secrets the Worker `clavifer-production` already has, and only after that writes the two files. It uploads nothing. This document keeps the configuration in `wrangler.jsonc` in the repository root; for a configuration file kept elsewhere the script takes `--config <path>`, hands it to wrangler, and prints the deploy command with it.

Verify: The command exits with status 0. It prints `Created work/production.secrets.json and work/production-bootstrap.token.`, then a line that starts with `Next:` and a line that starts with `Do not paste`. The `Next:` line names the deploy command of Step 2.11; do not run it before Step 2.10 is done. No secret value is printed. Existence checks on both files print `True`.

On a new deployment those are the only three lines. If the output also has the line `A Worker for env "production" already exists without these secrets; deploying replaces its code.`, the files have been written, but do not go on. Follow [A Worker that already exists](#a-worker-that-already-exists) below.

Rerun: Not possible, by design. Start again from the existence checks above.

If it fails:

- `work/production.secrets.json already exists; refusing to overwrite` or `work/production-bootstrap.token already exists; refusing to overwrite`: the existence checks were skipped, or a file appeared after them. Run the existence checks above and follow their result. The message about the token file is printed only when the secrets file is missing, which is the case where you stop and ask the human.
- `the Worker of env "production" already has …; refusing to generate new secrets`: this environment is already deployed. Stop and ask the human. Never work around this refusal.
- `wrangler secret list failed, so it is unknown whether env "production" already has secrets; nothing was generated`: wrangler could not reach the account. Return to Step 2.1.
- `wrangler secret list printed a list this script cannot read; nothing was generated`: wrangler's output has a shape the script does not know, so the script cannot tell whether the Worker has secrets. Stop and ask the human.

##### A Worker that already exists

This part of Step 2.9 applies when a Worker named `clavifer-production` is in the account without the four secrets. This procedure did not put it there, and deploying would replace its code. Stop and ask the human whether that Worker belongs to this deployment.

- The human confirms that it does and that its code may be replaced: continue with Step 2.10.
- The human says that it does not: stop the deployment. Keep the two generated files as they are and do not generate them again. The human chooses one of two ways out:
  - The human deletes or renames that Worker in the Cloudflare dashboard.
  - The human decides on another Worker name for this deployment. Change `name` in the `env.production` block of `wrangler.jsonc` to it and commit, as in Step 2.5.

  After either, run `npx wrangler secret list --env production`. It must fail with `Worker "…" (env: production) not found.`, naming the Worker this deployment will create. Only then continue with Step 2.10.

#### Step 2.10: Save the secrets before deploying

Who: Human

Say to the human:

> I generated the server secrets into `work/production.secrets.json` without reading them. Before I deploy, please open that file yourself and save its whole content in your password manager. Do not paste it here, and do not delete the file yet; the deployment reads it.
>
> This is the only copy of the key that encrypts your stored credentials. Cloudflare does not show it again after the upload.
>
> Tell me when it is saved.

Verify: The agent cannot check this. Continue only after the human confirms.

#### Step 2.11: Deploy for the first time

Who: Agent

Run:

```
npx wrangler deploy --env production --secrets-file work/production.secrets.json
```

This uploads the code and the four secrets in one request. The command always needs `--env production`; without `--env`, wrangler deploys the local development configuration.

`--secrets-file` does not look at what the Worker already has: every secret named in the file replaces the one on the Worker. The check in Step 2.9 is the only protection. So deploy only the file that Step 2.9 created in this checkout for this environment. Do not write a secrets file by hand, and do not use one from another environment or another checkout.

Verify: The command exits with status 0. Below the line `Deployed clavifer-production triggers`, its output has the line `<HOSTNAME> (custom domain)`. The table of bindings in the output lists the four secrets with `("(hidden)")` in place of their values; no secret value is printed.

Rerun: Allowed with the same, unchanged file until the command has succeeded once. After that, never pass `--secrets-file` again: every later deployment is `npx wrangler deploy --env production`, as in [Upgrading](#upgrading).

If it fails:

- An unknown error with code 10013 while uploading assets: run the same command again. Nothing was deployed.
- `You must use a real database in the database_id configuration`: Step 2.5 is incomplete.
- An error that contains `10042`: R2 is not enabled. Return to Step 1.5.
- An error about authentication or permissions while wrangler uses an API token: it is unverified whether a token built from the "Edit Cloudflare Workers" template can create a Worker that does not exist yet, and whether attaching the hostname needs further zone permissions. Stop, show the human the error, and offer Option B of Step 1.2 as the alternative.

#### Step 2.12: Confirm the secrets

Who: Agent

Run:

```
npx wrangler secret list --env production
```

Verify: The command prints a JSON array with exactly these four names and no values: `ACTIVE_KEK_ID`, `AUTH_SECRET`, `BOOTSTRAP_HASH`, `KEK_RING`.

Rerun: Safe.

If it fails:

- A name is missing: stop. Do not upload secrets one by one.

#### Step 2.13: Wait for the hostname

Who: Agent

The hostname can answer at once or only after a few minutes. A hostname one level below the domain is usually covered by a certificate the zone already has; in the maintainer's deployment the first request succeeded seconds after the deployment. Otherwise Cloudflare issues a certificate first, and until then the TLS handshake fails.

Run: Repeat every 30 seconds, for at most 15 minutes, until the output matches.

```
curl -sS https://<HOSTNAME>/healthz
```

Verify: The command prints `{"ok":true,"service":"clavifer","version":"0.5.0"}`. `version` is the version of the code that is running; this release is 0.5.0. Then run:

```
curl -sS https://<HOSTNAME>/setup
```

It prints `{"initialized":false}`.

Rerun: Safe.

If it fails:

- TLS or connection errors continue after 15 minutes: stop.
- `/setup` prints `{"initialized":true}`: the database already has an Owner. Stop and ask the human.

#### Step 2.14: Turn off Web Analytics injection for the hostname

Who: Agent detects and verifies. The rule is created by the Agent when an API token is set in the agent's shell, otherwise by the Human.

On zones of the Free plan, Cloudflare injects its Web Analytics script into HTML pages by default. The console's pages allow only their own scripts, so the browser blocks the injected script and reports a content security policy violation on every page load. A configuration rule turns the injection off for this hostname.

Run: First detect whether the zone injects.

```
curl -sS -H "Accept: text/html" https://<HOSTNAME>/
```

The output is a short HTML document. Decide by whether it contains the string `cloudflareinsights`:

- It does not: the zone is not injecting into this hostname. The step is done; create no rule.
- It does: create the rule as described below.

This check rests on what the maintainer observed in one deployment, not on a guarantee by Cloudflare. There, on a zone of the Free plan, a new hostname was injected by default, the string appeared only when the request carried `Accept: text/html`, and it was gone within ten seconds after the rule was added.

To find out who creates the rule, run the check for `CLOUDFLARE_API_TOKEN` from [Secrets never pass through the agent](#secrets-never-pass-through-the-agent). If it prints `False`, or if any request below fails with an authentication or permission error, say to the human:

> Please create one rule in the Cloudflare dashboard. Open the domain, go to Rules, and create a Configuration Rule. Match requests where Hostname equals `<HOSTNAME>`. In the settings, turn on the one Cloudflare's documentation calls "Disable Real User Monitoring (RUM)". Deploy the rule and tell me when it is active. Reference: https://developers.cloudflare.com/rules/configuration-rules/settings/

After the human confirms, continue at Verify.

If the check prints `True`, the agent creates the rule. The maintainer has run the list request and Case 2 below, on a zone that already had configuration rules, with a different kind of credential than the API token. Case 1, and whether a token with Zone · Config Rules · Edit is sufficient, are unverified.

List the rulesets of the zone. The commands name the token's variable and the shell fills in its value, which the rules for secrets allow.

PowerShell:

```powershell
curl -sS -H "Authorization: Bearer $env:CLOUDFLARE_API_TOKEN" "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/rulesets"
```

POSIX:

```sh
curl -sS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/rulesets"
```

The response has `"success": true` and a `result` array. Look for the entry with `"phase": "http_config_settings"` and `"kind": "zone"`. Then follow the case that applies. In the commands below, `<AUTH>` stands for the same `-H "Authorization: Bearer …"` argument as above, in the form for your shell.

Case 1, no such entry (unverified): the zone has no configuration rules. Write this to a new file `rum-rule.local.json` in the repository root, which git ignores:

```json
{
  "rules": [
    {
      "description": "Clavifer: no Web Analytics injection",
      "expression": "http.host eq \"<HOSTNAME>\"",
      "action": "set_config",
      "action_parameters": { "disable_rum": true }
    }
  ]
}
```

Then run:

```
curl -sS -X PUT <AUTH> -H "Content-Type: application/json" --data "@rum-rule.local.json" "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/rulesets/phases/http_config_settings/entrypoint"
```

Case 2, the entry exists: its `id` is `<RULESET_ID>`. Do not use the `PUT` request of Case 1: it replaces every configuration rule the zone already has. Read the existing rules first:

```
curl -sS <AUTH> "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/rulesets/<RULESET_ID>"
```

The rule counts as present only if `result.rules` holds a rule whose `expression` is exactly `http.host eq "<HOSTNAME>"` whose `action_parameters` has `"disable_rum": true`, and whose `enabled` is `true`. In that case the step is done. In every other case, including a rule that names `<HOSTNAME>` inside a longer expression, write this to `rum-rule.local.json`:

```json
{
  "description": "Clavifer: no Web Analytics injection",
  "expression": "http.host eq \"<HOSTNAME>\"",
  "action": "set_config",
  "action_parameters": { "disable_rum": true }
}
```

Then append it:

```
curl -sS -X POST <AUTH> -H "Content-Type: application/json" --data "@rum-rule.local.json" "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/rulesets/<RULESET_ID>/rules"
```

Keep the quotes around `@rum-rule.local.json`: PowerShell reads an unquoted `@` as its own syntax.

The response to the `PUT` or `POST` request has `"success": true`, and its `result.rules` contains the rule for `<HOSTNAME>` next to every rule that was there before. Then delete `rum-rule.local.json`.

Verify: Whoever created the rule, run the detection command from the start of this step again. Within one minute, its output no longer contains `cloudflareinsights`. Repeat it every 10 seconds until then; if the string is still there after one minute, stop.

Rerun: Start from the detection command. Without the string in its output, there is nothing to do.

If it fails:

- `"success": false` with an authentication or permission error: the token probably lacks Zone · Config Rules · Edit. Use the message for the human above.
- `"success": false` because the zone has reached its number of configuration rules (10 on the Free plan): stop and ask the human.

### Phase 3: Hand over to the Owner

The steps in this phase belong to the human. The agent sends each message and runs each check.

#### Step 3.1: Delete the secrets file

Who: Human

Say to the human:

> The deployment succeeded and the Worker has its four secrets. You saved `work/production.secrets.json` in your password manager in Step 2.10. Please check that the entry is there, then delete the file from this machine. Tell me when it is deleted.

Verify: An existence check on `work/production.secrets.json` prints `False`.

#### Step 3.2: Create the Owner

Who: Human

First run `curl -sS https://<HOSTNAME>/setup`. If it prints `{"initialized":true}`, the Owner already exists and the token is used up: do not send the message below. Run an existence check on `work/production-bootstrap.token`; if it prints `True`, ask the human to delete the file. The step is then done.

Say to the human:

> Please create the administrator account yourself.
>
> 1. Open `work/production-bootstrap.token` in your own editor and copy its content. Do not paste it into this conversation.
> 2. Open `https://<HOSTNAME>/` in your browser. The page shows the heading 创建管理员 (create the administrator).
> 3. Fill in 初始化令牌 (bootstrap token) with the copied value, 姓名 (name), 邮箱 (email) and 新密码 (new password, at least 12 characters). The email is your sign-in name; nothing is sent to it, and there is no password recovery by email. Save the password in your password manager.
> 4. Press 创建管理员 (create the administrator). The page signs you in and shows the console.
> 5. Delete `work/production-bootstrap.token`. The token cannot be used again.
>
> Tell me when the console is showing and the file is deleted.

Verify:

```
curl -sS https://<HOSTNAME>/setup
```

It prints `{"initialized":true}`. An existence check on `work/production-bootstrap.token` prints `False`.

Rerun: Not possible. After the Owner exists, the token is rejected with `bootstrap_already_used`.

If it fails:

- The page reports an error when the form is submitted, and the account is on Workers Free: the request has probably exceeded the 10 ms CPU limit (Cloudflare error 1102). This is unverified. Stop and ask the human about moving to Workers Paid.

#### Step 3.3: Register a Passkey

Who: Human

Say to the human:

> Please register a Passkey, so that you do not depend on the password alone. In the console, open 账户 (account). In the Passkey panel press 登记新的 Passkey (register a new Passkey), give it a name, press 登记 (register), and confirm with your authenticator when the browser asks. Tell me when the Passkey appears in the list.

Verify: The agent cannot check this. Continue after the human confirms.

#### Step 3.4: Configure automatic backups

Who: Human, with one Agent command

Backups are encrypted to an age public key, the recipient. The matching private key stays with the human and is needed to restore.

Say to the human:

> Automatic backups are encrypted to an age public key. Do you already have one that you want to use (it starts with `age1`), with its private key stored safely?

If the human has one, it is `<AGE_RECIPIENT>`. Otherwise the agent generates a key pair. First run an existence check on `work/production-backup.agekey`; if it prints `True`, stop and ask the human. Then run:

```
node scripts/backup-keygen.mjs work/production-backup.agekey
```

The command writes the private key to the file and prints two lines. The second is `Public recipient: ` followed by `<AGE_RECIPIENT>`. Do not open the file.

Then say to the human:

> 1. If I generated the key: open `work/production-backup.agekey` yourself, save its content in your password manager, and delete the file. Without this private key the backups cannot be read.
> 2. In the console, open 备份 (backup). In the panel 自动备份 (automatic backup) press 配置收件人 (configure the recipient).
> 3. Paste `<AGE_RECIPIENT>` into age 公钥收件人 (age public key recipient) and press 保存并立即备份 (save and back up now). If the page asks you to verify your identity again, do so; this change needs a sign-in from the last 10 minutes.
> 4. Saving and the first backup are two separate actions, and only the second proves that backups work. The page must report 设置已保存，并已完成一次备份。 (settings saved, one backup completed), and the line 最近成功 (last success) in the panel must show a time, not 尚未成功备份 (no successful backup yet). The badge 已启用 (enabled) alone only says that a recipient is set.
> 5. If the page reports 设置已保存，但首次备份没有完成 (settings saved, but the first backup did not complete), press 立即备份 (back up now) and look at the 最近成功 line again.
>
> Tell me what the 最近成功 line shows.

Verify: The agent cannot see the console. Continue after the human reports a time on the 最近成功 (last success) line. If the human reports 尚未成功备份 or a failure, stop and ask the human what the panel shows under 失败原因 (reason of failure). If the agent generated the key, an existence check on `work/production-backup.agekey` prints `False`.

Rerun: The key generation refuses to overwrite an existing file. The recipient can be changed in the console at any time; backups made before the change still need the old private key.

[Backup and restore](#backup-and-restore) describes what the backups contain.

### Phase 4: Connect an agent host

Continue with [clients.md](clients.md), using `https://<HOSTNAME>` as `<SERVER>`. It builds and installs the `clavifer` command, has the human create an installation in the console, logs in, and registers the MCP server in the agent host.

### Result

The deployment is complete when all of these hold:

- `curl -sS https://<HOSTNAME>/healthz` prints `"ok":true`.
- `curl -sS https://<HOSTNAME>/setup` prints `{"initialized":true}`.
- Existence checks on `work/production.secrets.json` and `work/production-bootstrap.token` print `False`. If the agent generated the backup key in Step 3.4, the same holds for `work/production-backup.agekey`.
- The human has confirmed the Passkey, and that the 最近成功 (last success) line on the backup page shows a time.
- The `doctor` check in Step 5 of [clients.md](clients.md) reports `"ok": true`.
- In a new session of the agent host, the four tools are visible and a call to `credentials.list` returns a result, as in Step 8 of [clients.md](clients.md).

## Staging environment

`wrangler.jsonc` defines a second environment, `staging`, for trying a new version before production. It is a complete, separate deployment: its own Worker, database, bucket, hostname, secrets and Owner. It is optional.

To create it, perform Part B again with the `staging` column of the table under [Names and placeholders](#names-and-placeholders):

- Skip Step 2.2 if production is already deployed. The `account_id` line at the top level applies to every environment, so both environments are in the same account.
- Use `--env staging` wherever a command has `--env production`.
- Use the database name `clavifer-staging` and the bucket name `clavifer-staging-backups`.
- Use `staging` in place of `production` in every file name under `work/`.
- In Step 2.5, edit the `env.staging` block. Its template hostname is `credentials-staging.example.com`. The check of that step then reads: the diff shows three changed lines, all between `"staging": {` and `"production": {`, and the `production` block and the top level are unchanged.
- In Step 2.14, use the staging hostname. If a rule is needed, the step adds one for it and keeps the rules that exist.
- In [clients.md](clients.md), use a different profile name and a different MCP server name, as described under [Connecting a second environment](clients.md#connecting-a-second-environment).

## Upgrading

An upgrade deploys new code over a running environment. Its secrets and data stay as they are. If a staging environment exists, upgrade it first, with `staging` in place of `production` and `clavifer-staging` as the database name.

The version to upgrade to is the latest commit of `origin/main`. The project has no separate release branch, and every version has an entry in [CHANGELOG.md](../CHANGELOG.md).

Steps U1 to U4 are Agent steps. In Step U5 the human installs the client. With a staging environment, perform Steps U1 and U2 once, Steps U3 and U4 for staging, then Steps U3 and U4 for production, and Step U5 once, after every environment is upgraded.

### Step U1: Get the new code

Run:

```
git switch deploy
git fetch origin
git merge origin/main
```

Then read the entries of [CHANGELOG.md](../CHANGELOG.md) between the old and the new version. The old version is the `version` that `curl -sS https://<HOSTNAME>/healthz` reports before the upgrade; the new one is the topmost entry of `CHANGELOG.md`. Follow any upgrade note there before continuing.

Verify: The merge completes, and `git diff origin/main -- wrangler.jsonc` shows only the `account_id` line from Step 2.2 and the values written in Step 2.5.

If it fails:

- `git switch deploy` fails because the branch does not exist: see [If the deploy branch is gone](#if-the-deploy-branch-is-gone).
- `git fetch origin` fails, or `origin` is not the Clavifer repository: stop and ask the human where the new version comes from.
- A merge conflict in `wrangler.jsonc`: stop and ask the human.

### Step U2: Install and build

Run:

```
npm ci
npm run build:web
```

Verify: Both commands exit with status 0.

### Step U3: Apply the database migrations

Perform Step 2.8. Migrations go first: new code that runs against an old schema fails on missing columns.

### Step U4: Deploy

Run:

```
npx wrangler deploy --env production
```

Do not pass `--secrets-file`, and do not run `scripts/init-secrets.mjs` for this environment.

The table of bindings in the output of this deployment does not list the four secrets, unlike the first deployment. That is expected and does not mean they are gone: `npx wrangler secret list --env production` still prints the four names of Step 2.12.

Verify: The command exits with status 0, and `curl -sS https://<HOSTNAME>/healthz` prints `"ok":true`. The `version` it prints is the version this upgrade goes to, which is the topmost entry of `CHANGELOG.md`.

Rerun: Safe.

If it fails:

- An unknown error with code 10013 while uploading assets: run the same command again. The previous version stays live until a deployment succeeds.

### Step U5: Update the command line client

Who: Agent builds and verifies; Human installs

Follow [Updating the client](clients.md#updating-the-client) in clients.md on every machine that uses this environment. The agent builds the client and updates the Skill; the human closes the agent hosts and runs the install script, because the agent's own agent host keeps the installed executable in use; a new session verifies. This step ends the current session, so it comes last.

### If the deploy branch is gone

The branch `deploy` exists only where it was created, unless the human pushed it to a private remote. In a new checkout, first ask the human whether such a remote has it. If it does, the human fetches it, and `git switch deploy` works.

Otherwise rebuild the branch. Nothing here creates or changes anything in Cloudflare.

1. Perform Steps 1.1 and 1.2, then Steps 2.1 and 2.2. They confirm the account, create the branch and write `account_id`.
2. Run `npx wrangler d1 list --json`. The `uuid` of the entry with `"name": "clavifer"` is `<DATABASE_ID>`. If there is no such entry, stop and ask the human. Do not create a database.
3. Ask the human for `<HOSTNAME>`, the hostname that serves the deployment now.
4. Perform the edit, the check and the commit of Step 2.5.
5. If a staging environment exists, repeat points 2 to 4 for it: the database is `clavifer-staging`, the hostname is the staging one, and the edit goes into the `env.staging` block.

Verify: `npx wrangler secret list --env production` prints the four names of Step 2.12, which shows that the configuration points at the deployed Worker, and `curl -sS https://<HOSTNAME>/healthz` prints `"ok":true`.

Do not perform any other step of Phase 2. Above all, never run `scripts/init-secrets.mjs` for an environment that is deployed, and never deploy it with `--secrets-file`: a new `KEK_RING` makes every stored credential impossible to decrypt.

Then continue with Step U1.

## Changing the hostname

A hostname can be attached to only one Worker at a time. To move the service to a new hostname:

1. Perform Step 2.6 for the new hostname.
2. In `wrangler.jsonc`, change `routes[0].pattern` and `vars.APP_ORIGIN` of the environment, as in Step 2.5, and commit.
3. Run `npx wrangler deploy --env production`.
4. Wait until `curl -sS https://<HOSTNAME>/healthz` answers on the new hostname, as in Step 2.13. Then perform Step 2.14 for the new hostname.
5. The human signs in at the new hostname with the password and registers every Passkey again. A Passkey is bound to the hostname it was registered on.
6. Log in again with every profile, as in the login step of [clients.md](clients.md), with the new address as `<SERVER>`. The client ID stays the same.

When a hostname moves from one environment to another, deploy the environment that gives it up first, confirm that the hostname no longer answers, and then deploy the environment that takes it.

## Removing a deployment

Remove a deployment only when the human asks for it in so many words. Removal deletes every credential stored in it, and nothing brings them back.

Without a terminal, none of the three delete commands waits for anyone: `wrangler delete` and `wrangler d1 delete` answer their own confirmation with yes, and `wrangler r2 bucket delete` asks nothing. So every check comes before the commands. `wrangler delete --dry-run` is no check; it does not show what would be deleted.

The names below are those of production. For staging, use the `staging` column of the table under [Names and placeholders](#names-and-placeholders).

1. In the checkout that deployed the environment, make sure the configuration points at this deployment:

   ```
   git branch --show-current
   npx wrangler secret list --env production
   npx wrangler d1 list --json
   npx wrangler r2 bucket info clavifer-backups --json
   ```

   The branch is `deploy`. The secret list has the four names of Step 2.12. The entry with `"name": "clavifer"` has the `uuid` that Step 2.5 wrote into `wrangler.jsonc` as `database_id`. The last command exits with status 0. If anything differs, stop.

2. Say to the human:

   > I am about to delete the Worker `clavifer-production`, the database `clavifer` with every stored credential, and the bucket `clavifer-backups`. This cannot be undone. Do you have a backup file and its age private key outside this account, or are you sure you no longer need the data? Please confirm that I should delete.

   Continue only after the human confirms.

3. Delete the Worker, with its name written out. This also removes the hostname, its DNS record, the schedule and the four secrets.

   ```
   npx wrangler delete clavifer-production --env production
   ```

   It prints `Successfully deleted clavifer-production`. Afterwards, `npx wrangler secret list --env production` fails with `Worker "clavifer-production" (env: production) not found.`

4. Delete the database.

   ```
   npx wrangler d1 delete clavifer --env production
   ```

   It prints `Deleted 'clavifer' successfully.` Afterwards, `npx wrangler d1 list --json` has no entry named `clavifer`.

5. Delete the bucket.

   ```
   npx wrangler r2 bucket delete clavifer-backups
   ```

   It prints `Deleted bucket clavifer-backups.` Afterwards, `npx wrangler r2 bucket info clavifer-backups --json` fails with `The specified bucket does not exist. [code: 10006]`. The maintainer deleted an empty bucket. A bucket that holds backup objects is expected to refuse deletion, and emptying a bucket is unverified: if the command fails, stop and ask the human.

6. About one minute after the Worker is deleted, the two requests of Step 2.6 have no `Answer` field again. During that minute and for some minutes after it, `curl` to the hostname can still receive a response with a 5xx status and exit with status 0. That response comes from Cloudflare's edge and does not mean the service is running.

7. If Step 2.14 created a rule, remove that one rule and no other. With an API token, read the ruleset as in Case 2 of Step 2.14, take the `id` of the rule whose `expression` is exactly `http.host eq "<HOSTNAME>"`, and send `DELETE` to `https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/rulesets/<RULESET_ID>/rules/` followed by that `id`. The response has `"success": true`, and its `result.rules` holds the remaining rules without the deleted one. Without a token, ask the human to delete the rule in the dashboard.

The files under `work/`, the branch `deploy`, and the logins on client machines are left as they are; the human decides what to do with them. [Disconnecting](clients.md#disconnecting) in clients.md describes how to clear a login whose installation no longer exists.

## Backup and restore

What the service does, as implemented:

- Every 15 minutes the Worker checks whether a new backup is due. It writes a new encrypted copy to the R2 bucket when a secret or connection has changed since the last successful backup, when the recipient has changed, or when the last successful backup is 24 hours old. This starts once a recipient is configured (Step 3.4).
- A copy contains the current values of all secrets and all connections. It does not contain earlier versions of secrets, the Owner account, sessions, installations, grants or the audit log.
- A copy is encrypted to the age recipient before it leaves the Worker. It does not depend on `KEK_RING`: a restore re-encrypts everything with the keys of the deployment it is restored into.
- After each successful backup the Worker deletes older copies. It keeps the newest copy of each of the last 30 days and the newest copy of each of the 12 months before that.
- One backup holds at most 500 secrets, 500 connections and 8 MiB of data.

The bucket is in the same Cloudflare account as the service. To keep a copy elsewhere, the human downloads it: on 备份 (backup), 下载最近副本 (download the latest copy) fetches the newest automatic copy, and 下载加密备份 (download an encrypted backup) creates a fresh one for a recipient entered on the spot. Nothing copies backups out of the account automatically.

### What the human must keep

| Item                                      | If it is lost                                                                                     |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Content of `work/production.secrets.json` | The database of this deployment cannot be decrypted. Recovery is a restore into a new deployment. |
| age private key                           | No backup can be read.                                                                            |
| Owner password and Passkeys               | Nobody can sign in. There is no recovery by email.                                                |

When every way to sign in is lost, a person with administrative access to the Cloudflare account can in principle reset the Owner directly in the database. This repository provides no tool and no procedure for that.

### Restore

A restore writes the content of one backup into a deployment in which no secret, connection or installation has ever been created. The human performs it, because it needs the age private key.

1. Create a new deployment with Part B, up to and including Step 3.2, with a new D1 database. Do not create installations, secrets or connections in it. The server refuses the restore with `restore_requires_empty_vault` as soon as one of them has ever been created, even if it was deleted or revoked afterwards: deleting and revoking leave the record in the database.
2. In the console, open 备份 (backup) and press 从备份恢复 (restore from a backup).
3. Choose the `.age` file under 备份文件 (backup file), at most 10 MiB, and paste the age private key, which starts with `AGE-SECRET-KEY-1`, into age 私钥 (age private key). The browser decrypts the file; the private key is not sent to the server.
4. Press 解密并恢复 (decrypt and restore) and confirm.

Secrets and connections return with their original IDs. Installations and grants do not return: create installations again with [clients.md](clients.md) and grant access again.

## Server keys

There is no procedure for rotating the four Worker secrets.

`KEK_RING` is a comma-separated list of `id:key` pairs, and `ACTIVE_KEK_ID` names the pair that encrypts new writes; each stored secret version records the ID of the key that encrypted it. No command adds a key or re-encrypts existing data, and changing these secrets by hand is untested. Do not change them on a deployment that holds data.

`BOOTSTRAP_HASH` is used only until the Owner exists.

The values of individual stored secrets are a different matter: the Owner replaces them at any time on the 凭据 (secrets) page, with 轮换 / 编辑 (rotate / edit).
