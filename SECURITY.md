# Security policy

Clavifer stores credentials, so security reports matter to this project. It is maintained by one person: reports are handled on a best-effort basis, and no response time is promised.

## Supported versions

Only the latest version, which is the tip of the `main` branch, receives security fixes. Check that a problem still exists there before you report it.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting:

<https://github.com/Ogannesson/clavifer/security/advisories/new>

Do not open a public issue or pull request for a vulnerability, and do not include real credentials, tokens, or the contents of `.dev.vars` in a report. Use synthetic values.

## What to include

- The version or commit, and the part affected: the Worker, the web console, the `clavifer` command, the Skill, or the install scripts.
- How the service runs: local development or a deployed Worker. For the command line, the operating system.
- What the attacker starts with. For example: no account, an installation without grants, an installation with a grant on one connection, or an Owner session older than 10 minutes.
- What the attacker gains.
- Steps to reproduce, or a proof of concept that uses synthetic credentials.
- The `x-request-id` response header of the requests involved, if you have it.
- A suggested fix, if you have one.

## Scope

In scope:

- Reading a stored secret value, or obtaining the credential of a connection, without a grant that allows it.
- Running a request that a connection's policy refuses: getting past a deny rule, an approval rule, the regular scope, or an expired or revoked grant.
- Reusing a one-time approval, using it for a different request, or using one that belongs to another installation.
- Sending a credential to an origin the Owner did not allow.
- Acting as the Owner without the Owner's sign-in, performing an operation that needs a recent sign-in with an older session, or forging a request to `/admin/*` from another site.
- Continuing to use a revoked installation.
- Defeating the encryption of stored secrets or of backups as implemented.
- Script injection in the console, or a review card that shows something other than what will run.
- The `clavifer` command writing tokens or secret values to a file, a log, or its output where the documentation says it does not.

Out of scope:

- Everything listed under [Known limits and non-goals](docs/security-model.md#known-limits-and-non-goals). Those are documented properties of the design, not vulnerabilities. Among them: an upstream that echoes a credential, plaintext on the local machine after a `secret:read` grant, and programs of the same operating system user sharing stored logins.
- Attacks that start from control of the Cloudflare account, the Owner's password or Passkey, or the Owner's browser.
- A vulnerability in a dependency without a demonstrated effect on Clavifer. Report it to the dependency.
- Misconfiguration of your own deployment.
- Denial of service by request volume.

If you are unsure whether something is in scope, report it privately anyway.

## What happens next

The maintainer replies in the private advisory. A confirmed vulnerability is fixed in a new version on `main`.
