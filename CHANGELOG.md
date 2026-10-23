# Changelog

All notable changes to this project are recorded in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

When upgrading to a version takes an extra step, that version's entry lists the step under `### Upgrade notes`.

## [0.5.0] - Unreleased

First public release.

### Added

- A credential service for a single Owner on Cloudflare Workers, D1, and R2. A one-time bootstrap token, issued by the deployment, creates the Owner on the console's `/setup` page; the Owner signs in with a password or a Passkey. A later token resets a lost password.
- Secrets with named fields and versions, encrypted with AES-256-GCM envelope encryption under a key derived from the service's one Worker secret, `ROOT_KEY`. A Worker whose root key does not match the one recorded at setup refuses every request but `/healthz`, and `clavifer doctor` explains why.
- Connections: a fixed upstream origin, a credential injected on the server in one of five ways (none, Bearer, header, Basic, or query parameter), allowed paths and methods, and deny, approval, and free rules.
- Installations for agent clients, created by the Owner, with OAuth device code login for the command line and authorization code login for remote MCP clients. Revocation takes effect on the next request.
- Grants per installation with an expiry, on a connection or on a secret, and for a secret optionally limited to some fields.
- Access requests from agents: grants with temporary scope extensions, one-time approvals bound to one exact request for 10 minutes, and drafts of new or changed connections that carry a test table. A request takes at most 256 KiB as stored, and an installation holds at most 20 pending requests and 1 MiB of them.
- Extra hosts and any host: a connection's credential can go to another origin for one approved request.
- An MCP server with four tools (`credentials.list`, `http.request`, `access.request`, `access.status`) and a REST API with a generated OpenAPI document.
- The `clavifer` command: login, named profiles, a stdio MCP bridge, `run` to start a program with granted secret fields in its environment, `request` and `status --wait`, and `doctor`. Tokens are kept in the operating system's credential store. Verified on Windows; the macOS and Linux builds are not verified on real machines.
- A web console for the Owner, in Chinese.
- Snapshots of the whole instance in the frozen format `clavifer-backup-v1`, encrypted with age: automatic backups to R2 with daily and monthly retention, a full export the Owner downloads, and an import into a new instance on `/setup`, for a migration or for a recovery after a lost root key.
- An audit log whose rows carry the request ID returned in the `x-request-id` response header. Old audit rows and access requests are sealed into encrypted archive files in R2 and never deleted.
- The deploy entry `npm run deploy`, which checks the configuration against the live Worker and database before it changes anything, and generates the root key without writing or printing it.
- A Skill for agent hosts and install scripts for the command line client and the Skill on Windows.

### Upgrade notes

- An instance deployed from a pre-release commit of this repository is not upgraded in place: the root key, the encryption context of stored secrets, the database schema and the backup format all changed. Such an instance may report version 0.5.0, but its `/healthz` has no `keys` field.
  - If its 备份 (backups) page offers 完整导出 (full export), download one, deploy 0.5.0 as a new instance with its own database and bucket, and import the file on the new instance's `/setup` page. Installations keep their client IDs and grants; every profile logs in again, and Passkeys come across only when the hostname stays the same.
  - Otherwise deploy 0.5.0 as a new instance and enter its data again.

  From 0.5.0 on, an instance moves to another one by a full export and an import, as [docs/deploy.md](docs/deploy.md) describes.
