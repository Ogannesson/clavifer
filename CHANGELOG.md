# Changelog

All notable changes to this project are recorded in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

When upgrading to a version takes an extra step, that version's entry lists the step under `### Upgrade notes`. 0.5.0 is the first public release and has none.

## [0.5.0] - Unreleased

First public release.

### Added

- A credential service for a single Owner on Cloudflare Workers, D1, and R2. A one-time bootstrap token creates the Owner, who signs in with a password or a Passkey.
- Secrets with named fields and versions, encrypted with AES-256-GCM envelope encryption under a key ring held as a Worker secret.
- Connections: a fixed upstream origin, a credential injected on the server in one of five ways (none, Bearer, header, Basic, or query parameter), allowed paths and methods, and deny, approval, and free rules.
- Installations for agent clients, created by the Owner, with OAuth device code login for the command line and authorization code login for remote MCP clients. Revocation takes effect on the next request.
- Grants per installation with an expiry, on a connection or on a secret, and for a secret optionally limited to some fields.
- Access requests from agents: grants with temporary scope extensions, one-time approvals bound to one exact request for 10 minutes, and drafts of new or changed connections that carry a test table.
- Extra hosts and any host: a connection's credential can go to another origin for one approved request.
- An MCP server with four tools (`credentials.list`, `http.request`, `access.request`, `access.status`) and a REST API with a generated OpenAPI document.
- The `clavifer` command: login, named profiles, a stdio MCP bridge, `run` to start a program with granted secret fields in its environment, `request` and `status --wait`, and `doctor`. Tokens are kept in the operating system's credential store. Verified on Windows; the macOS and Linux builds are not verified on real machines.
- A web console for the Owner, in Chinese.
- Backups encrypted with age: manual export, restore into an empty deployment, and automatic backups to R2 with daily and monthly retention.
- An audit log whose rows carry the request ID returned in the `x-request-id` response header.
- A Skill for agent hosts and install scripts for the command line client and the Skill on Windows.
