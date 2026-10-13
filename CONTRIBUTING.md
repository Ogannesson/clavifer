# Contributing

Clavifer is a small project with one maintainer. Bug fixes, tests, and documentation corrections are welcome. For a new feature, open an issue first and describe the use case: the project prefers leaving something out to carrying it.

Security problems do not go through issues or pull requests. See [SECURITY.md](SECURITY.md).

## Development setup

[Part A of docs/deploy.md](docs/deploy.md#part-a-local-trial) sets up a local instance: dependencies, local secrets, the local database, and the first Owner. It needs Node.js and git and no Cloudflare account.

Work on the command line client also needs Go, in the version `go.mod` names. The install scripts and `npm run test:system` need PowerShell 7.

The layout of the repository and the project's conventions are in [AGENTS.md](AGENTS.md), which is written for the coding agents that work on the code and is the authority for both.

## Checks before a pull request

These are the checks CI runs on Linux and Windows. Run them locally before you open a pull request.

| Command                            | What it checks                                                                                                     | Where it runs  |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------- |
| `npm run format:check`             | Prettier formatting. Markdown files are excluded.                                                                  | Linux, Windows |
| `npm run check`                    | Worker type generation and TypeScript                                                                              | Linux, Windows |
| `npm test`                         | Unit tests, with an in-process D1 database                                                                         | Linux, Windows |
| `npm run openapi:check`            | The committed `packages/contracts/openapi.json` matches the generated one                                          | Linux, Windows |
| `gofmt -l cmd/`                    | Go formatting; must print nothing                                                                                  | Linux, Windows |
| `go vet ./...` and `go test ./...` | The command line client                                                                                            | Linux, Windows |
| `npm run test:e2e`                 | End-to-end tests against an isolated local database, with the command line client; no external services            | Linux, Windows |
| `npm run test:system`              | The command line client against the real Windows Credential Manager. It writes synthetic entries and removes them. | Windows only   |

A few scripts are run by hand and are not part of CI:

- `scripts/build-cli-matrix.ps1` cross-compiles the command line client for Windows, Linux and macOS on amd64 and arm64. Nothing else checks that the macOS and arm64 builds compile.
- `scripts/test-installer.ps1` tests `integrations/adapters/install-skill.ps1` in a sandbox directory. It needs PowerShell 7.
- `scripts/e2e-backup.mjs` and `scripts/e2e-origin-change.mjs` are acceptance runs against a local database, for backups and for a deployment whose `APP_ORIGIN` changes. Run `npm run build` first.

One more check is not part of CI:

| Command              | What it checks                                                                                       | Where it runs                                           |
| -------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `npm run test:hosts` | Starts the local Codex and Claude Code to check that they discover the MCP tools. It calls no model. | A machine with both installed; verified on Windows only |

If you cannot run a check, for example `test:system` on Linux or macOS, say so in the pull request.

Tests use synthetic credentials only. Never put a real credential, token, or the contents of `.dev.vars` into a test, a fixture, a commit, or an issue.

## Conventions

- **Migrations only grow.** Add a new numbered file in `migrations/`. Never edit a migration that has been released.
- **Change the documentation with the behavior.** When a change alters what a sentence in `README.md` or `docs/` says, correct that sentence in the same pull request. Do not add a long new document for it. The same goes for what agents read: the tool descriptions and server instructions in `apps/worker/src/mcp.ts`, and the Skill in `integrations/skills/clavifer/`.
- **Regenerate the contract.** After changing a route or a request schema, run `npm run openapi:generate` and commit the result.
- **Keep decisions on the server.** Grants decide what an installation may do; OAuth scopes do not. The decision for a connection request stays in `decide()` and `invoke()` in `apps/worker/src/vault.ts`, so that real requests and draft tests share it.
- **Two stored identifiers never change.** The additional authenticated data of every encrypted secret starts with `agent-credentials` (`packages/core/crypto.ts`), and the backup format identifier is `agent-credentials-backup-v1` (`apps/worker/src/backup.ts`). Both carry the project's former name. Renaming either would make existing data unreadable.

Three rules for engineering trade-offs:

1. **Do not add what is not needed.** Before adding a step, a script, an abstraction, or a setting, ask what breaks without it.
2. **Validate only what can change.** User input and responses from external services are worth checking. A pinned dependency or the toolchain is not.
3. **No defensive fallbacks.** Do not add a fallback for a failure that should not happen. Fix the problem at its source.

## Commits and pull requests

- One logical change per pull request.
- Write the commit subject as a type and a plain sentence that says what changed, such as `fix: a free rule no longer runs outside the allowed paths`. The types in use are `feat`, `fix`, `docs`, `test`, `refactor`, and `chore`.
- In the pull request, say what changed and why, and which checks you ran.
- A change in behavior comes with a test that fails without it.

## License

Clavifer is licensed under the [Apache License 2.0](LICENSE). Contributions are accepted under the same license, as section 5 of the license states. There is no contributor license agreement and no sign-off requirement.
