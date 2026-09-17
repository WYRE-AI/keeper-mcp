# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `package.json`/`package-lock.json` still had the pre-org-transfer
  `@wyre-technology/keeper-mcp` scope and `repository.url`. The Release
  workflow started failing (`SemanticReleaseError: The git repository URL
  mismatches the GitHub URL` — `@semantic-release/github`'s
  `verifyConditions` fails closed on a mismatch between the configured
  `repositoryUrl` and the GitHub API context it authenticates against).
  Repointed both to `WYRE-AI`; safe since this package is `private: true`
  and never actually published. `server.json`, the `ghcr.io` image refs and
  reusable-workflow source in `.github/workflows/release.yml`, and
  `add-to-project.yml`'s `project-url` still reference `wyre-technology`
  and need a separate, more careful pass — not fixed here since none of
  them are what's currently breaking releases.

### Added

- Initial multitenant Streamable HTTP bridge over Keeper's Secrets Manager MCP
  server (`Keeper-Security/keeper-mcp-golang-docker`, pinned `v2.5.0`, built from
  source). The upstream is stdio-only and single-tenant per process; the bridge
  spawns one `ksm-mcp serve --batch` child per tenant credential, holds an MCP
  client session to each over stdio, and re-serves it on `POST /mcp`.
- Dual-era serving via `createMcpHandler(factory, { legacy: 'stateless' })` —
  both 2025-era `initialize`-handshake clients (the conduit gateway today) and
  modern 2026-07-28 envelope clients.
- `X-Keeper-Config-Base64` credential contract with a 401 gate that validates
  the config decodes to a usable KSM device configuration (`clientId`,
  `privateKey`, `appKey`) before any child is spawned. No fall-through to
  environment credentials.
- **Read-only v1 tool policy** (`src/tools.ts`): 9 read tools served, 10 blocked,
  default-deny in both dimensions — unlisted tools are refused, and each served
  tool declares the exact arguments it accepts, so a new upstream argument fails
  closed rather than passing through.
- `GET /health` reporting mode, served tool count and live tenant count without
  spawning a child.
- `scripts/check-upstream-tools.mjs`, run during the Docker build: re-derives the
  upstream tool surface from the pinned Go source and fails the build on any
  drift (new tool, renamed tool, or new argument on a served tool). The pin bump
  is enforced rather than left to a checklist.
- Build-time smoke tests: the upstream binary runs, and it still reads
  `KSM_CONFIG_BASE64`.

### Security

- `search_secrets` is documented and classified as an **admin**-tier credential
  read, not metadata. Its result is metadata-shaped (`{uid,title,type,folder}`)
  but its match runs case-insensitive substring over the record's notes and the
  values of its `login`/`url`/`hostname`/`address` fields, so a caller can test
  whether a secret contains a given substring without receiving it — a
  confirmation oracle (CWE-200). The matching is inside Keeper's binary and
  cannot be narrowed from the bridge; the server `instructions` now say so
  explicitly so a model does not treat a hit as a neutral metadata result.

- `get_all_secrets_unmasked` and `ksm_execute_confirmed_action` are blocked
  permanently, including in any future write-enabled release. The latter is the
  keystone: it executes an arbitrary named tool with a `user_decision` flag the
  *caller* supplies, so allowing it would collapse every other rule into one
  name.
- `get_record_type_schema` and `download_file` are blocked because they are
  broken upstream at this pin, not merely out of scope — record templates are
  never loaded, and `download_file` writes to a server-side path and never
  returns the bytes.
- Each tenant's child gets its own `HOME` subdirectory, so upstream's on-disk
  profile-store fallback can never become a shared surface.
- The `prompts` capability is deliberately never declared, which makes upstream's
  entire prompt surface — including the `ksm_confirm_action` confirmation flow —
  unreachable through this bridge by construction.
- Idle children are evicted after 15 minutes, shorter than the fleet's 60-minute
  default, to bound how long an authenticated KSM session lives in memory.
  `tools/list` is memoized process-wide so merely browsing the surface never
  spawns a child or opens a KSM session.
- Credential-validation errors describe the shape of the problem only; they never
  echo any part of the supplied config.

### Notes

- The strongest control for this vendor is **not** in this repo: a KSM
  application whose shares are non-editable rejects every write at Keeper's own
  server. That is a documented provisioning precondition of the credential
  contract — the bridge cannot verify it, because `ksm-mcp` never surfaces the
  SDK's per-record `IsEditable`.
