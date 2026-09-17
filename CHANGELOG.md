# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- **Read-only v1 tool policy** (`src/tools.ts`): 11 read tools served, 8 write
  and bulk-export tools blocked, with write-capable arguments stripped from both
  the advertised schemas and inbound calls. Keeper's upstream auto-approves every
  confirmation in batch mode — which a container must use, having no TTY — so
  this allowlist is the only safety boundary in the path.
- `GET /health` reporting mode, served tool count and live tenant count without
  spawning a child.
- Two build-time Docker smoke tests: the upstream binary runs, and it still reads
  `KSM_CONFIG_BASE64`.

### Security

- `get_all_secrets_unmasked` and `ksm_execute_confirmed_action` are blocked and
  remain blocked even in a future write-enabled release.
- Idle children are evicted after 15 minutes, shorter than the fleet's 60-minute
  default, to bound how long an authenticated KSM session lives in memory.
- Credential-validation errors describe the shape of the problem only; they never
  echo any part of the supplied config.
