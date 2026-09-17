# keeper-mcp

Multitenant Streamable HTTP bridge over [Keeper-Security/keeper-mcp-golang-docker](https://github.com/Keeper-Security/keeper-mcp-golang-docker) — Keeper's official Secrets Manager MCP server — built so the WYRE conduit gateway can forward per-tenant Keeper credentials as HTTP headers.

> **Upstream pin:** **`v2.5.0`** (MIT), built from source. See [Bumping the upstream pin](#bumping-the-upstream-pin).
>
> **v1 is READ-ONLY.** See [Read-only in v1](#read-only-in-v1--deliberate-and-load-bearing) — for this vendor that is a security boundary, not a scoping decision.

## Why

Keeper's server is **stdio-only**. There is no HTTP or SSE listener anywhere in its source — the `EXPOSE 8080` in its own Dockerfile is vestigial, and its `docker-entrypoint.sh` is unreachable because the published image is `FROM scratch` with no shell. It reads its credential from `KSM_CONFIG_BASE64` at process start, which makes it single-tenant per process.

Our gateway is multi-tenant: every request carries the calling org's credentials as HTTP headers, and the vendor container has to translate those headers into something the upstream understands.

Because the upstream has no HTTP mode to proxy to, this bridge holds an **MCP client session over stdio** to each tenant child and re-serves it over Streamable HTTP:

1. Listens on `:8080` with `POST /mcp` and `GET /health`.
2. 401-gates every `/mcp` request on `X-Keeper-Config-Base64` — including validating that it decodes to a usable KSM config. Missing/invalid credentials never fall through to environment credentials; that would be a cross-tenant leak.
3. Lazily spawns one `ksm-mcp serve --batch` child per credential (keyed by a hash), with the tenant's `KSM_CONFIG_BASE64` set, and connects an MCP client to it over stdio.
4. Serves both protocol eras on `/mcp` via the v2 SDK's `createMcpHandler(factory, { legacy: 'stateless' })` — 2025-era `initialize`-handshake clients (the conduit gateway today) and modern 2026-07-28 envelope clients.
5. Filters the child's surface through a read-only allowlist in both directions.
6. Evicts idle children after 15 minutes (`IDLE_EVICT_MS`).

Tool names **pass through unchanged**.

## Read-only in v1 — deliberate, and load-bearing

Keeper's upstream gates its destructive tools behind an interactive confirmation. In a container there is no TTY, and `internal/ui/confirm.go` collapses to exactly two behaviours:

| Setting | Effect |
|---|---|
| batch/auto-approve **off** | Every confirm-requiring tool hard-errors: *"interactive confirmation via terminal is not supported"*. That includes `get_secret` with `unmask: true` — the integration is useless. |
| batch/auto-approve **on** | **Every** confirmation is auto-approved, including `delete_secret` and `get_all_secrets_unmasked`. |

Keeper's own Docker documentation tells you to set `KSM_MCP_BATCH_MODE=true`. This bridge does too, because it has to — which means the upstream offers no safe middle setting and **the only possible safety boundary is this bridge's allowlist** (`src/tools.ts`). That is why v1 ships read-only.

### Served (11)

| Tool | Conduit tier | Note |
|---|---|---|
| `list_secrets` | read | Record metadata only |
| `search_secrets` | read | Metadata search |
| `list_folders` | read | Folder metadata |
| `get_record_type_schema` | read | Static schemas, no vault data |
| `health_check` | read | |
| `get_server_version` | read | |
| `get_secret` | admin | Returns a record; `unmask` honoured |
| `get_field` | admin | KSM notation query — the narrowest read |
| `get_totp_code` | admin | Live second factor |
| `download_file` | admin | Attachment inline; `save_path` **stripped** |
| `generate_password` | admin | `save_to_secret` + `folder_uid` **stripped** |

Conduit classifies credential reads as `admin` (`src/access/tool-classification.ts`), which outranks `write`. A Keeper read is a credential read by definition.

### Blocked (8)

`create_secret`, `update_secret`, `delete_secret`, `create_folder`, `delete_folder`, `upload_file`, `ksm_execute_confirmed_action`, `get_all_secrets_unmasked`

Two of those stay blocked **even in a write-enabled v2**:

- **`get_all_secrets_unmasked`** — one call that dumps every secret in the application's scope, unmasked, into the model's context.
- **`ksm_execute_confirmed_action`** — the upstream's confirmation-bypass executor.

### Argument stripping

Stripped from both the advertised `inputSchema` and the inbound `tools/call` arguments, so a client working from a stale or ignored schema still cannot reach a write path:

- `generate_password`: `save_to_secret`, `folder_uid` — these turn a local utility into a record **create**.
- `download_file`: `save_path` — would write tenant-controlled paths into a container filesystem shared with every other tenant's child.

Enabling writes is a reviewed, versioned change to the table in `src/tools.ts` plus the matching `VENDOR_TOOL_CONFIG` rows in conduit. Not a config flip, not an env var.

## Credential contract

The gateway forwards this header on every `/mcp` request. **conduit's vendor-config must match exactly.**

| Header | Child env var | Required |
|---|---|---|
| `X-Keeper-Config-Base64` | `KSM_CONFIG_BASE64` | yes |

The value is the base64 **device configuration** from Keeper Vault → Secrets Manager → *your application* → **Devices** → *Add Device* (it starts `ewog...`).

**Validity rule:** standard base64 that decodes to a flat JSON object of string values containing `clientId`, `privateKey` and `appKey`. `hostname` is optional — verified against upstream `internal/ksm/client.go` `InitializeWithConfig`, which requires exactly those three. Anything else → **HTTP 401** with a JSON-RPC error body that never echoes the supplied value back.

The bridge also forces on every child:

```
KSM_MCP_BATCH_MODE=true      # no TTY in a container (see above)
KSM_MCP_LOG_LEVEL=error
argv: ["serve", "--batch"]
```

`KSM_MCP_PROFILE` is deliberately **not** set: with `KSM_CONFIG_BASE64` present, upstream builds an in-memory profile and never touches the on-disk profile store, which is what keeps tenants from sharing state through the filesystem.

## Blast radius lives in Keeper, not here

This server can never reach beyond what the KSM **application** itself can see. Scope is set by that application's Folder Access and Record Permissions in the Keeper vault. Grant the narrowest folder set and read-only record permissions that the use case needs — that, not this bridge, is the real control.

## Configuration

| Env var | Default | Notes |
|---|---|---|
| `PORT` | `8080` | Public listen port. |
| `KSM_MCP_BIN` | `/usr/local/bin/ksm-mcp` | Upstream binary the bridge spawns. |
| `CHILD_HOME` | `/tmp/ksm-mcp-home` | Writable `HOME` for children. |
| `IDLE_EVICT_MS` | `900000` | Idle tenant timeout (15 min). Shorter than nutanix-mcp's 60 min on purpose: the Go child restarts in milliseconds, and every minute one stays open is a minute an authenticated KSM session sits in memory. |
| `SPAWN_TIMEOUT_MS` | `30000` | Max wait for a child to answer the MCP handshake. |

## Endpoints

- `POST /mcp` — Streamable HTTP MCP, dual-era. Requires the credential header.
- `GET /health` — unauthenticated liveness. Reports `mode`, served tool count, and live tenant count. Never spawns a child.

## Development

```bash
npm install
npm run lint     # tsc --noEmit
npm test         # vitest
npm run build
```

The test suite covers the allowlist policy, the credential contract, and the 401 gate over the real HTTP stack. None of it needs a Keeper account or a running child — the pool is pointed at a nonexistent binary so any accidental spawn fails loudly.

## Bumping the upstream pin

1. Change `KSM_MCP_REF` in the `Dockerfile`.
2. Diff the upstream, **paying particular attention to `internal/mcp/tools.go`**. New upstream tools default to blocked (they are simply absent from `ALLOWED_TOOLS`) — but they must be triaged into `src/tools.ts` explicitly, and the coverage test in `src/__tests__/tools.test.ts` asserts every upstream tool is accounted for as either allowed or blocked. Update that fixture list as part of the bump.
3. Re-run the build; both build-time smoke tests must pass.
4. Cut a release, then re-pin the digest in conduit's `azure/vendor-fleet.conduit-prod.bicepparam`.

Never track `main`, and never pull `keeper/keeper-mcp-server:latest` — the pin is a reviewed git tag we build ourselves.

## License

Apache-2.0 (this bridge). The upstream Keeper server is MIT and is built from source at image build time.
