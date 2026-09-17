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

### Boundary 1 (the strong one): a read-only KSM application

**Provision the Keeper application with non-editable shares.** A KSM application's
shared-folder grant is read-only unless explicitly made editable
(`secrets-manager share add --app <APP> --secret <FOLDER_UID>`; the Vault's Application
Access panel shows `Read-Only` vs `Editable`). With a non-editable grant, every write
fails at Keeper's own server — regardless of this bridge, its allowlist, batch mode, or
prompt injection.

This is a **provisioning precondition of the credential contract**, not a nice-to-have.
The bridge cannot verify it: the Keeper SDK carries `IsEditable` per record, but
`ksm-mcp` never reads it, so nothing here can detect an over-granted application. Scope
the application to the narrowest folder set the use case needs, read-only, and treat that
as the real control.

### Boundary 2: this bridge's allowlist

Keeper's upstream has no read-only mode — verified against the v2.5.0 pin: `serve` has six
flags and none restrict the surface, `getAvailableTools()` returns a hardcoded 19-element
slice that consults no config, and `Confirmation.DefaultDeny` is hardcoded false with no
plumbing. Nothing upstream can un-register a tool.

**On batch mode.** Keeper's own Docker documentation tells you to set
`KSM_MCP_BATCH_MODE=true`, and this bridge does. What that actually changes:

| Batch mode | Behaviour |
|---|---|
| **off** | `get_field` + `unmask` hard-errors (the single `Confirmer` call site upstream). The other eight confirm-requiring tools return a *successful* `{status: "confirmation_required"}` result pointing at the `ksm_confirm_action` prompt, expecting a two-phase completion. |
| **on** | Every confirmation is auto-approved, `delete_secret` included. |

Leaving it off would not buy a confirmation boundary here, because that two-phase flow is
unreachable through this bridge by construction: it is driven by an MCP *prompt*, and the
bridge never declares the `prompts` capability — and the tool that completes it,
`ksm_execute_confirmed_action`, is blocked below. So "off" yields stubs no client here can
satisfy, not safety. We force it on and put the boundary in `src/tools.ts` instead.

**What the allowlist uniquely buys, which a read-only grant does not:** blocking
`get_all_secrets_unmasked` and `ksm_execute_confirmed_action`. Both are reads-or-worse
that a read-only grant happily permits.

### Served (9)

| Tool | Conduit tier | Note |
|---|---|---|
| `list_secrets` | read | Record metadata only |
| `list_folders` | read | Folder metadata |
| `health_check` | read | |
| `get_server_version` | read | |
| `search_secrets` | admin | Metadata-shaped result, but matches on notes and `login`/`url`/`hostname`/`address` **values** — a confirmation oracle over secrets (CWE-200) |
| `get_secret` | admin | Returns a record; `unmask` honoured |
| `get_field` | admin | KSM notation query — the narrowest read |
| `get_totp_code` | admin | Live second factor |
| `generate_password` | admin | Local generation; record-creating args removed |

Conduit classifies credential reads as `admin` (`src/access/tool-classification.ts`), which
outranks `write`. A Keeper read is a credential read by definition.

### Blocked (10)

`create_secret`, `update_secret`, `delete_secret`, `create_folder`, `delete_folder`,
`upload_file`, `ksm_execute_confirmed_action`, `get_all_secrets_unmasked`,
`get_record_type_schema`, `download_file`

Four are worth explaining:

- **`ksm_execute_confirmed_action`** — not a peer of the others but the keystone. It takes
  `original_tool_name` plus a `user_decision` boolean **the caller supplies**, with no
  nonce and no correlation to any prompt, then dispatches straight into the confirmed
  executors. Allowing it would collapse every other rule here into one name. Blocked
  permanently.
- **`get_all_secrets_unmasked`** — one call that returns every secret in the application's
  scope, unmasked, into the model's context. Blocked permanently.
- **`get_record_type_schema`** — non-functional upstream at v2.5.0:
  `LoadRecordTemplates()` has no callers and the package has no `init()`, so every call
  returns "record templates not loaded".
- **`download_file`** — cannot work over MCP. Upstream's `DownloadFile(uid, fileUID,
  savePath)` returns only an `error` and writes bytes to a server-side path; the handler
  returns `{uid, file_uid, path, message}`, never the file. Honouring `save_path` would let
  a tenant write attacker-chosen paths into a container filesystem shared with every other
  tenant's child, and removing it leaves nowhere to write.

### Argument policy: allowlist, not blocklist

Each served tool declares the exact arguments it accepts (`allowArgs` in `src/tools.ts`),
enforced on both the advertised `inputSchema` and the inbound `tools/call`. A client
working from a stale or ignored schema therefore cannot reach a write path by passing an
argument anyway.

The default matters more than the current entries: when an upstream bump adds a parameter
to an already-served tool, it **fails closed** — it vanishes from the surface until
someone reviews it into the table — rather than passing through silently. Today the only
removals are `generate_password`'s `save_to_secret` and `folder_uid`, which would turn a
local utility into a record create.

Enabling writes is a reviewed, versioned change to `src/tools.ts` plus the matching
`VENDOR_TOOL_CONFIG` rows in conduit. Not a config flip, not an env var.

## Credential contract

The gateway forwards this header on every `/mcp` request. **conduit's vendor-config must match exactly.**

| Header | Child env var | Required |
|---|---|---|
| `X-Keeper-Config-Base64` | `KSM_CONFIG_BASE64` | yes |

The value is the base64 **device configuration** from Keeper Vault → Secrets Manager → *your application* → **Devices** → *Add Device* (it starts `ewog...`).

> **Precondition:** the application this device belongs to must hold **read-only
> (non-editable) shares**. See [Boundary 1](#boundary-1-the-strong-one-a-read-only-ksm-application)
> — it is the strongest control in the system and the bridge cannot verify it for you.

**Validity rule:** standard base64 that decodes to a flat JSON object of string values containing `clientId`, `privateKey` and `appKey`. `hostname` is optional — verified against upstream `internal/ksm/client.go` `InitializeWithConfig`, which requires exactly those three. Anything else → **HTTP 401** with a JSON-RPC error body that never echoes the supplied value back.

The bridge also forces on every child:

```
KSM_MCP_BATCH_MODE=true      # no TTY in a container (see above)
KSM_MCP_LOG_LEVEL=error
argv: ["serve", "--batch"]
```

`KSM_MCP_PROFILE` is deliberately **not** set: with `KSM_CONFIG_BASE64` present, upstream builds an in-memory profile and never touches the on-disk profile store, which is what keeps tenants from sharing state through the filesystem.

## Configuration

| Env var | Default | Notes |
|---|---|---|
| `PORT` | `8080` | Public listen port. |
| `KSM_MCP_BIN` | `/usr/local/bin/ksm-mcp` | Upstream binary the bridge spawns. |
| `CHILD_HOME` | `/tmp/ksm-mcp-home` | Root under which each tenant gets its **own** `HOME` subdirectory, created at spawn. |
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
2. Rebuild. `scripts/check-upstream-tools.mjs` runs in the Docker build, re-derives the tool surface from the pinned Go source, and **fails the build** on any drift — a new tool, a renamed one, or a new argument on an already-served tool. This is enforcement, not a checklist item.
3. Triage whatever it reports into `src/tools.ts` and `src/__tests__/fixtures.ts`. New tools are default-denied by the allowlist, but they still need an explicit decision recorded.
4. Re-run the build; both build-time smoke tests and the drift check must pass.
5. Cut a release, then re-pin the digest in conduit's `azure/vendor-fleet.conduit-prod.bicepparam`.

Never track `main`, and never pull `keeper/keeper-mcp-server:latest` — the pin is a reviewed git tag we build ourselves.

## License

Apache-2.0 (this bridge). The upstream Keeper server is MIT and is built from source at image build time.
