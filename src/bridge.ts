/**
 * Thin per-request MCP server that delegates to a tenant's child session,
 * with the read-only tool policy applied on the way through.
 *
 * The v2 SDK's `createMcpHandler(factory, { legacy: 'stateless' })` runs the
 * factory once per HTTP request — for BOTH protocol eras (2025-era classic
 * `initialize` handshake clients, served statelessly, and modern 2026-07-28
 * envelope clients, served natively). The factory reads the gateway's
 * per-request credential header and returns a thin Server whose `tools/list`
 * and `tools/call` handlers delegate to the pooled child MCP session.
 *
 * Note what is NOT declared here: `capabilities` contains only `tools`, and
 * only `tools/list` and `tools/call` are registered. Upstream also serves
 * `prompts/list` — including `ksm_confirm_action`, the prompt that drives its
 * confirmation flow — and that entire surface is unreachable through this
 * bridge as a result. That is the one boundary in this repo enforced by
 * construction rather than by name matching; do not add prompt passthrough
 * "for completeness" without re-reading the header of tools.ts.
 */
import { Server, type McpServerFactory } from "@modelcontextprotocol/server";
import type { Client } from "@modelcontextprotocol/client";
import { resolveCredentials, type KeeperCredentials } from "./credentials.js";
import { ALLOWED_TOOL_NAMES, filterTools, isAllowed, pickToolArgs, refusalMessage } from "./tools.js";
import type { ChildPool } from "./pool.js";

export const SERVER_NAME = "keeper-mcp";
export const SERVER_VERSION = "1.0.0";

const INSTRUCTIONS =
  "Keeper Secrets Manager, served read-only. Available tools: " +
  `${ALLOWED_TOOL_NAMES.join(", ")}. ` +
  "list_secrets and list_folders return metadata only; get_secret, get_field " +
  "(KSM notation) and get_totp_code return credential material. search_secrets " +
  "returns only metadata but MATCHES against record notes and login/url/hostname/" +
  "address values, so treat a hit as having revealed that the query string appears " +
  "in a secret. Creating, " +
  "modifying and deleting vault data is not exposed, and neither is the bulk " +
  "unmasked-export tool. Scope is set by the Keeper application's own folder access and " +
  "record permissions — this server can never reach beyond them. Treat every value " +
  "returned as live credential material: do not echo it into tickets, commits or logs.";

/**
 * Process-wide memo of the served tool surface.
 *
 * Upstream's tool table is a hardcoded slice that consults no config, and our
 * filter is static, so the result is identical for every tenant. Without this,
 * a client that merely BROWSES the surface spawns a Keeper child and leaves an
 * authenticated KSM session in memory for the full idle window without ever
 * calling a tool — the opposite of the posture the pool's short eviction
 * window is chosen for.
 *
 * Trade-off accepted: a well-formed config that Keeper nonetheless rejects now
 * surfaces on the first tools/call rather than on tools/list. The 401 gate
 * still catches malformed configs, and a clear error on first use beats the
 * gateway's silent tool-fetch failure.
 */
type ListedTools = Awaited<ReturnType<Client["listTools"]>>["tools"];

class ToolSurfaceCache {
  private tools: ListedTools | null = null;

  async get(load: () => Promise<ListedTools>): Promise<ListedTools> {
    this.tools ??= await load();
    return this.tools;
  }
}

/** Create a fresh thin server bound to one tenant's credentials. */
export function createBridgeServer(
  pool: ChildPool,
  creds: KeeperCredentials,
  toolCache: ToolSurfaceCache,
): Server {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} }, instructions: INSTRUCTIONS },
  );

  server.setRequestHandler("tools/list", async () => ({
    tools: await toolCache.get(async () => {
      const client = await pool.getSession(creds);
      const { tools } = await client.listTools();
      return filterTools(tools);
    }),
  }));

  server.setRequestHandler("tools/call", async (request) => {
    const toolName = request.params.name;
    // Refuse BEFORE touching the pool: a blocked tool must not even cause a
    // child to spawn, and the refusal must not depend on KSM being reachable.
    if (!isAllowed(toolName)) {
      return {
        content: [{ type: "text" as const, text: refusalMessage(toolName) }],
        isError: true,
      };
    }

    const client = await pool.getSession(creds);
    try {
      return await client.callTool({
        ...request.params,
        arguments: pickToolArgs(toolName, request.params.arguments),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text" as const, text: `Keeper MCP call failed: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

/**
 * A server for a request the 401 gate did not cover (defensive — it should be
 * unreachable). Every handler answers the same error, so there is no path on
 * which a missing credential falls through to environment credentials.
 */
function createUnauthorizedServer(): Server {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );
  const refuse = async (): Promise<never> => {
    throw new Error(
      "Missing Keeper credentials. Send X-Keeper-Config-Base64 with the base64 device " +
        "configuration from Keeper Vault > Secrets Manager > your application > Devices.",
    );
  };
  server.setRequestHandler("tools/list", refuse);
  server.setRequestHandler("tools/call", refuse);
  return server;
}

/** Bind the pool into the McpServerFactory shape `createMcpHandler` consumes. */
export function makeMcpServerFactory(pool: ChildPool): McpServerFactory {
  // One cache per handler — process-wide in production, isolated per test.
  const toolCache = new ToolSurfaceCache();
  return (ctx) => {
    const result = resolveCredentials(
      (name) => ctx.requestInfo?.headers.get(name) ?? undefined,
    );
    return result.ok
      ? createBridgeServer(pool, result.creds, toolCache)
      : createUnauthorizedServer();
  };
}
