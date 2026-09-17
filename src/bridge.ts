/**
 * Thin per-request MCP server that delegates to a tenant's child session,
 * with the read-only tool policy applied on the way through.
 *
 * The v2 SDK's `createMcpHandler(factory, { legacy: 'stateless' })` runs the
 * factory once per HTTP request — for BOTH protocol eras (2025-era classic
 * `initialize` handshake clients, served statelessly, and modern 2026-07-28
 * envelope clients, served natively). The factory reads the gateway's
 * per-request credential header and returns a thin Server whose `tools/list`
 * and `tools/call` handlers delegate to the pooled child MCP session for that
 * tenant.
 *
 * Tool names pass through unchanged; the SURFACE does not. Both directions are
 * filtered against `tools.ts`:
 *   - tools/list omits blocked tools and strips write-capable arguments from
 *     the schemas it does return.
 *   - tools/call refuses blocked tools outright, and re-strips those same
 *     arguments so a client working from a stale or ignored schema still
 *     cannot reach a write path.
 */
import { Server, type McpServerFactory } from "@modelcontextprotocol/server";
import { resolveCredentials, type KeeperCredentials } from "./credentials.js";
import { ALLOWED_TOOLS, filterTools, isAllowed, refusalMessage, stripToolArgs } from "./tools.js";
import type { ChildPool } from "./pool.js";

export const SERVER_NAME = "keeper-mcp";
export const SERVER_VERSION = "1.0.0";

const MISSING_CREDS_MESSAGE =
  "Missing Keeper credentials. Send X-Keeper-Config-Base64 with the base64 device " +
  "configuration from Keeper Vault > Secrets Manager > your application > Devices.";

const INSTRUCTIONS =
  `Keeper Secrets Manager, served read-only. ${Object.keys(ALLOWED_TOOLS).length} tools are ` +
  "available for finding and reading vault records: list_secrets, search_secrets and " +
  "list_folders return metadata; get_secret, get_field (KSM notation) and get_totp_code " +
  "return credential material; download_file returns attachments inline. Creating, " +
  "modifying and deleting vault data is not exposed, and neither is the bulk " +
  "unmasked-export tool. Scope is set by the Keeper application's own folder access and " +
  "record permissions — this server can never reach beyond them. Treat every value " +
  "returned as live credential material: do not echo it into tickets, commits or logs.";

/**
 * Create a fresh thin server bound to one tenant's credentials.
 *
 * `creds` may be absent only on paths the HTTP 401 gate did not cover
 * (defensive); handlers then answer a clear error instead of ever falling
 * through to environment credentials — that would be a cross-tenant leak.
 */
export function createBridgeServer(pool: ChildPool, creds?: KeeperCredentials): Server {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} }, instructions: INSTRUCTIONS },
  );

  server.setRequestHandler("tools/list", async () => {
    if (!creds) throw new Error(MISSING_CREDS_MESSAGE);
    const client = await pool.getSession(creds);
    const { tools } = await client.listTools();
    return { tools: filterTools(tools) };
  });

  server.setRequestHandler("tools/call", async (request) => {
    if (!creds) throw new Error(MISSING_CREDS_MESSAGE);

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
        arguments: stripToolArgs(toolName, request.params.arguments),
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

/** Bind the pool into the McpServerFactory shape `createMcpHandler` consumes. */
export function makeMcpServerFactory(pool: ChildPool): McpServerFactory {
  return (ctx) => {
    const { creds } = resolveCredentials(
      (name) => ctx.requestInfo?.headers.get(name) ?? undefined,
    );
    return createBridgeServer(pool, creds);
  };
}
