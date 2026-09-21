/**
 * HTTP layer: routing, CORS, health, the S2S gate, and the gateway 401 gate.
 *
 * The S2S check and the credential 401 rejection both live HERE, before the
 * MCP handler ever runs — `createMcpHandler` has no auth hooks, and a
 * throwing factory would surface as a 500. A missing/invalid S2S header or a
 * missing or malformed credential header must answer 401 with a JSON-RPC
 * error body and must NEVER fall through to environment credentials
 * (cross-tenant leak).
 */
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { createMcpHandler, type McpHttpHandler } from "@modelcontextprotocol/server";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { makeMcpServerFactory, SERVER_VERSION } from "./bridge.js";
import { GATEWAY_HEADERS, resolveCredentials } from "./credentials.js";
import { ALLOWED_TOOL_NAMES } from "./tools.js";
import { verifyS2sHeader, S2S_HEADER } from "./s2s-verify.js";
import type { ChildPool } from "./pool.js";

const S2S_SECRET = process.env.CONDUIT_S2S_SECRET || "";

const CORS_ALLOW_HEADERS = [
  "Content-Type",
  "Accept",
  "Authorization",
  "Mcp-Session-Id",
  "Mcp-Protocol-Version",
  ...GATEWAY_HEADERS,
].join(", ");

export interface BridgeHttp {
  httpServer: HttpServer;
  /** Close the MCP handler (call before closing the HTTP server). */
  closeMcpHandler: () => Promise<void>;
}

const logError =
  (label: string) =>
  (error: unknown): void => {
    process.stderr.write(
      `[ksm] MCP ${label} error: ${error instanceof Error ? error.message : String(error)}\n`,
    );
  };

export function createBridgeHttpServer(pool: ChildPool): BridgeHttp {
  const mcpHandler: McpHttpHandler = createMcpHandler(makeMcpServerFactory(pool), {
    legacy: "stateless", // dual-era posture — never 'reject' on fleet servers
    onerror: logError("serving"),
  });
  const handleMcp = toNodeHandler(mcpHandler, { onerror: logError("request adapter") });

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE");
    res.setHeader("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS);
    res.setHeader("Access-Control-Max-Age", "86400");
    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

    // Shallow, unauthenticated liveness probe. Must not touch credentials or
    // spawn children — credentials only arrive per-request via headers.
    if (url.pathname === "/health" || url.pathname === "/healthz") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ok",
          version: SERVER_VERSION,
          mode: "read-only",
          tools: ALLOWED_TOOL_NAMES.length,
          tenants: pool.size,
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    if (url.pathname === "/mcp") {
      if (S2S_SECRET && !verifyS2sHeader(req.headers[S2S_HEADER] as string | undefined, S2S_SECRET)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: {
              code: -32001,
              message: "Unauthorized: missing or invalid X-Gateway-S2S header (this endpoint only accepts requests signed by the gateway).",
              data: { required: [S2S_HEADER] },
            },
            id: null,
          }),
        );
        return;
      }

      const result = resolveCredentials((name) => {
        const value = req.headers[name];
        return Array.isArray(value) ? value[0] : value;
      });
      if (!result.ok) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: {
              code: -32001,
              message: `Unauthorized: ${result.error}`,
              data: { required: GATEWAY_HEADERS },
            },
            id: null,
          }),
        );
        return;
      }

      // The factory re-reads the same header from ctx.requestInfo per request.
      // Cast: the SDK's NodeIncomingMessageLike declares `method?: string`,
      // which node:http's IncomingMessage rejects under strict optionality.
      await handleMcp(req as unknown as Parameters<typeof handleMcp>[0], res);
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found", endpoints: ["/mcp", "/health"] }));
  });

  return { httpServer, closeMcpHandler: () => mcpHandler.close() };
}
