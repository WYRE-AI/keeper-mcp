/**
 * HTTP layer: routing, CORS, health, the S2S gate, and the gateway 401 gate.
 *
 * The S2S check and the credential 401 rejection both live HERE, before the
 * MCP handler ever runs — `createMcpHandler` has no auth hooks, and a
 * throwing factory would surface as a 500. A missing/invalid S2S header or a
 * missing or malformed credential header must answer 401 with a JSON-RPC
 * error body and must NEVER fall through to environment credentials
 * (cross-tenant leak).
 *
 * This bridge is gateway mode only. There is no AUTH_MODE=env fallback:
 * X-Keeper-Config-Base64 is the only credential source. Startup
 * (http-startup.ts) refuses to listen without a real CONDUIT_S2S_SECRET
 * unless MCP_ALLOW_INSECURE_DEV=1, which binds 127.0.0.1 and skips S2S.
 * An empty secret reaches this handler only on that bypass. A known
 * placeholder is not a usable HMAC key — /mcp is rejected rather than
 * verified against a public value.
 */
import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { createMcpHandler, type McpHttpHandler } from "@modelcontextprotocol/server";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { makeMcpServerFactory, SERVER_VERSION } from "./bridge.js";
import { GATEWAY_HEADERS, resolveCredentials } from "./credentials.js";
import { ALLOWED_TOOL_NAMES } from "./tools.js";
import { verifyS2sHeader, S2S_HEADER } from "./s2s-verify.js";
import { isKnownPlaceholderSecret } from "./http-startup.js";
import type { ChildPool } from "./pool.js";
import { MAX_REQUEST_BODY_BYTES } from "./input-limits.js";

const CORS_ALLOW_HEADERS = [
  "Content-Type",
  "Accept",
  "Authorization",
  "Mcp-Session-Id",
  "Mcp-Protocol-Version",
  "X-Gateway-S2S",
  ...GATEWAY_HEADERS,
].join(", ");

export interface BridgeHttp {
  httpServer: HttpServer;
  /** Close the MCP handler (call before closing the HTTP server). */
  closeMcpHandler: () => Promise<void>;
}

export interface BridgeHttpOptions {
  /**
   * Resolved S2S secret. Pass "" for the insecure-dev bypass. When omitted,
   * the value is read from CONDUIT_S2S_SECRET at call time (not module load).
   */
  s2sSecret?: string;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  return typeof raw === "string" && raw.length > 0 ? raw : undefined;
}

const logError =
  (label: string) =>
  (error: unknown): void => {
    process.stderr.write(
      `[ksm] MCP ${label} error: ${error instanceof Error ? error.message : String(error)}\n`,
    );
  };

export function createBridgeHttpServer(pool: ChildPool, options: BridgeHttpOptions = {}): BridgeHttp {
  const rawFromEnv = process.env.CONDUIT_S2S_SECRET || "";
  const configured = (options.s2sSecret !== undefined ? options.s2sSecret : rawFromEnv).trim();
  // Fail closed for direct callers that skip evaluateHttpStartup(). Only an
  // explicit `s2sSecret: ""` (the insecure-dev decision from startup) may
  // build a server that skips X-Gateway-S2S. The secret value is never logged.
  if (configured === "" && options.s2sSecret !== "") {
    throw new Error(
      "CONDUIT_S2S_SECRET is required to serve /mcp over HTTP. Pass s2sSecret: \"\" only for the MCP_ALLOW_INSECURE_DEV=1 bypass.",
    );
  }
  // A known placeholder must not be the HMAC key. Treat it as "enforce, but
  // no key matches" so a caller that skipped startup still fails closed.
  const placeholderSecret = configured !== "" && isKnownPlaceholderSecret(configured);
  const s2sSecret = configured !== "" && !placeholderSecret ? configured : "";

  const mcpHandler: McpHttpHandler = createMcpHandler(makeMcpServerFactory(pool), {
    legacy: "stateless", // dual-era posture — never 'reject' on fleet servers
    maxRequestBodySize: MAX_REQUEST_BODY_BYTES,
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
      // Empty s2sSecret skips the check only for the insecure-dev bypass.
      // A placeholder sets placeholderSecret and fails this branch closed.
      // A configured secret is always enforced, before credential extraction.
      if (
        placeholderSecret ||
        (s2sSecret && !verifyS2sHeader(headerValue(req.headers[S2S_HEADER]), s2sSecret))
      ) {
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

      // Body cap, after S2S so unauthenticated callers still get 401 first.
      const declaredLength = Number(headerValue(req.headers["content-length"]));
      if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32600, message: `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes` },
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
