#!/usr/bin/env node
/**
 * Multitenant Streamable HTTP bridge over keeper-security/ksm-mcp.
 *
 * Why this exists:
 *   Keeper's MCP server is stdio-ONLY — there is no HTTP or SSE listener
 *   anywhere in its source (the `EXPOSE 8080` in its own Dockerfile is
 *   vestigial) — and it reads KSM_CONFIG_BASE64 at process start, which makes
 *   it single-tenant per process. The conduit gateway forwards per-tenant
 *   credentials as HTTP headers on every request, so this bridge:
 *
 *   1. Listens on :8080 with POST /mcp and GET /health.
 *   2. 401-gates requests missing or malformed X-Keeper-Config-Base64.
 *   3. Lazily spawns one `ksm-mcp serve --batch` child per credential and
 *      holds an MCP client session over stdio to each (15-min idle eviction).
 *   4. Re-serves the child's tool surface over Streamable HTTP (dual-era),
 *      filtered through the read-only allowlist in tools.ts.
 *
 *   v1 is deliberately READ-ONLY. See tools.ts for why that boundary has to
 *   live here rather than in the upstream.
 */
import { createBridgeHttpServer } from "./http.js";
import { ChildPool } from "./pool.js";

const PORT = Number(process.env.PORT ?? process.env.MCP_HTTP_PORT ?? 8080);
const HOST = process.env.MCP_HTTP_HOST ?? "0.0.0.0";

const pool = new ChildPool();
const { httpServer, closeMcpHandler } = createBridgeHttpServer(pool);

httpServer.listen(PORT, HOST, () => {
  process.stderr.write(`[ksm] keeper-mcp bridge listening on http://${HOST}:${PORT}/mcp (read-only)\n`);
});

async function shutdown(signal: string): Promise<void> {
  process.stderr.write(`[ksm] received ${signal}, shutting down\n`);
  try {
    await closeMcpHandler();
    await pool.shutdown();
    await new Promise<void>((resolve, reject) => {
      httpServer.close((err) => (err ? reject(err) : resolve()));
    });
  } finally {
    process.exit(0);
  }
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
