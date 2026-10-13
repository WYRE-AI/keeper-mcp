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
 *   1. Listens on :8080 with POST /mcp and GET /health. Refuses to start
 *      unless CONDUIT_S2S_SECRET is set to a non-placeholder value.
 *      MCP_ALLOW_INSECURE_DEV=1 is the local-only escape hatch: it logs a
 *      warning and binds 127.0.0.1 only. A real secret honors MCP_HTTP_HOST
 *      (unset keeps 0.0.0.0).
 *   2. 401-gates /mcp on X-Gateway-S2S, then on a missing or malformed
 *      X-Keeper-Config-Base64. Gateway mode has no env-credential fallback.
 *   3. Lazily spawns one `ksm-mcp serve --batch` child per credential and
 *      holds an MCP client session over stdio to each (15-min idle eviction).
 *   4. Re-serves the child's tool surface over Streamable HTTP (dual-era),
 *      filtered through the read-only allowlist in tools.ts.
 *
 *   v1 is deliberately READ-ONLY. See tools.ts for why that boundary has to
 *   live here rather than in the upstream. /health stays unauthenticated
 *   and does not read credentials.
 */
import { createBridgeHttpServer } from "./http.js";
import { evaluateHttpStartup } from "./http-startup.js";
import { ChildPool } from "./pool.js";

const startup = evaluateHttpStartup(process.env);
if (!startup.ok) {
  process.stderr.write(`[ksm] ${startup.error}\n`);
  process.exit(1);
}
for (const warning of startup.warnings) {
  process.stderr.write(`[ksm] ${warning}\n`);
}

const PORT = Number(process.env.PORT ?? process.env.MCP_HTTP_PORT ?? 8080);
const HOST = startup.host;

const pool = new ChildPool();
const { httpServer, closeMcpHandler } = createBridgeHttpServer(pool, { s2sSecret: startup.secret });

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
