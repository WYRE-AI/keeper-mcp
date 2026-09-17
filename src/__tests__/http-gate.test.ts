/**
 * The 401 gate and health endpoint, over the REAL HTTP stack
 * (createMcpHandler + toNodeHandler) — no upstream child needed: `initialize`
 * is answered by the thin bridge server without ever touching the pool.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { createBridgeHttpServer, type BridgeHttp } from "../http.js";
import { ChildPool } from "../pool.js";

let bridge: BridgeHttp;
let pool: ChildPool;
let base: string;

const VALID_CONFIG_B64 = Buffer.from(
  JSON.stringify({
    hostname: "keepersecurity.com",
    clientId: "Zm9vYmFyY2xpZW50aWQ=",
    privateKey: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH",
    appKey: "YXBwa2V5YXBwa2V5YXBwa2V5",
  }),
).toString("base64");

/** Decode a JSON-RPC message from a streamable-HTTP response (JSON or SSE). */
async function mcpJson(res: Response): Promise<any> {
  const contentType = res.headers.get("content-type") ?? "";
  const text = await res.text();
  if (contentType.includes("text/event-stream")) {
    const dataLines = text.split("\n").filter((line) => line.startsWith("data:"));
    return JSON.parse(dataLines[dataLines.length - 1]!.slice(5).trim());
  }
  return JSON.parse(text);
}

const initBody = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "gate-test", version: "0" },
  },
});

const POST_HEADERS = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };

beforeAll(async () => {
  // Point at a binary that does not exist: nothing in these tests should ever
  // reach a spawn, and an ENOENT is a loud failure if one does.
  pool = new ChildPool({ upstreamBin: "/nonexistent/ksm-mcp" });
  bridge = createBridgeHttpServer(pool);
  await new Promise<void>((resolve) => bridge.httpServer.listen(0, "127.0.0.1", resolve));
  const { port } = bridge.httpServer.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await bridge.closeMcpHandler();
  await pool.shutdown();
  await new Promise<void>((resolve, reject) =>
    bridge.httpServer.close((err) => (err ? reject(err) : resolve())),
  );
});

describe("GET /health", () => {
  it("returns 200 without any credentials", async () => {
    const res = await fetch(`${base}/health`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("ok");
    expect(body.tenants).toBe(0);
  });

  it("advertises the read-only posture and tool count", async () => {
    const body = await (await fetch(`${base}/health`)).json();
    expect(body.mode).toBe("read-only");
    expect(body.tools).toBe(11);
  });
});

describe("POST /mcp 401 gate", () => {
  it("rejects a request with no credential header", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST", headers: POST_HEADERS, body: initBody });
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.code).toBe(-32001);
    expect(body.error.data.required).toContain("X-Keeper-Config-Base64");
  });

  it("rejects a malformed config rather than passing it to a child", async () => {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { ...POST_HEADERS, "X-Keeper-Config-Base64": "garbage!!" },
      body: initBody,
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error.message).toMatch(/Invalid X-Keeper-Config-Base64/);
  });

  it("rejects a base64 config missing required KSM fields", async () => {
    const incomplete = Buffer.from(JSON.stringify({ hostname: "keepersecurity.com" })).toString(
      "base64",
    );
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { ...POST_HEADERS, "X-Keeper-Config-Base64": incomplete },
      body: initBody,
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error.message).toContain("clientId");
  });

  it("does NOT fall through to environment credentials", async () => {
    // A cross-tenant leak would look like a 200 here.
    process.env.KSM_CONFIG_BASE64 = VALID_CONFIG_B64;
    try {
      const res = await fetch(`${base}/mcp`, { method: "POST", headers: POST_HEADERS, body: initBody });
      expect(res.status).toBe(401);
    } finally {
      delete process.env.KSM_CONFIG_BASE64;
    }
  });
});

describe("POST /mcp with valid credentials", () => {
  it("answers initialize without spawning a child", async () => {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { ...POST_HEADERS, "X-Keeper-Config-Base64": VALID_CONFIG_B64 },
      body: initBody,
    });
    expect(res.status).toBe(200);
    const body = await mcpJson(res);
    expect(body.result.serverInfo.name).toBe("keeper-mcp");
    expect(pool.size).toBe(0);
  });

  it("states the read-only posture in its instructions", async () => {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { ...POST_HEADERS, "X-Keeper-Config-Base64": VALID_CONFIG_B64 },
      body: initBody,
    });
    const body = await mcpJson(res);
    expect(body.result.instructions).toMatch(/read-only/i);
  });
});

describe("routing", () => {
  it("404s an unknown path", async () => {
    const res = await fetch(`${base}/nope`);
    expect(res.status).toBe(404);
    expect((await res.json()).endpoints).toEqual(["/mcp", "/health"]);
  });

  it("answers CORS preflight with the credential header allowed", async () => {
    const res = await fetch(`${base}/mcp`, { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-headers")).toContain("X-Keeper-Config-Base64");
  });
});
