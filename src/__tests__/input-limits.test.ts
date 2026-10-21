/**
 * Request limits (WYREAI-454): CVE-2026-111768 / GHSA-46jr-4wx8-v453 element cap,
 * GHSA-f897-62hf-6gxq body cap.
 */
import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createBridgeHttpServer, type BridgeHttp } from "../http.js";
import {
  countToolInputElements,
  MAX_REQUEST_BODY_BYTES,
  MAX_TOOL_INPUT_ELEMENTS,
  toolInputTooLarge,
  toolInputTooLargeResult,
} from "../input-limits.js";
import { ChildPool } from "../pool.js";
import { VALID_CONFIG_B64 } from "./fixtures.js";

describe("countToolInputElements", () => {
  it("counts array elements and object keys at every depth", () => {
    expect(countToolInputElements({ a: [1, 2, { b: 3, c: [4] }], d: "x" }, 100)).toBe(8);
    expect(countToolInputElements("scalar", 10)).toBe(0);
    expect(countToolInputElements(undefined, 10)).toBe(0);
  });

  it("exits early once the count exceeds max", () => {
    expect(countToolInputElements(new Array(1_000_000).fill(0), 10)).toBe(1_000_000);
    const nested = Array.from({ length: 100 }, () => new Array(100).fill(0));
    expect(countToolInputElements(nested, 10)).toBe(100);
  });

  it("does not overflow the stack on very deep nesting", () => {
    let deep: unknown = [];
    for (let i = 0; i < 200_000; i++) deep = [deep];
    expect(countToolInputElements(deep, 1000)).toBe(1001);
  });

  it("allows exactly the limit and rejects one over", () => {
    expect(toolInputTooLarge(new Array(MAX_TOOL_INPUT_ELEMENTS).fill(0))).toBe(false);
    expect(toolInputTooLarge(new Array(MAX_TOOL_INPUT_ELEMENTS + 1).fill(0))).toBe(true);
    expect(toolInputTooLarge({ a: [1, 2, 3] }, 4)).toBe(false);
    expect(toolInputTooLarge({ a: [1, 2, 3] }, 3)).toBe(true);
  });

  it("builds the error result", () => {
    expect(toolInputTooLargeResult("get_secret")).toEqual({
      content: [
        {
          type: "text",
          text: "Invalid arguments for tool get_secret: arguments contain more than the maximum of 10000 elements",
        },
      ],
      isError: true,
    });
  });
});

const S2S_SECRET = "s2s-canary-do-not-log-7f3a";
const mint = (secret: string): string => {
  const message = `t=${Math.floor(Date.now() / 1000)}`;
  return `${message},v1=${createHmac("sha256", secret).update(message).digest("hex")}`;
};
const HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

const open: Array<{ bridge: BridgeHttp; pool: ChildPool }> = [];

async function listen() {
  const pool = new ChildPool({ upstreamBin: "/nonexistent/ksm-mcp" });
  const getSession = vi.spyOn(pool, "getSession");
  const bridge = createBridgeHttpServer(pool, { s2sSecret: S2S_SECRET });
  await new Promise<void>((resolve) => bridge.httpServer.listen(0, "127.0.0.1", resolve));
  open.push({ bridge, pool });
  return { port: (bridge.httpServer.address() as AddressInfo).port, pool, getSession };
}

afterEach(async () => {
  while (open.length > 0) {
    const entry = open.pop();
    if (!entry) continue;
    await entry.bridge.closeMcpHandler();
    await entry.pool.shutdown();
    await new Promise<void>((resolve) => entry.bridge.httpServer.close(() => resolve()));
  }
});

describe("tools/call element cap through the HTTP handler", () => {
  it("rejects 10_001 nested elements without touching the pool", async () => {
    const server = await listen();
    const args = { fields: [new Array(MAX_TOOL_INPUT_ELEMENTS - 1).fill("x")] };
    expect(countToolInputElements(args, MAX_TOOL_INPUT_ELEMENTS)).toBe(MAX_TOOL_INPUT_ELEMENTS + 1);
    const res = await fetch(`http://127.0.0.1:${server.port}/mcp`, {
      method: "POST",
      headers: {
        ...HEADERS,
        "X-Gateway-S2S": mint(S2S_SECRET),
        "X-Keeper-Config-Base64": VALID_CONFIG_B64,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "get_secret", arguments: args },
      }),
    });
    const text = await res.text();
    expect(res.status).toBe(200);
    expect(text).toContain("maximum of 10000 elements");
    expect(text).toContain("isError");
    expect(server.getSession).not.toHaveBeenCalled();
    expect(server.pool.size).toBe(0);
  });
});

describe("HTTP body cap", () => {
  const oversized = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "ping",
    pad: "a".repeat(MAX_REQUEST_BODY_BYTES),
  });
  const post = (port: number, headers: Record<string, string>, body: string) =>
    fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { ...HEADERS, ...headers }, body });

  it("answers 413 with a JSON-RPC body for a valid S2S header", async () => {
    const server = await listen();
    const res = await post(
      server.port,
      { "X-Gateway-S2S": mint(S2S_SECRET), "X-Keeper-Config-Base64": VALID_CONFIG_B64 },
      oversized,
    );
    expect(res.status).toBe(413);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({
      jsonrpc: "2.0",
      error: { code: -32600, message: "Request body exceeds 262144 bytes" },
      id: null,
    });
  });

  it("answers 401, not 413, for a missing or invalid S2S header", async () => {
    const server = await listen();
    const missing = await post(server.port, { "X-Keeper-Config-Base64": VALID_CONFIG_B64 }, oversized);
    const invalid = await post(
      server.port,
      { "X-Gateway-S2S": mint("wrong"), "X-Keeper-Config-Base64": VALID_CONFIG_B64 },
      oversized,
    );
    expect(missing.status).toBe(401);
    expect(invalid.status).toBe(401);
  });

  it("still serves a normal small request", async () => {
    const server = await listen();
    const res = await post(
      server.port,
      { "X-Gateway-S2S": mint(S2S_SECRET), "X-Keeper-Config-Base64": VALID_CONFIG_B64 },
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } },
      }),
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("keeper-mcp");
  });
});
