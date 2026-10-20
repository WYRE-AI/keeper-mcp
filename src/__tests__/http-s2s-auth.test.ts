/**
 * HTTP transport fail-closed auth (CWE-306).
 *
 * Startup requires a non-placeholder CONDUIT_S2S_SECRET unless
 * MCP_ALLOW_INSECURE_DEV=1, which binds 127.0.0.1 only. /mcp rejects a
 * missing or invalid X-Gateway-S2S header before credentials are read.
 * Gateway mode rejects requests that omit X-Keeper-Config-Base64 and must
 * not fall back to KSM_CONFIG_BASE64 in the environment.
 */
import { createHmac } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createBridgeHttpServer, type BridgeHttp } from "../http.js";
import {
  evaluateHttpStartup,
  isKnownPlaceholderSecret,
  KNOWN_PLACEHOLDER_SECRETS,
} from "../http-startup.js";
import { ChildPool } from "../pool.js";
import { VALID_CONFIG_B64 } from "./fixtures.js";

const S2S_SECRET = "s2s-canary-do-not-log-7f3a";
const PLACEHOLDER = "changeme";

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac("sha256", secret).update(message).digest("hex");
  return `${message},v1=${hex}`;
}

const initBody = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "s2s-test", version: "0" },
  },
});

const POST_HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

interface Listening {
  bridge: BridgeHttp;
  pool: ChildPool;
  port: number;
  address: string;
}

const open: Listening[] = [];

async function listen(env: NodeJS.ProcessEnv): Promise<Listening> {
  const decision = evaluateHttpStartup(env);
  if (!decision.ok) throw new Error(`expected startup to allow listen: ${decision.error}`);
  const pool = new ChildPool({ upstreamBin: "/nonexistent/ksm-mcp" });
  const bridge = createBridgeHttpServer(pool, { s2sSecret: decision.secret });
  await new Promise<void>((resolve) => bridge.httpServer.listen(0, decision.host, resolve));
  const bound = bridge.httpServer.address() as AddressInfo | string | null;
  if (!bound || typeof bound === "string") throw new Error("HTTP server did not bind a TCP port");
  const session = { bridge, pool, port: bound.port, address: bound.address };
  open.push(session);
  return session;
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

afterEach(async () => {
  while (open.length > 0) {
    const session = open.pop();
    if (!session) continue;
    await session.bridge.closeMcpHandler();
    await session.pool.shutdown();
    await closeServer(session.bridge.httpServer);
  }
});

function loggedText(decision: { ok: true; warnings: string[] } | { ok: false; error: string }): string {
  return decision.ok ? decision.warnings.join("\n") : decision.error;
}

describe("evaluateHttpStartup", () => {
  it("refuses to start when CONDUIT_S2S_SECRET is unset or empty", () => {
    for (const env of [{}, { CONDUIT_S2S_SECRET: "" }, { CONDUIT_S2S_SECRET: "   " }]) {
      const decision = evaluateHttpStartup(env);
      expect(decision.ok).toBe(false);
      if (!decision.ok) {
        expect(decision.error).toContain("Refusing to start");
        expect(decision.error).toContain("CONDUIT_S2S_SECRET is empty");
        expect(decision.error).not.toContain(S2S_SECRET);
      }
    }
  });

  it("refuses when MCP_ALLOW_INSECURE_DEV is not exactly 1", () => {
    for (const flag of ["true", "0", "yes", ""]) {
      const decision = evaluateHttpStartup({ MCP_ALLOW_INSECURE_DEV: flag });
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.error).toContain("Refusing to start");
    }
  });

  it("rejects every known placeholder, even with MCP_ALLOW_INSECURE_DEV=1, without echoing it", () => {
    const decisions = KNOWN_PLACEHOLDER_SECRETS.map((placeholder) => {
      expect(isKnownPlaceholderSecret(`  ${placeholder.toUpperCase()}  `)).toBe(true);
      return evaluateHttpStartup({
        CONDUIT_S2S_SECRET: `  ${placeholder}  `,
        MCP_ALLOW_INSECURE_DEV: "1",
        MCP_HTTP_HOST: "127.0.0.1",
      });
    });
    const first = decisions[0];
    expect(first?.ok).toBe(false);
    if (!first || first.ok) return;
    expect(first.error).toContain("Refusing to start");
    expect(first.error).toContain("known placeholder");
    for (const decision of decisions) {
      // Identical text for every placeholder proves the value is not interpolated.
      expect(decision).toEqual(first);
    }
    expect(first.error).not.toContain(S2S_SECRET);
  });

  it("allows startup with a warning when MCP_ALLOW_INSECURE_DEV=1 and binds 127.0.0.1", () => {
    const decision = evaluateHttpStartup({ MCP_ALLOW_INSECURE_DEV: "1" });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.secret).toBe("");
    expect(decision.host).toBe("127.0.0.1");
    expect(decision.insecureDev).toBe(true);
    const text = loggedText(decision);
    expect(text).toContain("SECURITY WARNING");
    expect(text).toContain("MCP_ALLOW_INSECURE_DEV=1");
    expect(text).toContain("127.0.0.1");
    expect(text).not.toContain(S2S_SECRET);
  });

  it.each(["0.0.0.0", "10.1.2.3"])(
    "forces 127.0.0.1 when the dev bypass is set and MCP_HTTP_HOST is %s",
    (host) => {
      const decision = evaluateHttpStartup({
        MCP_ALLOW_INSECURE_DEV: "1",
        MCP_HTTP_HOST: host,
      });
      expect(decision.ok).toBe(true);
      if (!decision.ok) return;
      expect(decision.host).toBe("127.0.0.1");
      const text = loggedText(decision);
      expect(text).toContain(`MCP_HTTP_HOST=${host} is not a loopback address`);
      expect(text).toContain("Binding 127.0.0.1 only");
      expect(text).not.toContain(S2S_SECRET);
    },
  );

  it("forces 127.0.0.1 for a loopback MCP_HTTP_HOST without the override warning", () => {
    const decision = evaluateHttpStartup({
      MCP_ALLOW_INSECURE_DEV: "1",
      MCP_HTTP_HOST: "localhost",
    });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.host).toBe("127.0.0.1");
    expect(loggedText(decision)).not.toContain("not a loopback address");
  });

  it("honors a non-loopback MCP_HTTP_HOST when CONDUIT_S2S_SECRET is set", () => {
    const decision = evaluateHttpStartup({
      CONDUIT_S2S_SECRET: S2S_SECRET,
      MCP_HTTP_HOST: "0.0.0.0",
      MCP_ALLOW_INSECURE_DEV: "1",
    });
    expect(decision).toMatchObject({ ok: true, secret: S2S_SECRET, host: "0.0.0.0", insecureDev: false });
    if (!decision.ok) return;
    expect(decision.warnings).toEqual([]);
  });

  it("keeps the historical 0.0.0.0 bind when a secret is set and MCP_HTTP_HOST is unset", () => {
    const decision = evaluateHttpStartup({ CONDUIT_S2S_SECRET: S2S_SECRET });
    expect(decision).toMatchObject({ ok: true, host: "0.0.0.0", insecureDev: false });
  });
});

describe("HTTP bind", () => {
  it("listens on 127.0.0.1 when the dev bypass overrides MCP_HTTP_HOST", async () => {
    const server = await listen({ MCP_ALLOW_INSECURE_DEV: "1", MCP_HTTP_HOST: "0.0.0.0" });
    expect(server.address).toBe("127.0.0.1");
  });

  it("listens on the configured host when CONDUIT_S2S_SECRET is set", async () => {
    const server = await listen({ CONDUIT_S2S_SECRET: S2S_SECRET, MCP_HTTP_HOST: "0.0.0.0" });
    expect(server.address).toBe("0.0.0.0");
  });
});

describe("HTTP /mcp authentication", () => {
  async function post(port: number, headers: Record<string, string> = {}): Promise<Response> {
    return fetch(`http://127.0.0.1:${port}/mcp`, {
      method: "POST",
      headers: { ...POST_HEADERS, ...headers },
      body: initBody,
    });
  }

  it("returns 401 when the S2S header is missing or invalid and does not log the secret", async () => {
    const server = await listen({
      CONDUIT_S2S_SECRET: S2S_SECRET,
      MCP_HTTP_HOST: "127.0.0.1",
    });
    const missing = await post(server.port, { "X-Keeper-Config-Base64": VALID_CONFIG_B64 });
    const invalid = await post(server.port, {
      "X-Gateway-S2S": mintS2sHeader("wrong-secret"),
      "X-Keeper-Config-Base64": VALID_CONFIG_B64,
    });

    expect(missing.status).toBe(401);
    expect(invalid.status).toBe(401);
    const missingBody = await missing.text();
    const invalidBody = await invalid.text();
    expect(missingBody).toContain("X-Gateway-S2S");
    expect(invalidBody).toContain("X-Gateway-S2S");
    expect(missingBody).not.toContain(S2S_SECRET);
    expect(invalidBody).not.toContain(S2S_SECRET);
    expect(missingBody).not.toContain(VALID_CONFIG_B64);
    expect(server.pool.size).toBe(0);
  });

  it("returns 401 in gateway mode without credential headers and does not use env credentials", async () => {
    process.env.KSM_CONFIG_BASE64 = VALID_CONFIG_B64;
    try {
      const server = await listen({
        CONDUIT_S2S_SECRET: S2S_SECRET,
        MCP_HTTP_HOST: "127.0.0.1",
      });
      const response = await post(server.port, { "X-Gateway-S2S": mintS2sHeader(S2S_SECRET) });
      const body = await response.text();

      expect(response.status).toBe(401);
      expect(body).toContain("X-Keeper-Config-Base64");
      expect(body).not.toContain(VALID_CONFIG_B64);
      expect(body).not.toContain(S2S_SECRET);
      expect(server.pool.size).toBe(0);

      const partial = await post(server.port, {
        "X-Gateway-S2S": mintS2sHeader(S2S_SECRET),
        "X-Keeper-Config-Base64": "   ",
      });
      expect(partial.status).toBe(401);
      expect(server.pool.size).toBe(0);
    } finally {
      delete process.env.KSM_CONFIG_BASE64;
    }
  });

  it("accepts a valid S2S header plus the credential header", async () => {
    const server = await listen({
      CONDUIT_S2S_SECRET: S2S_SECRET,
      MCP_HTTP_HOST: "127.0.0.1",
    });
    const response = await post(server.port, {
      "X-Gateway-S2S": mintS2sHeader(S2S_SECRET),
      "X-Keeper-Config-Base64": VALID_CONFIG_B64,
    });
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).toContain("keeper-mcp");
    expect(body).not.toContain(S2S_SECRET);
    expect(body).not.toContain(VALID_CONFIG_B64);
    expect(server.pool.size).toBe(0);
  });

  it("rejects a header minted with a known placeholder instead of treating it as the key", async () => {
    const pool = new ChildPool({ upstreamBin: "/nonexistent/ksm-mcp" });
    const bridge = createBridgeHttpServer(pool, { s2sSecret: PLACEHOLDER });
    await new Promise<void>((resolve) => bridge.httpServer.listen(0, "127.0.0.1", resolve));
    open.push({
      bridge,
      pool,
      port: (bridge.httpServer.address() as AddressInfo).port,
      address: "127.0.0.1",
    });
    const response = await post(open[open.length - 1]!.port, {
      "X-Gateway-S2S": mintS2sHeader(PLACEHOLDER),
      "X-Keeper-Config-Base64": VALID_CONFIG_B64,
    });
    const body = await response.text();
    expect(response.status).toBe(401);
    expect(body).toContain("X-Gateway-S2S");
    expect(body).not.toContain(PLACEHOLDER);
    expect(pool.size).toBe(0);
  });

  it("serves /health and /healthz without authentication and without reading credentials", async () => {
    process.env.KSM_CONFIG_BASE64 = VALID_CONFIG_B64;
    try {
      const server = await listen({
        CONDUIT_S2S_SECRET: S2S_SECRET,
        MCP_HTTP_HOST: "127.0.0.1",
      });
      for (const path of ["/health", "/healthz"]) {
        const response = await fetch(`http://127.0.0.1:${server.port}${path}`);
        const body = await response.text();
        expect(response.status).toBe(200);
        expect(JSON.parse(body).status).toBe("ok");
        expect(body).not.toContain(S2S_SECRET);
        expect(body).not.toContain(VALID_CONFIG_B64);
      }
      expect(server.pool.size).toBe(0);
    } finally {
      delete process.env.KSM_CONFIG_BASE64;
    }
  });
  it("refuses to build an HTTP bridge without a secret unless the bypass is explicit", () => {
    const saved = process.env.CONDUIT_S2S_SECRET;
    delete process.env.CONDUIT_S2S_SECRET;
    try {
      const pool = new ChildPool();
      expect(() => createBridgeHttpServer(pool)).toThrow(/CONDUIT_S2S_SECRET is required/);
      expect(() => createBridgeHttpServer(pool, { s2sSecret: "   " })).toThrow(/CONDUIT_S2S_SECRET is required/);
    } finally {
      if (saved !== undefined) process.env.CONDUIT_S2S_SECRET = saved;
    }
  });
});
