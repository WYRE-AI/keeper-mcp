/**
 * The credential contract. The 401 gate keys off resolveCredentials, so every
 * rejection path here is a request that never reaches a child process.
 */
import { describe, expect, it } from "vitest";
import { CONFIG_HEADER, GATEWAY_HEADERS, hashCredentials, resolveCredentials } from "../credentials.js";
import { CHILD_ARGS, childEnv, childHomeFor } from "../child.js";
import { b64, VALID_CONFIG, VALID_CONFIG_B64 as VALID } from "./fixtures.js";

/** Header accessor over a plain object, matching the lowercase-name contract. */
const headers =
  (map: Record<string, string>) =>
  (name: string): string | undefined =>
    map[name];

describe("GATEWAY_HEADERS", () => {
  it("is the single config header conduit must send", () => {
    expect(GATEWAY_HEADERS).toEqual(["X-Keeper-Config-Base64"]);
    expect(CONFIG_HEADER).toBe("X-Keeper-Config-Base64");
  });
});

describe("resolveCredentials — accepts", () => {
  it("a well-formed base64 device config", () => {
    const result = resolveCredentials(headers({ "x-keeper-config-base64": VALID }));
    expect(result.ok).toBe(true);
    expect(result.ok && result.creds.configBase64).toBe(VALID);
  });

  it("a config without the optional hostname (upstream does not require it)", () => {
    const noHost = b64({
      clientId: VALID_CONFIG.clientId,
      privateKey: VALID_CONFIG.privateKey,
      appKey: VALID_CONFIG.appKey,
    });
    expect(resolveCredentials(headers({ "x-keeper-config-base64": noHost })).ok).toBe(true);
  });

  it("surrounding whitespace (copy-paste from the Keeper UI)", () => {
    const result = resolveCredentials(headers({ "x-keeper-config-base64": `  ${VALID}\n` }));
    expect(result.ok && result.creds.configBase64).toBe(VALID);
  });
});

/** Error text for a rejected resolve (fails loudly if it unexpectedly succeeded). */
function errorFor(header: string): string {
  const result = resolveCredentials(headers({ "x-keeper-config-base64": header }));
  if (result.ok) throw new Error("expected rejection, got success");
  return result.error;
}

describe("resolveCredentials — rejects", () => {
  it("a missing header", () => {
    const result = resolveCredentials(headers({}));
    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toMatch(/Missing required header/);
  });

  it("an empty header", () => {
    expect(errorFor("   ")).toMatch(/Missing required header/);
  });

  it("input that is not standard base64", () => {
    expect(errorFor("not base64!!")).toMatch(/not valid standard base64/);
  });

  it("base64 that does not decode to JSON", () => {
    expect(errorFor(Buffer.from("just a string").toString("base64"))).toMatch(/not JSON/);
  });

  it("JSON that is not an object", () => {
    expect(errorFor(b64([1, 2]))).toMatch(/not a JSON object/);
  });

  it.each(["clientId", "privateKey", "appKey"])("a config missing %s", (key) => {
    const partial: Record<string, string> = { ...VALID_CONFIG };
    delete partial[key];
    expect(errorFor(b64(partial))).toContain(key);
  });

  it("a REQUIRED key whose value is not a string", () => {
    expect(errorFor(b64({ ...VALID_CONFIG, appKey: 42 }))).toMatch(/non-string value\(s\) for: appKey/);
  });

  it("an OPTIONAL key whose value is not a string (upstream needs map[string]string)", () => {
    expect(errorFor(b64({ ...VALID_CONFIG, serverPublicKeyId: 10 }))).toMatch(
      /non-string value\(s\) for: serverPublicKeyId/,
    );
  });
});

describe("error messages", () => {
  it("never echo any part of the supplied config back to the caller", () => {
    const secretish = b64({ clientId: "SUPERSECRETVALUE" });
    const error = errorFor(secretish);
    expect(error).not.toContain("SUPERSECRETVALUE");
    expect(error).not.toContain(secretish);
  });
});

describe("childEnv", () => {
  const env = childEnv({ configBase64: VALID }, "/tmp/ksm-mcp-home/abc123");

  it("passes the config through unchanged", () => {
    expect(env.KSM_CONFIG_BASE64).toBe(VALID);
  });

  it("forces batch mode — there is no TTY in a container", () => {
    expect(env.KSM_MCP_BATCH_MODE).toBe("true");
  });

  it("does NOT set KSM_MCP_PROFILE (would engage the on-disk profile store)", () => {
    expect(env).not.toHaveProperty("KSM_MCP_PROFILE");
  });

  it("never sets auto-approve explicitly", () => {
    expect(env).not.toHaveProperty("KSM_MCP_AUTO_APPROVE");
  });

  it("gives the child the per-tenant HOME it was handed", () => {
    expect(env.HOME).toBe("/tmp/ksm-mcp-home/abc123");
  });
});

describe("childHomeFor", () => {
  it("gives each tenant its own HOME so the profile-store fallback cannot be shared", () => {
    expect(childHomeFor("/tmp/ksm-mcp-home", "aaaa1111")).toBe("/tmp/ksm-mcp-home/aaaa1111");
    expect(childHomeFor("/tmp/ksm-mcp-home", "aaaa1111")).not.toBe(
      childHomeFor("/tmp/ksm-mcp-home", "bbbb2222"),
    );
  });
});

describe("CHILD_ARGS", () => {
  it("runs the stdio serve command in batch mode", () => {
    expect([...CHILD_ARGS]).toEqual(["serve", "--batch"]);
  });
});

describe("hashCredentials", () => {
  it("is stable for the same config", () => {
    expect(hashCredentials({ configBase64: VALID })).toBe(hashCredentials({ configBase64: VALID }));
  });

  it("differs across tenants", () => {
    const other = b64({ ...VALID_CONFIG, clientId: "different" });
    expect(hashCredentials({ configBase64: VALID })).not.toBe(
      hashCredentials({ configBase64: other }),
    );
  });

  it("does not contain the config (it tags log lines)", () => {
    const hash = hashCredentials({ configBase64: VALID });
    expect(VALID).not.toContain(hash);
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
  });
});
