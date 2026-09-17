/**
 * The credential contract. The 401 gate keys off resolveCredentials, so every
 * rejection path here is a request that never reaches a child process.
 */
import { describe, expect, it } from "vitest";
import {
  CHILD_ARGS,
  credentialsToChildEnv,
  GATEWAY_HEADERS,
  hashCredentials,
  resolveCredentials,
} from "../credentials.js";

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64");

const VALID_CONFIG = {
  hostname: "keepersecurity.com",
  clientId: "Zm9vYmFyY2xpZW50aWQ=",
  privateKey: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH",
  appKey: "YXBwa2V5YXBwa2V5YXBwa2V5",
  serverPublicKeyId: "10",
};
const VALID = b64(VALID_CONFIG);

/** Header accessor over a plain object, matching the lowercase-name contract. */
const headers =
  (map: Record<string, string>) =>
  (name: string): string | undefined =>
    map[name];

describe("GATEWAY_HEADERS", () => {
  it("is the single config header conduit must send", () => {
    expect(GATEWAY_HEADERS).toEqual(["X-Keeper-Config-Base64"]);
  });
});

describe("resolveCredentials — accepts", () => {
  it("a well-formed base64 device config", () => {
    const { creds, error } = resolveCredentials(headers({ "x-keeper-config-base64": VALID }));
    expect(error).toBeUndefined();
    expect(creds?.configBase64).toBe(VALID);
  });

  it("a config without the optional hostname (upstream does not require it)", () => {
    const noHost = b64({
      clientId: VALID_CONFIG.clientId,
      privateKey: VALID_CONFIG.privateKey,
      appKey: VALID_CONFIG.appKey,
    });
    expect(resolveCredentials(headers({ "x-keeper-config-base64": noHost })).error).toBeUndefined();
  });

  it("surrounding whitespace (copy-paste from the Keeper UI)", () => {
    const { creds } = resolveCredentials(headers({ "x-keeper-config-base64": `  ${VALID}\n` }));
    expect(creds?.configBase64).toBe(VALID);
  });
});

describe("resolveCredentials — rejects", () => {
  it("a missing header", () => {
    expect(resolveCredentials(headers({})).error).toMatch(/Missing required header/);
  });

  it("an empty header", () => {
    expect(resolveCredentials(headers({ "x-keeper-config-base64": "   " })).error).toMatch(
      /Missing required header/,
    );
  });

  it("input that is not standard base64", () => {
    expect(
      resolveCredentials(headers({ "x-keeper-config-base64": "not base64!!" })).error,
    ).toMatch(/not valid standard base64/);
  });

  it("base64 that does not decode to JSON", () => {
    const notJson = Buffer.from("just a string").toString("base64");
    expect(resolveCredentials(headers({ "x-keeper-config-base64": notJson })).error).toMatch(
      /not JSON/,
    );
  });

  it("JSON that is not an object", () => {
    expect(resolveCredentials(headers({ "x-keeper-config-base64": b64([1, 2]) })).error).toMatch(
      /not a JSON object/,
    );
  });

  it.each(["clientId", "privateKey", "appKey"])("a config missing %s", (key) => {
    const partial: Record<string, string> = { ...VALID_CONFIG };
    delete partial[key];
    expect(resolveCredentials(headers({ "x-keeper-config-base64": b64(partial) })).error).toContain(
      key,
    );
  });

  it("a config with a non-string value (upstream unmarshals into map[string]string)", () => {
    const badType = b64({ ...VALID_CONFIG, appKey: 42 });
    expect(resolveCredentials(headers({ "x-keeper-config-base64": badType })).error).toMatch(
      /missing required field|non-string value/,
    );
  });
});

describe("error messages", () => {
  it("never echo any part of the supplied config back to the caller", () => {
    const secretish = b64({ clientId: "SUPERSECRETVALUE" });
    const { error } = resolveCredentials(headers({ "x-keeper-config-base64": secretish }));
    expect(error).toBeDefined();
    expect(error).not.toContain("SUPERSECRETVALUE");
    expect(error).not.toContain(secretish);
  });
});

describe("credentialsToChildEnv", () => {
  const env = credentialsToChildEnv({ configBase64: VALID });

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
