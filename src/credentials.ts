/**
 * Gateway credential contract for the Keeper Secrets Manager bridge.
 *
 * The conduit gateway forwards the calling org's KSM device configuration as
 * an HTTP header on every /mcp request. This module maps that header to a
 * validated value and stops there — how the child is launched lives in
 * child.ts.
 *
 * Contract (must match conduit's vendor-config EXACTLY):
 *   X-Keeper-Config-Base64 -> KSM_CONFIG_BASE64
 *
 * The value is the base64 "device configuration" Keeper hands out under
 * Secrets Manager > <application> > Devices > Add Device. It decodes to a flat
 * JSON object of string values; upstream's `InitializeWithConfig`
 * (internal/ksm/client.go) requires `clientId`, `privateKey` and `appKey`, and
 * treats everything else — including `hostname` — as optional.
 */
import { createHash } from "node:crypto";

/**
 * The one header conduit sends. Declared once: it feeds the CORS allow-list,
 * the 401 response's `required` hint, AND the per-request lookup, and a
 * mismatch between those would fail silently (CORS advertising a header the
 * code no longer reads).
 */
export const CONFIG_HEADER = "X-Keeper-Config-Base64";
const CONFIG_HEADER_LOWER = CONFIG_HEADER.toLowerCase();

export const GATEWAY_HEADERS = [CONFIG_HEADER] as const;

/** The three keys upstream refuses to start without. */
const REQUIRED_CONFIG_KEYS = ["clientId", "privateKey", "appKey"] as const;

export interface KeeperCredentials {
  /** The verified, still-encoded config — passed through to the child as-is. */
  configBase64: string;
}

export type CredentialResult =
  | { ok: true; creds: KeeperCredentials }
  | { ok: false; error: string };

/**
 * Validate the decoded config WITHOUT retaining it.
 *
 * We decode only to reject malformed input at the 401 gate rather than letting
 * a child spawn and die with an opaque error. The decoded object is private key
 * material, so it is never stored, never logged, and never returned — the
 * caller gets back the original encoded string and a verdict.
 */
function validateConfigBase64(configBase64: string): { ok: true } | { ok: false; error: string } {
  // Buffer.from(string, "base64") never throws — it is lenient where Go's
  // StdEncoding is strict. Re-encoding and comparing is what actually rejects
  // input upstream would refuse (stray characters, bad or missing padding);
  // without it, a config with junk appended decodes to byte-identical JSON here
  // and then fails confusingly at spawn.
  const buf = Buffer.from(configBase64, "base64");
  if (buf.length === 0) return { ok: false, error: "config decodes to empty bytes" };
  if (buf.toString("base64") !== configBase64) {
    return { ok: false, error: "config is not valid standard base64" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(buf.toString("utf8"));
  } catch {
    return { ok: false, error: "decoded config is not JSON" };
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, error: "decoded config is not a JSON object" };
  }

  // Upstream unmarshals into map[string]string, so a non-string value anywhere
  // makes the child fail at startup. One pass covers both the required-key
  // check and the value-type check, and reports each key once.
  const config = parsed as Record<string, unknown>;
  const badValues = Object.keys(config).filter((key) => typeof config[key] !== "string");
  if (badValues.length > 0) {
    return {
      ok: false,
      error: `decoded config has non-string value(s) for: ${badValues.sort().join(", ")}`,
    };
  }

  const missing = REQUIRED_CONFIG_KEYS.filter((key) => !config[key]);
  if (missing.length > 0) {
    return { ok: false, error: `decoded config is missing required field(s): ${missing.join(", ")}` };
  }

  return { ok: true };
}

/**
 * Resolve per-request credentials from a (lowercase-name) header accessor.
 *
 * Error strings describe the SHAPE of the problem only. They surface to the
 * caller in a 401 body, so they must never echo any part of the config back.
 */
export function resolveCredentials(
  getHeader: (lowerName: string) => string | undefined,
): CredentialResult {
  const configBase64 = getHeader(CONFIG_HEADER_LOWER)?.trim();

  if (!configBase64) {
    return { ok: false, error: `Missing required header ${CONFIG_HEADER}.` };
  }

  const validation = validateConfigBase64(configBase64);
  if (!validation.ok) {
    return {
      ok: false,
      error:
        `Invalid ${CONFIG_HEADER}: ${validation.error}. Expected the base64 device ` +
        "configuration from Keeper Vault > Secrets Manager > your application > " +
        "Devices > Add Device.",
    };
  }

  return { ok: true, creds: { configBase64 } };
}

/**
 * Stable pool key for a credential tuple.
 *
 * Hashed rather than used directly so the pool's keys — which tag child stderr
 * in logs and name the child's HOME directory — never contain credential
 * material.
 */
export function hashCredentials(creds: KeeperCredentials): string {
  return createHash("sha256").update(creds.configBase64).digest("hex").slice(0, 16);
}
