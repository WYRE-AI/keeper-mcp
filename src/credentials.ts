/**
 * Gateway credential contract for the Keeper Secrets Manager bridge.
 *
 * The conduit gateway forwards the calling org's KSM device configuration as
 * an HTTP header on every /mcp request. This module validates that header and
 * maps it onto the environment the upstream `ksm-mcp serve` child reads at
 * startup.
 *
 * Contract (must match conduit's vendor-config EXACTLY):
 *   X-Keeper-Config-Base64 -> KSM_CONFIG_BASE64   (required)
 *
 * The value is the base64 "device configuration" Keeper hands out under
 * Secrets Manager > <application> > Devices > Add Device. It decodes to a flat
 * JSON object of string values; upstream's `InitializeWithConfig`
 * (internal/ksm/client.go) requires `clientId`, `privateKey` and `appKey`, and
 * treats everything else — including `hostname` — as optional.
 */
import { createHash } from "node:crypto";

/** Exact gateway header names (lowercased by Node/fetch on receipt). */
export const GATEWAY_HEADERS = ["X-Keeper-Config-Base64"] as const;

/** The three keys upstream refuses to start without. */
const REQUIRED_CONFIG_KEYS = ["clientId", "privateKey", "appKey"] as const;

export interface KeeperCredentials {
  /** The verified, still-encoded config — passed through to the child as-is. */
  configBase64: string;
}

/**
 * Validate the decoded config WITHOUT retaining it.
 *
 * We decode only to reject malformed input at the 401 gate rather than letting
 * a child spawn and die with an opaque error. The decoded object is private key
 * material, so it is never stored, never logged, and never returned — the
 * caller gets back the original encoded string and a boolean verdict.
 */
function validateConfigBase64(configBase64: string): { ok: true } | { ok: false; error: string } {
  let decoded: string;
  try {
    // Keeper emits standard base64 with padding; upstream decodes with
    // StdEncoding, so anything it would reject we reject here too.
    const buf = Buffer.from(configBase64, "base64");
    if (buf.length === 0) return { ok: false, error: "config decodes to empty bytes" };
    // Buffer.from is lenient where Go's StdEncoding is strict — re-encoding and
    // comparing catches input Go would refuse (stray characters, bad padding).
    if (buf.toString("base64") !== configBase64) {
      return { ok: false, error: "config is not valid standard base64" };
    }
    decoded = buf.toString("utf8");
  } catch {
    return { ok: false, error: "config is not valid base64" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    return { ok: false, error: "decoded config is not JSON" };
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, error: "decoded config is not a JSON object" };
  }

  const config = parsed as Record<string, unknown>;
  const missing = REQUIRED_CONFIG_KEYS.filter(
    (key) => typeof config[key] !== "string" || config[key] === "",
  );
  if (missing.length > 0) {
    return {
      ok: false,
      error: `decoded config is missing required field(s): ${missing.join(", ")}`,
    };
  }

  // Upstream unmarshals into map[string]string — a non-string value makes the
  // child fail at startup, so reject it here where the error is legible.
  const nonString = Object.keys(config).filter((key) => typeof config[key] !== "string");
  if (nonString.length > 0) {
    return {
      ok: false,
      error: `decoded config has non-string value(s) for: ${nonString.join(", ")}`,
    };
  }

  return { ok: true };
}

/**
 * Resolve per-request credentials from a (lowercase-name) header accessor.
 * Returns `{ creds }` on success or `{ error }` naming what is wrong.
 *
 * Error strings describe the SHAPE of the problem only. They surface to the
 * caller in a 401 body, so they must never echo any part of the config back.
 */
export function resolveCredentials(
  getHeader: (lowerName: string) => string | undefined,
): { creds?: KeeperCredentials; error?: string } {
  const configBase64 = getHeader("x-keeper-config-base64")?.trim();

  if (!configBase64) {
    return { error: "Missing required header X-Keeper-Config-Base64." };
  }

  const validation = validateConfigBase64(configBase64);
  if (!validation.ok) {
    return {
      error:
        `Invalid X-Keeper-Config-Base64: ${validation.error}. Expected the base64 ` +
        "device configuration from Keeper Vault > Secrets Manager > your application > " +
        "Devices > Add Device.",
    };
  }

  return { creds: { configBase64 } };
}

/**
 * Environment variables for the upstream child process.
 *
 * KSM_MCP_BATCH_MODE is forced to "true" because there is no TTY in a
 * container: without it every confirm-requiring tool — including `get_secret`
 * with `unmask: true` — hard-errors with "interactive confirmation via terminal
 * is not supported". The cost is that the child auto-approves every
 * confirmation it is asked for (internal/ui/confirm.go), which is precisely why
 * the read-only allowlist in tools.ts exists in front of it. Do not relax one
 * without re-reading the other.
 *
 * KSM_MCP_PROFILE is deliberately NOT set: with KSM_CONFIG_BASE64 present,
 * upstream builds an in-memory profile and never touches the on-disk profile
 * store, which is what keeps tenants from sharing state through the filesystem.
 */
export function credentialsToChildEnv(creds: KeeperCredentials): Record<string, string> {
  return {
    KSM_CONFIG_BASE64: creds.configBase64,
    KSM_MCP_BATCH_MODE: "true",
    KSM_MCP_LOG_LEVEL: "error",
  };
}

/** Arguments for the upstream child process. */
export const CHILD_ARGS = ["serve", "--batch"] as const;

/**
 * Stable pool key for a credential tuple.
 *
 * Hashed rather than used directly so the pool's keys — which appear in log
 * lines tagging child stderr — never contain credential material.
 */
export function hashCredentials(creds: KeeperCredentials): string {
  return createHash("sha256").update(creds.configBase64).digest("hex").slice(0, 16);
}
