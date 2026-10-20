/**
 * Fail-closed HTTP startup for the keeper bridge (CWE-306).
 *
 * An empty CONDUIT_S2S_SECRET used to skip the X-Gateway-S2S check and still
 * listen. Startup now refuses unless the secret is set and is not a known
 * placeholder. MCP_ALLOW_INSECURE_DEV=1 is the only bypass for an empty
 * secret: it logs a warning, does not enforce X-Gateway-S2S, and binds
 * 127.0.0.1 even when MCP_HTTP_HOST is a wider address. A placeholder is
 * never accepted, including when that flag is set.
 *
 * A real secret honors MCP_HTTP_HOST. When that variable is unset the bind
 * stays 0.0.0.0, the historical container default, so a deploy that only
 * injects the secret stays reachable. The image and Compose set
 * MCP_HTTP_HOST=0.0.0.0 explicitly. The secret value is never written to
 * the messages returned here.
 */

/** Public example values. A copied placeholder must not verify as a real secret. */
export const KNOWN_PLACEHOLDER_SECRETS = [
  "replace-with-a-real-secret",
  "your-s2s-secret",
  "your-secret",
  "changeme",
  "change-me",
  "placeholder",
  "secret",
  "example",
  "replace-me",
  "s2s-secret",
  "conduit_s2s_secret",
] as const;

const PLACEHOLDER_SET = new Set<string>(KNOWN_PLACEHOLDER_SECRETS);

const LOOPBACK_HOST = "127.0.0.1";

const MISSING_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is empty. " +
  "Set CONDUIT_S2S_SECRET to the gateway-provisioned secret (openssl rand -hex 32), " +
  "or set MCP_ALLOW_INSECURE_DEV=1 for local development only.";

const PLACEHOLDER_S2S_SECRET_ERROR =
  "Refusing to start HTTP transport: CONDUIT_S2S_SECRET is a known placeholder. " +
  "Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value. " +
  "MCP_ALLOW_INSECURE_DEV does not allow a placeholder secret.";

const INSECURE_DEV_WARNING =
  "SECURITY WARNING: CONDUIT_S2S_SECRET is empty and MCP_ALLOW_INSECURE_DEV=1. " +
  "HTTP /mcp is starting with service-to-service authentication DISABLED, bound to 127.0.0.1 only. " +
  "Local development only; do not expose this port.";

export function isKnownPlaceholderSecret(secret: string): boolean {
  return PLACEHOLDER_SET.has(secret.trim().toLowerCase());
}

/** Hosts that count as loopback when deciding whether to log a bind override. */
export function isLoopbackBindHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[(.+)\]$/, "$1");
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}

export interface HttpStartupOk {
  ok: true;
  /** Empty only when the insecure-dev bypass is in effect. */
  secret: string;
  host: string;
  insecureDev: boolean;
  warnings: string[];
}

export interface HttpStartupRefuse {
  ok: false;
  error: string;
}

export type HttpStartup = HttpStartupOk | HttpStartupRefuse;

/**
 * Decide whether HTTP may listen, and on which address.
 * Read at process startup, not at module load, so tests can pass an env.
 */
export function evaluateHttpStartup(env: NodeJS.ProcessEnv = process.env): HttpStartup {
  const raw = (env.CONDUIT_S2S_SECRET ?? "").trim();
  if (raw && isKnownPlaceholderSecret(raw)) {
    return { ok: false, error: PLACEHOLDER_S2S_SECRET_ERROR };
  }

  const warnings: string[] = [];
  let insecureDev = false;
  if (!raw) {
    if (env.MCP_ALLOW_INSECURE_DEV === "1") {
      insecureDev = true;
      warnings.push(INSECURE_DEV_WARNING);
    } else {
      return { ok: false, error: MISSING_S2S_SECRET_ERROR };
    }
  }

  const configured = (env.MCP_HTTP_HOST ?? "").trim();
  if (!raw) {
    // No real secret: the dev bypass forces loopback. A wider MCP_HTTP_HOST,
    // including the image default 0.0.0.0, is ignored and logged.
    if (configured && !isLoopbackBindHost(configured)) {
      warnings.push(
        `WARNING: MCP_HTTP_HOST=${configured} is not a loopback address. ` +
          "MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET cannot listen there. " +
          `Binding ${LOOPBACK_HOST} only.`,
      );
    }
    return { ok: true, secret: "", host: LOOPBACK_HOST, insecureDev, warnings };
  }

  // A configured secret honors MCP_HTTP_HOST. Unset keeps the historical
  // 0.0.0.0 bind so container deploys that only inject the secret stay reachable.
  return {
    ok: true,
    secret: raw,
    host: configured || "0.0.0.0",
    insecureDev: false,
    warnings,
  };
}
