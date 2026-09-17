/**
 * The child-spawn contract: how a tenant's `ksm-mcp` process is launched.
 *
 * This lives next to the tool policy it necessitates rather than in
 * credentials.ts, because forcing batch mode and choosing the read-only
 * allowlist are two halves of ONE decision. See the header of tools.ts for the
 * full argument; the short version is that the upstream's two-phase
 * confirmation flow is unreachable through this bridge (no `prompts`
 * capability, and its completion tool is a self-approval trampoline we block),
 * so batch mode costs us no boundary we actually had — and the allowlist is
 * what stands in its place.
 */
import { join } from "node:path";
import type { KeeperCredentials } from "./credentials.js";

/** Arguments for the upstream child process. */
export const CHILD_ARGS = ["serve", "--batch"] as const;

/**
 * Environment for one tenant's child.
 *
 * `KSM_MCP_PROFILE` is deliberately NOT set: with `KSM_CONFIG_BASE64` present,
 * upstream builds an in-memory profile (`serve.go` `runServe`) and never
 * touches the on-disk profile store, which is what keeps tenants from sharing
 * state through the filesystem.
 */
export function childEnv(creds: KeeperCredentials, home: string): Record<string, string> {
  return {
    KSM_CONFIG_BASE64: creds.configBase64,
    KSM_MCP_BATCH_MODE: "true",
    KSM_MCP_LOG_LEVEL: "error",
    // Upstream falls back to $HOME/.keeper/ksm-mcp for its profile store if the
    // in-memory path is ever missed. Per-tenant, not merely off-image-default:
    // a single shared HOME would make that fallback a cross-tenant surface.
    HOME: home,
  };
}

/** Per-tenant HOME directory for a child, derived from its pool key. */
export function childHomeFor(baseDir: string, credHash: string): string {
  return join(baseDir, credHash);
}
