/**
 * The v1 tool policy: a READ-ONLY allowlist over Keeper's upstream surface.
 *
 * Why this file exists at all — the upstream offers no safe middle setting.
 * `ksm-mcp` gates its destructive tools behind an interactive confirmation,
 * but in a container there is no TTY, and `internal/ui/confirm.go` collapses
 * to exactly two behaviours:
 *
 *   - batch/auto-approve OFF -> every confirm-requiring tool hard-errors
 *     ("interactive confirmation via terminal is not supported"), which
 *     includes `get_secret` with `unmask: true` — i.e. the integration is
 *     useless.
 *   - batch/auto-approve ON  -> EVERY confirmation is auto-approved, including
 *     `delete_secret` and `get_all_secrets_unmasked`.
 *
 * Keeper's own Docker documentation tells you to set `KSM_MCP_BATCH_MODE=true`.
 * We do too (see credentials.ts) — because we have to — which means the only
 * place a safety boundary can live is here, in front of the child. This
 * allowlist IS the boundary.
 *
 * v1 is read-only, matching the fleet posture set by nutanix-mcp v1. Enabling
 * writes is a reviewed, versioned change to this table plus the matching
 * `VENDOR_TOOL_CONFIG` rows in conduit — never a config flag or an env var.
 */

export interface ToolPolicy {
  /**
   * Arguments removed from BOTH the advertised `inputSchema` and the inbound
   * `tools/call` arguments. Stripping the schema too is the point: a model
   * should never see an affordance the bridge is going to silently refuse.
   */
  stripArgs?: readonly string[];
  /** Why this tool is safe to expose, and any caveat. Kept next to the rule. */
  note: string;
}

/**
 * The 11 tools served in v1. Names pass through unchanged — upstream owns
 * them, and rewriting them here would break every Keeper doc a user reads.
 */
export const ALLOWED_TOOLS: Readonly<Record<string, ToolPolicy>> = {
  // --- metadata only: no credential material crosses the wire ---
  list_secrets: { note: "Record metadata (uid/title/type). Values are not included." },
  search_secrets: { note: "Metadata search over title/notes/fields." },
  list_folders: { note: "Folder metadata within the application's scope." },
  get_record_type_schema: { note: "Static record-type definitions; no vault data." },
  health_check: { note: "Upstream liveness plus KSM reachability." },
  get_server_version: { note: "Upstream version string." },

  // --- credential reads: legitimate, but classified `admin` in conduit ---
  get_secret: {
    note:
      "Returns one record. Masked unless the caller passes unmask:true. We honour " +
      "unmask — retrieving a credential IS the product — but keep it per-record and " +
      "intentional. The vault-wide equivalent (get_all_secrets_unmasked) is blocked.",
  },
  get_field: {
    note: "KSM notation query against a single field. The narrowest possible read.",
  },
  get_totp_code: {
    note: "Current TOTP code for a record that has one configured.",
  },
  download_file: {
    // save_path would let a tenant write attacker-chosen paths into a
    // container filesystem shared by every other tenant's child. Stripping it
    // forces the attachment to come back inline, through the MCP result.
    stripArgs: ["save_path"],
    note: "Attachment contents, returned inline. save_path is stripped (shared-container write).",
  },
  generate_password: {
    // save_to_secret + folder_uid turn this read-only utility into a record
    // CREATE. Stripped rather than blocking the tool, because generating a
    // password without touching the vault is genuinely useful.
    stripArgs: ["save_to_secret", "folder_uid"],
    note: "Local password generation. save_to_secret/folder_uid stripped (they create a record).",
  },
};

/**
 * Blocked tools, with the reason kept in-source so a future reader does not
 * have to reconstruct the argument. These are documentation, not enforcement —
 * enforcement is "not in ALLOWED_TOOLS" — but an explicit list means a new
 * upstream tool appearing in a version bump shows up as *unknown*, not as
 * silently-blocked-and-forgotten.
 */
export const BLOCKED_TOOLS: Readonly<Record<string, string>> = {
  create_secret: "Write. Deferred to a reviewed v2.",
  update_secret: "Write. Deferred to a reviewed v2.",
  delete_secret: "Destructive, irreversible. Auto-approved by the child in batch mode.",
  create_folder: "Write. Deferred to a reviewed v2.",
  delete_folder: "Destructive; can force-delete non-empty folders.",
  upload_file: "Write. Deferred to a reviewed v2.",
  ksm_execute_confirmed_action:
    "The upstream's confirmation-bypass executor. Stays blocked even in a write-enabled v2.",
  get_all_secrets_unmasked:
    "Single call that dumps every secret in the application's scope, unmasked, into the " +
    "model's context. Stays blocked even in a write-enabled v2.",
};

export function isAllowed(toolName: string): boolean {
  return Object.hasOwn(ALLOWED_TOOLS, toolName);
}

/** Human-readable refusal for a `tools/call` on a tool we do not serve. */
export function refusalMessage(toolName: string): string {
  const blockedReason = BLOCKED_TOOLS[toolName];
  if (blockedReason) {
    return (
      `Tool "${toolName}" is not available through Conduit. ${blockedReason} ` +
      `This Keeper integration is read-only: it serves ${Object.keys(ALLOWED_TOOLS).length} ` +
      `read tools and exposes no way to create, modify or delete vault data.`
    );
  }
  return (
    `Tool "${toolName}" is not served by this bridge. Available tools: ` +
    `${Object.keys(ALLOWED_TOOLS).sort().join(", ")}.`
  );
}

interface UpstreamTool {
  name: string;
  inputSchema?: { properties?: Record<string, unknown>; required?: string[] } & Record<
    string,
    unknown
  >;
  [key: string]: unknown;
}

/**
 * Filter the child's `tools/list` down to the allowlist and strip the
 * write-capable arguments out of the advertised schemas.
 *
 * Deterministic order (sorted by name): the 2026-07-28 spec asks list results
 * to be stable so clients and prompt caches can rely on them, and the upstream
 * makes no ordering promise of its own.
 */
export function filterTools<T extends UpstreamTool>(tools: readonly T[]): T[] {
  return tools
    .filter((tool) => isAllowed(tool.name))
    .map((tool) => {
      const { stripArgs } = ALLOWED_TOOLS[tool.name]!;
      if (!stripArgs?.length || !tool.inputSchema?.properties) return tool;

      const properties = { ...tool.inputSchema.properties };
      for (const arg of stripArgs) delete properties[arg];

      return {
        ...tool,
        inputSchema: {
          ...tool.inputSchema,
          properties,
          ...(tool.inputSchema.required
            ? { required: tool.inputSchema.required.filter((r) => !stripArgs.includes(r)) }
            : {}),
        },
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Remove stripped arguments from an inbound call. A client that ignores the
 * advertised schema (or an older cached copy of it) must not be able to reach
 * a write path by passing the argument anyway.
 */
export function stripToolArgs(
  toolName: string,
  args: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  const stripArgs = ALLOWED_TOOLS[toolName]?.stripArgs;
  if (!stripArgs?.length || !args) return args;
  const cleaned = { ...args };
  for (const arg of stripArgs) delete cleaned[arg];
  return cleaned;
}
