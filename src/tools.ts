/**
 * The v1 tool policy: a READ-ONLY allowlist over Keeper's upstream surface,
 * default-deny in both dimensions — which tools are served, and which
 * arguments each served tool accepts.
 *
 * ## Why a policy layer exists at all
 *
 * Keeper's upstream has no read-only mode. Verified against the v2.5.0 pin:
 * `serve` has six flags (`--batch`, `--auto-approve`, `--timeout`,
 * `--log-level`, `--config-base64`, `--no-logs`) and none of them restrict the
 * surface; `getAvailableTools()` returns a hardcoded 19-element slice that
 * consults no config; `types.Confirmation.DefaultDeny` exists but is hardcoded
 * false with no plumbing. Nothing upstream can un-register a tool.
 *
 * ## Why the bridge forces batch mode
 *
 * With batch mode off, confirm-requiring tools do NOT hard-error (with one
 * exception, `get_field` + `unmask`). They return a *successful* result of
 * `{status: "confirmation_required", confirmation_details: {prompt_name:
 * "ksm_confirm_action", ...}}` and expect a two-phase completion.
 *
 * That two-phase flow is unreachable through this bridge, by construction and
 * by choice:
 *   - it is driven by an MCP *prompt*, and this bridge never declares the
 *     `prompts` capability (see bridge.ts) — so the prompt cannot be fetched;
 *   - the tool that completes it, `ksm_execute_confirmed_action`, is blocked
 *     below — deliberately, because the caller supplies its own
 *     `user_decision: true`, making it a self-approval trampoline.
 *
 * So leaving batch mode off would not buy a confirmation boundary; it would
 * only return stubs no client here can satisfy. We force it on, and accept
 * that the child then auto-approves anything it is asked to do
 * (`internal/ui/confirm.go`). Which is precisely why this file exists.
 *
 * ## Where the real boundary lives
 *
 * This allowlist is the SECOND boundary, not the only one. The first is
 * Keeper-side: a KSM application's shared-folder grant is read-only unless
 * explicitly made editable, and a non-editable grant makes every write fail at
 * Keeper's own server regardless of anything here. That is a provisioning
 * precondition (see README) — the bridge cannot verify it, because ksm-mcp
 * never surfaces the SDK's per-record `IsEditable`.
 *
 * What this allowlist uniquely buys, which a read-only grant does NOT:
 * blocking `get_all_secrets_unmasked` and `ksm_execute_confirmed_action`.
 * Both are reads-or-worse that a read-only grant happily permits.
 *
 * Enabling writes is a reviewed, versioned change to this file plus the
 * matching `VENDOR_TOOL_CONFIG` rows in conduit — never a config flag.
 */

/**
 * Every tool the pinned upstream (v2.5.0) advertises, verbatim from
 * `internal/mcp/tools.go`. This is upstream-surface knowledge and is versioned
 * alongside the `KSM_MCP_REF` pin in the Dockerfile.
 *
 * It is the single source of truth: what we serve is `ALLOWED_TOOLS`, and what
 * we block is everything else here. `scripts/check-upstream-tools.mjs`
 * re-derives this list from the pinned Go source and fails the build if it has
 * drifted, so a version bump cannot quietly add an unreviewed tool.
 */
export const UPSTREAM_TOOLS = [
  "create_folder",
  "create_secret",
  "delete_folder",
  "delete_secret",
  "download_file",
  "generate_password",
  "get_all_secrets_unmasked",
  "get_field",
  "get_record_type_schema",
  "get_secret",
  "get_server_version",
  "get_totp_code",
  "health_check",
  "ksm_execute_confirmed_action",
  "list_folders",
  "list_secrets",
  "update_secret",
  "upload_file",
  "search_secrets",
] as const;

export type UpstreamToolName = (typeof UPSTREAM_TOOLS)[number];

/**
 * The tools served in v1, each with the exact arguments it may receive.
 *
 * `allowArgs` is an ALLOWLIST, not a blocklist. An upstream version bump that
 * adds a parameter to an already-served tool — a `save_path` on `get_secret`,
 * say — must then be reviewed into this table before it reaches a tenant,
 * instead of passing through silently. The lists below are the real upstream
 * schemas minus anything that writes.
 *
 * Names pass through unchanged; upstream owns them, and rewriting them here
 * would break every Keeper doc a user reads.
 */
export const ALLOWED_TOOLS = {
  // --- metadata only: no credential material crosses the wire ---
  /** Record metadata (uid/title/type). Values are not included. */
  list_secrets: { allowArgs: ["folder_uid", "folder_uids"] },
  /**
   * Metadata-shaped RESULT ({uid,title,type,folder}), but the MATCH runs
   * case-insensitive substring over the record's notes and the values of its
   * login/url/hostname/address fields. A caller never receives a secret but
   * can test whether one contains a given substring — a confirmation oracle
   * (CWE-200). Conduit classifies it `admin` for that reason; the matching is
   * inside Keeper's binary and cannot be narrowed from here.
   */
  search_secrets: { allowArgs: ["query"] },
  /** Folder metadata within the application's scope. */
  list_folders: { allowArgs: [] },
  /** Upstream liveness plus KSM reachability. */
  health_check: { allowArgs: [] },
  /** Upstream version string. */
  get_server_version: { allowArgs: [] },

  // --- credential reads: legitimate, but classified `admin` in conduit ---
  /**
   * One record, masked unless the caller passes `unmask`. We honour unmask —
   * retrieving a credential IS the product — but keep it per-record and
   * intentional. The vault-wide equivalent is blocked.
   */
  get_secret: { allowArgs: ["uid", "fields", "unmask"] },
  /** KSM notation query against a single field. The narrowest possible read. */
  get_field: { allowArgs: ["notation", "unmask"] },
  /** Current TOTP code for a record that has one configured. */
  get_totp_code: { allowArgs: ["uid"] },

  // --- local utility ---
  /**
   * Password generation. Upstream also accepts `save_to_secret` + `folder_uid`,
   * which turn this into a record CREATE; both are absent from `allowArgs`, so
   * they are stripped from the advertised schema and from inbound calls.
   */
  generate_password: {
    allowArgs: ["length", "lowercase", "uppercase", "digits", "special", "special_set"],
  },
} as const satisfies Record<string, { allowArgs: readonly string[] }>;

export type AllowedToolName = keyof typeof ALLOWED_TOOLS;

/** Served tool names, sorted once — the deterministic order `tools/list` uses. */
export const ALLOWED_TOOL_NAMES: readonly string[] = Object.keys(ALLOWED_TOOLS).sort();

/** Everything upstream offers that we do not serve. Derived, never hand-listed. */
export const BLOCKED_TOOLS: readonly string[] = UPSTREAM_TOOLS.filter(
  (name) => !Object.hasOwn(ALLOWED_TOOLS, name),
).sort();

/**
 * Reasons worth saying out loud in a refusal. Only the cases where a caller
 * (or a reviewer) would otherwise be misled about WHY — the plain writes are
 * self-evident from "this integration is read-only".
 */
const BLOCK_REASONS: Readonly<Record<string, string>> = {
  get_all_secrets_unmasked:
    "It returns every secret in the application's scope, unmasked, in a single call. " +
    "Blocked permanently, including in any future write-enabled release.",
  ksm_execute_confirmed_action:
    "It executes an arbitrary named tool with a caller-supplied approval flag, which " +
    "would bypass every other rule here. Blocked permanently.",
  get_record_type_schema:
    "It is non-functional upstream at the pinned version: record templates are never " +
    "loaded, so every call returns an internal error.",
  download_file:
    "Upstream writes the file to a server-side path and never returns its bytes, so it " +
    "cannot deliver an attachment over MCP.",
};

export function isAllowed(toolName: string): toolName is AllowedToolName {
  return Object.hasOwn(ALLOWED_TOOLS, toolName);
}

/** Human-readable refusal for a `tools/call` on a tool we do not serve. */
export function refusalMessage(toolName: string): string {
  const reason = BLOCK_REASONS[toolName];
  return (
    `Tool "${toolName}" is not available through this read-only Keeper integration.` +
    (reason ? ` ${reason}` : "") +
    ` Available tools: ${ALLOWED_TOOL_NAMES.join(", ")}.`
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

/** Keep only `keys` from `obj`. */
function pick(
  obj: Record<string, unknown>,
  keys: readonly string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    if (Object.hasOwn(obj, key)) out[key] = obj[key];
  }
  return out;
}

/**
 * Filter the child's `tools/list` down to the allowlist and narrow each
 * advertised schema to its allowed arguments.
 *
 * Deterministic order (sorted by name): the 2026-07-28 spec asks list results
 * to be stable so clients and prompt caches can rely on them, and the upstream
 * makes no ordering promise of its own.
 */
export function filterTools<T extends UpstreamTool>(tools: readonly T[]): T[] {
  return tools
    .filter((tool): tool is T & { name: AllowedToolName } => isAllowed(tool.name))
    .map((tool) => {
      // Widened from the literal tuple: an empty `allowArgs` infers as
      // `never[]`, which cannot be `.includes()`-ed against a string.
      const allowArgs: readonly string[] = ALLOWED_TOOLS[tool.name].allowArgs;
      if (!tool.inputSchema?.properties) return tool;
      return {
        ...tool,
        inputSchema: {
          ...tool.inputSchema,
          properties: pick(tool.inputSchema.properties, allowArgs),
          ...(tool.inputSchema.required
            ? { required: tool.inputSchema.required.filter((r) => allowArgs.includes(r)) }
            : {}),
        },
      };
    })
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/**
 * Narrow an inbound call's arguments to the allowed set.
 *
 * A client that ignores the advertised schema — or works from a stale cached
 * copy of it — must not be able to reach a write path by passing the argument
 * anyway. This is the enforcement half; `filterTools` is only the advertising
 * half.
 */
export function pickToolArgs(
  toolName: AllowedToolName,
  args: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!args) return args;
  const allowArgs: readonly string[] = ALLOWED_TOOLS[toolName].allowArgs;
  return pick(args, allowArgs);
}
