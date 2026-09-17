/**
 * Shared test fixtures.
 *
 * `UPSTREAM_TOOL_SCHEMAS` mirrors the REAL schemas of the pinned upstream
 * (v2.5.0 `internal/mcp/tools.go`), extracted from source rather than invented.
 * `scripts/check-upstream-tools.mjs` re-derives the same data from the pinned
 * Go source and fails if this has drifted, so a version bump cannot leave the
 * suite testing a surface that no longer exists.
 */

export const UPSTREAM_TOOL_SCHEMAS: Record<
  string,
  { properties: string[]; required: string[] }
> = {
  list_secrets: { properties: ["folder_uid", "folder_uids"], required: [] },
  get_secret: { properties: ["uid", "fields", "unmask"], required: ["uid"] },
  search_secrets: { properties: ["query"], required: ["query"] },
  get_field: { properties: ["notation", "unmask"], required: ["notation"] },
  generate_password: {
    properties: [
      "length",
      "lowercase",
      "uppercase",
      "digits",
      "special",
      "special_set",
      "save_to_secret",
      "folder_uid",
    ],
    required: [],
  },
  get_totp_code: { properties: ["uid"], required: ["uid"] },
  create_secret: {
    properties: ["folder_uid", "type", "title", "fields", "items", "properties", "value", "notes"],
    required: ["type", "value"],
  },
  update_secret: {
    properties: ["uid", "title", "fields", "items", "properties", "value", "notes"],
    required: ["type", "value"],
  },
  delete_secret: { properties: ["uid"], required: ["uid"] },
  upload_file: { properties: ["uid", "file_path", "title"], required: ["uid", "file_path", "title"] },
  download_file: { properties: ["uid", "file_uid", "save_path"], required: ["uid", "file_uid"] },
  list_folders: { properties: [], required: [] },
  create_folder: { properties: ["name", "parent_uid"], required: ["name"] },
  health_check: { properties: [], required: [] },
  get_server_version: { properties: [], required: [] },
  delete_folder: { properties: ["folder_uid", "force"], required: ["folder_uid"] },
  ksm_execute_confirmed_action: {
    properties: [
      "original_tool_name",
      "original_tool_args_json",
      "user_decision",
      "confirmation_context",
    ],
    required: ["original_tool_name", "original_tool_args_json", "user_decision"],
  },
  get_all_secrets_unmasked: { properties: ["folder_uid", "fields"], required: [] },
  get_record_type_schema: { properties: ["properties"], required: ["type"] },
};

/** The upstream tool list in the shape a `tools/list` response carries. */
export const upstreamToolList = (): Array<{
  name: string;
  inputSchema: { type: "object"; properties: Record<string, unknown>; required: string[] };
}> =>
  Object.entries(UPSTREAM_TOOL_SCHEMAS).map(([name, schema]) => ({
    name,
    inputSchema: {
      type: "object" as const,
      properties: Object.fromEntries(schema.properties.map((p) => [p, { type: "string" }])),
      required: [...schema.required],
    },
  }));

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64");

export const VALID_CONFIG = {
  hostname: "keepersecurity.com",
  clientId: "Zm9vYmFyY2xpZW50aWQ=",
  privateKey: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH",
  appKey: "YXBwa2V5YXBwa2V5YXBwa2V5",
  serverPublicKeyId: "10",
};

export const VALID_CONFIG_B64 = b64(VALID_CONFIG);

export { b64 };
