/**
 * The read-only tool policy. These tests are the executable form of the
 * security argument in src/tools.ts: the upstream child auto-approves every
 * confirmation in batch mode, so the allowlist here is the ONLY boundary
 * between a model and a tenant's vault.
 */
import { describe, expect, it } from "vitest";
import {
  ALLOWED_TOOLS,
  BLOCKED_TOOLS,
  filterTools,
  isAllowed,
  refusalMessage,
  stripToolArgs,
} from "../tools.js";

/** The 19 tools upstream v2.5.0 advertises (internal/mcp/tools.go). */
const UPSTREAM_TOOLS = [
  "list_secrets",
  "get_secret",
  "search_secrets",
  "get_field",
  "generate_password",
  "get_totp_code",
  "create_secret",
  "update_secret",
  "delete_secret",
  "upload_file",
  "download_file",
  "list_folders",
  "create_folder",
  "health_check",
  "get_server_version",
  "delete_folder",
  "ksm_execute_confirmed_action",
  "get_all_secrets_unmasked",
  "get_record_type_schema",
].map((name) => ({
  name,
  inputSchema: {
    type: "object" as const,
    properties: {
      uid: { type: "string" },
      save_path: { type: "string" },
      save_to_secret: { type: "string" },
      folder_uid: { type: "string" },
    },
    required: ["uid"],
  },
}));

describe("allowlist coverage", () => {
  it("accounts for every upstream tool as either allowed or blocked", () => {
    const unaccounted = UPSTREAM_TOOLS.map((t) => t.name).filter(
      (name) => !Object.hasOwn(ALLOWED_TOOLS, name) && !Object.hasOwn(BLOCKED_TOOLS, name),
    );
    expect(unaccounted).toEqual([]);
  });

  it("serves exactly the 11 read tools", () => {
    expect(Object.keys(ALLOWED_TOOLS).sort()).toEqual(
      [
        "download_file",
        "generate_password",
        "get_field",
        "get_record_type_schema",
        "get_secret",
        "get_server_version",
        "get_totp_code",
        "health_check",
        "list_folders",
        "list_secrets",
        "search_secrets",
      ].sort(),
    );
  });

  it("allows and blocks disjoint sets", () => {
    const overlap = Object.keys(ALLOWED_TOOLS).filter((n) => Object.hasOwn(BLOCKED_TOOLS, n));
    expect(overlap).toEqual([]);
  });

  it.each([
    "create_secret",
    "update_secret",
    "delete_secret",
    "create_folder",
    "delete_folder",
    "upload_file",
    "ksm_execute_confirmed_action",
    "get_all_secrets_unmasked",
  ])("blocks %s", (name) => {
    expect(isAllowed(name)).toBe(false);
  });
});

describe("filterTools", () => {
  const filtered = filterTools(UPSTREAM_TOOLS);

  it("drops every blocked tool from tools/list", () => {
    const names = filtered.map((t) => t.name);
    expect(names).not.toContain("delete_secret");
    expect(names).not.toContain("get_all_secrets_unmasked");
    expect(names).toHaveLength(11);
  });

  it("returns a deterministic (sorted) order", () => {
    const names = filtered.map((t) => t.name);
    expect(names).toEqual([...names].sort());
  });

  it("strips write-capable args from generate_password's advertised schema", () => {
    const tool = filtered.find((t) => t.name === "generate_password")!;
    expect(tool.inputSchema.properties).not.toHaveProperty("save_to_secret");
    expect(tool.inputSchema.properties).not.toHaveProperty("folder_uid");
  });

  it("strips save_path from download_file's advertised schema", () => {
    const tool = filtered.find((t) => t.name === "download_file")!;
    expect(tool.inputSchema.properties).not.toHaveProperty("save_path");
  });

  it("leaves non-stripped tools' schemas untouched", () => {
    const tool = filtered.find((t) => t.name === "get_secret")!;
    expect(tool.inputSchema.properties).toHaveProperty("save_path");
  });

  it("does not mutate the input tools", () => {
    expect(UPSTREAM_TOOLS.find((t) => t.name === "download_file")!.inputSchema.properties).toHaveProperty(
      "save_path",
    );
  });
});

describe("stripToolArgs", () => {
  it("removes stripped args a client sent anyway (stale or ignored schema)", () => {
    expect(
      stripToolArgs("generate_password", { length: 32, save_to_secret: "pwned", folder_uid: "f1" }),
    ).toEqual({ length: 32 });
  });

  it("removes save_path from download_file calls", () => {
    expect(stripToolArgs("download_file", { uid: "u1", save_path: "/etc/cron.d/x" })).toEqual({
      uid: "u1",
    });
  });

  it("passes through args for tools with no strip rule", () => {
    expect(stripToolArgs("get_secret", { uid: "u1", unmask: true })).toEqual({
      uid: "u1",
      unmask: true,
    });
  });

  it("tolerates undefined args", () => {
    expect(stripToolArgs("download_file", undefined)).toBeUndefined();
  });
});

describe("refusalMessage", () => {
  it("explains WHY a blocked tool is refused", () => {
    expect(refusalMessage("get_all_secrets_unmasked")).toContain("dumps every secret");
  });

  it("lists the available tools for an unknown tool name", () => {
    const message = refusalMessage("not_a_real_tool");
    expect(message).toContain("list_secrets");
  });

  it("never leaks a blocked tool as merely unknown", () => {
    expect(refusalMessage("delete_secret")).toContain("read-only");
  });
});
