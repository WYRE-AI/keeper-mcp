/**
 * The read-only tool policy. These tests are the executable form of the
 * security argument in src/tools.ts: the upstream child auto-approves every
 * confirmation in batch mode, so this allowlist is the last boundary inside
 * our own process between a model and a tenant's vault.
 */
import { describe, expect, it } from "vitest";
import {
  ALLOWED_TOOLS,
  ALLOWED_TOOL_NAMES,
  BLOCKED_TOOLS,
  UPSTREAM_TOOLS,
  filterTools,
  isAllowed,
  pickToolArgs,
  refusalMessage,
} from "../tools.js";
import { UPSTREAM_TOOL_SCHEMAS, upstreamToolList } from "./fixtures.js";

describe("allowlist coverage", () => {
  it("serves exactly the 9 read tools", () => {
    expect(ALLOWED_TOOL_NAMES).toEqual([
      "generate_password",
      "get_field",
      "get_secret",
      "get_server_version",
      "get_totp_code",
      "health_check",
      "list_folders",
      "list_secrets",
      "search_secrets",
    ]);
  });

  it("only ever allows tools the pinned upstream actually has", () => {
    const phantom = ALLOWED_TOOL_NAMES.filter(
      (name) => !(UPSTREAM_TOOLS as readonly string[]).includes(name),
    );
    expect(phantom).toEqual([]);
  });

  it("blocks everything upstream offers that is not allowed", () => {
    expect(BLOCKED_TOOLS).toEqual([
      "create_folder",
      "create_secret",
      "delete_folder",
      "delete_secret",
      "download_file",
      "get_all_secrets_unmasked",
      "get_record_type_schema",
      "ksm_execute_confirmed_action",
      "update_secret",
      "upload_file",
    ]);
  });

  it("accounts for every upstream tool exactly once", () => {
    expect([...ALLOWED_TOOL_NAMES, ...BLOCKED_TOOLS].sort()).toEqual([...UPSTREAM_TOOLS].sort());
  });

  it("stays in step with the upstream schema fixture", () => {
    expect(Object.keys(UPSTREAM_TOOL_SCHEMAS).sort()).toEqual([...UPSTREAM_TOOLS].sort());
  });
});

describe("the self-approval trampoline stays shut", () => {
  // A name allowlist has exactly one structural failure mode: an allowed tool
  // whose ARGUMENT names another tool. ksm_execute_confirmed_action is that
  // tool upstream — it takes original_tool_name plus a caller-supplied
  // user_decision — and it would collapse every other rule in this file into
  // one allowed name. This test generalises the rule to future upstream
  // additions rather than just re-asserting the one known case.
  it("blocks ksm_execute_confirmed_action", () => {
    expect(isAllowed("ksm_execute_confirmed_action")).toBe(false);
  });

  it("serves no tool that accepts another tool's name or an approval flag", () => {
    const upstreamNames = new Set<string>(UPSTREAM_TOOLS);
    const offenders: string[] = [];
    for (const name of ALLOWED_TOOL_NAMES) {
      for (const arg of ALLOWED_TOOLS[name as keyof typeof ALLOWED_TOOLS].allowArgs) {
        if (upstreamNames.has(arg) || /tool_name|tool_args|decision|confirm/i.test(arg)) {
          offenders.push(`${name}.${arg}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("filterTools", () => {
  const filtered = filterTools(upstreamToolList());

  it("drops every blocked tool from tools/list", () => {
    const names = filtered.map((t) => t.name);
    expect(names).toEqual([...ALLOWED_TOOL_NAMES]);
  });

  it("returns a deterministic (sorted) order", () => {
    const names = filtered.map((t) => t.name);
    expect(names).toEqual([...names].sort());
  });

  it("narrows each advertised schema to its allowed arguments", () => {
    for (const tool of filtered) {
      const allowed = ALLOWED_TOOLS[tool.name as keyof typeof ALLOWED_TOOLS].allowArgs;
      expect(Object.keys(tool.inputSchema.properties).sort()).toEqual(
        [...allowed].filter((a) => UPSTREAM_TOOL_SCHEMAS[tool.name]!.properties.includes(a)).sort(),
      );
    }
  });

  it("removes generate_password's record-creating arguments", () => {
    const tool = filtered.find((t) => t.name === "generate_password")!;
    expect(tool.inputSchema.properties).not.toHaveProperty("save_to_secret");
    expect(tool.inputSchema.properties).not.toHaveProperty("folder_uid");
    expect(tool.inputSchema.properties).toHaveProperty("length");
  });

  it("drops a newly-added upstream argument by default (fail closed)", () => {
    const withNewArg = upstreamToolList().map((tool) =>
      tool.name === "get_secret"
        ? {
            ...tool,
            inputSchema: {
              ...tool.inputSchema,
              properties: { ...tool.inputSchema.properties, write_back: { type: "string" } },
            },
          }
        : tool,
    );
    const got = filterTools(withNewArg).find((t) => t.name === "get_secret")!;
    expect(got.inputSchema.properties).not.toHaveProperty("write_back");
  });

  it("does not mutate the input tools", () => {
    const input = upstreamToolList();
    filterTools(input);
    expect(input.find((t) => t.name === "generate_password")!.inputSchema.properties).toHaveProperty(
      "save_to_secret",
    );
  });
});

describe("pickToolArgs", () => {
  it("removes disallowed args a client sent anyway (stale or ignored schema)", () => {
    expect(
      pickToolArgs("generate_password", { length: 32, save_to_secret: "pwned", folder_uid: "f1" }),
    ).toEqual({ length: 32 });
  });

  it("passes through every allowed arg", () => {
    expect(pickToolArgs("get_secret", { uid: "u1", unmask: true, fields: ["password"] })).toEqual({
      uid: "u1",
      unmask: true,
      fields: ["password"],
    });
  });

  it("drops an argument upstream does not have and we never allowed", () => {
    expect(pickToolArgs("get_secret", { uid: "u1", save_path: "/etc/cron.d/x" })).toEqual({
      uid: "u1",
    });
  });

  it("tolerates undefined args", () => {
    expect(pickToolArgs("list_folders", undefined)).toBeUndefined();
  });
});

describe("refusalMessage", () => {
  it("explains WHY the bulk export is refused", () => {
    expect(refusalMessage("get_all_secrets_unmasked")).toContain("every secret");
  });

  it("explains that the trampoline would bypass every other rule", () => {
    expect(refusalMessage("ksm_execute_confirmed_action")).toContain("bypass");
  });

  it("says a tool is broken upstream rather than implying we chose to withhold it", () => {
    expect(refusalMessage("get_record_type_schema")).toContain("non-functional");
    expect(refusalMessage("download_file")).toContain("never returns its bytes");
  });

  it("always names the read-only posture and the available tools", () => {
    for (const name of [...BLOCKED_TOOLS, "not_a_real_tool"]) {
      const message = refusalMessage(name);
      expect(message).toContain("read-only");
      expect(message).toContain("list_secrets");
    }
  });
});
