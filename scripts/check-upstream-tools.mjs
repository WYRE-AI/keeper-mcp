#!/usr/bin/env node
/**
 * Verify that our record of the upstream tool surface still matches the pinned
 * Keeper source.
 *
 * Why: the tool allowlist in src/tools.ts is default-deny, so a NEW upstream
 * tool is blocked automatically — but a new ARGUMENT on an already-served tool,
 * or a renamed tool, would otherwise pass unreviewed. Rather than trusting a
 * step in a README checklist, this re-derives the surface from the Go source
 * and fails on any drift.
 *
 * Run against a checkout of the pinned upstream:
 *   node scripts/check-upstream-tools.mjs /path/to/ksm-mcp
 *
 * The Docker build runs it with the build-stage checkout, so a version bump
 * that changes the surface fails the image build.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

const upstreamDir = process.argv[2];
if (!upstreamDir) {
  console.error("usage: check-upstream-tools.mjs <path-to-ksm-mcp-checkout>");
  process.exit(2);
}

const source = readFileSync(join(upstreamDir, "internal/mcp/tools.go"), "utf8");

// Each tool is `Name: "x"` followed by its schema; properties are the keys of
// the `"prop": map[string]interface{}{ "type": ...` entries before the next Name.
const nameMatches = [...source.matchAll(/Name:\s*"([a-z_]+)"/g)];
if (nameMatches.length === 0) {
  console.error("FAIL: found no tool definitions — has internal/mcp/tools.go moved?");
  process.exit(1);
}

const upstream = {};
nameMatches.forEach((match, i) => {
  const start = match.index;
  const end = i + 1 < nameMatches.length ? nameMatches[i + 1].index : source.length;
  const segment = source.slice(start, end);
  const properties = [...segment.matchAll(/"(\w+)": map\[string\]interface\{\}\{\s*\n\s*"type":/g)].map(
    (m) => m[1],
  );
  upstream[match[1]] = properties.sort();
});

// Our record, read straight out of the TypeScript so there is one place to update.
const fixture = readFileSync(new URL("../src/__tests__/fixtures.ts", import.meta.url), "utf8");
const known = {};
for (const block of fixture.matchAll(
  /(\w+):\s*\{\s*properties:\s*\[([^\]]*)\]/g,
)) {
  known[block[1]] = [...block[2].matchAll(/"(\w+)"/g)].map((m) => m[1]).sort();
}

const problems = [];
for (const [name, props] of Object.entries(upstream)) {
  if (!(name in known)) {
    problems.push(`NEW upstream tool "${name}" — triage it into ALLOWED_TOOLS or leave it blocked, and add it to fixtures.ts`);
    continue;
  }
  const added = props.filter((p) => !known[name].includes(p));
  const removed = known[name].filter((p) => !props.includes(p));
  if (added.length) {
    problems.push(`tool "${name}" gained argument(s): ${added.join(", ")} — review before serving`);
  }
  if (removed.length) {
    problems.push(`tool "${name}" lost argument(s): ${removed.join(", ")} — update fixtures.ts`);
  }
}
for (const name of Object.keys(known)) {
  if (!(name in upstream)) {
    problems.push(`tool "${name}" no longer exists upstream — remove it from fixtures.ts and the policy`);
  }
}

if (problems.length) {
  console.error("Upstream tool surface has drifted from src/__tests__/fixtures.ts:\n");
  for (const problem of problems) console.error(`  - ${problem}`);
  console.error("\nSee README 'Bumping the upstream pin'.");
  process.exit(1);
}

console.log(
  `upstream tool surface OK: ${Object.keys(upstream).length} tools, arguments unchanged`,
);
