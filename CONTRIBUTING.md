# Contributing to keeper-mcp

Thanks for your interest in contributing!

## Development setup

You need Node 20+. You do **not** need Go or a Keeper account to run the test
suite — the pool is pointed at a nonexistent binary in tests, so nothing spawns.

```bash
npm ci
npm run lint    # tsc --noEmit
npm test        # vitest
npm run build
```

Building the image additionally needs Docker; the Go toolchain comes from the
build stage, not your machine.

```bash
docker buildx build --platform linux/amd64 -t keeper-mcp:dev .
```

`--platform linux/amd64` is required — the fleet deploys to Azure Container Apps.

## Ground rules

- **Conventional commits** (`feat:`, `fix:`, `docs:`, `chore:`, …) — releases are
  cut by semantic-release, so the commit type drives versioning.
- **Keep the credential contract frozen.** The `X-Keeper-Config-Base64` →
  `KSM_CONFIG_BASE64` mapping in `src/credentials.ts` is mirrored by conduit's
  vendor-config; changing it is a coordinated, breaking change across two repos.
- **Read-only stays read-only** unless a maintainer signs off. This is not a
  scoping preference, it is a security boundary: Keeper's upstream auto-approves
  every confirmation in batch mode, and a container has no TTY to confirm in, so
  the allowlist in `src/tools.ts` is the only thing standing between a model and
  a tenant's vault. Read the header comment in that file before touching it.
- **`get_all_secrets_unmasked` and `ksm_execute_confirmed_action` stay blocked**
  even if writes are enabled later.
- **Never bump the upstream pin casually.** `KSM_MCP_REF` in the `Dockerfile` is
  a reviewed tag; follow
  [Bumping the upstream pin](README.md#bumping-the-upstream-pin). In particular,
  a bump that adds upstream tools must triage each new tool into `ALLOWED_TOOLS`
  or `BLOCKED_TOOLS` explicitly — the coverage test will fail until you do.

## Tests

`src/__tests__/tools.test.ts` is the executable form of the security argument.
If you change the tool policy, that file is the first place a reviewer will look;
make the tests say what you intend, not just what the code does.

## Reporting a security issue

Do not open a public issue. Contact the WYRE Technology maintainers directly.
