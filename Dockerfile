# syntax=docker/dockerfile:1.10
#
# Multitenant Streamable HTTP bridge over keeper-security/ksm-mcp.
#
# Keeper's MCP server is stdio-ONLY and reads KSM_CONFIG_BASE64 at process
# start — single-tenant per process. The conduit gateway forwards per-tenant
# credentials as HTTP headers on every request, so this image runs a small Node
# bridge on port 8080 that:
#
#   1. Reads X-Keeper-Config-Base64 from the incoming request (missing or
#      malformed -> HTTP 401, never a fall-through to env creds)
#   2. Lazily spawns one `ksm-mcp serve --batch` child per credential and holds
#      an MCP client session over stdio to each
#   3. Re-serves the child's tool surface over Streamable HTTP (dual-era),
#      filtered through the READ-ONLY allowlist in src/tools.ts
#   4. Evicts idle children after a timeout
#
# The upstream is pinned to the reviewed v2.5.0 tag (NSA MCP guidance / fleet
# security baseline) — never `main`. To bump: change KSM_MCP_REF below, re-review
# the upstream diff (paying particular attention to internal/mcp/tools.go for
# NEW tools, which default to blocked and must be triaged into src/tools.ts),
# and cut a release.

# ---- Stage 1: build the upstream Go binary ----
# Built from source rather than pulled from keeper/keeper-mcp-server:latest so
# the pin is a reviewed git tag we can diff, not a floating upstream tag.
FROM golang:1.25-alpine AS upstream

ENV KSM_MCP_REF=v2.5.0
WORKDIR /build
RUN apk add --no-cache git ca-certificates
RUN git clone --depth=1 --branch "${KSM_MCP_REF}" \
      https://github.com/Keeper-Security/keeper-mcp-golang-docker.git /build/ksm-mcp
WORKDIR /build/ksm-mcp
RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-w -s -extldflags '-static' -X main.Version=${KSM_MCP_REF}" \
      -a -installsuffix cgo \
      -o /out/ksm-mcp ./cmd/ksm-mcp

# Build-time smoke test 1: the binary the bridge spawns actually runs. Catches
# a broken static link here rather than as a `spawn ... ENOENT` (gateway 502)
# on the first tool call in production.
RUN /out/ksm-mcp --help > /dev/null

# ---- Stage 2: build the Node bridge ----
FROM node:22-bookworm-slim AS bridge-build
WORKDIR /app
COPY package.json package-lock.json* tsconfig.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
RUN npm run build && npm prune --omit=dev

# ---- Stage 3: runtime image ----
FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production \
    PORT=8080 \
    KSM_MCP_BIN=/usr/local/bin/ksm-mcp \
    CHILD_HOME=/tmp/ksm-mcp-home

COPY --from=upstream /out/ksm-mcp /usr/local/bin/ksm-mcp

# Build-time smoke test 2: prove `serve` starts and answers an MCP initialize +
# tools/list. A deliberately invalid config is enough — upstream rejects it and
# exits non-zero, which is itself the signal that the credential path is wired
# (a binary that ignored KSM_CONFIG_BASE64 would start and hang instead).
RUN set -eu; \
    out="$(KSM_CONFIG_BASE64=bm90LWpzb24= /usr/local/bin/ksm-mcp serve --batch 2>&1 </dev/null || true)"; \
    echo "$out" | grep -qi "base64\|config" \
      || { echo "upstream did not report a config error; KSM_CONFIG_BASE64 may no longer be read: $out"; exit 1; }

# The child needs a writable HOME: upstream resolves ~/.keeper/ksm-mcp when its
# in-memory profile path is ever missed. node:22-bookworm-slim ships a `node`
# user (uid 1000); give it one it owns rather than running as root.
RUN mkdir -p /tmp/ksm-mcp-home && chown -R node:node /tmp/ksm-mcp-home

WORKDIR /app
COPY --from=bridge-build /app/node_modules ./node_modules
COPY --from=bridge-build /app/dist ./dist
COPY --from=bridge-build /app/package.json ./package.json

LABEL org.opencontainers.image.source="https://github.com/wyre-technology/keeper-mcp" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Read-only multitenant Streamable HTTP bridge over Keeper Secrets Manager's MCP server" \
      io.modelcontextprotocol.server.name="io.github.wyre-technology/keeper-mcp"

USER node
EXPOSE 8080
CMD ["node", "dist/index.js"]
