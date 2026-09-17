/**
 * Per-tenant child pool for the upstream keeper-security/ksm-mcp server.
 *
 * The upstream is stdio-ONLY (`ksm-mcp serve`; there is no HTTP or SSE mode
 * anywhere in its source) and reads KSM_CONFIG_BASE64 at process start, which
 * makes it single-tenant per process. This pool lazily spawns one child per
 * credential and holds an MCP client session over stdio to each:
 *
 *   - Children are keyed by a hash of the config, never the config itself.
 *   - Concurrent requests for the same tenant share one spawn (the pool entry
 *     is registered synchronously; callers await its connect promise).
 *   - Idle children are evicted after IDLE_EVICT_MS (default 15 min).
 *   - Spawn/connect failures stay scoped to the requesting tenant: the entry is
 *     removed and the next request retries a fresh spawn.
 *
 * On the eviction window: nutanix-mcp uses 60 minutes because its Python child
 * pays a multi-second cold start parsing ~20 YAML API specs. Keeper's child is
 * a static Go binary that starts in milliseconds, so there is no reason to hold
 * one open as long — and every minute it stays open is a minute an authenticated
 * KSM session sits in memory. Short window, cheap respawn: take the short window.
 */
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/client/stdio";
import {
  CHILD_ARGS,
  credentialsToChildEnv,
  hashCredentials,
  type KeeperCredentials,
} from "./credentials.js";

export interface ChildPoolOptions {
  /** Path to the upstream `ksm-mcp` binary the bridge spawns. */
  upstreamBin?: string;
  /** Writable HOME for the child (upstream resolves its config dir under it). */
  childHome?: string;
  /** Idle tenant timeout before a child is evicted (ms). */
  idleEvictMs?: number;
  /** How long to wait for a spawned child to answer the MCP handshake (ms). */
  spawnTimeoutMs?: number;
}

interface TenantChild {
  client: Client;
  connectPromise: Promise<void>;
  lastUsed: number;
  credHash: string;
}

export class ChildPool {
  private readonly children = new Map<string, TenantChild>();
  private readonly sweeper: NodeJS.Timeout;
  private readonly upstreamBin: string;
  private readonly childHome: string;
  private readonly idleEvictMs: number;
  private readonly spawnTimeoutMs: number;

  constructor(options: ChildPoolOptions = {}) {
    this.upstreamBin = options.upstreamBin ?? process.env.KSM_MCP_BIN ?? "/usr/local/bin/ksm-mcp";
    this.childHome = options.childHome ?? process.env.CHILD_HOME ?? "/tmp/ksm-mcp-home";
    this.idleEvictMs = options.idleEvictMs ?? Number(process.env.IDLE_EVICT_MS ?? 15 * 60 * 1000);
    this.spawnTimeoutMs = options.spawnTimeoutMs ?? Number(process.env.SPAWN_TIMEOUT_MS ?? 30_000);

    this.sweeper = setInterval(() => this.evictIdle(), 60_000);
    this.sweeper.unref();
  }

  get size(): number {
    return this.children.size;
  }

  /** Get (or lazily spawn) the connected MCP client session for a tenant. */
  async getSession(creds: KeeperCredentials): Promise<Client> {
    const credHash = hashCredentials(creds);
    let child = this.children.get(credHash);
    if (!child) {
      child = this.spawn(creds, credHash);
    }
    child.lastUsed = Date.now();
    await child.connectPromise;
    child.lastUsed = Date.now();
    return child.client;
  }

  private spawn(creds: KeeperCredentials, credHash: string): TenantChild {
    const transport = new StdioClientTransport({
      command: this.upstreamBin,
      args: [...CHILD_ARGS],
      env: {
        ...getDefaultEnvironment(),
        ...credentialsToChildEnv(creds),
        // Upstream falls back to ~/.keeper/ksm-mcp for its profile store if it
        // ever misses the in-memory path. Point HOME at a writable scratch dir
        // so that fallback cannot land in a location shared across tenants.
        HOME: this.childHome,
      },
      stderr: "pipe",
    });
    // Tag child stderr with the tenant hash for debuggability. The hash is a
    // digest of the config, so this is safe to write to logs; the config is not.
    transport.stderr?.on("data", (chunk: Buffer) => {
      process.stderr.write(`[ksm:${credHash}] ${chunk}`);
    });

    const client = new Client({ name: "keeper-mcp-bridge", version: "1.0.0" });

    const child: TenantChild = {
      client,
      connectPromise: Promise.resolve(),
      lastUsed: Date.now(),
      credHash,
    };
    // Register BEFORE awaiting so concurrent requests share this spawn.
    this.children.set(credHash, child);

    child.connectPromise = (async () => {
      try {
        await client.connect(transport, { timeout: this.spawnTimeoutMs });
        // Child died later (crash, OOM, eviction race): drop the pool entry so
        // the next request respawns instead of hitting a dead session.
        client.onclose = () => {
          if (this.children.get(credHash) === child) {
            this.children.delete(credHash);
            process.stderr.write(`[ksm:${credHash}] child session closed\n`);
          }
        };
      } catch (err) {
        // Spawn/handshake failure — most commonly a missing binary (ENOENT) or
        // a config the upstream rejects. Scope it to this tenant: remove the
        // entry, kill the child, surface the real error to the caller.
        this.children.delete(credHash);
        try {
          await client.close();
        } catch {
          /* ignore */
        }
        const message = err instanceof Error ? err.message : String(err);
        throw new Error(`Failed to start Keeper MCP child process: ${message}`);
      }
    })();

    return child;
  }

  private evictIdle(): void {
    const now = Date.now();
    for (const [credHash, child] of this.children) {
      if (now - child.lastUsed > this.idleEvictMs) {
        process.stderr.write(`[ksm:${credHash}] evicting idle child after ${this.idleEvictMs}ms\n`);
        this.children.delete(credHash);
        child.client.close().catch(() => {
          /* ignore */
        });
      }
    }
  }

  async shutdown(): Promise<void> {
    clearInterval(this.sweeper);
    const closing = [...this.children.values()].map((child) =>
      child.client.close().catch(() => {
        /* ignore */
      }),
    );
    this.children.clear();
    await Promise.all(closing);
  }
}
