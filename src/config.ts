import { existsSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

/** Scopes gate every MCP tool. `dms.read` is deliberately absent from the default set. */
export const ALL_SCOPES = [
  "tweets.read",
  "likes.read",
  "graph.read",
  "media.read",
  "analytics.read",
  "dms.read",
] as const;

export type Scope = (typeof ALL_SCOPES)[number];

/**
 * Direct messages contain other people's words, so exposing them has to be a
 * deliberate act rather than a default. Everything else is your own content.
 */
export const DEFAULT_SCOPES: Scope[] = [
  "tweets.read",
  "likes.read",
  "graph.read",
  "media.read",
  "analytics.read",
];

export interface VaultConfig {
  /** Repo root. */
  root: string;
  /** Unpacked X archive root (the directory containing `data/`). */
  archiveDir: string;
  /** Normalized NDJSON corpus. */
  corpusDir: string;
  /** Content-addressed ciphertext store. */
  storeDir: string;
  /** SQLite FTS index (a derived cache, rebuildable from the store). */
  indexPath: string;
  auditLogPath: string;
  /**
   * Per-Mind remote access grants. Deliberately not inside corpus/ — that is a
   * derived cache which `vault rebuild` destroys and recreates, and an access
   * control list must not be collateral damage of a reindex.
   */
  grantsPath: string;
  scopes: Scope[];
}

/**
 * X names archive directories `twitter-<date>-<64 hex chars>`. Rather than
 * hardcode the hash we discover it, so a re-export drops in without config edits.
 */
export function findArchiveDir(root: string): string | null {
  const fromEnv = process.env.VAULT_ARCHIVE_DIR;
  if (fromEnv) {
    const abs = resolve(root, fromEnv);
    return existsSync(resolve(abs, "data", "manifest.js")) ? abs : null;
  }
  const candidates = readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory() && e.name.startsWith("twitter-"))
    .map((e) => resolve(root, e.name))
    .filter((dir) => existsSync(resolve(dir, "data", "manifest.js")))
    // Newest export wins when several are present.
    .sort()
    .reverse();
  return candidates[0] ?? null;
}

function parseScopes(): Scope[] {
  const raw = process.env.VAULT_SCOPES;
  if (!raw) return DEFAULT_SCOPES;
  if (raw.trim() === "*") return [...ALL_SCOPES];
  const requested = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const unknown = requested.filter((s) => !ALL_SCOPES.includes(s as Scope));
  if (unknown.length) {
    throw new Error(
      `Unknown scope(s) in VAULT_SCOPES: ${unknown.join(", ")}. Valid: ${ALL_SCOPES.join(", ")}`,
    );
  }
  return requested as Scope[];
}

export function loadConfig(root = process.cwd()): VaultConfig {
  const archiveDir = findArchiveDir(root);
  if (!archiveDir) {
    throw new Error(
      `No X archive found under ${root}. Expected a directory like ` +
        `twitter-<date>-<hash>/ containing data/manifest.js, or set VAULT_ARCHIVE_DIR.`,
    );
  }
  return {
    root,
    archiveDir,
    corpusDir: resolve(root, "corpus"),
    storeDir: resolve(root, "store"),
    indexPath: resolve(root, "corpus", "vault.db"),
    auditLogPath: resolve(root, "audit.log"),
    grantsPath: resolve(root, "grants.json"),
    scopes: parseScopes(),
  };
}
