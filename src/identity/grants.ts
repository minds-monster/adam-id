import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { ALL_SCOPES, type Scope } from "../config.js";

/**
 * Who is allowed to reach the vault remotely, and how far.
 *
 * This is the second of two gates. A Moca credential proves *who is calling*;
 * this table decides *what that caller may see*. Effective scopes are the
 * intersection of the two, which is what makes the pair worth having:
 *
 *   - a credential that is over-broad, stale, or issued by a compromised issuer
 *     still cannot exceed what was granted here;
 *   - a generous grant does nothing at all without a valid credential.
 *
 * It lives on local disk, on purpose. Revocation must not depend on Postgres
 * being up, the issuer being reachable, or Moca answering — the one moment you
 * need to cut off an agent is exactly the moment you cannot afford a dependency.
 */
export interface Grant {
  /** Hello Minds Mind id; matched against the credential's `mind_id` claim. */
  mindId: string;
  label: string;
  scopes: Scope[];
  createdAt: string;
  /** null means no expiry. Prefer setting one. */
  expiresAt: string | null;
  note?: string;
  /**
   * Tombstone rather than deletion, so revoking a grant does not erase the
   * record that it once existed — the audit log references mind ids, and a
   * reader six months from now needs to be able to resolve them.
   */
  revokedAt?: string;
  /**
   * The caller's AIR account DID, resolved once at grant time and cached so
   * issuance needs no per-credential round trip to Moca.
   */
  holderDid?: string;
}

interface GrantFile {
  version: 1;
  grants: Grant[];
}

/** Effective scopes: what the credential claims ∩ what was granted locally. */
export function effectiveScopes(asserted: Scope[], granted: Scope[]): Scope[] {
  const allowed = new Set(granted);
  return asserted.filter((s) => allowed.has(s));
}

export function parseScopeList(raw: string): Scope[] {
  const requested = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!requested.length) throw new Error("No scopes given.");
  const unknown = requested.filter((s) => !ALL_SCOPES.includes(s as Scope));
  if (unknown.length) {
    // Same wording as parseScopes() in config.ts — an unknown scope should read
    // identically whether it came from VAULT_SCOPES or from `vault grant`.
    throw new Error(
      `Unknown scope(s): ${unknown.join(", ")}. Valid: ${ALL_SCOPES.join(", ")}`,
    );
  }
  return [...new Set(requested)] as Scope[];
}

export class GrantStore {
  #path: string;

  constructor(path: string) {
    this.#path = path;
  }

  get path(): string {
    return this.#path;
  }

  #read(): GrantFile {
    if (!existsSync(this.#path)) return { version: 1, grants: [] };
    try {
      const parsed = JSON.parse(readFileSync(this.#path, "utf8")) as GrantFile;
      if (!Array.isArray(parsed.grants)) throw new Error("missing `grants` array");
      return parsed;
    } catch (err) {
      // Fail loudly. A grants file we cannot parse must never be treated as an
      // empty one: "no grants" and "unreadable grants" look the same to a caller
      // but mean opposite things to whoever is debugging at 2am.
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`Grants file at ${this.#path} is unreadable: ${message}`);
    }
  }

  #write(file: GrantFile): void {
    // Write-then-rename: a crash mid-write leaves the old file intact rather
    // than a truncated one. Truncation would fail closed, but silently, and a
    // security control that disappears quietly is worse than one that breaks.
    const tmp = `${this.#path}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(file, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    renameSync(tmp, this.#path);
  }

  list(includeInactive = false): Grant[] {
    const all = this.#read().grants;
    return includeInactive ? all : all.filter((g) => isActive(g));
  }

  /** The active grant for a mind, or null if absent, revoked, or expired. */
  get(mindId: string): Grant | null {
    const g = this.#read().grants.find((x) => x.mindId === mindId);
    return g && isActive(g) ? g : null;
  }

  /** Upsert. Scopes are replaced wholesale, never merged — a grant is a statement of the whole allowance. */
  put(grant: Omit<Grant, "createdAt"> & { createdAt?: string }): Grant {
    const file = this.#read();
    const existing = file.grants.find((g) => g.mindId === grant.mindId);
    const merged: Grant = {
      ...grant,
      createdAt: grant.createdAt ?? existing?.createdAt ?? new Date().toISOString(),
    };
    delete merged.revokedAt; // re-granting clears a prior tombstone
    file.grants = [...file.grants.filter((g) => g.mindId !== grant.mindId), merged];
    this.#write(file);
    return merged;
  }

  revoke(mindId: string): boolean {
    const file = this.#read();
    const g = file.grants.find((x) => x.mindId === mindId);
    if (!g || g.revokedAt) return false;
    g.revokedAt = new Date().toISOString();
    this.#write(file);
    return true;
  }
}

export function isActive(g: Grant, now = new Date()): boolean {
  if (g.revokedAt) return false;
  if (g.expiresAt && new Date(g.expiresAt) <= now) return false;
  return true;
}
