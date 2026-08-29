import { appendFileSync } from "node:fs";
import type { Scope } from "../config.js";

export type AuditOutcome = "ok" | "denied" | "error";

export interface AuditEntry {
  ts: string;
  tool: string;
  scope: Scope | null;
  outcome: AuditOutcome;
  /** Result size indicator, so a scrape shows up as such in the log. */
  resultCount?: number;
  durationMs?: number;
  detail?: string;
  args?: unknown;

  /**
   * Caller identity, present only for remote (HTTP) sessions. `credentialFingerprint`
   * is a truncated digest, never the credential itself — the audit log is a
   * plaintext file, and a bearer token written into it would be a second copy of
   * the key. `scopes` records the effective grant so a later reader can tell what
   * the session was *allowed* to do, not just what it did.
   */
  mindId?: string;
  subjectDid?: string;
  credentialFingerprint?: string;
  sessionId?: string;
  scopes?: Scope[];
}

/**
 * Append-only tool-call log.
 *
 * The agent is a non-human identity with read access to your entire archive, so
 * every call — especially every *denied* call — needs to leave a trace you can
 * review later. Failures to write the log are swallowed deliberately: losing an
 * audit line must not take down the server mid-session.
 */
export class AuditLog {
  #path: string;
  #echo: boolean;

  constructor(path: string, echo = process.env.VAULT_AUDIT_ECHO === "1") {
    this.#path = path;
    this.#echo = echo;
  }

  record(entry: Omit<AuditEntry, "ts">): void {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
    try {
      appendFileSync(this.#path, `${line}\n`, "utf8");
    } catch {
      // Never let audit-log IO break a tool call.
    }
    if (this.#echo) console.error(`[audit] ${line}`);
  }
}
