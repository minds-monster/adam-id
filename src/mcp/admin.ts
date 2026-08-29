import type { ServerResponse, IncomingMessage } from "node:http";
import type { VaultConfig } from "../config.js";
import { parseScopeList, type GrantStore } from "../identity/grants.js";
import { AuditLog } from "./audit.js";

/**
 * Operator-facing admin endpoints for provisioning Mind access.
 *
 * These routes are intentionally separate from the MCP path and from the
 * credential-gated authorization model. They run behind Cloudflare Access
 * and a static admin key, and they are the only way a remote system (e.g.
 * minds-monster/worker) can ask adam-id to mint a credential and grant it
 * access without holding the vault operator's shell session.
 */

export interface AdminOptions {
  /** Key required in the X-Admin-Api-Key header. */
  adminApiKey: string;
  /** Key required by the issuer's /admin/issue-sd-jwt endpoint. */
  issuerAdminKey: string;
  /**
   * Origin used to call the issuer's admin endpoints. In development this is
   * usually the loopback origin (e.g. http://127.0.0.1:3000). In production it
   * must be a URL the vault host can reach — typically the public issuer origin
   * if /admin/* is protected by Cloudflare Access, or a private origin inside the
   * same network. The `audience` claim inside the credential is always the public
   * issuer origin.
   */
  issuerAdminOrigin: string;
  /** Credential type the issuer should use. */
  vct: string;
  /** Cloudflare Access service-token id, when the issuer admin endpoint is behind Access. */
  cfAccessClientId?: string;
  /** Cloudflare Access service-token secret, when the issuer admin endpoint is behind Access. */
  cfAccessClientSecret?: string;
}

export interface AdminHandlers {
  handleIssueCredential(req: IncomingMessage, res: ServerResponse): Promise<void>;
  handleRevoke(req: IncomingMessage, res: ServerResponse): Promise<void>;
}

interface IssueRequest {
  mindId: string;
  scopes: string | string[];
  label?: string;
  holderDid?: string;
  days?: number;
  note?: string;
}

interface RevokeRequest {
  mindId: string;
  nonce?: string;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
  res.end(text);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += (chunk as Buffer).length;
    if (bytes > 100_000) throw new Error("Request body too large.");
    chunks.push(chunk as Buffer);
  }
  if (!chunks.length) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

export function createAdminHandlers(
  config: VaultConfig,
  grants: GrantStore,
  audit: AuditLog,
  opts: AdminOptions,
): AdminHandlers {
  function denied(res: ServerResponse, code: string, message: string): void {
    json(res, 401, { error: code, message });
  }

  function authenticate(req: IncomingMessage, res: ServerResponse): boolean {
    const key = req.headers["x-admin-api-key"];
    if (typeof key !== "string" || key !== opts.adminApiKey) {
      denied(res, "unauthorized", "Invalid or missing X-Admin-Api-Key header.");
      return false;
    }
    return true;
  }

  async function handleIssueCredential(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!authenticate(req, res)) return;

    let body: IssueRequest;
    try {
      const raw = (await readBody(req)) as IssueRequest;
      if (!raw || typeof raw.mindId !== "string" || raw.mindId.length === 0) {
        throw new Error("mindId is required.");
      }
      body = raw;
    } catch (err) {
      json(res, 400, { error: "bad_request", message: err instanceof Error ? err.message : "Bad body." });
      return;
    }

    const scopes = parseScopeList(Array.isArray(body.scopes) ? body.scopes.join(",") : body.scopes);
    if (!scopes.length) {
      json(res, 400, { error: "bad_request", message: "At least one scope is required." });
      return;
    }

    const days = typeof body.days === "number" && body.days > 0 ? body.days : 1;
    const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    const label = body.label?.trim() || body.mindId;

    // Mint the SD-JWT credential via the issuer's admin endpoint.
    let issued: { credential: string; credentialId: string; nonce: string; expiresAt: string };
    try {
      const issuerHeaders: Record<string, string> = {
        "content-type": "application/json",
        "x-admin-api-key": opts.issuerAdminKey,
      };
      if (opts.cfAccessClientId && opts.cfAccessClientSecret) {
        issuerHeaders["CF-Access-Client-Id"] = opts.cfAccessClientId;
        issuerHeaders["CF-Access-Client-Secret"] = opts.cfAccessClientSecret;
      }

      const issuerUrl = `${opts.issuerAdminOrigin.replace(/\/$/, "")}/admin/issue-sd-jwt`;
      const issuerBody = JSON.stringify({
        schemaId: "adam-id-access-v1",
        holderDID: body.holderDid ?? "did:air:id:testnet:placeholder",
        mindId: body.mindId,
        scopes,
        label,
        audience: "adam-id",
      });

      let issuerRes: Response | undefined;
      let lastErr: unknown;
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          issuerRes = await fetch(issuerUrl, {
            method: "POST",
            headers: issuerHeaders,
            body: issuerBody,
            signal: AbortSignal.timeout(15_000),
          });
          lastErr = undefined;
          break;
        } catch (err) {
          lastErr = err;
        }
      }
      if (lastErr !== undefined || !issuerRes) {
        throw new Error(
          `Cannot reach issuer admin endpoint at ${issuerUrl}: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`,
        );
      }
      if (!issuerRes.ok) {
        const text = await issuerRes.text().catch(() => "");
        throw new Error(`Issuer returned HTTP ${issuerRes.status}: ${text.slice(0, 200)}`);
      }
      issued = (await issuerRes.json()) as typeof issued;
    } catch (err) {
      audit.record({
        tool: "$admin.issue_credential",
        scope: null,
        outcome: "error",
        mindId: body.mindId,
        detail: `issuer call failed: ${err instanceof Error ? err.message : String(err)}`,
      });
      json(res, 502, {
        error: "issuer_failed",
        message: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    // Record the local grant. This is the kill switch: no credential works
    // without a matching grant, so creating both in one call is safe as long
    // as the admin key is guarded.
    const grant = grants.put({
      mindId: body.mindId,
      label,
      scopes,
      expiresAt,
      createdAt: new Date().toISOString(),
      holderDid: body.holderDid,
      note: body.note ?? `Issued via admin API; credential ${issued.credentialId}`,
    });

    audit.record({
      tool: "$admin.issue_credential",
      scope: null,
      outcome: "ok",
      mindId: body.mindId,
      detail: `credential=${issued.credentialId} scopes=${scopes.join(",")} expires=${expiresAt}`,
    });

    json(res, 200, {
      credential: issued.credential,
      credentialId: issued.credentialId,
      nonce: issued.nonce,
      expiresAt: issued.expiresAt,
      grant,
    });
  }

  async function handleRevoke(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!authenticate(req, res)) return;

    let body: RevokeRequest;
    try {
      const raw = (await readBody(req)) as RevokeRequest;
      if (!raw || typeof raw.mindId !== "string" || raw.mindId.length === 0) {
        throw new Error("mindId is required.");
      }
      body = raw;
    } catch (err) {
      json(res, 400, { error: "bad_request", message: err instanceof Error ? err.message : "Bad body." });
      return;
    }

    const revoked = grants.revoke(body.mindId);
    if (!revoked) {
      json(res, 404, { error: "not_found", message: `No active grant for mind ${body.mindId}.` });
      return;
    }

    audit.record({
      tool: "$admin.revoke",
      scope: null,
      outcome: "ok",
      mindId: body.mindId,
      detail: body.nonce ? `nonce=${body.nonce}` : "grant revoked",
    });

    json(res, 200, { ok: true, mindId: body.mindId });
  }

  return { handleIssueCredential, handleRevoke };
}
