import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { watch, type FSWatcher } from "node:fs";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { VaultConfig, Scope } from "../config.js";
import { getMeta, openIndex } from "../index/query.js";
import { AuditLog } from "./audit.js";
import { buildServer } from "./server.js";
import type { CallerIdentity, ToolContext } from "./tools.js";
import { CredentialError, CredentialVerifier, type VerifiedCredential } from "../identity/credential.js";
import { GrantStore, effectiveScopes, type Grant } from "../identity/grants.js";
import { createAdminHandlers } from "./admin.js";

/**
 * Credential-gated MCP over HTTP.
 *
 * Where the stdio transport treats possession of the machine as the credential,
 * this one has to decide, per caller, whether a remote agent may read a private
 * archive. Two gates must agree: a Moca credential proving who is calling, and a
 * local grant saying how far that caller may go. Effective scopes are the
 * intersection, so neither an over-broad credential nor a generous grant is
 * sufficient alone.
 *
 * The socket binds to loopback. Reaching it from outside is a deliberate act —
 * a Cloudflare Tunnel terminating on this machine — rather than a consequence of
 * starting the server.
 */

const DEFAULT_PORT = 8787;
const DEFAULT_HOST = "127.0.0.1";
const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]", "::1"];
/** Ceiling on a session regardless of how long the credential lives. */
const MAX_SESSION_MS = 60 * 60_000;

export interface HttpOptions {
  port?: number;
  host?: string;
}

interface Session {
  transport: StreamableHTTPServerTransport;
  caller: CallerIdentity;
  scopes: Scope[];
  nonce: string;
  timer: NodeJS.Timeout;
  close(reason: string): void;
}

/** Missing configuration is a startup failure, never a silently open server. */
class NotConfiguredError extends Error {
  constructor(missing: string[]) {
    super(
      `The HTTP transport is not configured. Missing:\n` +
        missing.map((m) => `  - ${m}`).join("\n") +
        `\n\nThe HTTP transport is credential-gated by design and will not start ` +
        `without an issuer to verify against. For local use, run \`vault serve\` (stdio) instead.`,
    );
    this.name = "NotConfiguredError";
  }
}

function readVerifierConfig(): CredentialVerifier {
  const issuer = process.env.VAULT_ISSUER_URL;
  const vct = process.env.VAULT_ISSUER_VCT;
  const jwksFile = process.env.VAULT_ISSUER_JWKS_FILE;
  const jwksUrl = process.env.VAULT_ISSUER_JWKS_URL;

  const missing: string[] = [];
  if (!issuer) missing.push("VAULT_ISSUER_URL — the credential issuer's origin (the expected `iss`)");
  if (!vct) missing.push("VAULT_ISSUER_VCT — the expected credential type");
  if (missing.length) throw new NotConfiguredError(missing);

  // The issuer publishes two identifiers per credential type and they are easy to
  // transpose: `schemaId` ("adam-id-access-v1") is what you POST to /admin/issue-sd-jwt,
  // while `vct` ("https://adam.id/vct/adam-id-access/v1") is what the credential carries
  // and therefore what this must match. Both are declared side by side in the issuer's
  // schema_adam_id_access.ts.
  //
  // Booting with the schema id here produces a server that looks entirely healthy and
  // rejects every genuine credential with `credential_vct` — a failure that surfaces at
  // some remote agent's first call rather than at startup, and reads as "wrong
  // credential" when it is really "wrong server config".
  if (!vct!.includes(":")) {
    throw new NotConfiguredError([
      `VAULT_ISSUER_VCT is "${vct}", which looks like an issuer schemaId rather than a ` +
        `credential type.\n    The vct is a URI — e.g. https://adam.id/vct/adam-id-access/v1 ` +
        `— and must match\n    the \`vct\` claim inside the credential exactly.`,
    ]);
  }

  return new CredentialVerifier({
    issuer: issuer!,
    expectedVct: vct!,
    expectedAudience: process.env.VAULT_ISSUER_AUDIENCE ?? "adam-id",
    jwksFile,
    jwksUrl,
    revocationBaseUrl: process.env.VAULT_REVOCATION_URL,
    // A successful check is cached, so revoking at the issuer takes up to this
    // long to stop a *new* session from a credential that was just used, and
    // does not touch sessions already open. `vault revoke` is the immediate
    // path: it is local, needs nothing to be reachable, and tears down live
    // sessions. Issuer revocation is the durable backstop, not the fast one.
    revocationTtlMs: process.env.VAULT_REVOCATION_TTL_MS
      ? Number(process.env.VAULT_REVOCATION_TTL_MS)
      : undefined,
    // Revocation is checked against the issuer unless explicitly disabled. The
    // local grant table remains the authoritative kill switch either way.
    checkRevocation: process.env.VAULT_SKIP_REVOCATION_CHECK !== "1",
  });
}

function readAdminConfig(issuerOrigin: string, vct: string) {
  const adminApiKey = process.env.VAULT_ADMIN_API_KEY;
  const issuerAdminKey = process.env.VAULT_ISSUER_ADMIN_KEY;
  if (!adminApiKey || !issuerAdminKey) {
    // Admin endpoints are optional. Missing config means /admin/* returns 503,
    // so the MCP path keeps working even if automated provisioning is not set up.
    return null;
  }
  const issuerAdminOrigin = process.env.VAULT_ISSUER_ADMIN_ORIGIN ?? "http://127.0.0.1:3000";
  const cfAccessClientId = process.env.CF_ACCESS_CLIENT_ID;
  const cfAccessClientSecret = process.env.CF_ACCESS_CLIENT_SECRET;
  return { adminApiKey, issuerAdminKey, issuerAdminOrigin, vct, cfAccessClientId, cfAccessClientSecret };
}

/**
 * Accept the credential from `Authorization`, falling back to a custom header.
 *
 * The fallback is not paranoia: the Hello Minds HTTP_Execute primitive has been
 * observed to rewrite headers, and the same fallback already earned its keep in
 * the x-relay worker.
 */
function bearerFrom(req: IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (auth?.toLowerCase().startsWith("bearer ")) return auth.slice(7).trim();
  const custom = req.headers["x-vault-credential"];
  if (typeof custom === "string" && custom.trim()) return custom.trim();
  return null;
}

function hostnameOf(value: string | undefined): string | null {
  if (!value) return null;
  try {
    return new URL(`http://${value.replace(/^https?:\/\//, "")}`).hostname.toLowerCase();
  } catch {
    return null;
  }
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
    // A vault read has no legitimate multi-megabyte request body.
    if (bytes > 1_000_000) throw new Error("Request body too large.");
    chunks.push(chunk as Buffer);
  }
  if (!chunks.length) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

function isInitialize(body: unknown): boolean {
  const one = (m: unknown) =>
    typeof m === "object" && m !== null && (m as { method?: string }).method === "initialize";
  return Array.isArray(body) ? body.some(one) : one(body);
}

export async function serveHttp(
  config: VaultConfig,
  opts: HttpOptions = {},
): Promise<void> {
  const verifier = readVerifierConfig();
  const port = opts.port ?? Number(process.env.VAULT_HTTP_PORT ?? DEFAULT_PORT);
  const host = opts.host ?? process.env.VAULT_HTTP_HOST ?? DEFAULT_HOST;

  const allowedHosts = new Set([
    ...LOOPBACK_HOSTS,
    `${DEFAULT_HOST}:${port}`,
    ...(process.env.VAULT_HTTP_ALLOWED_HOSTS ?? "")
      .split(",")
      .map((h) => hostnameOf(h.trim()))
      .filter((h): h is string => Boolean(h)),
  ]);

  // One shared handle: tool reads are synchronous better-sqlite3 calls, so
  // sessions can share it safely and a per-session handle would only add cost.
  const db = openIndex(config);
  const ownAccountId = getMeta(db, "account_id") ?? "";
  const username = getMeta(db, "username") ?? "unknown";
  const audit = new AuditLog(config.auditLogPath);
  const grants = new GrantStore(config.grantsPath);

  const adminConfig = readAdminConfig(verifier.issuer, process.env.VAULT_ISSUER_VCT ?? "");
  const admin = adminConfig ? createAdminHandlers(config, grants, audit, adminConfig) : null;

  const sessions = new Map<string, Session>();

  function denied(res: ServerResponse, status: number, code: string, message: string): void {
    audit.record({ tool: "$session.denied", scope: null, outcome: "denied", detail: `${code}: ${message}` });
    json(res, status, { error: code, message });
  }

  /**
   * The two gates, applied identically to every entry path.
   *
   * Returns null when it has already answered the request, so callers just
   * `if (!auth) return;`.
   */
  async function authenticate(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<{
    verified: VerifiedCredential;
    grant: Grant;
    scopes: Scope[];
    caller: CallerIdentity;
  } | null> {
    const token = bearerFrom(req);
    if (!token) {
      denied(res, 401, "no_credential", "Present a credential in Authorization: Bearer.");
      return null;
    }

    let verified: VerifiedCredential;
    try {
      verified = await verifier.verify(token);
      await verifier.assertNotRevoked(verified.nonce);
    } catch (err) {
      const code = err instanceof CredentialError ? err.code : "malformed";
      denied(res, 401, `credential_${code}`, err instanceof Error ? err.message : String(err));
      return null;
    }

    const grant = grants.get(verified.mindId);
    if (!grant) {
      denied(
        res,
        403,
        "grant_missing",
        `No active local grant for mind ${verified.mindId}. Run \`vault grant --mind ${verified.mindId} --scopes ...\`.`,
      );
      return null;
    }

    const scopes = effectiveScopes(verified.assertedScopes, grant.scopes);
    if (!scopes.length) {
      denied(
        res,
        403,
        "scope_not_granted",
        `Credential asserts [${verified.assertedScopes.join(", ")}] but the grant allows ` +
          `[${grant.scopes.join(", ")}]; the intersection is empty.`,
      );
      return null;
    }

    return {
      verified,
      grant,
      scopes,
      caller: {
        mindId: verified.mindId,
        label: grant.label || verified.label || verified.mindId,
        subjectDid: verified.subjectDid,
        credentialFingerprint: verified.fingerprint,
        expiresAt: verified.expiresAt.toISOString(),
      },
    };
  }

  /**
   * Serve a single call with no session at all.
   *
   * The session handshake assumes a client that can read a response HEADER. The
   * Hello Minds `HTTP_Execute` primitive cannot: it surfaces headers on errors
   * but not on 2xx, so `Mcp-Session-Id` is written to a channel the caller is
   * structurally unable to read, and every follow-up call fails `no_session`.
   * That is not a bug either side can fix from its own end.
   *
   * Stateless mode removes the requirement rather than working around it — the
   * SDK skips session validation entirely when `sessionIdGenerator` is
   * undefined, so `tools/list` and `tools/call` stand alone.
   *
   * This is strictly the stricter path, not a loosening: the credential, the
   * grant and the scope intersection are re-checked on every single call, where
   * a session caches all three for its lifetime. A revoked grant stops the next
   * call here, instead of at the next reconcile.
   */
  async function handleOneShot(
    req: IncomingMessage,
    res: ServerResponse,
    body: unknown,
    scopes: Scope[],
    caller: CallerIdentity,
  ): Promise<void> {
    audit.record({
      tool: "$oneshot",
      scope: null,
      outcome: "ok",
      mindId: caller.mindId,
      subjectDid: caller.subjectDid,
      credentialFingerprint: caller.credentialFingerprint,
      scopes,
      detail: "sessionless call; credential and grant re-verified",
    });

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless: no session id, no session validation
      enableJsonResponse: true,
    });
    const ctx: ToolContext = { db, config, ownAccountId, scopes, caller };
    const { server } = buildServer(ctx, audit, username, undefined);

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } finally {
      // Nothing here outlives the response; leaking a transport per call would
      // turn the cheapest path into the one that exhausts the process.
      await transport.close().catch(() => {});
      await server.close().catch(() => {});
    }
  }

  /**
   * Re-evaluate every live session against the current grants.
   *
   * Without this, `vault revoke` would only take effect at the next initialize —
   * which for a long-lived agent session could be hours. That is the difference
   * between revocation and revocation eventually.
   */
  function reconcileSessions(reason: string): void {
    for (const [sid, session] of sessions) {
      const grant = grants.get(session.caller.mindId);
      const now = grant ? effectiveScopes(session.scopes, grant.scopes) : [];
      if (now.length !== session.scopes.length) {
        session.close(grant ? `${reason}: scopes narrowed` : `${reason}: grant revoked`);
        sessions.delete(sid);
      }
    }
  }

  let watcher: FSWatcher | null = null;
  try {
    watcher = watch(config.grantsPath, { persistent: false }, () => reconcileSessions("grants changed"));
  } catch {
    // The file may not exist yet; every initialize still checks grants directly,
    // so a missing watcher costs liveness of teardown, not correctness of access.
  }

  const httpServer = createServer((req, res) => {
    void (async () => {
      try {
        // Host and Origin are checked before any authentication work, so a
        // rebinding probe never reaches the verifier or the credential path.
        const hostHeader = hostnameOf(req.headers.host);
        if (!hostHeader || !allowedHosts.has(hostHeader)) {
          json(res, 403, { error: "forbidden_host", message: `Host "${req.headers.host}" is not allowed.` });
          return;
        }
        const origin = hostnameOf(req.headers.origin);
        if (origin && !allowedHosts.has(origin)) {
          json(res, 403, { error: "forbidden_origin", message: `Origin "${req.headers.origin}" is not allowed.` });
          return;
        }

        const path = (req.url ?? "/").split("?")[0];

        if (path === "/admin/issue-credential") {
          if (!admin) {
            json(res, 503, { error: "not_configured", message: "Admin endpoints are not configured." });
            return;
          }
          await admin.handleIssueCredential(req, res);
          return;
        }
        if (path === "/admin/revoke") {
          if (!admin) {
            json(res, 503, { error: "not_configured", message: "Admin endpoints are not configured." });
            return;
          }
          await admin.handleRevoke(req, res);
          return;
        }

        if (path !== "/mcp") {
          json(res, 404, { error: "not_found", message: "The MCP endpoint is /mcp." });
          return;
        }

        const sid = req.headers["mcp-session-id"];
        const existing = typeof sid === "string" ? sessions.get(sid) : undefined;
        if (existing) {
          await existing.transport.handleRequest(req, res);
          return;
        }
        if (typeof sid === "string") {
          json(res, 404, { error: "unknown_session", message: "Session not found; re-initialize." });
          return;
        }

        let body: unknown;
        try {
          body = await readBody(req);
        } catch (err) {
          json(res, 400, { error: "bad_request", message: err instanceof Error ? err.message : "Bad body." });
          return;
        }
        // Authenticate before branching: a sessionless call and an initialize
        // must pass exactly the same two gates, and checking once is what keeps
        // them from drifting apart as either path changes.
        const auth = await authenticate(req, res);
        if (!auth) return;
        const { verified, grant, scopes, caller } = auth;

        // No session, not an initialize — serve it standalone rather than
        // demanding a handshake the caller may be unable to complete.
        if (!isInitialize(body)) {
          await handleOneShot(req, res, body, scopes, caller);
          return;
        }

        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          // The Minds HTTP_Execute primitive is a plain request/response call,
          // not an SSE client, so a streamed reply would never be read.
          enableJsonResponse: true,
          onsessioninitialized: (newSid) => {
            sessions.set(newSid, session);
            audit.record({
              tool: "$session.open",
              scope: null,
              outcome: "ok",
              sessionId: newSid,
              mindId: caller.mindId,
              subjectDid: caller.subjectDid,
              credentialFingerprint: caller.credentialFingerprint,
              scopes,
              detail:
                `asserted=[${verified.assertedScopes.join(" ")}] ` +
                `granted=[${grant.scopes.join(" ")}] effective=[${scopes.join(" ")}]`,
            });
          },
          onsessionclosed: (closedSid) => {
            sessions.get(closedSid)?.close("client closed");
            sessions.delete(closedSid);
          },
        });

        const ctx: ToolContext = { db, config, ownAccountId, scopes, caller };
        const { server } = buildServer(ctx, audit, username, undefined);

        // A session never outlives its credential, and never exceeds the ceiling
        // regardless of what expiry the credential claims.
        const ttl = Math.min(
          Math.max(verified.expiresAt.getTime() - Date.now(), 0),
          MAX_SESSION_MS,
        );

        let closed = false;
        const session: Session = {
          transport,
          caller,
          scopes,
          nonce: verified.nonce,
          timer: setTimeout(() => session.close("credential expired"), ttl),
          close(reason: string) {
            if (closed) return;
            closed = true;
            clearTimeout(session.timer);
            audit.record({
              tool: "$session.close",
              scope: null,
              outcome: "ok",
              mindId: caller.mindId,
              credentialFingerprint: caller.credentialFingerprint,
              detail: reason,
            });
            void transport.close().catch(() => {});
            void server.close().catch(() => {});
          },
        };

        await server.connect(transport);
        await transport.handleRequest(req, res, body);
      } catch (err) {
        if (!res.headersSent) {
          json(res, 500, { error: "internal", message: err instanceof Error ? err.message : "error" });
        }
      }
    })();
  });

  await new Promise<void>((ready) => httpServer.listen(port, host, ready));

  console.error(`personal-twitter-vault (http) ready for @${username}`);
  console.error(`  listening   http://${host}:${port}/mcp`);
  console.error(`  issuer      ${verifier.issuer}`);
  console.error(`  grants      ${grants.list().length} active (${config.grantsPath})`);
  console.error(`  audit log   ${config.auditLogPath}`);
  console.error(`  note        loopback only; expose deliberately via a tunnel`);

  await new Promise<void>((resolveClosed) => {
    const shutdown = () => {
      for (const [sid, s] of sessions) {
        s.close("server shutting down");
        sessions.delete(sid);
      }
      watcher?.close();
      httpServer.close(() => resolveClosed());
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
    httpServer.once("close", () => resolveClosed());
  });
  db.close();
}
