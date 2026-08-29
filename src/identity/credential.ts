import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  createLocalJWKSet,
  decodeJwt,
  errors as joseErrors,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import { ALL_SCOPES, type Scope } from "../config.js";

/**
 * Server-side verification of the Moca credential a remote agent presents.
 *
 * Why this exists in this shape: AIR's own credentials cannot be used here. An
 * AIR-issued VC is encrypted to the holder's public key and parked in DStorage,
 * and verifying one means `AirService.verifyCredential` — a browser iframe flow
 * that needs the holder's live session and their consent to decrypt. A headless
 * agent can neither retrieve, decrypt, nor present that. So the credential a
 * caller actually sends is an SD-JWT-VC signed by the same whitelisted AIR
 * partner key, which is verifiable here with nothing but `jose` and the issuer's
 * public JWKS.
 *
 * The claims this gates on (`mind_id`, `scopes`, `audience`) are always-disclosed
 * — they live in the signed JWT body, not behind SD disclosures. Selective
 * disclosure protects a holder from a verifier; here the verifier is the vault
 * owner, so there is no privacy to gain, and putting `scopes` behind a disclosure
 * would mean a holder who simply omits it presents something that verifies while
 * asserting nothing.
 */
export interface VerifiedCredential {
  mindId: string;
  /** The holder's AIR account DID (`sub`). Informational — authorization keys off mindId. */
  subjectDid: string;
  assertedScopes: Scope[];
  label: string | null;
  /** Revocation handle, checked against the issuer. */
  nonce: string;
  credentialId: string;
  issuer: string;
  expiresAt: Date;
  /** Truncated digest of the presentation, safe to write to the audit log. */
  fingerprint: string;
}

export type CredentialErrorCode =
  | "malformed"
  | "signature"
  | "expired"
  | "issuer"
  | "vct"
  | "audience"
  | "claims"
  | "revoked"
  | "jwks_unreachable";

export class CredentialError extends Error {
  readonly code: CredentialErrorCode;
  constructor(code: CredentialErrorCode, message: string) {
    super(message);
    this.name = "CredentialError";
    this.code = code;
  }
}

export interface CredentialVerifierOptions {
  /** Expected `iss`, and the origin whose issuer metadata is trusted. */
  issuer: string;
  expectedVct: string;
  expectedAudience?: string;
  /** Local JWKS file, for development without a reachable issuer. */
  jwksFile?: string;
  /**
   * Override where issuer metadata is fetched from. The `issuer` claim inside
   * the returned document must still match the expected `issuer`, so a local
   * loopback URL can serve the public origin's keys without the vault having to
   * reach the public internet on every verification.
   */
  jwksUrl?: string;
  /** Defaults to `issuer`. */
  revocationBaseUrl?: string;
  revocationTtlMs?: number;
  clockToleranceSec?: number;
  /** Set false only in tests that have no issuer to ask. */
  checkRevocation?: boolean;
}

const JWKS_TTL_MS = 10 * 60_000;

/**
 * Map a token's claims to vault scopes.
 *
 * Accepts either the OAuth-conventional space-delimited `scope` string or an
 * array `scopes` claim, and silently drops anything that isn't a scope this
 * server recognises — an unknown scope must never widen access.
 */
export function scopesFromClaims(claims: JWTPayload, fallback: Scope[] = []): Scope[] {
  const raw =
    typeof claims.scope === "string"
      ? claims.scope.split(/[\s,]+/)
      : Array.isArray(claims.scopes)
        ? (claims.scopes as unknown[]).map(String)
        : [];
  const mapped = raw.filter((s): s is Scope => (ALL_SCOPES as readonly string[]).includes(s));
  return mapped.length ? mapped : fallback;
}

function b64uDecode(s: string): string {
  return Buffer.from(s, "base64url").toString("utf8");
}

function b64uSha256(input: string): string {
  return createHash("sha256").update(input, "ascii").digest("base64url");
}

/**
 * Read SD-JWT disclosures into a plain object.
 *
 * Only used for cosmetic claims (`label`). A disclosure whose digest isn't
 * listed in `_sd` is dropped rather than trusted: an unverified disclosure is
 * attacker-controlled text, and while nothing is gated on it, it does reach the
 * audit log.
 */
function parseDisclosures(segments: string[], payload: JWTPayload): Record<string, unknown> {
  const listed = new Set(Array.isArray(payload._sd) ? (payload._sd as string[]) : []);
  const out: Record<string, unknown> = {};
  for (const seg of segments) {
    if (!seg) continue;
    if (!listed.has(b64uSha256(seg))) continue;
    try {
      const parsed = JSON.parse(b64uDecode(seg)) as unknown;
      if (Array.isArray(parsed) && parsed.length === 3 && typeof parsed[1] === "string") {
        out[parsed[1]] = parsed[2];
      }
    } catch {
      // A malformed disclosure is ignored; it cannot affect authorization.
    }
  }
  return out;
}

export class CredentialVerifier {
  #opts: Required<Pick<CredentialVerifierOptions, "issuer" | "expectedVct">> &
    CredentialVerifierOptions;
  #keys: { getKey: JWTVerifyGetKey; fetchedAt: number } | null = null;
  #revocations = new Map<string, { revoked: boolean; at: number }>();

  constructor(opts: CredentialVerifierOptions) {
    this.#opts = { ...opts };
  }

  get issuer(): string {
    return this.#opts.issuer;
  }

  /**
   * Resolve the issuer's signing keys.
   *
   * The issuer serves `{issuer, jwks}` rather than a bare JWKS, so
   * `createRemoteJWKSet` cannot be pointed at it directly — hence the manual
   * fetch. Asserting `body.issuer === expected` is the part that matters: it is
   * what stops a metadata document served from an unexpected origin from
   * nominating its own signing keys.
   */
  async #getKeys(force = false): Promise<JWTVerifyGetKey> {
    if (!force && this.#keys && Date.now() - this.#keys.fetchedAt < JWKS_TTL_MS) {
      return this.#keys.getKey;
    }

    let jwks: { keys: unknown[] };
    if (this.#opts.jwksFile) {
      try {
        jwks = JSON.parse(readFileSync(this.#opts.jwksFile, "utf8")) as { keys: unknown[] };
      } catch (err) {
        throw new CredentialError(
          "jwks_unreachable",
          `Cannot read JWKS file ${this.#opts.jwksFile}: ${err instanceof Error ? err.message : err}`,
        );
      }
    } else {
      const url =
        this.#opts.jwksUrl ?? `${this.#opts.issuer.replace(/\/$/, "")}/.well-known/jwt-vc-issuer`;
      let body: { issuer?: string; jwks?: { keys: unknown[] } };
      let lastErr: unknown;
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          body = (await res.json()) as typeof body;
          lastErr = undefined;
          break;
        } catch (err) {
          lastErr = err;
        }
      }
      if (lastErr !== undefined) {
        throw new CredentialError(
          "jwks_unreachable",
          `Cannot fetch issuer metadata from ${url}: ${lastErr instanceof Error ? lastErr.message : lastErr}`,
        );
      }
      if (body!.issuer !== this.#opts.issuer) {
        throw new CredentialError(
          "issuer",
          `Issuer metadata at ${url} claims to be "${body!.issuer}", expected "${this.#opts.issuer}".`,
        );
      }
      if (!body!.jwks?.keys?.length) {
        throw new CredentialError("jwks_unreachable", `Issuer metadata at ${url} has no keys.`);
      }
      jwks = body!.jwks;
    }

    const getKey = createLocalJWKSet(jwks as Parameters<typeof createLocalJWKSet>[0]);
    this.#keys = { getKey, fetchedAt: Date.now() };
    return getKey;
  }

  async verify(presentation: string): Promise<VerifiedCredential> {
    const compact = presentation.trim();
    if (!compact) throw new CredentialError("malformed", "Empty credential.");

    // SD-JWT presentation format: <jws>~<disclosure>~...~[<kb-jwt>]
    const [jws, ...rest] = compact.split("~");
    if (!jws || jws.split(".").length !== 3) {
      throw new CredentialError("malformed", "Not a JWT/SD-JWT presentation.");
    }

    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(jws, await this.#getKeys(), {
        issuer: this.#opts.issuer,
        algorithms: ["ES256"],
        clockTolerance: this.#opts.clockToleranceSec ?? 30,
      }));
    } catch (err) {
      if (err instanceof joseErrors.JWKSNoMatchingKey) {
        // Unknown kid: the issuer may have rotated. Refetch once, then give up.
        try {
          ({ payload } = await jwtVerify(jws, await this.#getKeys(true), {
            issuer: this.#opts.issuer,
            algorithms: ["ES256"],
            clockTolerance: this.#opts.clockToleranceSec ?? 30,
          }));
        } catch (retryErr) {
          throw toCredentialError(retryErr);
        }
      } else {
        throw toCredentialError(err);
      }
    }

    if (payload.vct !== this.#opts.expectedVct) {
      throw new CredentialError(
        "vct",
        `Credential type is "${String(payload.vct)}", expected "${this.#opts.expectedVct}".`,
      );
    }

    // `audience` is a custom string claim, not the JWT `aud` — the issuer's
    // SD-JWT payload has no `aud`, so this cannot be delegated to jwtVerify.
    if (this.#opts.expectedAudience && payload.audience !== this.#opts.expectedAudience) {
      throw new CredentialError(
        "audience",
        `Credential audience is "${String(payload.audience)}", expected "${this.#opts.expectedAudience}".`,
      );
    }

    const mindId = typeof payload.mind_id === "string" ? payload.mind_id : "";
    if (!mindId) throw new CredentialError("claims", "Credential has no mind_id claim.");
    const nonce = payload.nonce === undefined ? "" : String(payload.nonce);
    if (!nonce) throw new CredentialError("claims", "Credential has no nonce; it could not be revoked.");
    if (!payload.exp) throw new CredentialError("claims", "Credential has no expiry.");

    // Fallback is deliberately empty: a credential that asserts no recognised
    // scope grants nothing, and must fail loudly rather than inherit a default.
    const assertedScopes = scopesFromClaims(payload, []);
    if (!assertedScopes.length) {
      throw new CredentialError("claims", "Credential asserts no scopes this vault recognises.");
    }

    const disclosed = parseDisclosures(rest, payload);
    const label =
      typeof disclosed.label === "string"
        ? disclosed.label
        : typeof payload.label === "string"
          ? payload.label
          : null;

    return {
      mindId,
      subjectDid: typeof payload.sub === "string" ? payload.sub : "",
      assertedScopes,
      label,
      nonce,
      credentialId: typeof payload.id === "string" ? payload.id : "",
      issuer: String(payload.iss),
      expiresAt: new Date(payload.exp * 1000),
      fingerprint: fingerprint(compact),
    };
  }

  /**
   * Ask the issuer whether this credential has been revoked.
   *
   * Fails closed. Failing open would turn "take the issuer offline" into a
   * revocation bypass, and since the local grant table is an instant, offline
   * kill switch, a strict check here costs almost nothing.
   */
  async assertNotRevoked(nonce: string): Promise<void> {
    if (this.#opts.checkRevocation === false) return;

    const ttl = this.#opts.revocationTtlMs ?? 60_000;
    const cached = this.#revocations.get(nonce);
    if (cached && Date.now() - cached.at < ttl) {
      if (cached.revoked) throw new CredentialError("revoked", "Credential has been revoked.");
      return;
    }

    const base = (this.#opts.revocationBaseUrl ?? this.#opts.issuer).replace(/\/$/, "");
    const url = `${base}/revocation-status/${encodeURIComponent(nonce)}`;

    let revoked: boolean | null = null;
    for (let attempt = 0; attempt < 2 && revoked === null; attempt++) {
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(3_000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        revoked = Boolean(((await res.json()) as { isRevoked?: boolean }).isRevoked);
      } catch {
        if (attempt === 1) {
          throw new CredentialError(
            "revoked",
            `Cannot reach the revocation endpoint at ${url}; refusing rather than assuming valid.`,
          );
        }
      }
    }

    this.#revocations.set(nonce, { revoked: revoked === true, at: Date.now() });
    if (revoked) throw new CredentialError("revoked", "Credential has been revoked.");
  }

  invalidateRevocation(nonce: string): void {
    this.#revocations.delete(nonce);
  }
}

/** Truncated digest — enough to correlate audit lines, useless as a credential. */
export function fingerprint(presentation: string): string {
  return createHash("sha256").update(presentation).digest("hex").slice(0, 16);
}

/** Read claims without verifying. Diagnostics only — never for authorization. */
export function peekClaims(presentation: string): JWTPayload | null {
  try {
    return decodeJwt(presentation.split("~")[0] ?? "");
  } catch {
    return null;
  }
}

function toCredentialError(err: unknown): CredentialError {
  if (err instanceof CredentialError) return err;
  if (err instanceof joseErrors.JWTExpired) {
    return new CredentialError("expired", "Credential has expired.");
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    const code = err.claim === "iss" ? "issuer" : "claims";
    return new CredentialError(code, err.message);
  }
  if (
    err instanceof joseErrors.JWSSignatureVerificationFailed ||
    err instanceof joseErrors.JWKSNoMatchingKey
  ) {
    return new CredentialError("signature", "Credential signature does not verify.");
  }
  if (err instanceof joseErrors.JOSEAlgNotAllowed) {
    return new CredentialError("signature", `Disallowed signing algorithm: ${err.message}`);
  }
  return new CredentialError("malformed", err instanceof Error ? err.message : String(err));
}
