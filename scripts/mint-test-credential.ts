/**
 * Mint a development credential with the same shape the real issuer produces.
 *
 * This exists so the whole verification and HTTP path can be built and proven
 * before Postgres, the issuer, a tunnel, or Moca exist. It is emphatically not
 * the real issuer: it signs with a throwaway key written to .dev/, which is
 * gitignored, and the vault only trusts that key when explicitly pointed at it
 * via VAULT_ISSUER_JWKS_FILE.
 *
 *   npx tsx scripts/mint-test-credential.ts --mind <id> --scopes tweets.read
 *     [--label L] [--minutes 60] [--issuer URL] [--vct VCT] [--audience A]
 *     [--sub did:air:...] [--alg ES256] [--nonce N]
 */
import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes, randomUUID, createHash } from "node:crypto";
import { resolve } from "node:path";
import { SignJWT, exportJWK, exportPKCS8, generateKeyPair, importPKCS8 } from "jose";

const ROOT = resolve(import.meta.dirname, "..");
export const DEV_DIR = resolve(ROOT, ".dev");
export const DEV_JWKS = resolve(DEV_DIR, "issuer-jwks.json");
const DEV_KEY = resolve(DEV_DIR, "issuer-key.pem");

export const TEST_ISSUER = "https://issuer.test.local";
export const TEST_VCT = "https://adam.id/vct/adam-id-access/v1";
export const TEST_AUDIENCE = "adam-id";
const KID = "dev-key-1";

/** Load the dev signing key, generating and persisting it on first use. */
async function loadOrCreateKey(alg: string) {
  mkdirSync(DEV_DIR, { recursive: true });
  if (existsSync(DEV_KEY) && existsSync(DEV_JWKS)) {
    return importPKCS8(readFileSync(DEV_KEY, "utf8"), alg);
  }
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  writeFileSync(DEV_KEY, await exportPKCS8(privateKey), { mode: 0o600 });
  const jwk = await exportJWK(publicKey);
  writeFileSync(
    DEV_JWKS,
    `${JSON.stringify({ keys: [{ ...jwk, kid: KID, alg, use: "sig" }] }, null, 2)}\n`,
  );
  return privateKey;
}

export interface MintOptions {
  mindId: string;
  scopes: string[];
  label?: string;
  minutes?: number;
  issuer?: string;
  vct?: string;
  audience?: string;
  sub?: string;
  nonce?: string;
  alg?: string;
  /** Omit claims to exercise rejection paths. */
  omit?: string[];
  /**
   * Sign with a throwaway key that is not in the published JWKS, to exercise the
   * "correct kid, wrong key" path — the shape an impersonation attempt takes.
   */
  foreignKey?: boolean;
}

/**
 * Build an SD-JWT presentation matching the issuer's output: `mind_id`,
 * `scopes` and `audience` in the signed body, `label` behind a disclosure.
 */
export async function mint(opts: MintOptions): Promise<string> {
  const alg = opts.alg ?? "ES256";
  const key = opts.foreignKey
    ? (await generateKeyPair(alg, { extractable: true })).privateKey
    : await loadOrCreateKey(alg);
  const omit = new Set(opts.omit ?? []);

  // One SD disclosure for `label`: base64url([salt, name, value]), with its
  // digest listed in _sd — the same construction @sd-jwt/core emits.
  const label = opts.label ?? `Test Mind ${opts.mindId}`;
  const disclosure = Buffer.from(
    JSON.stringify([randomBytes(16).toString("base64url"), "label", label]),
  ).toString("base64url");
  const digest = createHash("sha256").update(disclosure, "ascii").digest("base64url");

  const now = Math.floor(Date.now() / 1000);
  const exp = now + (opts.minutes ?? 60) * 60;

  const claims: Record<string, unknown> = {
    vct: opts.vct ?? TEST_VCT,
    id: `urn:${randomUUID()}`,
    nonce: opts.nonce ?? BigInt(`0x${randomBytes(8).toString("hex")}`).toString(),
    mind_id: opts.mindId,
    scopes: opts.scopes,
    audience: opts.audience ?? TEST_AUDIENCE,
    _sd: [digest],
    _sd_alg: "sha-256",
  };
  for (const k of omit) delete claims[k];

  const jwt = await new SignJWT(claims)
    .setProtectedHeader({ alg, kid: KID, typ: "vc+sd-jwt" })
    .setIssuer(opts.issuer ?? TEST_ISSUER)
    .setSubject(opts.sub ?? "did:air:id:test:5P44fsVUhPctDTWH2Nz26pZJFsg6CqyiAELTGeVQDB")
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(key);

  return `${jwt}~${disclosure}~`;
}

function option(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? undefined : argv[i + 1];
}

const invokedDirectly = process.argv[1]?.endsWith("mint-test-credential.ts");
if (invokedDirectly) {
  const argv = process.argv.slice(2);
  const mindId = option(argv, "mind");
  const scopes = option(argv, "scopes");
  if (!mindId || !scopes) {
    console.error("usage: mint-test-credential.ts --mind <id> --scopes a,b [--minutes N]");
    process.exit(1);
  }
  const minutes = option(argv, "minutes");
  const credential = await mint({
    mindId,
    scopes: scopes.split(",").map((s) => s.trim()),
    label: option(argv, "label"),
    minutes: minutes ? Number(minutes) : undefined,
    issuer: option(argv, "issuer"),
    vct: option(argv, "vct"),
    audience: option(argv, "audience"),
    sub: option(argv, "sub"),
    nonce: option(argv, "nonce"),
    alg: option(argv, "alg"),
  });
  console.error(`dev issuer   ${TEST_ISSUER}`);
  console.error(`dev jwks     ${DEV_JWKS}`);
  console.error(`\nVAULT_ISSUER_JWKS_FILE=${DEV_JWKS}\n`);
  console.log(credential);
}
