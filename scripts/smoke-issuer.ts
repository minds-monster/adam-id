/**
 * Integration check against a live issuer.
 *
 * Unlike smoke-credential (which uses a throwaway dev key) this exercises the
 * real thing: a credential minted by air-issuer-service and signed with the
 * whitelisted AIR partner key, verified here by fetching the issuer's published
 * JWKS over HTTP, with revocation checked against the issuer's database.
 *
 * Requires the issuer running and reachable:
 *   ISSUER_URL=http://127.0.0.1:3000 \
 *   ISSUER_ADMIN_KEY=... \
 *   npx tsx scripts/smoke-issuer.ts
 */
import { CredentialError, CredentialVerifier } from "../src/identity/credential.js";

const ISSUER = process.env.ISSUER_URL ?? "http://127.0.0.1:3000";
const ADMIN_KEY = process.env.ISSUER_ADMIN_KEY;
const SCHEMA = process.env.ISSUER_SCHEMA_ID ?? "adam-id-access-v1";
const VCT = process.env.VAULT_ISSUER_VCT ?? "https://adam.id/vct/adam-id-access/v1";
const MIND = "240b453e-f36b-1410-8466-00039ce7df11";
const HOLDER = process.env.ISSUER_HOLDER_DID ?? "did:air:id:testnet:placeholder";

if (!ADMIN_KEY) {
  console.error("ISSUER_ADMIN_KEY is required (the issuer's ADMIN_API_KEY).");
  process.exit(1);
}

let failures = 0;
function check(label: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "  ✓" : "  ✗"} ${label}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

async function issue(scopes: string[], label = "Adam (Hello Minds)") {
  const res = await fetch(`${ISSUER}/admin/issue-sd-jwt`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admin-api-key": ADMIN_KEY! },
    body: JSON.stringify({ schemaId: SCHEMA, holderDID: HOLDER, mindId: MIND, scopes, label }),
  });
  if (!res.ok) throw new Error(`issue failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as { credential: string; nonce: string; credentialId: string };
}

async function revoke(nonce: string) {
  const res = await fetch(`${ISSUER}/admin/revoke-sd-jwt`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admin-api-key": ADMIN_KEY! },
    body: JSON.stringify({ nonce }),
  });
  if (!res.ok) throw new Error(`revoke failed: ${res.status} ${await res.text()}`);
}

// No jwksFile: keys are fetched from the issuer's /.well-known/jwt-vc-issuer,
// which is the path that will be used in production.
const verifier = new CredentialVerifier({
  issuer: ISSUER,
  expectedVct: VCT,
  expectedAudience: "adam-id",
  revocationTtlMs: 1, // don't let the cache mask a revocation in this test
});

console.log("\nlive issuer → live verifier");
{
  const { credential, nonce } = await issue(["tweets.read", "analytics.read"]);
  const v = await verifier.verify(credential);
  check("a credential from the real issuer verifies", v.mindId === MIND, v.mindId);
  check("signed by the AIR partner key, fetched over HTTP", v.issuer === ISSUER, v.issuer);
  check(
    "scopes survive the round trip",
    v.assertedScopes.join(",") === "tweets.read,analytics.read",
    v.assertedScopes.join(","),
  );
  check("the label disclosure is parsed", v.label === "Adam (Hello Minds)", `${v.label}`);
  check("the holder DID is carried", v.subjectDid === HOLDER, v.subjectDid);
  check("nonce matches the issuance record", v.nonce === nonce);

  let live = false;
  try {
    await verifier.assertNotRevoked(nonce);
    live = true;
  } catch {
    live = false;
  }
  check("a fresh credential is not revoked", live);
}

console.log("\nrevocation is honoured");
{
  const { credential, nonce } = await issue(["tweets.read"]);
  await verifier.verify(credential); // valid before revoking
  await revoke(nonce);
  verifier.invalidateRevocation(nonce);

  let code = "";
  try {
    await verifier.assertNotRevoked(nonce);
  } catch (err) {
    code = err instanceof CredentialError ? err.code : String(err);
  }
  check("a revoked credential is rejected", code === "revoked", code || "accepted");

  // The signature is still perfectly valid — revocation is the only thing
  // standing between a leaked credential and access, so it has to be decisive.
  const stillVerifies = await verifier
    .verify(credential)
    .then(() => true)
    .catch(() => false);
  check("revocation is what stops it, not the signature", stillVerifies);
}

console.log("\nthe issuer refuses a credential that would authorize nothing");
{
  const res = await fetch(`${ISSUER}/admin/issue-sd-jwt`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admin-api-key": ADMIN_KEY! },
    body: JSON.stringify({ schemaId: SCHEMA, holderDID: HOLDER, mindId: MIND, scopes: [] }),
  });
  check("empty scopes are rejected at issuance", res.status === 400, `${res.status}`);

  const bad = await fetch(`${ISSUER}/admin/issue-sd-jwt`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admin-api-key": "wrong-key" },
    body: JSON.stringify({ schemaId: SCHEMA, holderDID: HOLDER, mindId: MIND, scopes: ["tweets.read"] }),
  });
  check("a bad admin key is refused", bad.status === 403, `${bad.status}`);
}

console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
