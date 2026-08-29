/**
 * Verifier checks: every way a credential can be wrong must be rejected, and
 * rejected with the *right* reason.
 *
 * The distinct error codes matter operationally — "expired" tells you to
 * re-issue, "issuer" tells you something is impersonating your issuer. Collapsing
 * them into a generic 401 would make the difference invisible at exactly the
 * moment it counts.
 *
 *   npx tsx scripts/verify-credential-checks.ts
 */
import { CredentialError, CredentialVerifier } from "../src/identity/credential.js";
import { DEV_JWKS, TEST_AUDIENCE, TEST_ISSUER, TEST_VCT, mint } from "./mint-test-credential.js";

let failures = 0;
function check(label: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "  ✓" : "  ✗"} ${label}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

function verifier(overrides: Partial<ConstructorParameters<typeof CredentialVerifier>[0]> = {}) {
  return new CredentialVerifier({
    issuer: TEST_ISSUER,
    expectedVct: TEST_VCT,
    expectedAudience: TEST_AUDIENCE,
    jwksFile: DEV_JWKS,
    checkRevocation: false,
    ...overrides,
  });
}

/** Assert that verifying `credential` fails with exactly `code`. */
async function expectCode(label: string, credential: string, code: string, v = verifier()) {
  try {
    await v.verify(credential);
    check(label, false, "accepted, but should have been rejected");
  } catch (err) {
    const actual = err instanceof CredentialError ? err.code : `${err}`;
    check(label, actual === code, `${actual}`);
  }
}

const MIND = "240b453e-f36b-1410-8466-00039ce7df11";

console.log("\ncredential verification");
{
  const good = await mint({ mindId: MIND, scopes: ["tweets.read", "analytics.read"] });
  const v = verifier();
  const result = await v.verify(good);
  check("a well-formed credential verifies", result.mindId === MIND, result.mindId);
  check(
    "asserted scopes are read from the signed body",
    result.assertedScopes.join(",") === "tweets.read,analytics.read",
    result.assertedScopes.join(","),
  );
  check("the label disclosure is parsed", result.label === `Test Mind ${MIND}`, `${result.label}`);
  check("a fingerprint is produced", /^[0-9a-f]{16}$/.test(result.fingerprint), result.fingerprint);
  check(
    "the fingerprint is not the credential",
    !good.includes(result.fingerprint),
    "no substring overlap",
  );
  check("expiry is surfaced", result.expiresAt.getTime() > Date.now());
  check("a revocation nonce is present", result.nonce.length > 0);
}

console.log("\nrejections");
{
  await expectCode("expired credential", await mint({ mindId: MIND, scopes: ["tweets.read"], minutes: -60 }), "expired");
  await expectCode(
    "wrong issuer",
    await mint({ mindId: MIND, scopes: ["tweets.read"], issuer: "https://evil.example" }),
    "issuer",
  );
  await expectCode(
    "wrong vct",
    await mint({ mindId: MIND, scopes: ["tweets.read"], vct: "https://adam.id/vct/other/v1" }),
    "vct",
  );
  await expectCode(
    "wrong audience",
    await mint({ mindId: MIND, scopes: ["tweets.read"], audience: "some-other-vault" }),
    "audience",
  );
  await expectCode("no mind_id", await mint({ mindId: MIND, scopes: ["tweets.read"], omit: ["mind_id"] }), "claims");
  await expectCode("no nonce", await mint({ mindId: MIND, scopes: ["tweets.read"], omit: ["nonce"] }), "claims");
  await expectCode("no recognised scopes", await mint({ mindId: MIND, scopes: ["not.a.scope"] }), "claims");
  await expectCode("empty scopes", await mint({ mindId: MIND, scopes: [] }), "claims");

  // Flip a byte in the signature; everything else stays valid.
  const good = await mint({ mindId: MIND, scopes: ["tweets.read"] });
  const [jws, ...rest] = good.split("~");
  const [h, p, s] = jws.split(".");
  const flipped = `${h}.${p}.${s.slice(0, -2)}${s.slice(-2) === "AA" ? "AB" : "AA"}`;
  await expectCode("tampered signature", [flipped, ...rest].join("~"), "signature");

  // A structurally perfect credential signed by a key we do not trust — the
  // shape an impersonation attempt takes, right down to a matching kid.
  await expectCode(
    "correct kid, foreign signing key",
    await mint({ mindId: MIND, scopes: ["tweets.read"], foreignKey: true }),
    "signature",
  );

  await expectCode("garbage", "not-a-credential", "malformed");
  await expectCode("empty", "   ", "malformed");
}

console.log("\nunknown scopes are dropped, not honoured");
{
  const mixed = await mint({ mindId: MIND, scopes: ["tweets.read", "admin.everything", "dms.read"] });
  const result = await verifier().verify(mixed);
  check(
    "only recognised scopes survive",
    result.assertedScopes.join(",") === "tweets.read,dms.read",
    result.assertedScopes.join(","),
  );
}

console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
