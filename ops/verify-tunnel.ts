/**
 * Verify the tunnelled deployment.
 *
 * Phase 6 is where a mistake stops being local, so this checks the properties
 * that matter in the order they matter: the issuer's keys must be publicly
 * fetchable, the vault must NOT be reachable without the service token, and the
 * whole credential loop must still close over the public origins.
 *
 *   ISSUER_ORIGIN=https://issuer.minds.monster \
 *   VAULT_ORIGIN=https://vault.minds.monster \
 *   ISSUER_ADMIN_KEY=... \
 *   CF_ACCESS_CLIENT_ID=... CF_ACCESS_CLIENT_SECRET=... \
 *   npx tsx ops/verify-tunnel.ts
 */
import { CredentialVerifier } from "../src/identity/credential.js";

const ISSUER = process.env.ISSUER_ORIGIN ?? "https://issuer.minds.monster";
/** Where minting happens. Loopback, because /admin/* is not routed publicly. */
const ISSUER_LOCAL = process.env.ISSUER_LOCAL_ORIGIN ?? "http://127.0.0.1:3000";
const VAULT = process.env.VAULT_ORIGIN ?? "https://vault.minds.monster";
const ADMIN_KEY = process.env.ISSUER_ADMIN_KEY;
const CF_ID = process.env.CF_ACCESS_CLIENT_ID;
const CF_SECRET = process.env.CF_ACCESS_CLIENT_SECRET;
const VCT = process.env.VAULT_ISSUER_VCT ?? "https://adam.id/vct/adam-id-access/v1";
const MIND = process.env.MIND_ID ?? "240b453e-f36b-1410-8466-00039ce7df11";
const HOLDER = process.env.ISSUER_HOLDER_DID ?? "did:air:id:testnet:placeholder";

let failures = 0;
function check(label: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "  ✓" : "  ✗"} ${label}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

const INIT = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "verify", version: "1" } },
};

const accessHeaders = CF_ID && CF_SECRET
  ? { "CF-Access-Client-Id": CF_ID, "CF-Access-Client-Secret": CF_SECRET }
  : {};

async function post(url: string, headers: Record<string, string>, body: unknown) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body),
    // Same reason as above: an Access redirect must be visible as a redirect,
    // not silently followed to a page that returns 200.
    redirect: "manual",
    signal: AbortSignal.timeout(20_000),
  });
  return { status: res.status, text: (await res.text()).slice(0, 200) };
}

console.log("\nissuer metadata is public");
{
  // Deliberately no Access headers: adam-id fetches keys before it has anything
  // to authenticate with, so this path must work for an anonymous caller.
  //
  // `redirect: "manual"` is load-bearing. Cloudflare Access answers a gated
  // request with a 302 to a login page that itself returns 200 HTML, so a
  // following fetch reports success on exactly the configuration that is broken.
  const res = await fetch(`${ISSUER}/.well-known/jwt-vc-issuer`, {
    redirect: "manual",
    signal: AbortSignal.timeout(15_000),
  });
  const isJson = (res.headers.get("content-type") ?? "").includes("json");
  const redirected = res.status >= 300 && res.status < 400;

  check(
    "/.well-known/jwt-vc-issuer is reachable anonymously",
    res.status === 200 && isJson,
    redirected
      ? `HTTP ${res.status} → ${(res.headers.get("location") ?? "").slice(0, 60)}… (Access is gating this path)`
      : `HTTP ${res.status}${isJson ? "" : " (not JSON)"}`,
  );

  if (res.status === 200 && isJson) {
    const body = (await res.json()) as { issuer?: string; jwks?: { keys?: unknown[] } };
    check("metadata `issuer` matches the public origin", body.issuer === ISSUER, `${body.issuer}`);
    check("a signing key is published", (body.jwks?.keys?.length ?? 0) > 0);
  } else {
    console.log("     → adam-id cannot fetch signing keys; every verification will");
    console.log("       fail jwks_unreachable. Add a Bypass/Everyone policy for");
    console.log("       issuer.minds.monster/.well-known/* ABOVE any catch-all.");
  }
}

console.log("\nthe issuer's admin surface is not on the internet");
{
  // /admin/issue-sd-jwt mints bearer credentials. It is reachable over loopback
  // by an operator and nowhere else — enforced in the tunnel's ingress rules, so
  // it holds regardless of what Access policies exist.
  const res = await post(
    `${ISSUER}/admin/issue-sd-jwt`,
    { "x-admin-api-key": "probe" },
    { schemaId: "adam-id-access-v1", holderDID: HOLDER, mindId: "probe", scopes: ["tweets.read"] },
  );
  check(
    "/admin/* is not routed publicly",
    res.status === 404,
    `HTTP ${res.status}${res.status === 403 ? " (reached the origin's guard — it IS routable)" : ""}`,
  );
}

console.log("\nthe vault is not reachable without the service token");
{
  const bare = await post(`${VAULT}/mcp`, {}, INIT);
  // Access returns 302 (redirect to login) or 403 for a service-auth app.
  check(
    "an unauthenticated request is stopped at the edge",
    bare.status === 403 || bare.status === 302 || bare.status === 401,
    `HTTP ${bare.status}`,
  );
  check(
    "it is stopped by Access, not by the vault",
    !bare.text.includes("no_credential"),
    bare.text.includes("no_credential") ? "reached the origin — Access is NOT enforcing" : "blocked at edge",
  );
}

if (!ADMIN_KEY) {
  console.log("\n(skipping credential checks — set ISSUER_ADMIN_KEY)");
} else {
  console.log("\nthe credential loop closes over public origins");
  // Minted over loopback on purpose — see the admin-surface check above. The
  // credential's `iss` is still the public origin, so verification below
  // exercises the public JWKS path regardless of where minting happened.
  const issued = await fetch(`${ISSUER_LOCAL}/admin/issue-sd-jwt`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-admin-api-key": ADMIN_KEY, ...accessHeaders },
    body: JSON.stringify({
      schemaId: "adam-id-access-v1",
      holderDID: HOLDER,
      mindId: MIND,
      scopes: ["tweets.read"],
      label: "tunnel verification",
    }),
    redirect: "manual",
  });
  const mintedOk = issued.status === 200 || issued.status === 201;
  check(
    "a credential can be minted through the tunnel",
    mintedOk,
    issued.status >= 300 && issued.status < 400
      ? `HTTP ${issued.status} (Access is gating /admin/* — expected if the service token is scoped to the vault app only)`
      : `HTTP ${issued.status}`,
  );

  if (mintedOk) {
    const { credential } = (await issued.json()) as { credential: string };

    // Fetches keys from the public issuer, exactly as the vault does.
    const verifier = new CredentialVerifier({ issuer: ISSUER, expectedVct: VCT, expectedAudience: "adam-id" });
    const v = await verifier.verify(credential).catch((e: unknown) => e as Error);
    check(
      "it verifies against the public issuer's JWKS",
      !(v instanceof Error),
      v instanceof Error ? v.message : `iss ${(v as { issuer: string }).issuer}`,
    );

    if (CF_ID && CF_SECRET) {
      const ok = await post(`${VAULT}/mcp`, { ...accessHeaders, authorization: `Bearer ${credential}` }, INIT);
      check("service token + credential is accepted end to end", ok.status === 200, `HTTP ${ok.status} ${ok.text.slice(0, 80)}`);

      const noCred = await post(`${VAULT}/mcp`, accessHeaders, INIT);
      check(
        "service token alone is not enough",
        noCred.status === 401,
        `HTTP ${noCred.status}`,
      );
    } else {
      console.log("  (skipping vault checks — set CF_ACCESS_CLIENT_ID/SECRET)");
    }
  }
}

console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
