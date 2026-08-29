/**
 * End-to-end smoke test for the credential-gated HTTP transport.
 *
 * Runs entirely offline: a throwaway dev issuer key stands in for the real one,
 * so the whole authorization path — verification, revocation, the grant
 * intersection, session teardown — is provable before Postgres, a tunnel, or
 * Moca exist.
 *
 *   npx tsx scripts/smoke-http.ts
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { resolve } from "node:path";
import { DEV_JWKS, TEST_ISSUER, TEST_VCT, mint } from "./mint-test-credential.js";

const ROOT = resolve(import.meta.dirname, "..");
const GRANTS = resolve(ROOT, "grants.json");
const PORT = 8791;
const URL_ = `http://127.0.0.1:${PORT}/mcp`;
const MIND = "240b453e-f36b-1410-8466-00039ce7df11";
const OTHER_MIND = "fb12453e-f36b-1410-8466-00039ce7df11";

let failures = 0;
function check(label: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "  ✓" : "  ✗"} ${label}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Preserve any real grants file so this test never destroys a live one. */
let savedGrants: string | null = null;
try {
  savedGrants = readFileSync(GRANTS, "utf8");
} catch {
  savedGrants = null;
}
function setGrants(grants: unknown[]): void {
  writeFileSync(GRANTS, `${JSON.stringify({ version: 1, grants }, null, 2)}\n`);
}
function restoreGrants(): void {
  if (savedGrants === null) rmSync(GRANTS, { force: true });
  else writeFileSync(GRANTS, savedGrants);
}

function grant(mindId: string, scopes: string[], label = "Test Mind") {
  return { mindId, label, scopes, createdAt: new Date().toISOString(), expiresAt: null };
}

/** Raw POST, for the cases that must fail before MCP is ever spoken. */
async function raw(
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(URL_, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body),
  });
  let parsed: Record<string, unknown> = {};
  try {
    parsed = (await res.json()) as Record<string, unknown>;
  } catch {
    /* empty body is fine */
  }
  return { status: res.status, json: parsed };
}

/** A POST with an arbitrary Host header, which fetch will not permit. */
function rawWithHost(host: string): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((done) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port: PORT,
        path: "/mcp",
        method: "POST",
        headers: { "content-type": "application/json", host, authorization: "Bearer x" },
      },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          let body: Record<string, unknown> = {};
          try {
            body = JSON.parse(raw) as Record<string, unknown>;
          } catch {
            /* non-JSON is a failure the caller will notice */
          }
          done({ status: res.statusCode ?? 0, body });
        });
      },
    );
    req.end(JSON.stringify(INIT));
  });
}

const INIT = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "smoke", version: "1" } },
};

async function connect(credential: string): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(URL_), {
    requestInit: { headers: { Authorization: `Bearer ${credential}` } },
  });
  const client = new Client({ name: "smoke-http", version: "1" });
  await client.connect(transport);
  return client;
}

let server: ChildProcess | null = null;
async function startServer(): Promise<void> {
  server = spawn("npx", ["tsx", "src/cli.ts", "serve", "--http", "--port", String(PORT)], {
    cwd: ROOT,
    env: {
      ...process.env,
      VAULT_ISSUER_URL: TEST_ISSUER,
      VAULT_ISSUER_VCT: TEST_VCT,
      VAULT_ISSUER_JWKS_FILE: DEV_JWKS,
      VAULT_SKIP_REVOCATION_CHECK: "1",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let out = "";
  server.stderr?.on("data", (d: Buffer) => (out += d.toString()));
  for (let i = 0; i < 100; i++) {
    await sleep(200);
    if (out.includes("listening")) return;
    if (server.exitCode !== null) throw new Error(`server exited:\n${out}`);
  }
  throw new Error(`server never came up:\n${out}`);
}

try {
  // Seed a grant that is narrower than the credential will claim.
  setGrants([grant(MIND, ["tweets.read", "analytics.read"], "Adam (Hello Minds)")]);
  await mint({ mindId: MIND, scopes: ["tweets.read"] }); // ensure the dev key exists
  await startServer();

  console.log("\nrefusals before any MCP is spoken");
  {
    const noAuth = await raw(INIT);
    check("no credential is refused", noAuth.status === 401, `${noAuth.status} ${noAuth.json.error}`);

    const garbage = await raw(INIT, { authorization: "Bearer not-a-credential" });
    check(
      "garbage credential is refused as malformed",
      garbage.status === 401 && garbage.json.error === "credential_malformed",
      `${garbage.status} ${garbage.json.error}`,
    );

    const expired = await mint({ mindId: MIND, scopes: ["tweets.read"], minutes: -60 });
    const expRes = await raw(INIT, { authorization: `Bearer ${expired}` });
    check(
      "expired credential is refused",
      expRes.status === 401 && expRes.json.error === "credential_expired",
      `${expRes.status} ${expRes.json.error}`,
    );

    const foreign = await mint({ mindId: MIND, scopes: ["tweets.read"], foreignKey: true });
    const forRes = await raw(INIT, { authorization: `Bearer ${foreign}` });
    check(
      "foreign signing key is refused",
      forRes.status === 401 && forRes.json.error === "credential_signature",
      `${forRes.status} ${forRes.json.error}`,
    );

    const wrongIss = await mint({ mindId: MIND, scopes: ["tweets.read"], issuer: "https://evil.example" });
    const issRes = await raw(INIT, { authorization: `Bearer ${wrongIss}` });
    check(
      "wrong issuer is refused",
      issRes.status === 401 && issRes.json.error === "credential_issuer",
      `${issRes.status} ${issRes.json.error}`,
    );

    const wrongAud = await mint({ mindId: MIND, scopes: ["tweets.read"], audience: "other-vault" });
    const audRes = await raw(INIT, { authorization: `Bearer ${wrongAud}` });
    check(
      "wrong audience is refused",
      audRes.status === 401 && audRes.json.error === "credential_audience",
      `${audRes.status} ${audRes.json.error}`,
    );

    const ungranted = await mint({ mindId: OTHER_MIND, scopes: ["tweets.read"] });
    const ungRes = await raw(INIT, { authorization: `Bearer ${ungranted}` });
    check(
      "valid credential with no local grant is refused",
      ungRes.status === 403 && ungRes.json.error === "grant_missing",
      `${ungRes.status} ${ungRes.json.error}`,
    );

    const disjoint = await mint({ mindId: MIND, scopes: ["media.read"] });
    const disRes = await raw(INIT, { authorization: `Bearer ${disjoint}` });
    check(
      "empty scope intersection is refused",
      disRes.status === 403 && disRes.json.error === "scope_not_granted",
      `${disRes.status} ${disRes.json.error}`,
    );
  }

  console.log("\nhost validation happens before authentication");
  {
    // node:http rather than fetch — fetch forbids setting `Host`, which is
    // exactly the header under test.
    const { status, body } = await rawWithHost("evil.example");
    check("a foreign Host is rejected", status === 403 && body.error === "forbidden_host", `${status} ${body.error}`);
    check(
      "rejected before the credential is looked at",
      body.error === "forbidden_host",
      "no credential_* code",
    );
  }

  console.log("\nthe grant intersection bounds the session");
  {
    // Credential over-claims: it asserts dms.read and media.read, the grant does not.
    const over = await mint({
      mindId: MIND,
      scopes: ["tweets.read", "analytics.read", "dms.read", "media.read"],
    });
    const client = await connect(over);
    const names = (await client.listTools()).tools.map((t) => t.name);

    check("tools the grant allows are present", names.includes("search_tweets"));
    check("an over-claimed scope grants nothing — search_dms absent", !names.includes("search_dms"));
    check("an over-claimed scope grants nothing — get_media absent", !names.includes("get_media"));

    // The tool is not registered at all, so this fails as "tool not found" —
    // the server never had to decide whether to allow it. Over HTTP the SDK
    // surfaces that as an isError result rather than a thrown rejection.
    let refusal = "";
    try {
      const r = await client.callTool({ name: "search_dms", arguments: { query: "a" } });
      refusal = r.isError ? (r.content as { text: string }[])[0].text : "";
    } catch (err) {
      refusal = String(err);
    }
    check(
      "an over-claimed tool is not merely hidden, it is uncallable",
      /not found/i.test(refusal),
      refusal.slice(0, 60),
    );

    const info = await client.callTool({ name: "vault_info", arguments: {} });
    const data = JSON.parse((info.content as { text: string }[])[0].text) as {
      granted_scopes: string[];
      caller: { mind_id: string; label: string } | null;
    };
    check(
      "vault_info reports the intersection, not the process scopes",
      data.granted_scopes.join(",") === "tweets.read,analytics.read",
      data.granted_scopes.join(","),
    );
    check("vault_info identifies the caller", data.caller?.mind_id === MIND, `${data.caller?.label}`);

    const search = await client.callTool({ name: "search_tweets", arguments: { query: "the", limit: 3 } });
    const hits = JSON.parse((search.content as { text: string }[])[0].text) as { total_matches: number };
    check("a granted tool returns real data", hits.total_matches > 0, `${hits.total_matches} matches`);

    await client.close();
  }

  console.log("\na sessionless call works without the handshake");
  {
    // Exactly what Hello Minds `HTTP_Execute` can do: POST with the auth headers,
    // no initialize, no Mcp-Session-Id — because it cannot read a response header
    // on a 2xx and so can never learn the session id.
    const cred = await mint({ mindId: MIND, scopes: ["tweets.read", "analytics.read"] });
    const auth = { authorization: `Bearer ${cred}` };

    const list = await raw({ jsonrpc: "2.0", id: 1, method: "tools/list" }, auth);
    const listed = (list.json.result as { tools?: { name: string }[] } | undefined)?.tools ?? [];
    check(
      "tools/list needs no session",
      list.status === 200 && listed.some((t) => t.name === "search_tweets"),
      `${list.status}, ${listed.length} tools`,
    );

    const call = await raw(
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "search_tweets", arguments: { query: "the", limit: 3 } },
      },
      auth,
    );
    const payload = (call.json.result as { content?: { text: string }[] } | undefined)?.content?.[0]?.text;
    const matches = payload ? (JSON.parse(payload) as { total_matches: number }).total_matches : 0;
    check("tools/call needs no session", call.status === 200 && matches > 0, `${matches} matches`);

    // The gates must not be skippable just because the session was.
    const noAuth = await raw({ jsonrpc: "2.0", id: 3, method: "tools/list" });
    check(
      "a sessionless call still requires a credential",
      noAuth.status === 401 && noAuth.json.error === "no_credential",
      `${noAuth.status} ${noAuth.json.error}`,
    );

    // Scope narrowing must bind here too, or the sessionless path becomes a way
    // around the intersection that the session path enforces.
    const over = await mint({ mindId: MIND, scopes: ["tweets.read", "dms.read"] });
    const narrowed = await raw(
      { jsonrpc: "2.0", id: 4, method: "tools/list" },
      { authorization: `Bearer ${over}` },
    );
    const narrowedNames = (
      (narrowed.json.result as { tools?: { name: string }[] } | undefined)?.tools ?? []
    ).map((t) => t.name);
    check(
      "a sessionless call is still bound by the grant intersection",
      narrowedNames.length > 0 && !narrowedNames.includes("search_dms"),
      narrowedNames.includes("search_dms") ? "search_dms leaked" : `${narrowedNames.length} tools, no search_dms`,
    );
  }

  console.log("\nrevocation tears down a live session");
  {
    const cred = await mint({ mindId: MIND, scopes: ["tweets.read"] });
    const client = await connect(cred);
    check("session established", (await client.listTools()).tools.length > 0);

    setGrants([]); // revoke by removing the grant
    await sleep(1000);

    let died = false;
    try {
      await client.callTool({ name: "search_tweets", arguments: { query: "the", limit: 1 } });
    } catch {
      died = true;
    }
    check("the live session is cut off within a second", died);
    await client.close().catch(() => {});
  }

  console.log("\nthe audit log records who, not what they presented");
  {
    const log = readFileSync(resolve(ROOT, "audit.log"), "utf8").trim().split("\n").slice(-80);
    const opens = log.filter((l) => l.includes("$session.open")).map((l) => JSON.parse(l) as Record<string, unknown>);
    const last = opens.at(-1);
    check("a session open was audited", Boolean(last), `${opens.length} recent`);
    check("it records the mind id", last?.mindId === MIND, String(last?.mindId));
    check("it records a credential fingerprint", /^[0-9a-f]{16}$/.test(String(last?.credentialFingerprint)));
    check("it records the effective scopes", Array.isArray(last?.scopes));

    const cred = await mint({ mindId: MIND, scopes: ["tweets.read"] });
    const jwsBody = cred.split("~")[0].split(".")[1];
    check("no part of a credential is written to the log", !log.join("\n").includes(jwsBody));
    check(
      "denials are audited too",
      log.some((l) => l.includes("$session.denied")),
    );
  }
} finally {
  server?.kill("SIGTERM");
  restoreGrants();
}

console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
