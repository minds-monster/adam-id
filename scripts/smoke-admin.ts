/**
 * Smoke test for the adam-id admin provisioning endpoints.
 *
 * Requires the HTTP server and issuer service to be running, plus:
 *   VAULT_ADMIN_API_KEY, VAULT_ISSUER_ADMIN_KEY
 *
 *   npx tsx scripts/smoke-admin.ts
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const PORT = process.env.VAULT_HTTP_PORT ?? 8787;
const URL_ = `http://127.0.0.1:${PORT}`;
const ADMIN_KEY = process.env.VAULT_ADMIN_API_KEY;

let failures = 0;
function check(label: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "  ✓" : "  ✗"} ${label}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

async function post(path: string, body: unknown, apiKey?: string) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (apiKey) headers["x-admin-api-key"] = apiKey;
  const res = await fetch(`${URL_}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    /* ignore */
  }
  return { status: res.status, json, text };
}

async function callMcp(credential: string, body: unknown) {
  const res = await fetch(`${URL_}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${credential}`,
      host: "vault.minds.monster",
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    /* ignore */
  }
  return { status: res.status, json, text };
}

if (!ADMIN_KEY) {
  console.error("VAULT_ADMIN_API_KEY is not set. Skipping admin smoke test.");
  process.exit(0);
}

const mindId = `smoke-admin-${Date.now()}`;

console.log("\nadmin endpoint auth");
{
  const noKey = await post("/admin/issue-credential", { mindId, scopes: "tweets.read" });
  check("missing admin key is rejected", noKey.status === 401, `${noKey.status}`);

  const badKey = await post("/admin/issue-credential", { mindId, scopes: "tweets.read" }, "wrong");
  check("bad admin key is rejected", badKey.status === 401, `${badKey.status}`);
}

console.log("\nissue + verify credential");
let credential = "";
{
  const issued = await post(
    "/admin/issue-credential",
    { mindId, scopes: "tweets.read,analytics.read", label: "Smoke Test Mind", days: 1 },
    ADMIN_KEY,
  );
  check("issue returns 200", issued.status === 200, `${issued.status}`);
  check("issue returns a credential", typeof issued.json.credential === "string" && issued.json.credential.length > 0);
  check("issue returns a credentialId", typeof issued.json.credentialId === "string");
  check("issue returns a grant with matching scopes", (issued.json.grant as { scopes?: string[] })?.scopes?.join(",") === "tweets.read,analytics.read");

  credential = String(issued.json.credential ?? "");

  const list = await callMcp(credential, { jsonrpc: "2.0", id: 1, method: "tools/list" });
  check("issued credential works on /mcp", list.status === 200, `${list.status}`);
  const tools = ((list.json.result as { tools?: { name: string }[] } | undefined)?.tools ?? []).map((t) => t.name);
  check("tools are scope-bound", tools.includes("search_tweets") && !tools.includes("search_likes"));

  const search = await callMcp(credential, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "search_tweets", arguments: { query: "the", limit: 1 } },
  });
  check("granted tool returns data", search.status === 200, `${search.status}`);
}

console.log("\nrevoke");
{
  const revoked = await post("/admin/revoke", { mindId }, ADMIN_KEY);
  check("revoke returns 200", revoked.status === 200, `${revoked.status}`);

  const after = await callMcp(credential, { jsonrpc: "2.0", id: 3, method: "tools/list" });
  check("revoked credential is denied", after.status === 403, `${after.status}`);
}

console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
