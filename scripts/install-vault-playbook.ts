/**
 * Install the adam-id vault contract onto a Hello Minds Mind.
 *
 * Mirrors adam-mind/ops/install-vault-playbook.ts so the install can run from the
 * adam-id project when the session is pinned here.
 *
 * Usage:
 *   npm run install-vault-playbook -- \
 *     --credential-file <path> --cf-id-file <path> --cf-secret-file <path> \
 *     [--mind <name|guid>] [--alias <alias>] [--playbook <name|path>] [--dry-run]
 *
 * Secrets may also come from environment variables:
 *   ADAM_ID_VC, CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET
 *
 * The Builder API key is read from MINDS_BUILDER_API_KEY.
 *
 * CREDENTIAL CAVEAT: the Builder API has no tenet-write route, so all three secrets
 * transit the conversation transcript and are persisted by the Mind via LTM_Push.
 * The credential expires within 24h by design; `vault revoke --mind <id>` cuts access
 * immediately if the transcript is ever exposed.
 */
import { readFile } from "node:fs/promises";
import { createMindsClient } from "@animocabrands/minds-client-lib";

const MINDS = {
  adam: "240b453e-f36b-1410-8466-00039ce7df11",
  beta: "fb12453e-f36b-1410-8466-00039ce7df11",
  trend: "749b453e-f36b-1410-8466-00039ce7df11",
} as const;

type MindName = keyof typeof MINDS;

const argv = process.argv.slice(2);
const dryRun = argv.includes("--dry-run");

function opt(name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function secret(name: string, envVar: string): Promise<string> {
  const file = opt(`${name}-file`);
  if (file) return (await readFile(file, "utf8")).trim();
  const inline = opt(name);
  if (inline) return inline;
  return (process.env[envVar] ?? "").trim();
}

function resolveMindId(nameOrId?: string): string | undefined {
  if (!nameOrId) return undefined;
  const key = nameOrId.trim().toLowerCase();
  if (key in MINDS) return MINDS[key as MindName];
  if (/^[0-9a-f-]{36}$/.test(key)) return key;
  throw new Error(
    `Unknown mind "${nameOrId}". Known: ${Object.keys(MINDS).join(", ")}, or a GUID.`,
  );
}

function mindName(id: string): string {
  const hit = Object.entries(MINDS).find(([, v]) => v.toLowerCase() === id.toLowerCase());
  return hit ? hit[0] : id;
}

function errText(err: unknown): string {
  if (err && typeof err === "object" && "message" in err) return String(err.message);
  return String(err);
}

function stripHtml(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function parseFencedJson(text: string): unknown | null {
  const fenced = [...text.matchAll(/```(?:json)?\s*\n?([\s\S]*?)```/g)];
  for (const m of fenced.reverse()) {
    const parsed = tryParse(m[1]);
    if (parsed !== null) return parsed;
  }
  for (const candidate of balancedObjects(text).reverse()) {
    const parsed = tryParse(candidate);
    if (parsed !== null) return parsed;
  }
  return null;
}

function tryParse(s: string | undefined): unknown | null {
  if (!s?.trim()) return null;
  try {
    return JSON.parse(s.trim());
  } catch {
    return null;
  }
}

function balancedObjects(text: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== "{") continue;
    let depth = 0;
    let inStr = false;
    let esc = false;
    for (let j = i; j < text.length; j++) {
      const ch = text[j]!;
      if (esc) {
        esc = false;
        continue;
      }
      if (ch === "\\" && inStr) {
        esc = true;
        continue;
      }
      if (ch === '"') inStr = !inStr;
      if (inStr) continue;
      if (ch === "{") depth++;
      else if (ch === "}") {
        depth--;
        if (depth === 0) {
          out.push(text.slice(i, j + 1));
          i = j;
          break;
        }
      }
    }
  }
  return out;
}

const credential = await secret("credential", "ADAM_ID_VC");
const cfId = await secret("cf-id", "CF_ACCESS_CLIENT_ID");
const cfSecret = await secret("cf-secret", "CF_ACCESS_CLIENT_SECRET");
const playbookArg = opt("playbook") ?? "adam-id-vault-v3";

if (!credential || !cfId || !cfSecret) {
  console.error(
    "Usage: npm run install-vault-playbook -- \\\n" +
      "         --credential-file <path> --cf-id-file <path> --cf-secret-file <path> \\\n" +
      "         [--mind <name|guid>] [--alias <alias>] [--playbook <name|path>] [--dry-run]\\n\\n" +
      "Each secret may also come from the environment:\\n" +
      "  ADAM_ID_VC, CF_ACCESS_CLIENT_ID, CF_ACCESS_CLIENT_SECRET\\n\\n" +
      "Inline --credential/--cf-secret still work but put the secret in the process list. " +
      "Prefer a file or the environment.",
  );
  process.exit(2);
}

let credentialMindId: string | undefined;
let credentialScopes: string[] = [];
try {
  const payload = JSON.parse(
    Buffer.from(credential.split("~")[0]!.split(".")[1] ?? "", "base64url").toString("utf8"),
  ) as { exp?: number; mind_id?: string; scopes?: string[]; iss?: string };
  const expiresIn = (payload.exp ?? 0) * 1000 - Date.now();
  if (expiresIn <= 0) {
    console.error(`Credential expired ${Math.round(-expiresIn / 60000)} minutes ago. Re-mint first.`);
    process.exit(2);
  }
  credentialMindId = payload.mind_id;
  credentialScopes = payload.scopes ?? [];
  console.log(
    `Credential : mind=${payload.mind_id ? mindName(payload.mind_id) : "?"} (${payload.mind_id})`,
  );
  console.log(`             scopes=[${credentialScopes.join(" ")}]`);
  console.log(`             iss=${payload.iss} expires in ${Math.round(expiresIn / 60000)} min`);
} catch {
  console.error("Could not decode the credential — is it the full SD-JWT including trailing ~ ?");
  process.exit(2);
}

const builderApiKey = process.env.MINDS_BUILDER_API_KEY;
if (!builderApiKey) {
  console.error("MINDS_BUILDER_API_KEY is not set.");
  process.exit(2);
}

const playbookUrl = playbookArg.includes("/")
  ? new URL(playbookArg, `file://${process.cwd()}/`)
  : new URL(`../playbooks/${playbookArg}.md`, import.meta.url);

let template: string;
try {
  template = await readFile(playbookUrl, "utf8");
} catch {
  console.error(`No such playbook: ${playbookUrl.pathname}`);
  process.exit(2);
}

const playbook =
  template +
  `
KEY MATERIAL (v1 delivery — no tenet write API exists yet)
  Until these live in tenets.apiKeys.*, use these literal values on every vault call.
  Treat all three as secrets: never echo them, never include them in a reply, an
  artifact, or a skill body.

  ADAM_ID_VC        = ${credential}
  ADAM_ID_CF_ID     = ${cfId}
  ADAM_ID_CF_SECRET = ${cfSecret}
`;

console.log(`Playbook   : ${playbookArg} (${playbook.length} chars)`);
console.log(`CF token   : ${cfId}\n`);

if (dryRun) {
  console.log("--- playbook that WOULD be sent (secrets redacted) ---\n");
  console.log(
    playbook
      .replace(credential, "<CREDENTIAL REDACTED>")
      .replace(cfSecret, "<CF_SECRET REDACTED>"),
  );
  console.log("\n--dry-run: nothing sent.");
  process.exit(0);
}

console.warn(
  "WARNING: the credential and the Cloudflare service token will be written into the\n" +
    "         Mind conversation transcript and persisted to its long-term memory.\n" +
    "         The credential expires within 24h by design. `vault revoke --mind <id>`\n" +
    "         cuts access immediately if the transcript is ever exposed.\n",
);

const targetMind = resolveMindId(opt("mind")) ?? credentialMindId ?? MINDS.adam;
if (credentialMindId && credentialMindId.toLowerCase() !== targetMind.toLowerCase()) {
  console.error(
    `Credential is minted for ${mindName(credentialMindId)} (${credentialMindId})\n` +
      `but this run targets ${mindName(targetMind)} (${targetMind}).\n\n` +
      `Re-mint for ${mindName(targetMind)}, or pass --mind ${mindName(credentialMindId)}.`,
  );
  process.exit(2);
}

const client = createMindsClient({ builderApiKey });

const alias = opt("alias") ?? "relay:x-ops";
const boundTo = await client.getMindIdForAlias(alias).catch(() => undefined);
if (boundTo && boundTo.toLowerCase() !== targetMind.toLowerCase()) {
  console.error(
    `Alias "${alias}" belongs to ${mindName(boundTo)}, but this run targets ` +
      `${mindName(targetMind)}. Pass --alias for a ${mindName(targetMind)} conversation, or ` +
      `set --mind ${mindName(boundTo)} if that is the Mind you meant.`,
  );
  process.exit(2);
}

await client.ensureConversation(alias, targetMind);

console.log(`Sending vault playbook to ${mindName(targetMind)} via ${alias} ...`);

const before = await client.getLatestHistoryFingerprint(alias);
await client.sendMessage({ alias, messageText: playbook });
const outcome = await client.waitForReply({
  alias,
  timeoutMs: 240_000,
  afterFingerprint: before ?? undefined,
  sentMessageText: playbook,
});

if (outcome.timedOut) {
  console.error("Mind did not reply within 240s.");
  process.exit(1);
}

const text = stripHtml(String(outcome.reply.messageText ?? ""));
const json = parseFencedJson(text);

console.log("\n--- Mind reply ---");
console.log(text.slice(0, 2000));

const r = (json ?? {}) as Record<string, unknown>;
const expectedVersion = Number(template.match(/ADAM_ID_VAULT v(\d+)/)?.[1] ?? 0);
const ok =
  r.ok === true &&
  r.playbook === "ADAM_ID_VAULT" &&
  r.stored === true &&
  Number(r.version) === expectedVersion;

console.log("\n--- verdict ---");
console.log(
  `  contract acknowledged: ${ok} (playbook=${r.playbook ?? "none"} v${r.version ?? "?"}, expected v${expectedVersion})`,
);
if (r.playbook === "ADAM_ID_VAULT" && Number(r.version) !== expectedVersion) {
  console.log(
    `  ⚠ acknowledged v${r.version} but sent v${expectedVersion} — likely replaying old memory.`,
  );
}
if (!ok) {
  console.log("  The Mind did not return the expected acknowledgement. It may still have");
  console.log("  stored the contract — check by asking it to call vault_info.");
}

const leaked = text.includes(credential.slice(0, 40)) || text.includes(cfSecret);
console.log(`  secrets absent from reply: ${!leaked}`);
if (leaked) console.log("  ⚠ the Mind echoed key material back — rotate it now.");

process.exit(ok && !leaked ? 0 : 1);
