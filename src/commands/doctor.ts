import { existsSync, statSync } from "node:fs";
import { ALL_SCOPES, findArchiveDir, loadConfig, type VaultConfig } from "../config.js";
import { keyStatus } from "../crypto/keyring.js";
import { readManifest } from "../archive/loader.js";
import { CORPUS_FILES, type CorpusStats } from "../corpus/model.js";
import { corpusPath, readJson } from "../corpus/io.js";
import { makeAnchor, storagePath, type StoreManifest } from "./seal.js";
import { McspStorageAdapter } from "../storage/mcsp.js";
import { LocalStorageAdapter } from "../storage/local.js";
import { MOCA_TESTNET_RPC, mocaTestnet } from "../anchor/moca-testnet.js";
import { GrantStore } from "../identity/grants.js";

const OK = "✓";
const NO = "✗";
const WARN = "!";

function line(mark: string, label: string, detail: string): void {
  console.error(`  ${mark} ${label.padEnd(22)} ${detail}`);
}

/** Report what's wired up and what still needs doing. Read-only and safe to run anytime. */
export async function doctor(root = process.cwd()): Promise<number> {
  let config: VaultConfig | null = null;
  console.error("archive");
  const archiveDir = findArchiveDir(root);
  if (!archiveDir) {
    line(NO, "archive", `none found under ${root} (set VAULT_ARCHIVE_DIR)`);
  } else {
    const m = readManifest(archiveDir);
    line(OK, "archive", `@${m.userInfo.userName}, exported ${m.archiveInfo.generationDate.slice(0, 10)}`);
    config = loadConfig(root);
  }

  console.error("\ncorpus");
  if (config) {
    const stats = readJson<CorpusStats>(corpusPath(config.corpusDir, CORPUS_FILES.stats));
    if (!stats) {
      line(NO, "corpus", "not ingested — run `vault ingest`");
    } else {
      line(
        OK,
        "corpus",
        `${stats.posts} posts, ${stats.likes} likes, ${stats.directMessages} dms, ` +
          `${stats.mediaFiles} media (${(stats.mediaBytes / 1e9).toFixed(2)} GB)`,
      );
      line(
        stats.engagementKnown / stats.posts > 0.5 ? OK : WARN,
        "engagement coverage",
        `${((stats.engagementKnown / stats.posts) * 100).toFixed(1)}% of posts have recorded likes/retweets`,
      );
    }
    if (existsSync(config.indexPath)) {
      const size = statSync(config.indexPath).size;
      line(OK, "search index", `${config.indexPath} (${(size / 1e6).toFixed(1)} MB)`);
    } else {
      line(NO, "search index", "not built — run `vault index`");
    }
  }

  console.error("\nencryption");
  const key = keyStatus();
  line(key.present ? OK : NO, "vault key", key.present ? key.source : "not created — run `vault seal`");

  if (config) {
    const manifest = readJson<StoreManifest>(storagePath(config, "manifest.json"));
    if (manifest) {
      line(
        OK,
        "sealed store",
        `${manifest.objectCount} objects, ${(manifest.ciphertextBytes / 1e9).toFixed(2)} GB, ` +
          `root ${manifest.merkleRoot.slice(0, 16)}…`,
      );
    } else {
      line(NO, "sealed store", "nothing sealed yet — run `vault seal`");
    }
    const localStore = new LocalStorageAdapter(config.storeDir);
    line(OK, "storage: local", localStore.describe());
    line(WARN, "storage: mcsp", new McspStorageAdapter().describe());
  }

  console.error("\nanchoring");
  try {
    const res = await fetch(MOCA_TESTNET_RPC, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
      signal: AbortSignal.timeout(8000),
    });
    const body = (await res.json()) as { result?: string };
    const block = body.result ? Number.parseInt(body.result, 16) : null;
    line(OK, "moca testnet rpc", `chainId ${mocaTestnet.id}, block ${block?.toLocaleString() ?? "?"}`);
  } catch (err) {
    line(WARN, "moca testnet rpc", `unreachable: ${err instanceof Error ? err.message : String(err)}`);
  }
  line(
    process.env.MOCA_ANCHOR_PRIVATE_KEY ? OK : WARN,
    "anchor signer",
    process.env.MOCA_ANCHOR_PRIVATE_KEY
      ? "MOCA_ANCHOR_PRIVATE_KEY set"
      : "unset — anchoring falls back to a local receipt with no on-chain proof",
  );
  if (config) {
    const receipt = await makeAnchor(config, "local").latest();
    line(
      receipt ? OK : WARN,
      "last anchor",
      receipt ? `${receipt.root.slice(0, 16)}… at ${receipt.anchoredAt}` : "never anchored",
    );
  }

  console.error("\nmoca identity");
  line(
    process.env.MOCA_PARTNER_ID ? OK : WARN,
    "partner id",
    process.env.MOCA_PARTNER_ID ?? "unset (used by the browser companion page)",
  );
  line(
    process.env.VAULT_ISSUER_URL ? OK : WARN,
    "credential issuer",
    process.env.VAULT_ISSUER_URL ?? "unset — `serve --http` will refuse to start",
  );
  line(
    process.env.VAULT_ISSUER_VCT ? OK : WARN,
    "credential type",
    process.env.VAULT_ISSUER_VCT ?? "unset — the expected `vct` claim",
  );
  if (process.env.VAULT_ISSUER_JWKS_FILE) {
    line(WARN, "jwks source", `local file (development) — ${process.env.VAULT_ISSUER_JWKS_FILE}`);
  }
  line(
    WARN,
    "credential services",
    "pending activation — until then the KEK is local, not CAK-derived",
  );

  console.error("\nmcp server");
  if (config) {
    line(OK, "granted scopes", config.scopes.join(", "));
    const withheld = ALL_SCOPES.filter((s) => !config!.scopes.includes(s));
    if (withheld.length) line(WARN, "withheld scopes", withheld.join(", "));
    line(
      existsSync(config.auditLogPath) ? OK : WARN,
      "audit log",
      existsSync(config.auditLogPath) ? config.auditLogPath : "no calls recorded yet",
    );
  }

  console.error("\nremote access");
  if (config) {
    if (!existsSync(config.grantsPath)) {
      line(WARN, "grants", "none — the HTTP transport would reject every caller");
    } else {
      const store = new GrantStore(config.grantsPath);
      const active = store.list();
      const total = store.list(true).length;
      line(
        active.length ? OK : WARN,
        "grants",
        `${active.length} active of ${total} (${config.grantsPath})`,
      );
      const soon = active.filter(
        (g) => g.expiresAt && new Date(g.expiresAt).getTime() - Date.now() < 86_400_000,
      );
      for (const g of soon) line(WARN, "expiring soon", `${g.label} — ${g.expiresAt}`);
      const forever = active.filter((g) => !g.expiresAt);
      for (const g of forever) line(WARN, "no expiry", `${g.label} — consider re-granting with --days`);
    }
  }

  return 0;
}
