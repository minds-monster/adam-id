#!/usr/bin/env node
import "./load-env.js"; // must stay first: side-effect import, see the file for why
import { loadConfig } from "./config.js";
import { ingest, printStats } from "./commands/ingest.js";
import { buildIndex } from "./index/build.js";
import { serve } from "./mcp/server.js";
import { serveHttp } from "./mcp/http.js";
import { makeAnchor, sealVault, verifyVault, type VerifyReport } from "./commands/seal.js";
import { rebuild } from "./commands/rebuild.js";
import { doctor } from "./commands/doctor.js";
import { loadOrCreateAgentKey } from "./identity/agent-key.js";
import { GrantStore, isActive, parseScopeList } from "./identity/grants.js";
import { readJson } from "./corpus/io.js";
import { storagePath, type StoreManifest } from "./commands/seal.js";

const USAGE = `vault — personal X data vault

  ingest                    parse the X archive into the normalized corpus
  index                     build the SQLite FTS5 search index
  seal   [--skip-media]     encrypt corpus + media into the content-addressed store
         [--storage local|mcsp] [--anchor local|moca-testnet]
  verify [--spot-checks N]  re-hash the store, recompute the Merkle root, test decryption
  anchor [--anchor ...]     publish the current store root
  rebuild                   reconstruct corpus + index from sealed objects alone
  agent-key                 create/show the agent's keypair for Moca registration
  serve  [--http] [--port N]
                            MCP server over stdio, or credential-gated HTTP
  doctor                    report archive, corpus, key, storage and anchor status

Remote access (Moca-credentialled MCP over HTTP):
  grants                    list who may reach the vault remotely, and how far
  grant  --mind <id> --scopes a,b
         [--label L] [--days N] [--note "..."] [--holder-did did:air:...]
  revoke --mind <id>        cut off a Mind immediately

Environment:
  VAULT_ARCHIVE_DIR         override archive autodiscovery
  VAULT_SCOPES              comma-separated scopes, or '*'  (default excludes dms.read)
  VAULT_PASSPHRASE          derive the vault key instead of using the macOS Keychain
  VAULT_AUDIT_ECHO=1        mirror the audit log to stderr
  MOCA_ANCHOR_PRIVATE_KEY   testnet signer for on-chain anchoring
  MCSP_ENDPOINT             MCSP base url (backend not yet implemented)

  VAULT_ISSUER_URL          credential issuer origin — the expected \`iss\`
  VAULT_ISSUER_VCT          expected credential type
  VAULT_ISSUER_AUDIENCE     expected \`audience\` claim  (default: adam-id)
  VAULT_ISSUER_JWKS_FILE    local JWKS, for development without a live issuer
  VAULT_HTTP_PORT/HOST      bind address           (default: 127.0.0.1:8787)
  VAULT_HTTP_ALLOWED_HOSTS  extra Host values to accept, e.g. your tunnel name

  VAULT_ADMIN_API_KEY       enables POST /admin/issue-credential and /admin/revoke
  VAULT_ISSUER_ADMIN_KEY    issuer key used by /admin/issue-credential
  VAULT_ISSUER_ADMIN_ORIGIN issuer URL reachable by the vault (default: loopback)
  CF_ACCESS_CLIENT_ID/SECRET  only when the issuer admin endpoint is behind Access
`;

function flag(argv: string[], name: string): boolean {
  return argv.includes(`--${name}`);
}

function option(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  if (i === -1) return undefined;
  const value = argv[i + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`--${name} requires a value`);
  }
  return value;
}

function reportVerify(r: VerifyReport): number {
  console.error(`objects            ${r.objectCount}`);
  console.error(`recomputed root    ${r.recomputedRoot}`);
  console.error(`manifest root      ${r.manifestRoot}`);
  console.error(`anchored root      ${r.anchoredRoot ?? "(never anchored)"}`);
  if (r.anchorReference) console.error(`anchor reference   ${r.anchorReference}`);
  console.error(`decryption checks  ${r.decryptionSpotChecks} passed`);
  if (r.ok) {
    console.error(`\n✓ store verified — ciphertext, Merkle root and anchor all agree`);
    return 0;
  }
  console.error(`\n✗ ${r.problems.length} problem(s):`);
  for (const p of r.problems) console.error(`   - ${p}`);
  return 1;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const [command] = argv;

  if (!command || command === "help" || command === "--help" || command === "-h") {
    console.error(USAGE);
    return command ? 0 : 1;
  }

  switch (command) {
    case "ingest": {
      printStats(ingest(loadConfig()));
      return 0;
    }

    case "index": {
      const s = buildIndex(loadConfig());
      console.error(
        `indexed ${s.posts} posts, ${s.likes} likes, ${s.dms} dms, ${s.accounts} accounts, ` +
          `${s.media} media rows`,
      );
      console.error(`index: ${s.path}`);
      return 0;
    }

    case "seal": {
      const config = loadConfig();
      const { manifest, anchor } = await sealVault(config, {
        skipMedia: flag(argv, "skip-media"),
        storageBackend: option(argv, "storage"),
        anchorBackend: option(argv, "anchor"),
      });
      console.error(`\nsealed ${manifest.objectCount} objects`);
      console.error(`  plaintext   ${(manifest.plaintextBytes / 1e9).toFixed(2)} GB`);
      console.error(`  ciphertext  ${(manifest.ciphertextBytes / 1e9).toFixed(2)} GB`);
      console.error(`  merkle root ${manifest.merkleRoot}`);
      console.error(`  anchored    ${anchor.reference} (chain ${anchor.chainId ?? "none"})`);
      return 0;
    }

    case "verify": {
      const spot = option(argv, "spot-checks");
      return reportVerify(
        await verifyVault(loadConfig(), {
          storageBackend: option(argv, "storage"),
          anchorBackend: option(argv, "anchor"),
          spotChecks: spot ? Number(spot) : undefined,
        }),
      );
    }

    case "anchor": {
      const config = loadConfig();
      const manifest = readJson<StoreManifest>(storagePath(config, "manifest.json"));
      if (!manifest) throw new Error("Nothing sealed yet — run `vault seal` first.");
      const anchor = makeAnchor(config, option(argv, "anchor") ?? "local");
      console.error(`anchor: ${anchor.describe()}`);
      const receipt = await anchor.anchor(manifest.merkleRoot);
      console.error(`anchored ${receipt.root}`);
      console.error(`  reference ${receipt.reference} (chain ${receipt.chainId ?? "none"})`);
      return 0;
    }

    case "rebuild": {
      const r = await rebuild(loadConfig(), { storageBackend: option(argv, "storage") });
      console.error(`rebuilt ${r.collections} collections (${r.records} records) from sealed objects`);
      return 0;
    }

    case "agent-key": {
      const key = loadOrCreateAgentKey();
      console.error(key.createdLocally ? "generated a new agent keypair" : "existing agent keypair");
      console.error(`  curve     ${key.curve}`);
      console.error(`  encoding  ${key.encoding}`);
      console.error(`  private   stored in the macOS Keychain, never transmitted`);
      console.error(`\npublic key — paste into web/companion.html to registerAgentKey:\n`);
      console.log(key.publicKeySpkiBase64);
      return 0;
    }

    case "grants": {
      const config = loadConfig();
      const store = new GrantStore(config.grantsPath);
      const all = store.list(true);
      if (!all.length) {
        console.error(`no grants (${config.grantsPath})`);
        console.error(`the HTTP transport will reject every caller until one exists`);
        return 0;
      }
      for (const g of all) {
        const state = g.revokedAt
          ? `revoked ${g.revokedAt}`
          : isActive(g)
            ? `active${g.expiresAt ? `, expires ${g.expiresAt}` : ", no expiry"}`
            : `expired ${g.expiresAt}`;
        console.error(`${g.mindId}  ${g.label}`);
        console.error(`  scopes  ${g.scopes.join(", ")}`);
        console.error(`  state   ${state}`);
        if (g.holderDid) console.error(`  holder  ${g.holderDid}`);
        if (g.note) console.error(`  note    ${g.note}`);
      }
      return 0;
    }

    case "grant": {
      const config = loadConfig();
      const mindId = option(argv, "mind");
      const rawScopes = option(argv, "scopes");
      if (!mindId) throw new Error("--mind is required");
      if (!rawScopes) throw new Error("--scopes is required");

      const scopes = parseScopeList(rawScopes);
      if (scopes.includes("dms.read") && !flag(argv, "include-dms")) {
        // DMs contain other people's words. Exposing them to a *remote* agent
        // whose credential will sit in a conversation transcript deserves a
        // second, deliberate keystroke — the same reasoning that keeps
        // dms.read out of DEFAULT_SCOPES, applied where the stakes are higher.
        throw new Error(
          "dms.read exposes other people's messages to a remote agent. " +
            "Pass --include-dms as well if you really mean it.",
        );
      }

      const days = option(argv, "days");
      const expiresAt = days
        ? new Date(Date.now() + Number(days) * 86_400_000).toISOString()
        : null;
      if (days && !Number.isFinite(Number(days))) throw new Error("--days must be a number");

      const store = new GrantStore(config.grantsPath);
      const grant = store.put({
        mindId,
        label: option(argv, "label") ?? mindId,
        scopes,
        expiresAt,
        note: option(argv, "note"),
        holderDid: option(argv, "holder-did"),
      });
      console.error(`granted ${grant.label} (${grant.mindId})`);
      console.error(`  scopes   ${grant.scopes.join(", ")}`);
      console.error(`  expires  ${grant.expiresAt ?? "never — consider --days"}`);
      console.error(`  file     ${config.grantsPath}`);
      return 0;
    }

    case "revoke": {
      const config = loadConfig();
      const mindId = option(argv, "mind");
      if (!mindId) throw new Error("--mind is required");
      const store = new GrantStore(config.grantsPath);
      if (!store.revoke(mindId)) {
        console.error(`no active grant for ${mindId} — nothing to revoke`);
        return 1;
      }
      console.error(`revoked ${mindId}`);
      console.error(`live sessions are torn down within a second; new ones are refused`);
      return 0;
    }

    case "serve": {
      const config = loadConfig();
      if (flag(argv, "http")) {
        const port = option(argv, "port");
        await serveHttp(config, { port: port ? Number(port) : undefined });
        return 0;
      }
      await serve(config);
      return 0;
    }

    case "doctor":
      return doctor();

    default:
      console.error(`Unknown command: ${command}\n`);
      console.error(USAGE);
      return 1;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    console.error(err instanceof Error ? `error: ${err.message}` : err);
    process.exit(1);
  });
