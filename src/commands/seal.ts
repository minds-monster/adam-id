import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { VaultConfig } from "../config.js";
import { loadKeyring } from "../crypto/keyring.js";
import { open, rewrap, seal as sealBytes, sha256 } from "../crypto/envelope.js";
import { merkleRoot, type MerkleLeaf } from "../crypto/merkle.js";
import type { StorageAdapter } from "../storage/adapter.js";
import { LocalStorageAdapter } from "../storage/local.js";
import { McspStorageAdapter } from "../storage/mcsp.js";
import { LocalAnchorAdapter, type AnchorAdapter } from "../anchor/adapter.js";
import { MocaTestnetAnchorAdapter } from "../anchor/moca-testnet.js";
import { CORPUS_FILES } from "../corpus/model.js";
import { corpusPath, ensureDir, readJson, readNdjson, writeJson } from "../corpus/io.js";

/**
 * Bytes available on the volume holding `dir`, or null if it can't be determined.
 * `statfs` is Node 18.15+; treat absence as "unknown" rather than as an error so
 * the preflight check degrades to a no-op instead of blocking a valid seal.
 */
async function freeSpace(dir: string): Promise<number | null> {
  try {
    const { statfs } = await import("node:fs/promises");
    const target = existsSync(dir) ? dir : resolve(dir, "..");
    const s = await statfs(target);
    return Number(s.bsize) * Number(s.bavail);
  } catch {
    return null;
  }
}

/** Sealed-store manifest: the index of every object plus the root that covers them. */
export interface StoreManifest {
  version: number;
  sealedAt: string;
  merkleRoot: string;
  objectCount: number;
  plaintextBytes: number;
  ciphertextBytes: number;
  objects: { key: string; cipherSha256: string; bytes: number; plaintextSha256: string }[];
}

const MANIFEST_FILE = "manifest.json";
const ANCHOR_FILE = "anchor.json";

export function storagePath(config: VaultConfig, file: string): string {
  return resolve(config.storeDir, file);
}

export function makeStorage(config: VaultConfig, backend: string): StorageAdapter {
  switch (backend) {
    case "local":
      return new LocalStorageAdapter(config.storeDir);
    case "mcsp":
      return new McspStorageAdapter();
    default:
      throw new Error(`Unknown storage backend "${backend}" (expected: local, mcsp)`);
  }
}

export function makeAnchor(config: VaultConfig, backend: string): AnchorAdapter {
  const path = storagePath(config, ANCHOR_FILE);
  switch (backend) {
    case "local":
      return new LocalAnchorAdapter(path);
    case "moca-testnet":
      return new MocaTestnetAnchorAdapter(path);
    default:
      throw new Error(`Unknown anchor backend "${backend}" (expected: local, moca-testnet)`);
  }
}

/**
 * Objects are batched rather than one-per-record. 8,270 individual post objects
 * would mean 8,270 wrapped DEKs and 8,270 round trips to a remote backend for no
 * privacy gain — the whole corpus is equally sensitive. Media is one object per
 * file because those are already large and are fetched individually.
 */
const BATCH_SIZE = 500;

export interface SealOptions {
  storageBackend?: string;
  anchorBackend?: string;
  /** Skip media, which is 2 GB and slow, when iterating on the text pipeline. */
  skipMedia?: boolean;
}

export async function sealVault(
  config: VaultConfig,
  opts: SealOptions = {},
): Promise<{ manifest: StoreManifest; anchor: Awaited<ReturnType<AnchorAdapter["anchor"]>> }> {
  const { kek, source } = loadKeyring({ create: true });
  const storage = makeStorage(config, opts.storageBackend ?? "local");
  const anchor = makeAnchor(config, opts.anchorBackend ?? "local");
  ensureDir(config.storeDir);

  console.error(`key:      ${source}`);
  console.error(`storage:  ${storage.describe()}`);
  console.error(`anchor:   ${anchor.describe()}`);

  const mediaRows = opts.skipMedia
    ? []
    : readNdjson<{ relPath: string; bytes: number }>(
        corpusPath(config.corpusDir, CORPUS_FILES.media),
      );

  // Preflight before writing anything. Sealing media writes a second, encrypted
  // copy of every file, so it needs as much free space again as the media itself.
  // Failing partway would leave objects on disk with no manifest to reconcile
  // them against, so this check has to happen before the first write, not after
  // the corpus is already sealed.
  if (mediaRows.length) {
    const needed = mediaRows.reduce((s, m) => s + m.bytes, 0);
    const free = await freeSpace(config.storeDir);
    if (free !== null && free < needed * 1.1) {
      throw new Error(
        `Sealing media needs about ${(needed / 1e9).toFixed(2)} GB but only ` +
          `${(free / 1e9).toFixed(2)} GB is free on this volume.\n` +
          `Free up space, or run \`vault seal --skip-media\` to seal the text corpus only ` +
          `(media stays readable from the archive either way).`,
      );
    }
  }

  const leaves: MerkleLeaf[] = [];
  const objects: StoreManifest["objects"] = [];
  let plaintextBytes = 0;
  let ciphertextBytes = 0;

  const putObject = async (key: string, plaintext: Buffer): Promise<void> => {
    const sealed = sealBytes(plaintext, kek);
    const res = await storage.put(key, sealed.ciphertext, sealed.header);
    leaves.push({ key, cipherSha256: res.cipherSha256 });
    objects.push({
      key,
      cipherSha256: res.cipherSha256,
      bytes: res.bytes,
      plaintextSha256: sealed.header.plaintextSha256,
    });
    plaintextBytes += plaintext.length;
    ciphertextBytes += res.bytes;
  };

  // --- Corpus collections, batched as NDJSON shards -------------------------
  for (const [name, file] of Object.entries(CORPUS_FILES)) {
    const path = corpusPath(config.corpusDir, file);
    if (file.endsWith(".json")) {
      const value = readJson<unknown>(path);
      if (value === null) continue;
      await putObject(`corpus/${name}.json`, Buffer.from(JSON.stringify(value), "utf8"));
      continue;
    }
    const rows = readNdjson<unknown>(path);
    if (!rows.length) continue;
    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
      const shard = rows.slice(i, i + BATCH_SIZE);
      const body = `${shard.map((r) => JSON.stringify(r)).join("\n")}\n`;
      const idx = String(Math.floor(i / BATCH_SIZE)).padStart(4, "0");
      await putObject(`corpus/${name}/${idx}.ndjson`, Buffer.from(body, "utf8"));
    }
    console.error(`sealed ${name}: ${rows.length} records`);
  }

  // --- Media, one object per file ------------------------------------------
  if (mediaRows.length) {
    let done = 0;
    for (const m of mediaRows) {
      const abs = resolve(config.archiveDir, m.relPath);
      let bytes: Buffer;
      try {
        bytes = readFileSync(abs);
      } catch {
        console.error(`  skipped unreadable media: ${m.relPath}`);
        continue;
      }
      await putObject(`media/${m.relPath.replace(/^data\//, "")}`, bytes);
      done++;
      if (done % 250 === 0) {
        console.error(`  media ${done}/${mediaRows.length} (${(ciphertextBytes / 1e9).toFixed(2)} GB)`);
      }
    }
    console.error(`sealed media: ${done} files`);
  } else {
    console.error("sealed media: skipped (--skip-media)");
  }

  const root = merkleRoot(leaves);
  const manifest: StoreManifest = {
    version: 1,
    sealedAt: new Date().toISOString(),
    merkleRoot: root,
    objectCount: objects.length,
    plaintextBytes,
    ciphertextBytes,
    objects: objects.sort((a, b) => (a.key < b.key ? -1 : 1)),
  };
  writeJson(storagePath(config, MANIFEST_FILE), manifest);

  const receipt = await anchor.anchor(root);
  return { manifest, anchor: receipt };
}

export interface VerifyReport {
  ok: boolean
  objectCount: number;
  recomputedRoot: string;
  manifestRoot: string;
  anchoredRoot: string | null;
  anchorReference: string | null;
  problems: string[];
  decryptionSpotChecks: number;
}

/**
 * Verify store integrity.
 *
 * Three independent checks, because each catches a different failure:
 *  1. every manifest object still exists with the recorded ciphertext digest
 *     (catches corruption or partial writes)
 *  2. the Merkle root recomputed from disk matches the manifest and the anchor
 *     (catches additions and deletions, which per-object digests would miss)
 *  3. a sample of objects actually decrypts and matches its plaintext digest
 *     (catches a wrong or rotated key, which hashing alone would not)
 */
export async function verifyVault(
  config: VaultConfig,
  opts: { storageBackend?: string; anchorBackend?: string; spotChecks?: number } = {},
): Promise<VerifyReport> {
  const manifest = readJson<StoreManifest>(storagePath(config, MANIFEST_FILE));
  if (!manifest) {
    throw new Error(`No sealed store found at ${config.storeDir} — run \`vault seal\` first.`);
  }
  const storage = makeStorage(config, opts.storageBackend ?? "local");
  const anchor = makeAnchor(config, opts.anchorBackend ?? "local");
  const problems: string[] = [];

  const onDisk = await storage.list();
  const byKey = new Map(onDisk.map((o) => [o.key, o]));

  for (const expected of manifest.objects) {
    const actual = byKey.get(expected.key);
    if (!actual) {
      problems.push(`missing object: ${expected.key}`);
      continue;
    }
    if (actual.cipherSha256 !== expected.cipherSha256) {
      problems.push(`ciphertext digest mismatch: ${expected.key}`);
    }
  }
  for (const found of onDisk) {
    if (!manifest.objects.some((o) => o.key === found.key)) {
      problems.push(`unexpected object not in manifest: ${found.key}`);
    }
  }

  const recomputedRoot = merkleRoot(
    onDisk.map((o) => ({ key: o.key, cipherSha256: o.cipherSha256 })),
  );
  if (recomputedRoot !== manifest.merkleRoot) {
    problems.push(
      `Merkle root mismatch: store yields ${recomputedRoot}, manifest records ${manifest.merkleRoot}`,
    );
  }

  let anchoredRoot: string | null = null;
  let anchorReference: string | null = null;
  const receipt = await anchor.latest();
  if (receipt) {
    anchoredRoot = receipt.root;
    anchorReference = receipt.reference;
    if (receipt.root !== recomputedRoot) {
      problems.push(
        `anchored root ${receipt.root} does not match the current store root ${recomputedRoot}`,
      );
    }
  } else {
    problems.push("no anchor receipt found — the store's root has never been published");
  }

  // Spot-check real decryption on a spread of objects.
  const spotCheckCount = Math.min(opts.spotChecks ?? 5, onDisk.length);
  let checked = 0;
  if (spotCheckCount > 0) {
    const { kek } = loadKeyring();
    const stride = Math.max(1, Math.floor(onDisk.length / spotCheckCount));
    for (let i = 0; i < onDisk.length && checked < spotCheckCount; i += stride) {
      const obj = onDisk[i]!;
      try {
        const { ciphertext, header } = await storage.get(obj.key);
        const plaintext = open({ ciphertext, header }, kek);
        if (sha256(plaintext) !== header.plaintextSha256) {
          problems.push(`plaintext digest mismatch after decryption: ${obj.key}`);
        }
        checked++;
      } catch (err) {
        problems.push(
          `decryption failed for ${obj.key}: ${err instanceof Error ? err.message : String(err)}`,
        );
        checked++;
      }
    }
  }

  return {
    ok: problems.length === 0,
    objectCount: onDisk.length,
    recomputedRoot,
    manifestRoot: manifest.merkleRoot,
    anchoredRoot,
    anchorReference,
    problems,
    decryptionSpotChecks: checked,
  };
}

/**
 * Rotate the KEK by re-wrapping every object's data key.
 *
 * This is the CAK migration path: when Moca Credential Services activate and
 * `issueCredential` returns a `cakPublicKey`, the new KEK derived from it replaces
 * the local one here. Ciphertext is never rewritten, so rotating a 2 GB store
 * costs a few hundred kilobytes of header updates.
 */
export async function rewrapAll(
  config: VaultConfig,
  newKek: Buffer,
  opts: { storageBackend?: string } = {},
): Promise<number> {
  const { kek: oldKek } = loadKeyring();
  const storage = makeStorage(config, opts.storageBackend ?? "local");
  const objects = await storage.list();
  for (const obj of objects) {
    const { ciphertext, header } = await storage.get(obj.key);
    await storage.put(obj.key, ciphertext, rewrap(header, oldKek, newKek));
  }
  return objects.length;
}
