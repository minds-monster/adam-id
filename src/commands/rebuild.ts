import type { VaultConfig } from "../config.js";
import { loadKeyring } from "../crypto/keyring.js";
import { open } from "../crypto/envelope.js";
import { CORPUS_FILES } from "../corpus/model.js";
import { corpusPath, ensureDir } from "../corpus/io.js";
import { writeFileSync } from "node:fs";
import { makeStorage } from "./seal.js";
import { buildIndex } from "../index/build.js";

/**
 * Rebuild the corpus and search index from sealed objects alone.
 *
 * This is what makes the ciphertext store the record of truth rather than a
 * backup: if the corpus directory and index are deleted, everything the MCP
 * server serves can be reconstructed from encrypted objects plus your key. It is
 * also the restore path once objects live on MCSP instead of local disk.
 */
export async function rebuild(
  config: VaultConfig,
  opts: { storageBackend?: string } = {},
): Promise<{ collections: number; records: number }> {
  const { kek } = loadKeyring();
  const storage = makeStorage(config, opts.storageBackend ?? "local");
  ensureDir(config.corpusDir);

  const objects = (await storage.list("corpus/")).sort((a, b) => (a.key < b.key ? -1 : 1));
  if (!objects.length) {
    throw new Error(`No sealed corpus objects found in ${storage.describe()}.`);
  }

  // Group shards back into their collections: corpus/<name>/<idx>.ndjson, and
  // singletons at corpus/<name>.json.
  const shards = new Map<string, Buffer[]>();
  const singles = new Map<string, Buffer>();

  for (const obj of objects) {
    const { ciphertext, header } = await storage.get(obj.key);
    const plaintext = open({ ciphertext, header }, kek);
    const rel = obj.key.slice("corpus/".length);
    if (rel.endsWith(".json") && !rel.includes("/")) {
      singles.set(rel.slice(0, -".json".length), plaintext);
    } else {
      const name = rel.split("/")[0]!;
      const bucket = shards.get(name);
      if (bucket) bucket.push(plaintext);
      else shards.set(name, [plaintext]);
    }
  }

  let records = 0;
  for (const [name, parts] of shards) {
    const file = CORPUS_FILES[name as keyof typeof CORPUS_FILES];
    if (!file) {
      console.error(`  skipping unknown collection: ${name}`);
      continue;
    }
    const body = Buffer.concat(parts);
    writeFileSync(corpusPath(config.corpusDir, file), body);
    records += body.toString("utf8").split("\n").filter((l) => l.trim()).length;
    console.error(`  restored ${name} (${parts.length} shard${parts.length === 1 ? "" : "s"})`);
  }
  for (const [name, body] of singles) {
    const file = CORPUS_FILES[name as keyof typeof CORPUS_FILES];
    if (!file) continue;
    writeFileSync(corpusPath(config.corpusDir, file), body);
    console.error(`  restored ${name}`);
  }

  buildIndex(config);
  return { collections: shards.size + singles.size, records };
}
