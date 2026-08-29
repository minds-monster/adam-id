import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { EnvelopeHeader } from "../crypto/envelope.js";
import { sha256 } from "../crypto/envelope.js";
import type { PutResult, StorageAdapter, StoredObject } from "./adapter.js";

/**
 * Filesystem-backed store: the record of truth until MCSP is provisioned.
 *
 * Layout is content-addressed by object key, with the header beside the blob:
 *   store/objects/<key>.bin    ciphertext
 *   store/objects/<key>.json   envelope header
 *
 * Keys may contain slashes (e.g. `media/tweets_media/123-abc.mp4`), so they map
 * onto nested directories. Keys are validated to keep that mapping from escaping
 * the store root.
 */
export class LocalStorageAdapter implements StorageAdapter {
  readonly name = "local";
  #root: string;

  constructor(storeDir: string) {
    this.#root = resolve(storeDir, "objects");
  }

  describe(): string {
    return `local filesystem at ${this.#root}`;
  }

  #paths(key: string): { bin: string; meta: string } {
    if (key.includes("..") || key.startsWith("/")) {
      throw new Error(`Unsafe object key: ${key}`);
    }
    const base = join(this.#root, key);
    const resolved = resolve(base);
    if (!resolved.startsWith(this.#root)) {
      throw new Error(`Object key escapes the store root: ${key}`);
    }
    return { bin: `${resolved}.bin`, meta: `${resolved}.json` };
  }

  async put(key: string, ciphertext: Buffer, header: EnvelopeHeader): Promise<PutResult> {
    const { bin, meta } = this.#paths(key);
    mkdirSync(dirname(bin), { recursive: true });
    try {
      // Header first: a blob without a header is unopenable, whereas a header
      // without a blob is merely incomplete. Either way a failure must not leave
      // half an object behind, so both are removed before rethrowing.
      writeFileSync(meta, JSON.stringify(header), "utf8");
      writeFileSync(bin, ciphertext);
    } catch (err) {
      for (const p of [bin, meta]) {
        try {
          if (existsSync(p)) rmSync(p);
        } catch {
          // Best effort — the original failure is what matters.
        }
      }
      throw err;
    }
    return {
      key,
      locator: bin,
      cipherSha256: sha256(ciphertext),
      bytes: ciphertext.length,
    };
  }

  async get(key: string): Promise<{ ciphertext: Buffer; header: EnvelopeHeader }> {
    const { bin, meta } = this.#paths(key);
    if (!existsSync(bin)) throw new Error(`No such object: ${key}`);
    return {
      ciphertext: readFileSync(bin),
      header: JSON.parse(readFileSync(meta, "utf8")) as EnvelopeHeader,
    };
  }

  async has(key: string): Promise<boolean> {
    return existsSync(this.#paths(key).bin);
  }

  async list(prefix = ""): Promise<StoredObject[]> {
    if (!existsSync(this.#root)) return [];
    const out: StoredObject[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const abs = join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(abs);
        } else if (entry.name.endsWith(".bin")) {
          const key = abs.slice(this.#root.length + 1, -4);
          if (prefix && !key.startsWith(prefix)) continue;
          // An orphaned blob (header missing, e.g. an interrupted write) is
          // skipped rather than thrown on. It will then show up as a missing
          // object during verification, which is the accurate diagnosis.
          if (!existsSync(`${abs.slice(0, -4)}.json`)) continue;
          const ciphertext = readFileSync(abs);
          out.push({
            key,
            locator: abs,
            cipherSha256: sha256(ciphertext),
            bytes: ciphertext.length,
            header: JSON.parse(readFileSync(`${abs.slice(0, -4)}.json`, "utf8")) as EnvelopeHeader,
          });
        }
      }
    };
    walk(this.#root);
    return out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  }
}
