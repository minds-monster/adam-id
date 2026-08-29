import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve } from "node:path";

/**
 * Every data file in an X archive is a JS assignment rather than plain JSON:
 *
 *   window.YTD.tweets.part0 = [ { "tweet": { ... } }, ... ]
 *   window.__THAR_CONFIG = { ... }                          // manifest.js
 *
 * So we slice from the first bracket and hand the rest to JSON.parse. The
 * prefix never contains `[` or `{`, which makes the slice unambiguous.
 */
function parseAssignment(source: string, open: "[" | "{"): unknown {
  const start = source.indexOf(open);
  if (start === -1) {
    throw new Error(`Malformed archive file: no '${open}' found`);
  }
  return JSON.parse(source.slice(start));
}

export interface ManifestFile {
  fileName: string;
  globalName: string;
  count: string;
}

export interface ManifestDataType {
  files?: ManifestFile[];
  mediaDirectory?: string;
}

export interface Manifest {
  userInfo: { accountId: string; userName: string; displayName: string };
  archiveInfo: { sizeBytes: string; generationDate: string; isPartialArchive: string };
  dataTypes: Record<string, ManifestDataType>;
}

export function readManifest(archiveDir: string): Manifest {
  const path = resolve(archiveDir, "data", "manifest.js");
  if (!existsSync(path)) {
    throw new Error(`Not an X archive (missing data/manifest.js): ${archiveDir}`);
  }
  return parseAssignment(readFileSync(path, "utf8"), "{") as Manifest;
}

/** Declared record count for a data type, summed across parts. */
export function declaredCount(manifest: Manifest, type: string): number {
  const files = manifest.dataTypes[type]?.files ?? [];
  return files.reduce((sum, f) => sum + Number(f.count ?? 0), 0);
}

/** Data types that actually carry records, largest first. */
export function populatedDataTypes(manifest: Manifest): { type: string; count: number }[] {
  return Object.keys(manifest.dataTypes)
    .map((type) => ({ type, count: declaredCount(manifest, type) }))
    .filter((t) => t.count > 0)
    .sort((a, b) => b.count - a.count);
}

/**
 * Load every record of a data type, concatenating parts in manifest order.
 *
 * Records arrive single-key wrapped (`{ "tweet": {...} }`). We unwrap here so
 * callers deal in payloads, not envelopes. Returns [] for types with no files,
 * which is normal — many of the ~70 declared types are empty for any account.
 */
export function loadDataType<T = Record<string, unknown>>(
  archiveDir: string,
  manifest: Manifest,
  type: string,
): T[] {
  const files = manifest.dataTypes[type]?.files ?? [];
  const out: T[] = [];
  for (const file of files) {
    const path = resolve(archiveDir, file.fileName);
    if (!existsSync(path)) continue;
    const parsed = parseAssignment(readFileSync(path, "utf8"), "[") as unknown[];
    for (const entry of parsed) {
      out.push(unwrap(entry) as T);
    }
  }
  return out;
}

/**
 * `{ tweet: {...} }` -> `{...}`. Anything that isn't a single-key object is
 * passed through untouched, so unfamiliar data types still ingest.
 */
export function unwrap(entry: unknown): unknown {
  if (entry && typeof entry === "object" && !Array.isArray(entry)) {
    const keys = Object.keys(entry as object);
    if (keys.length === 1) {
      return (entry as Record<string, unknown>)[keys[0]!];
    }
  }
  return entry;
}

export interface MediaFile {
  /** Path relative to the archive root. */
  relPath: string;
  fileName: string;
  /** Media files are named `{tweetId}-{mediaId}.{ext}` — this is the prefix. */
  sourceId: string;
  mediaId: string;
  ext: string;
  bytes: number;
  /** Which archive media directory it came from, e.g. `tweets_media`. */
  collection: string;
}

const MIME_BY_EXT: Record<string, string> = {
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  gif: "image/gif",
  webp: "image/webp",
  mp4: "video/mp4",
  mov: "video/quicktime",
};

export function mimeForExt(ext: string): string {
  return MIME_BY_EXT[ext.toLowerCase()] ?? "application/octet-stream";
}

export function isImage(ext: string): boolean {
  return mimeForExt(ext).startsWith("image/");
}

/**
 * Enumerate media on disk. We scan the directories the manifest declares rather
 * than trusting tweet entities, because entities reference CDN URLs while the
 * archive stores local copies — and the two sets do not always agree.
 */
export function scanMedia(archiveDir: string, manifest: Manifest): MediaFile[] {
  const dirs = new Set<string>();
  for (const dt of Object.values(manifest.dataTypes)) {
    if (dt.mediaDirectory) dirs.add(dt.mediaDirectory);
  }
  const out: MediaFile[] = [];
  for (const relDir of [...dirs].sort()) {
    const absDir = resolve(archiveDir, relDir);
    if (!existsSync(absDir)) continue;
    const collection = relDir.replace(/^data\//, "");
    for (const fileName of readdirSync(absDir)) {
      if (fileName.startsWith(".")) continue;
      const abs = resolve(absDir, fileName);
      const st = statSync(abs);
      if (!st.isFile()) continue;
      const dot = fileName.lastIndexOf(".");
      const ext = dot === -1 ? "" : fileName.slice(dot + 1);
      const stem = dot === -1 ? fileName : fileName.slice(0, dot);
      const dash = stem.indexOf("-");
      out.push({
        relPath: `${relDir}/${fileName}`,
        fileName,
        sourceId: dash === -1 ? stem : stem.slice(0, dash),
        mediaId: dash === -1 ? "" : stem.slice(dash + 1),
        ext,
        bytes: st.size,
        collection,
      });
    }
  }
  return out;
}
