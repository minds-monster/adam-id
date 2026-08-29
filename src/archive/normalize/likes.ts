import type { Manifest } from "../loader.js";
import { loadDataType } from "../loader.js";
import type { Like } from "../../corpus/model.js";
import { unescapeHtml } from "../../util/text.js";

interface RawLike {
  tweetId?: string;
  fullText?: string;
  expandedUrl?: string;
}

/**
 * Liked tweets are the strongest topical-interest signal in the archive: 11k of
 * them versus 8k authored posts. Note the archive stores no like timestamp and
 * no author, only id/text/url — so likes can be searched but not dated.
 */
export function normalizeLikes(archiveDir: string, manifest: Manifest): Like[] {
  const out: Like[] = [];
  const seen = new Set<string>();
  for (const raw of loadDataType<RawLike>(archiveDir, manifest, "like")) {
    if (!raw.tweetId || seen.has(raw.tweetId)) continue;
    seen.add(raw.tweetId);
    out.push({
      tweetId: raw.tweetId,
      text: unescapeHtml(raw.fullText ?? ""),
      url: raw.expandedUrl ?? null,
    });
  }
  return out;
}
