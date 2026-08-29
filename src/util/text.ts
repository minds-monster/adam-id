/** Tweet text in the archive is HTML-escaped; note-tweet text is not. */
const ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
  "&apos;": "'",
  "&nbsp;": " ",
};

export function unescapeHtml(s: string): string {
  return s.replace(/&(?:amp|lt|gt|quot|#39|apos|nbsp);/g, (m) => ENTITIES[m] ?? m);
}

const TCO = /https:\/\/t\.co\/\w+/g;
const LEADING_MENTIONS = /^(?:@\w+[\s,]+)+/;

/**
 * Fingerprint for matching note-tweets to their tweets. Note-tweet records carry
 * no tweet id (`noteTweetId` is a separate id space), so the join is textual.
 * We must therefore neutralise every way the two representations differ:
 *   - tweets are HTML-escaped, notes are not
 *   - tweets carry trailing t.co links, notes carry expanded urls separately
 *   - reply tweets prefix the leading @mentions, notes omit them
 * With all three normalised, all 358 notes in this archive match.
 */
export function matchKey(s: string, len = 40): string {
  let t = unescapeHtml(s);
  t = t.replace(TCO, " ");
  t = t.trim().replace(LEADING_MENTIONS, "");
  t = t.replace(/\s+/g, " ").trim().toLowerCase();
  return t.slice(0, len);
}

/**
 * Comparable body length: strips t.co links and the leading @mentions that reply
 * tweets carry but note-tweets omit. Without stripping mentions the tweet side
 * looks artificially longer and genuine long-form merges get skipped.
 */
export function normalizedLength(s: string): number {
  return unescapeHtml(s).replace(TCO, "").trim().replace(LEADING_MENTIONS, "").trim().length;
}

/** `Sat Aug 01 18:15:28 +0000 2026` -> ISO 8601. */
export function parseTwitterDate(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) throw new Error(`Unparseable date: ${s}`);
  return d.toISOString();
}

export function wordCount(s: string): number {
  const t = s.trim();
  return t ? t.split(/\s+/).length : 0;
}

/** Rough grapheme-aware emoji detector, used for style stats. */
export const EMOJI_RE =
  /[\u{1F300}-\u{1FAFF}\u{1F000}-\u{1F2FF}\u{2600}-\u{27BF}\u{FE0F}\u{1F1E6}-\u{1F1FF}]/gu;

export function countEmoji(s: string): number {
  return (s.match(EMOJI_RE) ?? []).length;
}
