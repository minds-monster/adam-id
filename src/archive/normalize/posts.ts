import type { Manifest } from "../loader.js";
import { loadDataType, mimeForExt } from "../loader.js";
import type { Post, PostKind, PostMedia } from "../../corpus/model.js";
import { matchKey, normalizedLength, parseTwitterDate, unescapeHtml, wordCount } from "../../util/text.js";

/** Raw tweet shape as it appears in tweets.js / community-tweet.js / deleted-tweets.js. */
interface RawTweet {
  id_str?: string;
  id?: string;
  created_at?: string;
  full_text?: string;
  lang?: string;
  source?: string;
  favorite_count?: string;
  retweet_count?: string;
  in_reply_to_status_id_str?: string;
  in_reply_to_user_id_str?: string;
  in_reply_to_screen_name?: string;
  entities?: {
    hashtags?: { text: string }[];
    user_mentions?: { id_str: string; screen_name: string }[];
    urls?: { expanded_url?: string }[];
    media?: RawMedia[];
  };
  extended_entities?: { media?: RawMedia[] };
}

interface RawMedia {
  id_str?: string;
  type?: string;
  media_url_https?: string;
  expanded_url?: string;
}

interface RawNoteTweet {
  noteTweetId?: string;
  createdAt?: string;
  core?: { text?: string };
}

/** Collections that contain first-person authored posts. */
const POST_COLLECTIONS = ["tweets", "communityTweet", "deletedTweets"] as const;

const STATUS_URL = /(?:twitter|x)\.com\/[^/]+\/status(?:es)?\/(\d+)/;

function sourceLabel(raw: string | undefined): string | null {
  if (!raw) return null;
  // `source` is an anchor tag: <a href="...">Twitter Web App</a>
  const m = raw.match(/>([^<]+)</);
  return m ? m[1]! : raw;
}

function mediaType(t: string | undefined): PostMedia["type"] {
  if (t === "photo" || t === "video" || t === "animated_gif") return t;
  return "unknown";
}

function classify(raw: RawTweet, text: string, ownAccountId: string, quotedStatusId: string | null): PostKind {
  if (text.startsWith("RT @")) return "retweet";
  if (raw.in_reply_to_status_id_str) {
    return raw.in_reply_to_user_id_str === ownAccountId ? "self_reply" : "reply";
  }
  if (quotedStatusId) return "quote";
  return "original";
}

function extractQuotedStatusId(raw: RawTweet): string | null {
  for (const u of raw.entities?.urls ?? []) {
    const m = u.expanded_url?.match(STATUS_URL);
    if (m) return m[1]!;
  }
  return null;
}

export interface NormalizedPosts {
  posts: Post[];
  longFormMerged: number;
  /** accountId -> screenName harvested from mentions. */
  handles: Map<string, string>;
}

export function normalizePosts(
  archiveDir: string,
  manifest: Manifest,
  ownAccountId: string,
): NormalizedPosts {
  const handles = new Map<string, string>();
  const raws: { raw: RawTweet; collection: string }[] = [];

  for (const collection of POST_COLLECTIONS) {
    for (const raw of loadDataType<RawTweet>(archiveDir, manifest, collection)) {
      raws.push({ raw, collection });
    }
  }

  // --- Long-form merge index ------------------------------------------------
  // note-tweet.js holds the untruncated body for long posts but carries no tweet
  // id, so we index candidates by a normalized text prefix and disambiguate
  // collisions (63 in this archive) by nearest creation time.
  const byKey = new Map<string, { raw: RawTweet; collection: string }[]>();
  for (const entry of raws) {
    const key = matchKey(entry.raw.full_text ?? "");
    if (!key) continue;
    const bucket = byKey.get(key);
    if (bucket) bucket.push(entry);
    else byKey.set(key, [entry]);
  }

  const longFormFor = new Map<RawTweet, string>();
  for (const note of loadDataType<RawNoteTweet>(archiveDir, manifest, "noteTweet")) {
    const noteText = note.core?.text;
    if (!noteText) continue;
    const candidates = byKey.get(matchKey(noteText));
    if (!candidates?.length) continue;
    const noteTime = note.createdAt ? Date.parse(note.createdAt) : NaN;
    let best = candidates[0]!;
    if (candidates.length > 1 && !Number.isNaN(noteTime)) {
      let bestDelta = Infinity;
      for (const c of candidates) {
        const t = c.raw.created_at ? Date.parse(parseTwitterDate(c.raw.created_at)) : NaN;
        const delta = Number.isNaN(t) ? Infinity : Math.abs(t - noteTime);
        if (delta < bestDelta) {
          bestDelta = delta;
          best = c;
        }
      }
    }
    // Only override when the note actually adds text; a few notes are shorter
    // than the tweet field once t.co links are discounted.
    if (normalizedLength(noteText) > normalizedLength(best.raw.full_text ?? "")) {
      longFormFor.set(best.raw, noteText);
    }
  }

  // --- Normalize -----------------------------------------------------------
  const posts: Post[] = [];
  const seen = new Set<string>();
  let longFormMerged = 0;

  for (const { raw, collection } of raws) {
    const id = raw.id_str ?? raw.id;
    if (!id || seen.has(id)) continue;
    seen.add(id);

    const longForm = longFormFor.get(raw);
    if (longForm) longFormMerged++;
    const text = unescapeHtml(longForm ?? raw.full_text ?? "");

    for (const m of raw.entities?.user_mentions ?? []) {
      if (m.id_str && m.screen_name) handles.set(m.id_str, m.screen_name);
    }

    // extended_entities carries the full media set; entities.media truncates to one.
    const rawMedia = raw.extended_entities?.media ?? raw.entities?.media ?? [];
    const media: PostMedia[] = rawMedia.map((m) => {
      const url = m.media_url_https ?? "";
      const dot = url.lastIndexOf(".");
      const ext = dot === -1 ? "" : url.slice(dot + 1).split("?")[0]!;
      return {
        mediaId: m.id_str ?? "",
        relPath: null, // filled in by the media linker, which scans disk
        ext,
        mime: mimeForExt(ext),
        bytes: 0,
        thumbnailUrl: m.media_url_https ?? null,
        type: mediaType(m.type),
      };
    });

    const quotedStatusId = extractQuotedStatusId(raw);
    const likes = Number(raw.favorite_count ?? 0);
    const retweets = Number(raw.retweet_count ?? 0);

    posts.push({
      id,
      createdAt: raw.created_at ? parseTwitterDate(raw.created_at) : new Date(0).toISOString(),
      text,
      longForm: Boolean(longForm),
      kind: classify(raw, text, ownAccountId, quotedStatusId),
      lang: raw.lang ?? null,
      source: sourceLabel(raw.source),
      collection,
      inReplyToStatusId: raw.in_reply_to_status_id_str ?? null,
      inReplyToUserId: raw.in_reply_to_user_id_str ?? null,
      inReplyToScreenName: raw.in_reply_to_screen_name ?? null,
      quotedStatusId,
      likes,
      retweets,
      // Only 67% of this archive carries nonzero engagement. The archive gives
      // us no way to distinguish "genuinely got zero likes" from "X did not
      // populate this count", so this flag means precisely "has nonzero
      // recorded engagement" — aggregates report it as coverage, not truth.
      engagementKnown: likes > 0 || retweets > 0,
      hashtags: (raw.entities?.hashtags ?? []).map((h) => h.text).filter(Boolean),
      mentions: (raw.entities?.user_mentions ?? []).map((m) => ({
        id: m.id_str,
        screenName: m.screen_name,
      })),
      urls: (raw.entities?.urls ?? []).map((u) => u.expanded_url ?? "").filter(Boolean),
      media,
      threadId: null,
      threadPos: null,
      threadLength: null,
      likesPercentile: null,
      charCount: text.length,
      wordCount: wordCount(text),
    });
  }

  // Newest first, with the snowflake id as tiebreaker — created_at is only
  // second-resolution, so timestamp alone gives a nondeterministic order.
  posts.sort((a, b) => {
    if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? 1 : -1;
    const ai = BigInt(a.id);
    const bi = BigInt(b.id);
    return ai < bi ? 1 : ai > bi ? -1 : 0;
  });
  return { posts, longFormMerged, handles };
}
