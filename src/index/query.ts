import Database from "better-sqlite3";
import type { Database as Db } from "better-sqlite3";
import { existsSync } from "node:fs";
import type { VaultConfig } from "../config.js";
import type { AccountRef, Post, PostMedia, Profile } from "../corpus/model.js";
import { countEmoji } from "../util/text.js";
import { SCHEMA_VERSION } from "./schema.js";

export function openIndex(config: VaultConfig): Db {
  if (!existsSync(config.indexPath)) {
    throw new Error(`No search index at ${config.indexPath} — run \`vault index\` first.`);
  }
  const db = new Database(config.indexPath, { readonly: true });
  const row = db.prepare(`SELECT value FROM meta WHERE key = 'schema_version'`).get() as
    | { value: string }
    | undefined;
  if (row?.value !== SCHEMA_VERSION) {
    db.close();
    throw new Error(
      `Index schema is v${row?.value ?? "?"} but this build expects v${SCHEMA_VERSION} — ` +
        `run \`vault index\` to rebuild.`,
    );
  }
  return db;
}

/**
 * Translate a user query into FTS5 MATCH syntax.
 *
 * FTS5 treats many characters as operators, so an unescaped query like
 * `AI: what's next?` is a syntax error rather than a search. We therefore quote
 * every term (doubling internal quotes, which is FTS5's escape) and combine them
 * with implicit AND.
 *
 * Bare words become *prefix* queries. This matters a lot on this corpus: handles
 * tokenize as one word, so `@SongjamSpace` is the single token `songjamspace` and
 * an exact search for `songjam` misses all 1,300 of those posts. Prefix matching
 * finds them. Wrap a term in quotes to force an exact match instead.
 *
 * Preserved deliberately:
 *   - "quoted phrases" stay exact phrases
 *   - a bare `OR` between terms becomes a real disjunction
 */
export function toFtsQuery(raw: string): string {
  const tokens: { text: string; isOr: boolean; exact: boolean }[] = [];
  const re = /"([^"]*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    const phrase = m[1];
    const word = m[2];
    if (phrase !== undefined) {
      // Quoted -> exact phrase, no prefix expansion.
      if (phrase.trim()) tokens.push({ text: phrase, isOr: false, exact: true });
    } else if (word) {
      if (word.toUpperCase() === "OR") {
        tokens.push({ text: "", isOr: true, exact: false });
      } else if (word.toUpperCase() === "AND") {
        // Implicit AND already; drop the noise word.
      } else {
        tokens.push({ text: word, isOr: false, exact: false });
      }
    }
  }

  const parts: string[] = [];
  for (const t of tokens) {
    if (t.isOr) {
      if (parts.length) parts.push("OR");
      continue;
    }
    const body = t.text.endsWith("*") ? t.text.slice(0, -1) : t.text;
    // Strip characters the tokenizer would drop anyway. A term that reduces to
    // nothing (e.g. a lone "?") would otherwise emit an empty phrase.
    const cleanedBody = body.replace(/"/g, '""');
    if (!/[\p{L}\p{N}]/u.test(cleanedBody)) continue;
    const quoted = `"${cleanedBody}"`;
    parts.push(t.exact ? quoted : `${quoted}*`);
  }

  // Collapse dangling/duplicate operators that a malformed query could leave.
  const cleaned: string[] = [];
  for (const p of parts) {
    if (p === "OR" && (!cleaned.length || cleaned[cleaned.length - 1] === "OR")) continue;
    cleaned.push(p);
  }
  while (cleaned.length && cleaned[cleaned.length - 1] === "OR") cleaned.pop();
  return cleaned.join(" ");
}

interface PostRow {
  id: string;
  created_at: string;
  text: string;
  long_form: number;
  kind: string;
  lang: string | null;
  source: string | null;
  collection: string;
  in_reply_to_id: string | null;
  in_reply_to_user: string | null;
  quoted_status_id: string | null;
  likes: number;
  retweets: number;
  engagement_known: number;
  likes_percentile: number | null;
  thread_id: string | null;
  thread_pos: number | null;
  thread_length: number | null;
  has_media: number;
  media_count: number;
  char_count: number;
  word_count: number;
  hashtags: string;
  mentions: string;
  urls: string;
  media: string;
  hour?: number;
  weekday?: number;
}

function toPost(r: PostRow): Post {
  return {
    id: r.id,
    createdAt: r.created_at,
    text: r.text,
    longForm: Boolean(r.long_form),
    kind: r.kind as Post["kind"],
    lang: r.lang,
    source: r.source,
    collection: r.collection,
    inReplyToStatusId: r.in_reply_to_id,
    inReplyToUserId: r.in_reply_to_user,
    inReplyToScreenName: null,
    quotedStatusId: r.quoted_status_id,
    likes: r.likes,
    retweets: r.retweets,
    engagementKnown: Boolean(r.engagement_known),
    hashtags: JSON.parse(r.hashtags) as string[],
    mentions: JSON.parse(r.mentions) as { id: string; screenName: string }[],
    urls: JSON.parse(r.urls) as string[],
    media: JSON.parse(r.media) as PostMedia[],
    threadId: r.thread_id,
    threadPos: r.thread_pos,
    threadLength: r.thread_length,
    likesPercentile: r.likes_percentile,
    charCount: r.char_count,
    wordCount: r.word_count,
  };
}

const POST_COLS = `p.id, p.created_at, p.text, p.long_form, p.kind, p.lang, p.source, p.collection,
  p.in_reply_to_id, p.in_reply_to_user, p.quoted_status_id, p.likes, p.retweets, p.engagement_known,
  p.likes_percentile, p.thread_id, p.thread_pos, p.thread_length, p.has_media, p.media_count,
  p.char_count, p.word_count, p.hashtags, p.mentions, p.urls, p.media`;

export interface SearchFilters {
  query?: string;
  kinds?: string[];
  from?: string;
  to?: string;
  minLikes?: number;
  hasMedia?: boolean;
  lang?: string;
  longFormOnly?: boolean;
  excludeRetweets?: boolean;
  sort?: "relevance" | "newest" | "oldest" | "likes";
  limit?: number;
  offset?: number;
}

interface WhereBuild {
  clauses: string[];
  params: unknown[];
}

function buildFilters(f: SearchFilters): WhereBuild {
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (f.kinds?.length) {
    clauses.push(`p.kind IN (${f.kinds.map(() => "?").join(",")})`);
    params.push(...f.kinds);
  }
  if (f.excludeRetweets) clauses.push(`p.kind != 'retweet'`);
  if (f.from) {
    clauses.push(`p.created_at >= ?`);
    params.push(f.from);
  }
  if (f.to) {
    clauses.push(`p.created_at <= ?`);
    params.push(f.to);
  }
  if (typeof f.minLikes === "number") {
    clauses.push(`p.likes >= ?`);
    params.push(f.minLikes);
  }
  if (typeof f.hasMedia === "boolean") {
    clauses.push(`p.has_media = ?`);
    params.push(f.hasMedia ? 1 : 0);
  }
  if (f.lang) {
    clauses.push(`p.lang = ?`);
    params.push(f.lang);
  }
  if (f.longFormOnly) clauses.push(`p.long_form = 1`);
  return { clauses, params };
}

export interface SearchResult {
  total: number;
  posts: Post[];
  /**
   * The FTS5 expression actually executed, or null when no text filter applied.
   * Surfaced so a query that reduces to nothing (e.g. "?") is visibly reported
   * as "no text filter" instead of silently returning the whole corpus.
   */
  interpretedQuery: string | null;
  /** Set when a non-empty query contained no searchable terms. */
  queryIgnored?: string;
}

export function searchPosts(db: Db, f: SearchFilters): SearchResult {
  const limit = Math.min(Math.max(f.limit ?? 20, 1), 200);
  const offset = Math.max(f.offset ?? 0, 0);
  const { clauses, params } = buildFilters(f);

  const ftsQuery = f.query?.trim() ? toFtsQuery(f.query) : "";
  const useFts = ftsQuery.length > 0;

  const from = useFts
    ? `FROM posts_fts f JOIN posts p ON p.rowid = f.rowid`
    : `FROM posts p`;
  const where: string[] = [...clauses];
  const whereParams: unknown[] = [];
  if (useFts) {
    where.unshift(`posts_fts MATCH ?`);
    whereParams.push(ftsQuery);
  }
  whereParams.push(...params);
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const sort = f.sort ?? (useFts ? "relevance" : "newest");
  const orderSql =
    sort === "relevance" && useFts
      ? `ORDER BY f.rank`
      : sort === "likes"
        ? `ORDER BY p.likes DESC, p.created_at DESC`
        : sort === "oldest"
          ? `ORDER BY p.created_at ASC, p.id ASC`
          : `ORDER BY p.created_at DESC, p.id DESC`;

  const total = (
    db.prepare(`SELECT COUNT(*) AS n ${from} ${whereSql}`).get(...whereParams) as { n: number }
  ).n;

  const rows = db
    .prepare(`SELECT ${POST_COLS} ${from} ${whereSql} ${orderSql} LIMIT ? OFFSET ?`)
    .all(...whereParams, limit, offset) as PostRow[];

  const result: SearchResult = {
    total,
    posts: rows.map(toPost),
    interpretedQuery: useFts ? ftsQuery : null,
  };
  if (f.query?.trim() && !useFts) {
    result.queryIgnored =
      `The query ${JSON.stringify(f.query)} contained no searchable words, so no text ` +
      `filter was applied and these results cover the whole corpus (subject to other filters).`;
  }
  return result;
}

export function getPost(db: Db, id: string): Post | null {
  const row = db.prepare(`SELECT ${POST_COLS} FROM posts p WHERE p.id = ?`).get(id) as
    | PostRow
    | undefined;
  return row ? toPost(row) : null;
}

/** Every post in the same self-thread, in posting order. */
export function getThread(db: Db, id: string): Post[] {
  const anchor = db.prepare(`SELECT thread_id FROM posts WHERE id = ?`).get(id) as
    | { thread_id: string | null }
    | undefined;
  if (!anchor) return [];
  if (!anchor.thread_id) {
    const single = getPost(db, id);
    return single ? [single] : [];
  }
  const rows = db
    .prepare(
      `SELECT ${POST_COLS} FROM posts p WHERE p.thread_id = ? ORDER BY p.thread_pos ASC, p.id ASC`,
    )
    .all(anchor.thread_id) as PostRow[];
  return rows.map(toPost);
}

/** The conversation a reply sits in, walking up through other people's posts too. */
export function getReplyContext(db: Db, id: string, maxDepth = 20): Post[] {
  const chain: Post[] = [];
  let cursor: string | null = id;
  const seen = new Set<string>();
  while (cursor && chain.length < maxDepth && !seen.has(cursor)) {
    seen.add(cursor);
    const post = getPost(db, cursor);
    if (!post) break;
    chain.unshift(post);
    cursor = post.inReplyToStatusId;
  }
  return chain;
}

export interface StyleReport {
  population: number;
  basis: string;
  charCount: { mean: number; median: number; p10: number; p90: number; max: number };
  wordCount: { mean: number; median: number };
  perPostRates: {
    withEmoji: number;
    withHashtag: number;
    withLink: number;
    withMention: number;
    withMedia: number;
    withQuestion: number;
    multiParagraph: number;
    allLowercase: number;
  };
  meanEmojiPerPost: number;
  topHashtags: { tag: string; n: number }[];
  topMentions: { screenName: string; n: number }[];
  commonOpeners: { opener: string; n: number }[];
  postingByHour: Record<string, number>;
  postingByWeekday: Record<string, number>;
  longFormPosts: number;
  threadedPosts: number;
}

function quantiles(sorted: number[], q: number): number {
  if (!sorted.length) return 0;
  const i = Math.min(sorted.length - 1, Math.max(0, Math.round(q * (sorted.length - 1))));
  return sorted[i]!;
}

/**
 * Derive writing-style statistics from the corpus.
 *
 * Retweets are excluded by default: they are other people's words and would
 * otherwise pollute every measurement of "your" voice. Replies are included,
 * since they are genuinely yours and dominate your output.
 */
export function analyzeStyle(db: Db, f: SearchFilters = {}): StyleReport {
  const filters: SearchFilters = { excludeRetweets: true, ...f };
  const { clauses, params } = buildFilters(filters);
  const whereSql = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = db
    .prepare(
      `SELECT p.text, p.char_count, p.word_count, p.hashtags, p.mentions, p.urls,
              p.has_media, p.long_form, p.thread_length, p.hour, p.weekday
       FROM posts p ${whereSql}`,
    )
    .all(...params) as (PostRow & { hour: number; weekday: number })[];

  const n = rows.length;
  const safeDiv = (x: number) => (n ? Number((x / n).toFixed(4)) : 0);
  const chars = rows.map((r) => r.char_count).sort((a, b) => a - b);
  const words = rows.map((r) => r.word_count).sort((a, b) => a - b);

  const hashtagCounts = new Map<string, number>();
  const mentionCounts = new Map<string, number>();
  const openerCounts = new Map<string, number>();
  const byHour: Record<string, number> = {};
  const byWeekday: Record<string, number> = {};

  let withEmoji = 0;
  let emojiTotal = 0;
  let withHashtag = 0;
  let withLink = 0;
  let withMention = 0;
  let withMedia = 0;
  let withQuestion = 0;
  let multiParagraph = 0;
  let allLowercase = 0;
  let longForm = 0;
  let threaded = 0;

  for (const r of rows) {
    const tags = JSON.parse(r.hashtags) as string[];
    const mentions = JSON.parse(r.mentions) as { screenName: string }[];
    const urls = JSON.parse(r.urls) as string[];

    const emoji = countEmoji(r.text);
    if (emoji) withEmoji++;
    emojiTotal += emoji;
    if (tags.length) withHashtag++;
    if (urls.length) withLink++;
    if (mentions.length) withMention++;
    if (r.has_media) withMedia++;
    if (r.text.includes("?")) withQuestion++;
    if (r.text.includes("\n\n")) multiParagraph++;
    // Only counts as a stylistic choice if there were letters to capitalise.
    if (/[a-z]/.test(r.text) && r.text === r.text.toLowerCase()) allLowercase++;
    if (r.long_form) longForm++;
    if ((r.thread_length ?? 1) > 1) threaded++;

    for (const t of tags) hashtagCounts.set(t, (hashtagCounts.get(t) ?? 0) + 1);
    for (const m of mentions) {
      if (m.screenName) mentionCounts.set(m.screenName, (mentionCounts.get(m.screenName) ?? 0) + 1);
    }

    // Opening 3 words, with leading reply mentions stripped so openers reflect
    // how you actually start a thought rather than who you replied to.
    const body = r.text.replace(/^(?:@\w+[\s,]+)+/, "").trim();
    const opener = body.split(/\s+/).slice(0, 3).join(" ").toLowerCase().replace(/[.,!?:;]+$/, "");
    if (opener) openerCounts.set(opener, (openerCounts.get(opener) ?? 0) + 1);

    byHour[String(r.hour)] = (byHour[String(r.hour)] ?? 0) + 1;
    byWeekday[String(r.weekday)] = (byWeekday[String(r.weekday)] ?? 0) + 1;
  }

  const top = <T>(m: Map<string, number>, k: number, key: string): T[] =>
    [...m.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, k)
      .map(([v, count]) => ({ [key]: v, n: count })) as T[];

  return {
    population: n,
    basis: filters.excludeRetweets
      ? "authored posts only (retweets excluded — they are not your words)"
      : "all matching posts, including retweets",
    charCount: {
      mean: n ? Number((chars.reduce((s, v) => s + v, 0) / n).toFixed(1)) : 0,
      median: quantiles(chars, 0.5),
      p10: quantiles(chars, 0.1),
      p90: quantiles(chars, 0.9),
      max: n ? chars[n - 1]! : 0,
    },
    wordCount: {
      mean: n ? Number((words.reduce((s, v) => s + v, 0) / n).toFixed(1)) : 0,
      median: quantiles(words, 0.5),
    },
    perPostRates: {
      withEmoji: safeDiv(withEmoji),
      withHashtag: safeDiv(withHashtag),
      withLink: safeDiv(withLink),
      withMention: safeDiv(withMention),
      withMedia: safeDiv(withMedia),
      withQuestion: safeDiv(withQuestion),
      multiParagraph: safeDiv(multiParagraph),
      allLowercase: safeDiv(allLowercase),
    },
    meanEmojiPerPost: safeDiv(emojiTotal),
    topHashtags: top<{ tag: string; n: number }>(hashtagCounts, 15, "tag"),
    topMentions: top<{ screenName: string; n: number }>(mentionCounts, 15, "screenName"),
    commonOpeners: top<{ opener: string; n: number }>(openerCounts, 15, "opener"),
    postingByHour: byHour,
    postingByWeekday: byWeekday,
    longFormPosts: longForm,
    threadedPosts: threaded,
  };
}

export type GroupDimension = "kind" | "year" | "hour" | "weekday" | "has_media" | "long_form" | "lang";

const GROUP_SQL: Record<GroupDimension, string> = {
  kind: "p.kind",
  year: "p.year",
  hour: "p.hour",
  weekday: "p.weekday",
  has_media: "p.has_media",
  long_form: "p.long_form",
  lang: "p.lang",
};

export interface EngagementGroup {
  group: string;
  posts: number;
  withRecordedEngagement: number;
  coverage: number;
  meanLikes: number | null;
  medianLikes: number | null;
  maxLikes: number | null;
  totalLikes: number;
  meanRetweets: number | null;
}

/**
 * Engagement aggregates, grouped along one dimension.
 *
 * Statistics are computed over posts with *recorded* engagement only, and every
 * row reports its own coverage. Missing counts are not zeros: including them
 * would drag every mean toward zero and make thin buckets look bad rather than
 * unknown.
 */
export function engagementStats(
  db: Db,
  dimension: GroupDimension,
  f: SearchFilters = {},
): { dimension: GroupDimension; caveat: string; groups: EngagementGroup[] } {
  const filters: SearchFilters = { excludeRetweets: true, ...f };
  const { clauses, params } = buildFilters(filters);
  const whereSql = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const col = GROUP_SQL[dimension];

  const rows = db
    .prepare(
      `SELECT ${col} AS grp,
              COUNT(*) AS posts,
              SUM(p.engagement_known) AS known,
              SUM(CASE WHEN p.engagement_known THEN p.likes ELSE 0 END) AS total_likes,
              AVG(CASE WHEN p.engagement_known THEN p.likes END) AS mean_likes,
              AVG(CASE WHEN p.engagement_known THEN p.retweets END) AS mean_rts,
              MAX(p.likes) AS max_likes
       FROM posts p ${whereSql}
       GROUP BY grp ORDER BY grp`,
    )
    .all(...params) as {
    grp: string | number | null;
    posts: number;
    known: number;
    total_likes: number;
    mean_likes: number | null;
    mean_rts: number | null;
    max_likes: number | null;
  }[];

  // Medians need the raw distribution, which GROUP BY can't give us in SQLite.
  const medianStmt = db.prepare(
    `SELECT p.likes FROM posts p ${whereSql ? `${whereSql} AND` : "WHERE"} ${col} IS ? ` +
      `AND p.engagement_known = 1 ORDER BY p.likes`,
  );

  const groups: EngagementGroup[] = rows.map((r) => {
    const likes = (medianStmt.all(...params, r.grp) as { likes: number }[]).map((x) => x.likes);
    return {
      group: String(r.grp),
      posts: r.posts,
      withRecordedEngagement: r.known,
      coverage: r.posts ? Number((r.known / r.posts).toFixed(4)) : 0,
      meanLikes: r.mean_likes === null ? null : Number(r.mean_likes.toFixed(2)),
      medianLikes: likes.length ? quantiles(likes, 0.5) : null,
      maxLikes: r.max_likes,
      totalLikes: r.total_likes,
      meanRetweets: r.mean_rts === null ? null : Number(r.mean_rts.toFixed(2)),
    };
  });

  return {
    dimension,
    caveat:
      "Statistics cover posts with nonzero recorded engagement only; `coverage` is the " +
      "fraction of each group that qualifies. The archive contains no impressions, " +
      "reply counts, or bookmarks, so reach cannot be assessed.",
    groups,
  };
}

export interface LikeRow {
  tweetId: string;
  text: string;
  url: string | null;
}

export function searchLikes(
  db: Db,
  query: string,
  limit = 20,
  offset = 0,
): { total: number; likes: LikeRow[] } {
  const lim = Math.min(Math.max(limit, 1), 200);
  const q = query.trim() ? toFtsQuery(query) : "";
  if (!q) {
    const total = (db.prepare(`SELECT COUNT(*) AS n FROM likes`).get() as { n: number }).n;
    const rows = db
      .prepare(`SELECT tweet_id, text, url FROM likes LIMIT ? OFFSET ?`)
      .all(lim, offset) as { tweet_id: string; text: string; url: string | null }[];
    return { total, likes: rows.map((r) => ({ tweetId: r.tweet_id, text: r.text, url: r.url })) };
  }
  const total = (
    db
      .prepare(`SELECT COUNT(*) AS n FROM likes_fts f JOIN likes l ON l.rowid = f.rowid WHERE likes_fts MATCH ?`)
      .get(q) as { n: number }
  ).n;
  const rows = db
    .prepare(
      `SELECT l.tweet_id, l.text, l.url FROM likes_fts f JOIN likes l ON l.rowid = f.rowid
       WHERE likes_fts MATCH ? ORDER BY f.rank LIMIT ? OFFSET ?`,
    )
    .all(q, lim, offset) as { tweet_id: string; text: string; url: string | null }[];
  return { total, likes: rows.map((r) => ({ tweetId: r.tweet_id, text: r.text, url: r.url })) };
}

export interface DmRow {
  messageId: string;
  conversationId: string;
  createdAt: string;
  senderId: string;
  senderHandle: string | null;
  isGroup: boolean;
  outbound: boolean;
  text: string;
}

export function searchDms(
  db: Db,
  query: string,
  ownAccountId: string,
  limit = 20,
  offset = 0,
): { total: number; messages: DmRow[] } {
  const lim = Math.min(Math.max(limit, 1), 200);
  const q = query.trim() ? toFtsQuery(query) : "";
  const base = `FROM dms_fts f JOIN dms d ON d.rowid = f.rowid WHERE dms_fts MATCH ?`;
  const total = q
    ? (db.prepare(`SELECT COUNT(*) AS n ${base}`).get(q) as { n: number }).n
    : (db.prepare(`SELECT COUNT(*) AS n FROM dms`).get() as { n: number }).n;
  const rows = (
    q
      ? db
          .prepare(
            `SELECT d.message_id, d.conversation_id, d.created_at, d.sender_id, d.is_group, d.text
             ${base} ORDER BY f.rank LIMIT ? OFFSET ?`,
          )
          .all(q, lim, offset)
      : db
          .prepare(
            `SELECT message_id, conversation_id, created_at, sender_id, is_group, text
             FROM dms ORDER BY created_at DESC LIMIT ? OFFSET ?`,
          )
          .all(lim, offset)
  ) as {
    message_id: string;
    conversation_id: string;
    created_at: string;
    sender_id: string;
    is_group: number;
    text: string;
  }[];

  const handle = db.prepare(`SELECT screen_name FROM accounts WHERE account_id = ?`);
  return {
    total,
    messages: rows.map((r) => ({
      messageId: r.message_id,
      conversationId: r.conversation_id,
      createdAt: r.created_at,
      senderId: r.sender_id,
      senderHandle:
        (handle.get(r.sender_id) as { screen_name: string | null } | undefined)?.screen_name ?? null,
      isGroup: Boolean(r.is_group),
      outbound: r.sender_id === ownAccountId,
      text: r.text,
    })),
  };
}

export function getAudience(
  db: Db,
  opts: { relation?: "followers" | "following" | "mutuals" | "all"; withHandleOnly?: boolean; limit?: number; offset?: number } = {},
): { total: number; resolvedHandles: number; caveat: string; accounts: AccountRef[] } {
  const rel = opts.relation ?? "all";
  const lim = Math.min(Math.max(opts.limit ?? 50, 1), 500);
  const clauses: string[] = [];
  if (rel === "followers") clauses.push("follower = 1");
  if (rel === "following") clauses.push("following = 1");
  if (rel === "mutuals") clauses.push("follower = 1 AND following = 1");
  if (opts.withHandleOnly) clauses.push("screen_name IS NOT NULL");
  const whereSql = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";

  const total = (db.prepare(`SELECT COUNT(*) AS n FROM accounts ${whereSql}`).get() as { n: number })
    .n;
  const resolved = (
    db
      .prepare(
        `SELECT COUNT(*) AS n FROM accounts ${whereSql ? `${whereSql} AND` : "WHERE"} screen_name IS NOT NULL`,
      )
      .get() as { n: number }
  ).n;
  const rows = db
    .prepare(
      `SELECT account_id, screen_name, follower, following FROM accounts ${whereSql}
       ORDER BY (screen_name IS NULL), screen_name, account_id LIMIT ? OFFSET ?`,
    )
    .all(lim, opts.offset ?? 0) as {
    account_id: string;
    screen_name: string | null;
    follower: number;
    following: number;
  }[];

  return {
    total,
    resolvedHandles: resolved,
    caveat:
      "X exports the social graph as numeric account ids with no usernames. Handles shown " +
      "here were recovered by harvesting mentions elsewhere in the archive, so most accounts " +
      "have no name available.",
    accounts: rows.map((r) => ({
      accountId: r.account_id,
      screenName: r.screen_name,
      follower: Boolean(r.follower),
      following: Boolean(r.following),
    })),
  };
}

export function getProfile(db: Db): Profile | null {
  const row = db.prepare(`SELECT value FROM meta WHERE key = 'profile'`).get() as
    | { value: string }
    | undefined;
  return row ? (JSON.parse(row.value) as Profile) : null;
}

export function getMeta(db: Db, key: string): string | null {
  const row = db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as
    | { value: string }
    | undefined;
  return row?.value ?? null;
}
