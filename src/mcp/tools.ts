import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";
import type { Database as Db } from "better-sqlite3";
import type { Scope, VaultConfig } from "../config.js";
import { isImage, mimeForExt } from "../archive/loader.js";
import type { Post } from "../corpus/model.js";
import {
  analyzeStyle,
  engagementStats,
  getAudience,
  getMeta,
  getPost,
  getProfile,
  getReplyContext,
  getThread,
  searchDms,
  searchLikes,
  searchPosts,
  type GroupDimension,
  type SearchFilters,
} from "../index/query.js";

/** A tool the MCP server exposes, bound to the single scope that gates it. */
export interface VaultTool {
  name: string;
  scope: Scope;
  title: string;
  description: string;
  schema: z.ZodRawShape;
  run(ctx: ToolContext, args: Record<string, unknown>): ToolResult;
}

/**
 * Who is calling, when the caller is remote.
 *
 * Absent over stdio, where the transport is a subprocess of the client and
 * possession of the machine is the credential. Present over HTTP, where the
 * caller proved a Moca credential. The raw credential is never carried here —
 * only a fingerprint, so the audit log can correlate calls without recording a
 * bearer token that would grant access to anyone who read the log.
 */
export interface CallerIdentity {
  mindId: string;
  label: string;
  subjectDid: string;
  credentialFingerprint: string;
  expiresAt: string;
}

export interface ToolContext {
  db: Db;
  config: VaultConfig;
  ownAccountId: string;
  /**
   * Scopes for *this session*, not the process. Over stdio these are
   * config.scopes; over HTTP they are the credential's claims intersected with
   * the local grant. Tools are registered from this, so it is the boundary.
   */
  scopes: Scope[];
  caller?: CallerIdentity;
}

export interface ToolResult {
  /** Structured payload returned as JSON text. */
  data?: unknown;
  /** Extra content blocks (used by get_media to return real images). */
  images?: { base64: string; mime: string }[];
  /** Rough size indicator for the audit log. */
  count?: number;
}

const DATE = z
  .string()
  .describe("ISO 8601 date or datetime, e.g. 2025-01-01 or 2025-01-01T12:00:00Z");

const KINDS = ["original", "reply", "self_reply", "retweet", "quote"] as const;

const searchShape = {
  query: z
    .string()
    .optional()
    .describe(
      'Keyword query. Bare words match as prefixes, so "songjam" also finds "@SongjamSpace". ' +
        'Wrap in double quotes for an exact phrase. "OR" between terms works.',
    ),
  kinds: z.array(z.enum(KINDS)).optional().describe("Restrict to these post kinds."),
  from: DATE.optional(),
  to: DATE.optional(),
  min_likes: z.number().int().min(0).optional(),
  has_media: z.boolean().optional(),
  lang: z.string().optional().describe("BCP-47-ish language code as X recorded it, e.g. 'en'."),
  long_form_only: z.boolean().optional().describe("Only posts whose full text exceeded the short limit."),
  include_retweets: z
    .boolean()
    .optional()
    .describe("Default false. Retweets are other people's words, so they are excluded by default."),
  sort: z.enum(["relevance", "newest", "oldest", "likes"]).optional(),
  limit: z.number().int().min(1).max(200).optional(),
  offset: z.number().int().min(0).optional(),
};

function toFilters(a: Record<string, unknown>): SearchFilters {
  return {
    query: a.query as string | undefined,
    kinds: a.kinds as string[] | undefined,
    from: a.from as string | undefined,
    to: a.to as string | undefined,
    minLikes: a.min_likes as number | undefined,
    hasMedia: a.has_media as boolean | undefined,
    lang: a.lang as string | undefined,
    longFormOnly: a.long_form_only as boolean | undefined,
    excludeRetweets: a.include_retweets === true ? false : true,
    sort: a.sort as SearchFilters["sort"],
    limit: a.limit as number | undefined,
    offset: a.offset as number | undefined,
  };
}

/** Trim a post for listing: full text, but no media blobs or entity noise. */
function brief(p: Post) {
  return {
    id: p.id,
    created_at: p.createdAt,
    kind: p.kind,
    text: p.text,
    likes: p.likes,
    retweets: p.retweets,
    engagement_recorded: p.engagementKnown,
    likes_percentile: p.likesPercentile,
    long_form: p.longForm,
    thread: p.threadLength && p.threadLength > 1 ? { id: p.threadId, pos: p.threadPos, length: p.threadLength } : null,
    media_count: p.media.length,
    url: `https://x.com/i/status/${p.id}`,
  };
}

function full(p: Post) {
  return {
    ...brief(p),
    lang: p.lang,
    source: p.source,
    collection: p.collection,
    in_reply_to: p.inReplyToStatusId,
    quoted_status_id: p.quotedStatusId,
    hashtags: p.hashtags,
    mentions: p.mentions,
    urls: p.urls,
    char_count: p.charCount,
    word_count: p.wordCount,
    media: p.media.map((m) => ({
      media_id: m.mediaId,
      type: m.type,
      mime: m.mime,
      bytes: m.bytes,
      available: Boolean(m.relPath),
      thumbnail_url: m.thumbnailUrl,
    })),
  };
}

export const TOOLS: VaultTool[] = [
  {
    name: "search_tweets",
    scope: "tweets.read",
    title: "Search your posts",
    description:
      "Full-text search across everything you posted (originals, replies, quotes, threads, " +
      "long-form). Returns your actual text plus recorded likes/retweets. Retweets are " +
      "excluded unless include_retweets is set, because they are not your words.",
    schema: searchShape,
    run: ({ db }, a) => {
      const r = searchPosts(db, toFilters(a));
      return {
        count: r.posts.length,
        data: {
          total_matches: r.total,
          returned: r.posts.length,
          interpreted_query: r.interpretedQuery,
          ...(r.queryIgnored ? { warning: r.queryIgnored } : {}),
          posts: r.posts.map(brief),
        },
      };
    },
  },

  {
    name: "get_tweet",
    scope: "tweets.read",
    title: "Get one post",
    description:
      "Fetch a single post by id with full metadata, optionally with its self-thread and the " +
      "conversation it replied into.",
    schema: {
      id: z.string().describe("Tweet id."),
      with_thread: z.boolean().optional().describe("Include the whole self-thread."),
      with_reply_context: z
        .boolean()
        .optional()
        .describe("Walk up the reply chain, including other people's posts where the archive has them."),
    },
    run: ({ db }, a) => {
      const id = String(a.id);
      const post = getPost(db, id);
      if (!post) return { count: 0, data: { found: false, id } };
      return {
        count: 1,
        data: {
          found: true,
          post: full(post),
          ...(a.with_thread ? { thread: getThread(db, id).map(brief) } : {}),
          ...(a.with_reply_context ? { reply_context: getReplyContext(db, id).map(brief) } : {}),
        },
      };
    },
  },

  {
    name: "get_thread",
    scope: "tweets.read",
    title: "Get a self-thread",
    description:
      "Return every post in the same self-thread, in posting order. Threads are built only from " +
      "replies to your own posts, so other people's replies are never spliced in.",
    schema: { id: z.string().describe("Any post id within the thread.") },
    run: ({ db }, a) => {
      const posts = getThread(db, String(a.id));
      return {
        count: posts.length,
        data: { length: posts.length, posts: posts.map(brief) },
      };
    },
  },

  {
    name: "get_timeline",
    scope: "tweets.read",
    title: "Browse your timeline",
    description:
      "List your posts over a date range, newest first by default. Use sort='likes' to see what " +
      "performed best in that window.",
    schema: {
      from: DATE.optional(),
      to: DATE.optional(),
      kinds: z.array(z.enum(KINDS)).optional(),
      include_retweets: z.boolean().optional(),
      sort: z.enum(["newest", "oldest", "likes"]).optional(),
      limit: z.number().int().min(1).max(200).optional(),
      offset: z.number().int().min(0).optional(),
    },
    run: ({ db }, a) => {
      const r = searchPosts(db, { ...toFilters(a), sort: (a.sort as SearchFilters["sort"]) ?? "newest" });
      return {
        count: r.posts.length,
        data: { total_matches: r.total, returned: r.posts.length, posts: r.posts.map(brief) },
      };
    },
  },

  {
    name: "analyze_style",
    scope: "tweets.read",
    title: "Analyze your writing style",
    description:
      "Measured stylistic profile of your writing: length distribution, how often you use emoji, " +
      "hashtags, links, questions, line breaks and lowercase, your most common opening phrases, " +
      "and when you post. All figures are counted from the corpus, not estimated. Retweets are " +
      "excluded. Use this before drafting so a new post matches how you actually write.",
    schema: {
      from: DATE.optional().describe("Narrow to recent writing, e.g. the last year, to capture your current voice."),
      to: DATE.optional(),
      kinds: z.array(z.enum(KINDS)).optional(),
      include_retweets: z.boolean().optional(),
    },
    run: ({ db }, a) => ({ count: 1, data: analyzeStyle(db, toFilters(a)) }),
  },

  {
    name: "engagement_stats",
    scope: "analytics.read",
    title: "Engagement statistics",
    description:
      "Aggregate likes/retweets grouped by one dimension (kind, year, hour, weekday, has_media, " +
      "long_form, lang). Every group reports its own coverage, because X populated engagement " +
      "for only ~67% of this archive. The archive has no impressions, reply counts or bookmarks, " +
      "so reach cannot be assessed.",
    schema: {
      dimension: z
        .enum(["kind", "year", "hour", "weekday", "has_media", "long_form", "lang"])
        .describe("What to group by."),
      from: DATE.optional(),
      to: DATE.optional(),
      kinds: z.array(z.enum(KINDS)).optional(),
      include_retweets: z.boolean().optional(),
    },
    run: ({ db }, a) => {
      const r = engagementStats(db, a.dimension as GroupDimension, toFilters(a));
      return { count: r.groups.length, data: r };
    },
  },

  {
    name: "top_performers",
    scope: "analytics.read",
    title: "Best and worst performing posts",
    description:
      "Your highest- or lowest-engagement posts, optionally within a window or a single kind. " +
      "Ranks by recorded likes; posts with no recorded engagement are excluded rather than " +
      "treated as zero.",
    schema: {
      direction: z.enum(["top", "bottom"]).optional().describe("Default 'top'."),
      from: DATE.optional(),
      to: DATE.optional(),
      kinds: z.array(z.enum(KINDS)).optional(),
      has_media: z.boolean().optional(),
      limit: z.number().int().min(1).max(100).optional(),
    },
    run: ({ db }, a) => {
      const direction = (a.direction as string) ?? "top";
      // min_likes >= 1 is how we exclude unrecorded engagement, since a missing
      // count and a true zero are indistinguishable in this archive.
      const r = searchPosts(db, {
        ...toFilters(a),
        minLikes: 1,
        sort: "likes",
        limit: direction === "top" ? ((a.limit as number) ?? 10) : 200,
      });
      const posts =
        direction === "top"
          ? r.posts
          : [...r.posts].reverse().slice(0, (a.limit as number) ?? 10);
      return {
        count: posts.length,
        data: {
          direction,
          population_with_recorded_engagement: r.total,
          caveat:
            "Ranked by likes among posts with nonzero recorded engagement only. No impressions " +
            "data exists in an X archive, so this measures reaction, not reach.",
          posts: posts.map(brief),
        },
      };
    },
  },

  {
    name: "search_likes",
    scope: "likes.read",
    title: "Search tweets you liked",
    description:
      "Search the 11,411 tweets you liked — the best available signal of what topics and voices " +
      "you engage with. Note the archive stores no timestamp or author for likes, only the text.",
    schema: {
      query: z.string().describe("Keyword query; bare words match as prefixes."),
      limit: z.number().int().min(1).max(200).optional(),
      offset: z.number().int().min(0).optional(),
    },
    run: ({ db }, a) => {
      const r = searchLikes(db, String(a.query ?? ""), a.limit as number, a.offset as number);
      return {
        count: r.likes.length,
        data: {
          total_matches: r.total,
          note: "Likes carry no date or author in an X archive.",
          likes: r.likes,
        },
      };
    },
  },

  {
    name: "get_audience",
    scope: "graph.read",
    title: "Your followers and following",
    description:
      "List your social graph. X exports it as bare numeric account ids, so most entries have no " +
      "username; the handles present were recovered by harvesting mentions elsewhere in the archive.",
    schema: {
      relation: z.enum(["followers", "following", "mutuals", "all"]).optional(),
      with_handle_only: z
        .boolean()
        .optional()
        .describe("Only return accounts whose username could be resolved — usually what you want."),
      limit: z.number().int().min(1).max(500).optional(),
      offset: z.number().int().min(0).optional(),
    },
    run: ({ db }, a) => {
      const r = getAudience(db, {
        relation: a.relation as "followers" | "following" | "mutuals" | "all" | undefined,
        withHandleOnly: a.with_handle_only as boolean | undefined,
        limit: a.limit as number | undefined,
        offset: a.offset as number | undefined,
      });
      return { count: r.accounts.length, data: r };
    },
  },

  {
    name: "get_media",
    scope: "media.read",
    title: "Get media from a post",
    description:
      "Return the images attached to one of your posts, inline, so they can actually be looked at. " +
      "Video cannot be returned inline over MCP: for video you get the file path, size, and the " +
      "CDN thumbnail URL instead.",
    schema: {
      tweet_id: z.string().describe("The post whose media you want."),
      max_images: z.number().int().min(1).max(4).optional().describe("Default 4."),
    },
    run: ({ db, config }, a) => {
      const post = getPost(db, String(a.tweet_id));
      if (!post) return { count: 0, data: { found: false, id: a.tweet_id } };
      const maxImages = (a.max_images as number) ?? 4;
      const images: { base64: string; mime: string }[] = [];
      const described: unknown[] = [];

      for (const m of post.media) {
        const entry: Record<string, unknown> = {
          media_id: m.mediaId,
          type: m.type,
          mime: m.mime,
          bytes: m.bytes,
          path: m.relPath,
          thumbnail_url: m.thumbnailUrl,
        };
        if (!m.relPath) {
          entry.status = "not included in the archive export";
        } else if (isImage(m.ext) && images.length < maxImages) {
          // Resolve strictly under the archive dir so a crafted relPath can't
          // read arbitrary files off disk.
          const abs = resolve(config.archiveDir, m.relPath);
          if (!abs.startsWith(resolve(config.archiveDir))) {
            entry.status = "refused: path escapes the archive directory";
          } else {
            images.push({ base64: readFileSync(abs).toString("base64"), mime: mimeForExt(m.ext) });
            entry.status = "returned inline";
          }
        } else if (isImage(m.ext)) {
          entry.status = `not returned (max_images=${maxImages} reached)`;
        } else {
          entry.status = "video — cannot be returned inline; use the path or thumbnail";
        }
        described.push(entry);
      }

      return {
        count: post.media.length,
        images,
        data: { found: true, tweet_id: post.id, media: described },
      };
    },
  },

  {
    name: "search_dms",
    scope: "dms.read",
    title: "Search direct messages",
    description:
      "Search your DMs. This is off by default because DMs contain other people's words; it is " +
      "only available when dms.read is explicitly granted.",
    schema: {
      query: z.string().describe("Keyword query."),
      limit: z.number().int().min(1).max(200).optional(),
      offset: z.number().int().min(0).optional(),
    },
    run: ({ db, ownAccountId }, a) => {
      const r = searchDms(db, String(a.query ?? ""), ownAccountId, a.limit as number, a.offset as number);
      return { count: r.messages.length, data: { total_matches: r.total, messages: r.messages } };
    },
  },

  {
    name: "vault_info",
    scope: "tweets.read",
    title: "What's in the vault",
    description:
      "Summary of the vault: whose archive it is, what it contains, when it was exported, and " +
      "which data limitations to keep in mind. Call this first to understand what you can ask for.",
    schema: {},
    run: ({ db, scopes, caller }) => {
      const profile = getProfile(db);
      const stats = getMeta(db, "corpus_stats");
      return {
        count: 1,
        data: {
          profile,
          granted_scopes: scopes,
          // Telling a remote agent who it is authenticated as makes a scope
          // surprise diagnosable from inside the conversation, rather than
          // leaving the model to guess why a tool it expected is missing.
          caller: caller
            ? { mind_id: caller.mindId, label: caller.label, expires_at: caller.expiresAt }
            : null,
          corpus: stats ? JSON.parse(stats) : null,
          index_built_at: getMeta(db, "built_at"),
          limitations: [
            "Engagement is likes and retweets only. X archives contain no impressions, views, " +
              "reply counts, bookmarks or profile clicks.",
            "Engagement counts are populated for roughly 67% of posts, and a missing count is " +
              "indistinguishable from a true zero.",
            "Likes have no timestamp or author, only text.",
            "The social graph is numeric account ids; most usernames are unavailable.",
            "Follower count over time is not recorded, so engagement cannot be normalized by " +
              "audience size — comparisons are within (year, kind) buckets instead.",
          ],
        },
      };
    },
  },
];
