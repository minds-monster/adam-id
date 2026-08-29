import Database from "better-sqlite3";
import { existsSync, rmSync } from "node:fs";
import type { VaultConfig } from "../config.js";
import type { MediaFile } from "../archive/loader.js";
import {
  CORPUS_FILES,
  type AccountRef,
  type CorpusStats,
  type DirectMessage,
  type Like,
  type Post,
  type Profile,
} from "../corpus/model.js";
import { corpusPath, ensureDir, readJson, readNdjson } from "../corpus/io.js";
import { SCHEMA, SCHEMA_VERSION } from "./schema.js";

export interface IndexStats {
  posts: number;
  likes: number;
  dms: number;
  accounts: number;
  media: number;
  path: string;
}

export function buildIndex(config: VaultConfig): IndexStats {
  const posts = readNdjson<Post>(corpusPath(config.corpusDir, CORPUS_FILES.posts));
  if (!posts.length) {
    throw new Error("Corpus is empty — run `vault ingest` first.");
  }
  const likes = readNdjson<Like>(corpusPath(config.corpusDir, CORPUS_FILES.likes));
  const dms = readNdjson<DirectMessage>(corpusPath(config.corpusDir, CORPUS_FILES.dms));
  const accounts = readNdjson<AccountRef>(corpusPath(config.corpusDir, CORPUS_FILES.accounts));
  const media = readNdjson<MediaFile>(corpusPath(config.corpusDir, CORPUS_FILES.media));
  const profile = readJson<Profile>(corpusPath(config.corpusDir, CORPUS_FILES.profile));
  const stats = readJson<CorpusStats>(corpusPath(config.corpusDir, CORPUS_FILES.stats));

  ensureDir(config.corpusDir);
  // Rebuild from scratch: the index is disposable and a partial rebuild over a
  // stale file is far more dangerous than a slow clean one.
  for (const suffix of ["", "-wal", "-shm"]) {
    const p = `${config.indexPath}${suffix}`;
    if (existsSync(p)) rmSync(p);
  }

  const db = new Database(config.indexPath);
  db.exec(SCHEMA);

  const insertPost = db.prepare(`
    INSERT INTO posts (
      id, created_at, year, hour, weekday, text, long_form, kind, lang, source, collection,
      in_reply_to_id, in_reply_to_user, quoted_status_id, likes, retweets, engagement_known,
      likes_percentile, thread_id, thread_pos, thread_length, has_media, media_count,
      char_count, word_count, hashtags, mentions, urls, media
    ) VALUES (
      @id, @created_at, @year, @hour, @weekday, @text, @long_form, @kind, @lang, @source, @collection,
      @in_reply_to_id, @in_reply_to_user, @quoted_status_id, @likes, @retweets, @engagement_known,
      @likes_percentile, @thread_id, @thread_pos, @thread_length, @has_media, @media_count,
      @char_count, @word_count, @hashtags, @mentions, @urls, @media
    )
  `);

  const insertLike = db.prepare(
    `INSERT INTO likes (tweet_id, text, url) VALUES (@tweet_id, @text, @url)`,
  );
  const insertDm = db.prepare(`
    INSERT INTO dms (message_id, conversation_id, created_at, sender_id, recipient_id, is_group, text)
    VALUES (@message_id, @conversation_id, @created_at, @sender_id, @recipient_id, @is_group, @text)
  `);
  const insertAccount = db.prepare(`
    INSERT INTO accounts (account_id, screen_name, follower, following)
    VALUES (@account_id, @screen_name, @follower, @following)
  `);
  const insertMedia = db.prepare(`
    INSERT OR IGNORE INTO media (rel_path, source_id, media_id, ext, bytes, collection)
    VALUES (@rel_path, @source_id, @media_id, @ext, @bytes, @collection)
  `);

  const load = db.transaction(() => {
    for (const p of posts) {
      const d = new Date(p.createdAt);
      insertPost.run({
        id: p.id,
        created_at: p.createdAt,
        year: Number(p.createdAt.slice(0, 4)),
        // Local time, because "what hour do I post best at" is a question about
        // your day, not about UTC.
        hour: d.getHours(),
        weekday: d.getDay(),
        text: p.text,
        long_form: p.longForm ? 1 : 0,
        kind: p.kind,
        lang: p.lang,
        source: p.source,
        collection: p.collection,
        in_reply_to_id: p.inReplyToStatusId,
        in_reply_to_user: p.inReplyToUserId,
        quoted_status_id: p.quotedStatusId,
        likes: p.likes,
        retweets: p.retweets,
        engagement_known: p.engagementKnown ? 1 : 0,
        likes_percentile: p.likesPercentile,
        thread_id: p.threadId,
        thread_pos: p.threadPos,
        thread_length: p.threadLength,
        has_media: p.media.length ? 1 : 0,
        media_count: p.media.length,
        char_count: p.charCount,
        word_count: p.wordCount,
        hashtags: JSON.stringify(p.hashtags),
        mentions: JSON.stringify(p.mentions),
        urls: JSON.stringify(p.urls),
        media: JSON.stringify(p.media),
      });
    }
    for (const l of likes) {
      insertLike.run({ tweet_id: l.tweetId, text: l.text, url: l.url });
    }
    for (const m of dms) {
      insertDm.run({
        message_id: m.messageId,
        conversation_id: m.conversationId,
        created_at: m.createdAt,
        sender_id: m.senderId,
        recipient_id: m.recipientId,
        is_group: m.isGroup ? 1 : 0,
        text: m.text,
      });
    }
    for (const a of accounts) {
      insertAccount.run({
        account_id: a.accountId,
        screen_name: a.screenName,
        follower: a.follower ? 1 : 0,
        following: a.following ? 1 : 0,
      });
    }
    for (const f of media) {
      insertMedia.run({
        rel_path: f.relPath,
        source_id: f.sourceId,
        media_id: f.mediaId,
        ext: f.ext,
        bytes: f.bytes,
        collection: f.collection,
      });
    }

    // External-content FTS tables are populated by a rebuild rather than per-row
    // inserts — one pass over the base table instead of 8k index writes.
    db.exec(`INSERT INTO posts_fts(posts_fts) VALUES('rebuild')`);
    db.exec(`INSERT INTO likes_fts(likes_fts) VALUES('rebuild')`);
    db.exec(`INSERT INTO dms_fts(dms_fts) VALUES('rebuild')`);

    const setMeta = db.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`);
    setMeta.run("schema_version", SCHEMA_VERSION);
    setMeta.run("built_at", new Date().toISOString());
    setMeta.run("account_id", profile?.accountId ?? "");
    setMeta.run("username", profile?.username ?? "");
    setMeta.run("profile", JSON.stringify(profile ?? {}));
    setMeta.run("corpus_stats", JSON.stringify(stats ?? {}));
  });

  load();
  db.exec("ANALYZE");
  db.close();

  return {
    posts: posts.length,
    likes: likes.length,
    dms: dms.length,
    accounts: accounts.length,
    media: media.length,
    path: config.indexPath,
  };
}
