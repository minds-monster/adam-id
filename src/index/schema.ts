/**
 * SQLite schema for the search index.
 *
 * The index is a *derived cache*: it can always be rebuilt from the corpus (or,
 * once sealed, from the ciphertext store), which is why it carries no data that
 * doesn't exist upstream and can be deleted freely.
 *
 * FTS5 external-content tables are used throughout (`content=`), so text lives
 * once in the base table and the FTS index only stores terms. Triggers are
 * unnecessary because we rebuild wholesale rather than mutate incrementally.
 */
export const SCHEMA = `
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
  rowid            INTEGER PRIMARY KEY,
  id               TEXT NOT NULL UNIQUE,
  created_at       TEXT NOT NULL,
  year             INTEGER NOT NULL,
  -- Local-time hour/weekday, so "when do I post well" answers match your day.
  hour             INTEGER NOT NULL,
  weekday          INTEGER NOT NULL,
  text             TEXT NOT NULL,
  long_form        INTEGER NOT NULL,
  kind             TEXT NOT NULL,
  lang             TEXT,
  source           TEXT,
  collection       TEXT NOT NULL,
  in_reply_to_id   TEXT,
  in_reply_to_user TEXT,
  quoted_status_id TEXT,
  likes            INTEGER NOT NULL,
  retweets         INTEGER NOT NULL,
  engagement_known INTEGER NOT NULL,
  likes_percentile INTEGER,
  thread_id        TEXT,
  thread_pos       INTEGER,
  thread_length    INTEGER,
  has_media        INTEGER NOT NULL,
  media_count      INTEGER NOT NULL,
  char_count       INTEGER NOT NULL,
  word_count       INTEGER NOT NULL,
  hashtags         TEXT NOT NULL,
  mentions         TEXT NOT NULL,
  urls             TEXT NOT NULL,
  media            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS posts_created_at ON posts(created_at);
CREATE INDEX IF NOT EXISTS posts_kind       ON posts(kind);
CREATE INDEX IF NOT EXISTS posts_likes      ON posts(likes);
CREATE INDEX IF NOT EXISTS posts_thread     ON posts(thread_id, thread_pos);
CREATE INDEX IF NOT EXISTS posts_year_kind  ON posts(year, kind);

CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
  text,
  content='posts',
  content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);

CREATE TABLE IF NOT EXISTS likes (
  rowid    INTEGER PRIMARY KEY,
  tweet_id TEXT NOT NULL UNIQUE,
  text     TEXT NOT NULL,
  url      TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS likes_fts USING fts5(
  text,
  content='likes',
  content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);

CREATE TABLE IF NOT EXISTS dms (
  rowid           INTEGER PRIMARY KEY,
  message_id      TEXT NOT NULL UNIQUE,
  conversation_id TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  sender_id       TEXT NOT NULL,
  recipient_id    TEXT,
  is_group        INTEGER NOT NULL,
  text            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS dms_created ON dms(created_at);
CREATE INDEX IF NOT EXISTS dms_conv    ON dms(conversation_id);

CREATE VIRTUAL TABLE IF NOT EXISTS dms_fts USING fts5(
  text,
  content='dms',
  content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);

CREATE TABLE IF NOT EXISTS accounts (
  account_id  TEXT PRIMARY KEY,
  screen_name TEXT,
  follower    INTEGER NOT NULL,
  following   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS accounts_screen_name ON accounts(screen_name);

CREATE TABLE IF NOT EXISTS media (
  rel_path   TEXT PRIMARY KEY,
  source_id  TEXT NOT NULL,
  media_id   TEXT NOT NULL,
  ext        TEXT NOT NULL,
  bytes      INTEGER NOT NULL,
  collection TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS media_source ON media(source_id);
`;

/** Bump when the schema or derived columns change, forcing a rebuild. */
export const SCHEMA_VERSION = "1";
