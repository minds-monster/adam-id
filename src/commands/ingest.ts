import type { VaultConfig } from "../config.js";
import { populatedDataTypes, readManifest, scanMedia } from "../archive/loader.js";
import { normalizePosts } from "../archive/normalize/posts.js";
import { normalizeLikes } from "../archive/normalize/likes.js";
import { normalizeDms } from "../archive/normalize/dms.js";
import { harvestHandles, normalizeAccounts, normalizeProfile } from "../archive/normalize/graph.js";
import { linkMedia } from "../corpus/media.js";
import { buildThreads } from "../corpus/threads.js";
import { computePercentiles } from "../corpus/engagement.js";
import { CORPUS_FILES, type CorpusStats } from "../corpus/model.js";
import { corpusPath, ensureDir, writeJson, writeNdjson } from "../corpus/io.js";

function tally<T>(rows: T[], key: (row: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const row of rows) {
    const k = key(row);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

export function ingest(config: VaultConfig): CorpusStats {
  const manifest = readManifest(config.archiveDir);
  const ownAccountId = manifest.userInfo.accountId;
  ensureDir(config.corpusDir);

  console.error(`archive:  ${config.archiveDir}`);
  console.error(`account:  @${manifest.userInfo.userName} (${ownAccountId})`);
  console.error(`exported: ${manifest.archiveInfo.generationDate}`);
  console.error(`declared: ${populatedDataTypes(manifest).length} populated data types\n`);

  console.error("parsing posts...");
  const { posts, longFormMerged, handles: mentionHandles } = normalizePosts(
    config.archiveDir,
    manifest,
    ownAccountId,
  );

  console.error("parsing likes...");
  const likes = normalizeLikes(config.archiveDir, manifest);

  console.error("parsing direct messages...");
  const dms = normalizeDms(config.archiveDir, manifest);

  console.error("scanning media...");
  const media = scanMedia(config.archiveDir, manifest);
  const mediaLink = linkMedia(posts, media);

  console.error("deriving threads and engagement...");
  const profile = normalizeProfile(config.archiveDir, manifest);
  const handles = harvestHandles(posts, dms, mentionHandles, profile);
  const accounts = normalizeAccounts(config.archiveDir, manifest, handles);
  const threads = buildThreads(posts, ownAccountId);
  computePercentiles(posts);

  const stats: CorpusStats = {
    generatedAt: new Date().toISOString(),
    archiveGeneratedAt: manifest.archiveInfo.generationDate,
    posts: posts.length,
    postsByKind: tally(posts, (p) => p.kind),
    postsByYear: tally(posts, (p) => p.createdAt.slice(0, 4)),
    engagementKnown: posts.filter((p) => p.engagementKnown).length,
    longFormMerged,
    threads,
    likes: likes.length,
    directMessages: dms.length,
    accounts: accounts.length,
    resolvedHandles: accounts.filter((a) => a.screenName).length,
    mediaFiles: media.length,
    mediaBytes: media.reduce((s, m) => s + m.bytes, 0),
    mediaLinkedToPosts: mediaLink.linkedPosts,
    mediaLinkedFiles: mediaLink.linkedFiles,
    mediaMissingFiles: mediaLink.missingFiles,
    mediaUnreferencedFiles: mediaLink.unreferencedFiles,
  };

  console.error("writing corpus...");
  writeNdjson(corpusPath(config.corpusDir, CORPUS_FILES.posts), posts);
  writeNdjson(corpusPath(config.corpusDir, CORPUS_FILES.likes), likes);
  writeNdjson(corpusPath(config.corpusDir, CORPUS_FILES.dms), dms);
  writeNdjson(corpusPath(config.corpusDir, CORPUS_FILES.accounts), accounts);
  writeNdjson(corpusPath(config.corpusDir, CORPUS_FILES.media), media);
  writeJson(corpusPath(config.corpusDir, CORPUS_FILES.profile), profile);
  writeJson(
    corpusPath(config.corpusDir, CORPUS_FILES.handles),
    Object.fromEntries([...handles].sort((a, b) => a[0].localeCompare(b[0]))),
  );
  writeJson(corpusPath(config.corpusDir, CORPUS_FILES.stats), stats);

  return stats;
}

export function printStats(stats: CorpusStats): void {
  const pct = (n: number, d: number) => (d ? `${((n / d) * 100).toFixed(1)}%` : "—");
  console.error("");
  console.error(`posts                ${stats.posts}`);
  for (const [kind, n] of Object.entries(stats.postsByKind).sort((a, b) => b[1] - a[1])) {
    console.error(`  ${kind.padEnd(18)} ${n}`);
  }
  console.error(
    `engagement recorded  ${stats.engagementKnown} (${pct(stats.engagementKnown, stats.posts)} coverage)`,
  );
  console.error(`long-form merged     ${stats.longFormMerged}`);
  console.error(`multi-post threads   ${stats.threads}`);
  console.error(`likes                ${stats.likes}`);
  console.error(`direct messages      ${stats.directMessages}`);
  console.error(
    `graph accounts       ${stats.accounts} (${stats.resolvedHandles} handles resolved, ${pct(
      stats.resolvedHandles,
      stats.accounts,
    )})`,
  );
  console.error(
    `media files          ${stats.mediaFiles} (${(stats.mediaBytes / 1e9).toFixed(2)} GB, ` +
      `${stats.mediaLinkedToPosts} posts have media)`,
  );
  console.error(
    `  linked / missing / unreferenced   ${stats.mediaLinkedFiles} / ` +
      `${stats.mediaMissingFiles} / ${stats.mediaUnreferencedFiles}`,
  );
  console.error(`years                ${JSON.stringify(stats.postsByYear)}`);
}
