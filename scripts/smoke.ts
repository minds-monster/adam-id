/**
 * End-to-end smoke test: drives the MCP server as a real client over stdio.
 *
 * This exists because the useful failures in this project are protocol-level —
 * a tool that throws on serialization, a scope that leaks, an image that comes
 * back as text — and none of those show up in a unit test of the query layer.
 *
 *   npm run smoke
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { resolve } from "node:path";
import { DEFAULT_SCOPES } from "../src/config.js";
import { TOOLS } from "../src/mcp/tools.js";

const ROOT = resolve(import.meta.dirname, "..");

let failures = 0;
function check(label: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "  ✓" : "  ✗"} ${label}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures++;
}

async function connect(scopes?: string) {
  const transport = new StdioClientTransport({
    command: "npx",
    args: ["tsx", "src/cli.ts", "serve"],
    cwd: ROOT,
    env: { ...process.env, ...(scopes ? { VAULT_SCOPES: scopes } : {}) } as Record<string, string>,
    stderr: "pipe",
  });
  const client = new Client({ name: "smoke", version: "1" });
  await client.connect(transport);
  return client;
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  let r: {
    content: { type: string; text?: string; data?: string; mimeType?: string }[];
    isError?: boolean;
  };
  try {
    r = (await client.callTool({ name, arguments: args })) as typeof r;
  } catch (err) {
    // An unregistered tool rejects at the protocol level rather than returning
    // an error result, so normalize both shapes into one.
    return {
      isError: true,
      images: [] as { type: string; data?: string; mimeType?: string }[],
      json: null,
      text: err instanceof Error ? err.message : String(err),
    };
  }
  const text = r.content
    .filter((c) => c.type === "text")
    .map((c) => c.text ?? "")
    .join("");
  // Error results carry a plain-text message, not JSON, so parsing must not throw.
  let json: Record<string, unknown> | null = null;
  try {
    json = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    json = null;
  }
  return {
    isError: Boolean(r.isError),
    images: r.content.filter((c) => c.type === "image"),
    json,
    text,
  };
}

console.log("\ndefault scopes (dms.read withheld)");
{
  const client = await connect();
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  // Derived from the TOOLS table rather than hardcoded: the property under test
  // is "exactly the granted tools appear", not "there are N tools". A literal
  // count fails spuriously the first time anyone adds a tool.
  const expected = TOOLS.filter((t) => DEFAULT_SCOPES.includes(t.scope)).map((t) => t.name).sort();
  check(
    "exactly the default-scoped tools are registered",
    JSON.stringify(names.slice().sort()) === JSON.stringify(expected),
    `${names.length} tools`,
  );
  check("search_dms absent without dms.read", !names.includes("search_dms"));

  const info = await call(client, "vault_info");
  const corpus = info.json?.corpus as { posts: number } | null;
  check("vault_info reports the corpus", (corpus?.posts ?? 0) > 0, `${corpus?.posts} posts`);
  check(
    "vault_info states data limitations",
    Array.isArray(info.json?.limitations) && (info.json!.limitations as unknown[]).length >= 5,
  );

  const search = await call(client, "search_tweets", { query: "agentic ai", limit: 5 });
  check(
    "search_tweets returns hits",
    ((search.json?.total_matches as number) ?? 0) > 0,
    `${search.json?.total_matches} matches`,
  );

  // Prefix expansion is what makes handle-heavy text findable at all.
  const prefix = await call(client, "search_tweets", { query: "songjam", limit: 1 });
  const exact = await call(client, "search_tweets", { query: '"songjam"', limit: 1 });
  check(
    "bare terms match as prefixes, quoted terms exactly",
    (prefix.json?.total_matches as number) > (exact.json?.total_matches as number),
    `${prefix.json?.total_matches} vs ${exact.json?.total_matches}`,
  );

  const style = await call(client, "analyze_style", {});
  const chars = style.json?.charCount as { median: number } | undefined;
  check("analyze_style computes a length distribution", (chars?.median ?? 0) > 0, `median ${chars?.median} chars`);

  const eng = await call(client, "engagement_stats", { dimension: "kind" });
  const groups = (eng.json?.groups ?? []) as { group: string; coverage: number }[];
  check("engagement_stats groups by kind", groups.length > 1, `${groups.length} groups`);
  check("engagement_stats reports coverage per group", groups.every((g) => typeof g.coverage === "number"));

  const top = await call(client, "top_performers", { limit: 3 });
  const topPosts = (top.json?.posts ?? []) as { likes: number }[];
  check("top_performers excludes unrecorded engagement", topPosts.every((p) => p.likes >= 1));

  // Find a post with real image media and confirm it comes back as image content.
  const withMedia = await call(client, "search_tweets", {
    has_media: true,
    kinds: ["original"],
    sort: "likes",
    limit: 8,
  });
  let inlineImages = 0;
  for (const p of (withMedia.json?.posts ?? []) as { id: string }[]) {
    const media = await call(client, "get_media", { tweet_id: p.id, max_images: 2 });
    if (media.images.length) {
      inlineImages = media.images.length;
      check(
        "get_media returns real inline images",
        media.images.every((i) => i.mimeType?.startsWith("image/") && (i.data?.length ?? 0) > 1000),
        `${inlineImages} image(s), ${media.images[0]!.mimeType}`,
      );
      break;
    }
  }
  if (!inlineImages) check("get_media returns real inline images", false, "no image media found");

  const thread = await call(client, "search_tweets", { query: "", limit: 1 });
  void thread;
  const missing = await call(client, "get_tweet", { id: "0" });
  check("get_tweet handles an unknown id without erroring", !missing.isError && missing.json?.found === false);

  const denied = await call(client, "search_dms", { query: "x" });
  check("calling a withheld tool is refused", denied.isError, denied.text.slice(0, 60));

  await client.close();
}

console.log("\nexplicit dms.read grant");
{
  const client = await connect("tweets.read,dms.read");
  const { tools } = await client.listTools();
  check("search_dms appears when granted", tools.some((t) => t.name === "search_dms"));
  check("unrelated tools stay withheld", !tools.some((t) => t.name === "get_media"));
  const dms = await call(client, "search_dms", { query: "moca", limit: 2 });
  check("search_dms returns messages", typeof dms.json?.total_matches === "number", `${dms.json?.total_matches} matches`);
  await client.close();
}

console.log(failures ? `\n${failures} check(s) failed\n` : "\nall checks passed\n");
process.exit(failures ? 1 : 0);
