import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { loadConfig, type VaultConfig } from "../config.js";
import { getMeta, openIndex } from "../index/query.js";
import { AuditLog } from "./audit.js";
import { TOOLS, type ToolContext } from "./tools.js";

/**
 * Build an MCP server exposing exactly the tools `ctx.scopes` permits.
 *
 * Tools whose scope is not granted are never registered — the caller cannot see
 * or call them, which is a stronger guarantee than refusing at call time. That
 * property is why this filters at build time and why each transport gets its own
 * server instance: stdio builds one from VAULT_SCOPES, HTTP builds one per
 * session from a verified Moca credential intersected with the local grant.
 * Sharing a single server across sessions would force it to advertise the union
 * of every scope and refuse later, which is strictly weaker.
 */
export function buildServer(
  ctx: ToolContext,
  audit: AuditLog,
  username: string,
  sessionId?: string,
): { server: McpServer; registered: string[]; withheld: string[] } {
  const server = new McpServer(
    { name: "personal-twitter-vault", version: "0.1.0" },
    {
      instructions:
        `Private vault over @${username}'s X archive. Call vault_info first to see what is ` +
        `available and which data limitations apply. When drafting posts, ground them in real ` +
        `retrieved posts and cite the tweet ids you drew on. Engagement is likes/retweets only — ` +
        `never claim reach, impressions or view counts, which this data does not contain.`,
    },
  );

  // Identity fields stamped onto every audit line for this session. Empty over
  // stdio, so the log shape is unchanged for local use.
  const who = ctx.caller
    ? {
        mindId: ctx.caller.mindId,
        subjectDid: ctx.caller.subjectDid,
        credentialFingerprint: ctx.caller.credentialFingerprint,
        ...(sessionId ? { sessionId } : {}),
      }
    : {};

  const granted = new Set(ctx.scopes);
  const registered: string[] = [];
  const withheld: string[] = [];

  for (const tool of TOOLS) {
    if (!granted.has(tool.scope)) {
      withheld.push(`${tool.name} (needs ${tool.scope})`);
      audit.record({
        tool: tool.name,
        scope: tool.scope,
        outcome: "denied",
        detail: "scope not granted; tool not registered",
        ...who,
      });
      continue;
    }
    registered.push(tool.name);

    server.registerTool(
      tool.name,
      { title: tool.title, description: tool.description, inputSchema: tool.schema },
      async (args: Record<string, unknown>) => {
        const started = Date.now();
        try {
          const result = tool.run(ctx, args ?? {});
          audit.record({
            tool: tool.name,
            scope: tool.scope,
            outcome: "ok",
            resultCount: result.count,
            durationMs: Date.now() - started,
            args,
            ...who,
          });
          const content: ({ type: "text"; text: string } | { type: "image"; data: string; mimeType: string })[] =
            [{ type: "text", text: JSON.stringify(result.data ?? null, null, 2) }];
          for (const img of result.images ?? []) {
            content.push({ type: "image", data: img.base64, mimeType: img.mime });
          }
          return { content };
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          audit.record({
            tool: tool.name,
            scope: tool.scope,
            outcome: "error",
            durationMs: Date.now() - started,
            detail: message,
            args,
            ...who,
          });
          return {
            isError: true,
            content: [{ type: "text" as const, text: `${tool.name} failed: ${message}` }],
          };
        }
      },
    );
  }

  return { server, registered, withheld };
}

/**
 * MCP server over stdio.
 *
 * Authorization is deliberately simple at this transport: a stdio server is a
 * subprocess of the client, so possession of the machine is the credential and
 * the granted scope set (VAULT_SCOPES) is the boundary. There is no separate
 * caller identity to verify, so `ctx.caller` stays undefined and the audit log
 * keeps the shape it has always had.
 *
 * For the credential-gated remote path, see serveHttp() in ./http.ts.
 */
export async function serve(config: VaultConfig = loadConfig()): Promise<void> {
  const db = openIndex(config);
  const ownAccountId = getMeta(db, "account_id") ?? "";
  const username = getMeta(db, "username") ?? "unknown";
  const audit = new AuditLog(config.auditLogPath);
  const ctx: ToolContext = { db, config, ownAccountId, scopes: config.scopes };

  const { server, registered, withheld } = buildServer(ctx, audit, username);

  // stderr only — stdout is the MCP transport and must carry nothing else.
  console.error(`personal-twitter-vault ready for @${username}`);
  console.error(`  scopes:     ${config.scopes.join(", ")}`);
  console.error(`  tools:      ${registered.join(", ")}`);
  if (withheld.length) console.error(`  withheld:   ${withheld.join(", ")}`);
  console.error(`  audit log:  ${config.auditLogPath}`);

  const transport = new StdioServerTransport();
  await server.connect(transport);

  // connect() resolves as soon as the transport is wired up. Hold the process
  // open until the client disconnects, otherwise the CLI would exit immediately
  // and the client would see the connection close mid-handshake.
  await new Promise<void>((resolveClosed) => {
    server.server.onclose = () => resolveClosed();
  });
  db.close();
}

// Run directly when invoked as `tsx src/mcp/server.ts`; stay inert when imported
// by the CLI, which calls serve() itself.
const invokedDirectly =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (invokedDirectly) {
  serve().catch((err: unknown) => {
    console.error(err instanceof Error ? `error: ${err.message}` : err);
    process.exit(1);
  });
}
