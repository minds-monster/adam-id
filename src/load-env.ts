/**
 * Load .env before anything else reads process.env.
 *
 * This has to be its own module, imported first for its side effect. ES module imports
 * are hoisted and evaluated before any statement in the importing file, so the same code
 * written inline at the top of cli.ts would run *after* every other import had already
 * been evaluated — and any module reading process.env at import time would see nothing.
 *
 * Why it exists at all: `npm run vault` does not load .env, and tsx does not either, so
 * whether the server came up correctly depended on which shell had exported what. The
 * failure is quiet and badly misleading — the process starts, binds, serves loopback
 * fine, and rejects only the tunnel, with `forbidden_host` naming the very hostname you
 * configured. ops/TUNNEL.md calls VAULT_HTTP_ALLOWED_HOSTS "the one that costs an hour
 * if forgotten"; this is that hour, removed.
 *
 * Values already in the environment win — loadEnvFile does not overwrite them — so an
 * explicit `VAULT_x=… vault serve` still beats the file, and CI, which sets everything
 * directly and ships no .env, is unaffected.
 */
try {
  process.loadEnvFile(new URL("../.env", import.meta.url).pathname);
} catch {
  // No .env is entirely normal — the environment may be supplied directly.
}
