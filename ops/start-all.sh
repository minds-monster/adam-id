#!/usr/bin/env bash
#
# Bring the whole vault stack up, in dependency order, idempotently.
#
# Nothing here is a system service, so a reboot or a logout takes all of it down and a
# Mind's next call gets a 502. Run this after either.
#
# Order matters: the issuer needs Postgres; the vault verifies credentials against the
# issuer at session start; the tunnel is what makes either reachable. Starting the vault
# first works but its first credential check fails until the issuer answers.
#
#   ops/start-all.sh          start anything not already up
#   ops/start-all.sh status   report only, change nothing
#
set -uo pipefail

VAULT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISSUER_DIR="$(cd "$VAULT_DIR/../air-issuer-service" && pwd)"
LOG_DIR="${TMPDIR:-/tmp}"
CLOUDFLARED="${CLOUDFLARED:-$HOME/.local/bin/cloudflared}"

up()      { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
running() { pgrep -f "$1" >/dev/null 2>&1; }
say()     { printf "  %-12s %s\n" "$1" "$2"; }

status() {
  echo "stack status"
  running "/Library/PostgreSQL/18/bin/postgres" && say postgres "up" || say postgres "DOWN"
  up 3000 && say issuer "up (127.0.0.1:3000)" || say issuer "DOWN"
  running "cloudflared tunnel run" && say tunnel "up" || say tunnel "DOWN"
  up 8787 && say vault "up (127.0.0.1:8787)" || say vault "DOWN"
}

if [ "${1:-start}" = "status" ]; then status; exit 0; fi

# 1. Postgres. Installed as a launchd service by the EDB installer, so this only reports —
#    if it is down, something is wrong that a script should not paper over.
if ! running "/Library/PostgreSQL/18/bin/postgres"; then
  echo "postgres is not running. Start it before continuing (EDB installs it as a" >&2
  echo "launchd service; check /Library/PostgreSQL/18)." >&2
  exit 1
fi
say postgres "up"

# 2. Issuer. Serves the JWKS the vault verifies against and the revocation endpoint.
if up 3000; then
  say issuer "already up"
else
  ( cd "$ISSUER_DIR" && nohup npm run start > "$LOG_DIR/issuer.log" 2>&1 & )
  for _ in $(seq 1 40); do up 3000 && break; sleep 2; done
  up 3000 && say issuer "started" || { echo "issuer failed to start; see $LOG_DIR/issuer.log" >&2; exit 1; }
fi

# 3. Tunnel. Both hostnames ride one tunnel; see ops/cloudflared-config.yml.
if running "cloudflared tunnel run"; then
  say tunnel "already up"
else
  nohup "$CLOUDFLARED" tunnel run adam-id > "$LOG_DIR/tunnel.log" 2>&1 &
  for _ in $(seq 1 20); do grep -q "Registered tunnel connection" "$LOG_DIR/tunnel.log" 2>/dev/null && break; sleep 2; done
  grep -q "Registered tunnel connection" "$LOG_DIR/tunnel.log" 2>/dev/null \
    && say tunnel "started" || { echo "tunnel failed; see $LOG_DIR/tunnel.log" >&2; exit 1; }
fi

# 4. Vault. Reads .env for the issuer URL, allowed hosts and port. Refuses to start
#    without an issuer configured, so a misconfigured run fails here rather than serving
#    unauthenticated.
if up 8787; then
  say vault "already up"
else
  ( cd "$VAULT_DIR" && set -a && . ./.env && set +a \
      && nohup npx tsx src/cli.ts serve --http > "$LOG_DIR/vault-http.log" 2>&1 & )
  for _ in $(seq 1 30); do up 8787 && break; sleep 2; done
  up 8787 && say vault "started" || { echo "vault failed; see $LOG_DIR/vault-http.log" >&2; exit 1; }
fi

echo
echo "reachability"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-redirs 0 https://issuer.minds.monster/.well-known/jwt-vc-issuer)
say "issuer jwks" "$code $([ "$code" = 200 ] && echo '(public, as required)' || echo '(EXPECTED 200 — verification will fail)')"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST https://vault.minds.monster/mcp -H 'content-type: application/json' -d '{}')
say "vault edge" "$code $([ "$code" = 403 ] && echo '(Access enforcing)' || echo '(EXPECTED 403)')"

echo
echo "active grants:"
( cd "$VAULT_DIR" && npx tsx src/cli.ts grants 2>&1 | sed 's/^/  /' | head -12 )
