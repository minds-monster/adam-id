# Mind Connect System — Handover

## Repos involved

| Repo | Path | Role |
|---|---|---|
| **adam-id** | `/Users/adamplace/adam-id` | Personal vault: corpus, grants, credential verification, MCP server, admin issue-credential endpoint. |
| **air-issuer-service** | `/Users/adamplace/air-issuer-service` | SD-JWT issuer: signs credentials; admin endpoint `POST /admin/issue-sd-jwt`. |
| **minds-monster** | `/Users/adamplace/minds-monster` | Website + Cloudflare Worker: public "Connect your Mind" flow, credential renewal, chat proxy. |
| **adam-mind** | `/Users/adamplace/adam-mind` | X posting relay (related ecosystem, not directly in the Mind-connect flow). |

---

## 1. adam-id

**Key files**
- `src/mcp/admin.ts` — `/admin/issue-credential` handler; calls issuer admin endpoint.
- `src/mcp/http.ts` — wires admin handlers into HTTP server.
- `src/identity/credential.ts` — SD-JWT verification against issuer JWKS.
- `ops/cloudflared-config.yml` — tunnel ingress for `issuer.minds.monster` and `vault.minds.monster`.
- `.env` — secrets + config.

**Required env**
```bash
VAULT_ISSUER_URL=https://issuer.minds.monster
VAULT_ISSUER_VCT=https://adam.id/vct/adam-id-access/v1
VAULT_ISSUER_ADMIN_ORIGIN=https://issuer.minds.monster
VAULT_ISSUER_ADMIN_KEY=<issuer ADMIN_API_KEY>
VAULT_ADMIN_API_KEY=<shared with minds-monster worker>
CF_ACCESS_CLIENT_ID=<adam-id-to-issuer service token>
CF_ACCESS_CLIENT_SECRET=<adam-id-to-issuer service token secret>
VAULT_HTTP_ALLOWED_HOSTS=vault.minds.monster
```

**Recent change**
- `ops/cloudflared-config.yml` now routes `issuer.minds.monster/admin/*` through the tunnel so adam-id can reach it publicly.

---

## 2. air-issuer-service

**Key files**
- `src/app.controller.ts` — admin routes (`/admin/issue-sd-jwt`, `/admin/revoke-sd-jwt`).
- `src/issuer/dtos/issue-sd-jwt-request-body.dto.ts` — request schema.
- `.env` — `ADMIN_API_KEY`, `SD_JWT_ISSUER_ORIGIN=https://issuer.minds.monster`.

**Required state**
- Must serve `/.well-known/jwt-vc-issuer` publicly (verified: 200).
- Must serve `/admin/issue-sd-jwt` behind Cloudflare Access Service Auth.

---

## 3. minds-monster

**Key files**
- `index.html` — frontend connect widget + chat UI.
- `worker/src/index.ts` — routes: `/connect/init`, `/connect/status`, `/connect/issue-credential`, `/connect/renew`, `/chat`, etc.
- `worker/src/minds.ts` — HelloMinds API client for chat-based approval.
- `worker/wrangler.toml` — non-secret vars + production env block.
- `worker/.dev.vars` — local secrets.
- `worker/deploy.sh` — production deploy + `wrangler secret put`.

**Required env / secrets**
```bash
ADAM_ID_ADMIN_URL=https://vault.minds.monster
ADAM_ID_ADMIN_API_KEY=<same as VAULT_ADMIN_API_KEY>
CF_ACCESS_CLIENT_ID=<minds-monster-to-vault service token>
CF_ACCESS_CLIENT_SECRET=<minds-monster-to-vault service token secret>
MINDS_BUILDER_API_KEY=<HelloMinds builder API key>
ADMIN_API_KEY=<for /admin/approve-connection>
```

**Recent changes**
- `wrangler.toml` has `[env.production.vars]` with `ADAM_ID_ADMIN_URL = "https://vault.minds.monster"`.
- `.dev.vars` cleaned up to use only `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`.

---

## Current blockers

1. **Issuer admin endpoint returns 404 through Cloudflare Access**
   - With the new `adam-id-to-issuer-admin-ultimate-edition` token, Access passes (no 403 HTML).
   - But `POST https://issuer.minds.monster/admin/issue-sd-jwt` returns HTTP 404 with an empty body.
   - Likely cause: the running `air-issuer-service` process is not serving that route (old build or stale process).
   - Fix: restart/rebuild `air-issuer-service`.

2. **Config files not yet updated with the new tokens**
   - New token pairs exist but have not yet been written into:
     - `adam-id/.env`
     - `minds-monster/worker/.dev.vars`

3. **Worker not deployed**
   - After blocker 1 and the config update, run `minds-monster/worker/deploy.sh`.

---

## Verified working

- `adam-id` typechecks pass.
- `minds-monster/worker` typechecks pass.
- `https://issuer.minds.monster/.well-known/jwt-vc-issuer` → 200 public.
- `https://vault.minds.monster/mcp` with vault token → 401 (Access passed; missing credential is expected).

---

## Next steps

1. Restart / rebuild `air-issuer-service` and confirm `/admin/issue-sd-jwt` responds.
2. Update `adam-id/.env` and `minds-monster/worker/.dev.vars` with the new tokens.
3. Run `scripts/smoke-admin.ts` in adam-id.
4. Run `minds-monster/worker/deploy.sh`.
5. Test the live connect flow from `index.html`.
