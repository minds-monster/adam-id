# Phase 6 — exposing the vault through Cloudflare

Everything up to here runs on loopback. This is the step that lets a remote Mind
reach the vault, so it is also the step where a mistake is exposed to the
internet rather than to `127.0.0.1`. The order below is deliberate: the issuer
goes up first and is verified before the vault is exposed at all.

## What runs where

| hostname | path | reachable from the internet? |
|---|---|---|
| `issuer.minds.monster` | `/.well-known/*` | **yes, anonymously** — adam-id fetches signing keys here before it holds any credential |
| `issuer.minds.monster` | `/revocation-status/*`, `/credential-status/*` | yes, anonymously |
| `issuer.minds.monster` | everything else, incl. `/admin/*` | **no — 404 at the edge** |
| `vault.minds.monster` | `/mcp` | Access service token **and** a valid credential |

`/admin/*` is excluded in the tunnel's ingress rules, not merely in an Access
policy. `/admin/issue-sd-jwt` mints bearer credentials, and "guarded by an API
key header" is thin cover for an endpoint that hands out access to a private
archive. Enforcing it in ingress means it holds even if a dashboard policy is
missing, reordered, or set to Allow instead of Bypass. Mint over `127.0.0.1:3000`.

## 1. Create the tunnel

```bash
cloudflared tunnel login                 # browser; select the minds.monster zone
cloudflared tunnel create adam-id        # prints a UUID and writes ~/.cloudflared/<uuid>.json
cloudflared tunnel route dns adam-id issuer.minds.monster
cloudflared tunnel route dns adam-id vault.minds.monster

cp ops/cloudflared-config.yml ~/.cloudflared/config.yml
# replace REPLACE_WITH_TUNNEL_UUID in that file (two places) with the UUID above
cloudflared tunnel run adam-id
```

## 2. Access policies (Zero Trust → Access → Applications)

Two applications, and the first one is the one people get wrong:

**a. `issuer.minds.monster/.well-known/*` — Bypass / Everyone.**
adam-id fetches the issuer's signing keys from `/.well-known/jwt-vc-issuer`
*unauthenticated*, before it holds any credential. Put Access in front of that
path and every verification fails with `jwks_unreachable`. Create this bypass
policy **before** any catch-all rule on the issuer host, since Access evaluates
in order.

The failure mode to watch for: creating the application for `/.well-known/*` but
leaving its policy **Action** as *Allow* rather than *Bypass*. Allow still
requires an identity, so the path 302s to the Access login page — which then
returns HTTP 200 HTML, so a naive `curl` or a redirect-following `fetch` reports
success on a configuration that is broken. `npm run verify:tunnel` sets
`redirect: "manual"` and asserts the content type for exactly this reason.

If the only thing that needs to be public on this host is `/.well-known/*` and
the status endpoints — which is the case here — simply having **no** Access
application on the issuer host is also correct, since ingress already 404s
everything else.

**b. `vault.minds.monster/*` — Service Auth, service token only.**
Create the token under Access → Service Auth. You get a Client ID and Secret;
the secret is shown once. This is the second, independent gate: the credential
will end up in a conversation transcript, so a URL guarded only by the
credential is not a boundary. Either secret can be revoked from the dashboard
without touching Postgres or the vault.

Optionally restrict the rest of the issuer host (`issuer.minds.monster/admin/*`)
to your own identity — `/admin/issue-sd-jwt` mints bearer credentials.

## 3. Repoint the issuer at its public origin

The `iss` of every credential is also where a verifier fetches keys, so it has to
become the public hostname. In `air-issuer-service/.env`:

```
SD_JWT_ISSUER_ORIGIN=https://issuer.minds.monster
```

Leave `ISSUER_ORIGIN` alone — that is the `iss` of the *partner* JWT that Moca
validates against a whitelist, and repointing it would break partner auth
(confirmed working against `air.api.sandbox.air3.com` with the ES256 partner key).

Restart the issuer, then confirm the metadata agrees with itself:

```bash
curl -s https://issuer.minds.monster/.well-known/jwt-vc-issuer | jq .issuer
# must print "https://issuer.minds.monster" — a mismatch here is rejected by
# adam-id on purpose, as it is how a rogue metadata document would look.
```

**Credentials minted before this change do not verify after it.** Their `iss` is
still the old origin. Re-mint.

## 4. Point the vault at the public issuer

In `adam-id/.env`:

```
VAULT_ISSUER_URL=https://issuer.minds.monster
VAULT_ISSUER_VCT=https://adam.id/vct/adam-id-access/v1
VAULT_HTTP_ALLOWED_HOSTS=vault.minds.monster
```

`VAULT_HTTP_ALLOWED_HOSTS` is the one that costs an hour if forgotten. Tunnelled
requests arrive with `Host: vault.minds.monster`; the host guard rejects anything
not on the list, so without it every request returns `forbidden_host` — before
authentication, so the audit log shows a denial with no credential detail.

## 5. Verify

```bash
npm run verify:tunnel     # see ops/verify-tunnel.ts
```

Checks, in order: issuer metadata is public and self-consistent; the vault is
*not* reachable without the service token; it *is* reachable with it; a
credential minted from the public issuer verifies; and a request with a wrong
Host is refused.

## After a reboot

None of this is a system service except Postgres, so a restart or a logout takes the
issuer, the tunnel and the vault down, and a Mind's next call gets a 502 through the
tunnel or nothing at all.

```bash
ops/start-all.sh          # idempotent; starts whatever is down, in dependency order
ops/start-all.sh status   # report only
```

It finishes by checking the two properties that are easy to lose silently: that the
issuer's JWKS is publicly readable (200) and that the vault is refused at the edge without
a service token (403).

## Public issuance via the minds-monster worker

The guide above assumes a single machine where an operator mints credentials over
`127.0.0.1:3000`. For **minds.monster** — where any visitor clicks "Connect your
Mind" and gets a credential — the chain is different:

```
minds.monster  →  worker /connect/issue-credential
                        →  adam-id /admin/issue-credential  (CF Access + admin key)
                                →  issuer /admin/issue-sd-jwt  (CF Access + issuer admin key)
```

In this model the issuer admin endpoint **must** be reachable by adam-id. The
safest way is to route it through the same tunnel and protect it with a Cloudflare
Access *service-token* policy (not a human identity policy):

1. Add an ingress rule for `issuer.minds.monster/admin/*` in
   `ops/cloudflared-config.yml` (see the commented example in that file).
2. In Zero Trust → Access → Applications, create an application for
   `issuer.minds.monster/admin/*` with **Service Auth** action.
3. Give adam-id the service token via `CF_ACCESS_CLIENT_ID` and
   `CF_ACCESS_CLIENT_SECRET`, plus the issuer admin key via
   `VAULT_ISSUER_ADMIN_KEY`.
4. Set `VAULT_ISSUER_ADMIN_ORIGIN=https://issuer.minds.monster` so adam-id calls
   the public origin instead of loopback.

Then deploy/adam-id with:

```
VAULT_ISSUER_URL=https://issuer.minds.monster
VAULT_ISSUER_VCT=https://adam.id/vct/adam-id-access/v1
VAULT_ISSUER_ADMIN_ORIGIN=https://issuer.minds.monster
VAULT_ISSUER_ADMIN_KEY=<issuer ADMIN_API_KEY>
VAULT_ADMIN_API_KEY=<random key for the worker>
CF_ACCESS_CLIENT_ID=<issuer admin service token id>
CF_ACCESS_CLIENT_SECRET=<issuer admin service token secret>
VAULT_HTTP_ALLOWED_HOSTS=vault.minds.monster
```

And deploy the worker with:

```
ADAM_ID_ADMIN_URL=https://vault.minds.monster
ADAM_ID_ADMIN_API_KEY=<same random key>
CF_ACCESS_CLIENT_ID=<vault service token id>
CF_ACCESS_CLIENT_SECRET=<vault service token secret>
```

The worker README has the rest of the worker-specific deploy steps.

## What this does not fix

The credential remains a bearer token — no `cnf` key binding, and a Mind has no
secret store, so both the credential and the service token transit the
conversation transcript. This step adds a second secret and a revocation surface
that does not depend on the issuer being up. It does not stop disclosure. Keep
expiry short and scopes minimal.
