# adam-id

A private vault over your X (Twitter) archive, exposed to an AI agent through MCP so it can
draft posts in your voice, grounded in what you actually wrote and how it actually performed.

Your archive never leaves your machine. Everything is encrypted at rest under a key you hold,
the ciphertext store is the record of truth, and every tool call the agent makes is logged.

## Quick start

```bash
npm install
npm run vault -- ingest     # parse the archive into a normalized corpus
npm run vault -- index      # build the SQLite FTS5 search index
npm run vault -- doctor     # check what's wired up
npm run smoke               # drive the MCP server end-to-end
```

Then register it with Claude Code using [config/mcp-config.json](config/mcp-config.json) and ask
it to draft something. Optionally encrypt the corpus for durable storage:

```bash
npm run vault -- seal --skip-media   # encrypt the text corpus, anchor a Merkle root
npm run vault -- verify              # prove the store is intact and decryptable
```

The first `seal` generates a 32-byte key and stores it in your macOS Keychain
(`adam-id-vault` / `master-kek`). **Back that up** — without it the store cannot be opened. On a
headless machine set `VAULT_PASSPHRASE` instead.

Sealing media (`seal` without `--skip-media`) writes a second, encrypted copy of every file, so
it needs ~2.2 GB free on top of the archive; `seal` checks up front and refuses rather than
failing halfway. This machine currently has ~2.1 GB free, so only the text corpus has been
sealed here. Nothing depends on media being sealed: `get_media` reads from the archive either
way. Media sealing exists for eventual upload to MCSP, where a local second copy isn't the point.

## What's in the archive

Measured from this export (2026-08-02), not estimated:

| | count | | count |
|---|---|---|---|
| posts | 8,270 | likes | 11,411 |
| — replies | 5,968 | followers | 2,422 |
| — originals | 946 | following | 910 |
| — retweets | 856 | DM messages | 35,251 |
| — quotes | 351 | media files | 2,940 (2.13 GB) |
| — self-replies | 149 | multi-post threads | 87 |

`posts` spans `tweets.js`, `community-tweet.js` and `deleted-tweets.js`. 342 posts had their
truncated text replaced with the full body from `note-tweet.js`.

### What the archive does not contain

These limits are structural, not implementation gaps, and the agent is told about them:

- **No impressions, views, reply counts, bookmarks or profile clicks.** X archives contain none
  of it — there is no bookmarks file at all. Performance analysis is likes and retweets only.
  The X Analytics CSV export is the only source for reach, and could be joined on tweet id later.
- **Engagement is recorded for ~67% of posts**, and a missing count is indistinguishable from a
  true zero. Aggregates therefore compute over posts with nonzero recorded engagement and report
  `coverage` alongside every statistic, rather than treating absence as zero.
- **No follower history**, so engagement can't be normalized by audience size. Percentiles are
  computed within `(year, kind)` buckets instead — the strongest honest comparison available.
- **Likes have no timestamp or author**, only text.
- **The social graph is numeric account ids with no usernames.** Handles for ~30% of accounts
  were recovered by harvesting mentions from elsewhere in the archive.

## Architecture

```
twitter-*/                 read-only X archive
   │ ingest                generic YTD parser driven by manifest.js
corpus/*.ndjson            canonical records + threads, percentiles, media links
   │ index                 SQLite FTS5 (BM25)  ── the queryable working set
   │ seal                  AES-256-GCM envelope per object + Merkle root
store/objects/             ciphertext  ──[StorageAdapter]──→ MCSP (not provisioned)
                                       ──[AnchorAdapter]───→ Moca testnet
   │ rebuild                           ← restores corpus + index from ciphertext alone
mcp serve                  scoped, audited tools ← Claude Code / Animoca Mind
```

The search index is a **derived cache**. `vault rebuild` reconstructs the corpus and index from
sealed objects plus your key, which is what makes the ciphertext store the record of truth
rather than a backup. This is verified in practice: deleting `corpus/` and rebuilding produces
a byte-identical fingerprint across search, style and engagement queries.

**You cannot search ciphertext.** MCSP holds encrypted blobs; the index is local and decrypted.
That is stated plainly here because the alternative reading — searchable encryption — is not
what this does.

## MCP tools

Each tool is gated by one scope. A tool whose scope isn't granted is **never registered**, so the
agent cannot see or call it — a stronger guarantee than refusing at call time.

| tool | scope |
|---|---|
| `vault_info` — what's in the vault and which limitations apply | tweets.read |
| `search_tweets` — full-text with date/kind/likes/media filters | tweets.read |
| `get_tweet` — one post, optionally with thread and reply context | tweets.read |
| `get_thread` — a whole self-thread in order | tweets.read |
| `get_timeline` — browse a date range | tweets.read |
| `analyze_style` — measured length, emoji/hashtag/link rates, openers, cadence | tweets.read |
| `engagement_stats` — aggregates grouped by kind/year/hour/weekday/media | analytics.read |
| `top_performers` — best and worst posts by recorded likes | analytics.read |
| `search_likes` — the 11,411 tweets you liked | likes.read |
| `get_audience` — followers/following, handles where resolvable | graph.read |
| `get_media` — images inline; video as path + thumbnail | media.read |
| `search_dms` — **off by default** | dms.read |

`VAULT_SCOPES` controls the grant. `dms.read` is excluded by default because DMs contain other
people's words; turning them on should be deliberate. Every call, and every denial, appends to
`audit.log`.

Search note: bare terms match as **prefixes**, because handles tokenize as one word — an exact
search for `songjam` misses all ~1,300 posts mentioning `@SongjamSpace`. Quote a term for an
exact match (`"songjam"` → 208 hits vs 1,265).

## Encryption

Envelope encryption: each object gets a fresh random data key (DEK) under AES-256-GCM, and the
DEK is wrapped under a key-encryption key (KEK) held in the macOS Keychain (or derived from
`VAULT_PASSPHRASE`).

The indirection earns its keep twice. A per-object DEK means one random nonce per key, avoiding
GCM nonce reuse. And rotating the KEK only rewraps the small DEK blobs — **migrating to a
Moca CAK-derived key will not re-encrypt the 2 GB of media.**

`vault verify` runs three independent checks, because each catches a different failure:

1. every object still matches its recorded ciphertext digest (corruption, partial writes)
2. the Merkle root recomputed from disk matches the manifest and the anchor (additions and
   deletions, which per-object digests alone would miss)
3. a sample of objects actually decrypts and matches its plaintext digest (a wrong or rotated
   key, which hashing alone would not catch)

Anchoring publishes one Merkle root rather than 2,940 per-object proofs — leaves are sorted by
key so the root is order-independent, and leaf/node hashes use distinct domain prefixes to
prevent second-preimage confusion.

Verified in practice: flipping a single byte in one ciphertext blob is caught by all three
checks independently, and an interrupted write is reported as a specific inconsistency rather
than crashing the verifier.

## Moca integration status

| piece | state |
|---|---|
| Moca testnet RPC | **working** — chainId 223400, verified live |
| Merkle-root anchoring | **implemented** — needs a funded `MOCA_ANCHOR_PRIVATE_KEY` |
| Agent keypair (`registerAgentKey`) | **implemented** — `vault agent-key` + companion page |
| Credential verification | **working** — [src/identity/credential.ts](src/identity/credential.ts), 22 checks in `npm run smoke:credential` |
| Credential-gated HTTP transport | **working** — `vault serve --http`, 26 checks in `npm run smoke:http` |
| Per-Mind grant table | **working** — `vault grant` / `revoke` / `grants` |
| SD-JWT-VC issuance | **working** — `POST /admin/issue-sd-jwt`, signed by the real partner key |
| Issuer-side revocation | **working** — `POST /admin/revoke-sd-jwt`, no iden3 dependency |
| Dashboard AIR credential | **working** — `XDataAccess` issued to DStorage via Direct Issuance |
| Cloudflare Tunnel exposure | **working** — `vault.minds.monster` behind an Access service token |
| Mind playbook | **written** — `adam-mind/playbooks/adam-id-vault-v1.md`, not yet installed |
| CAK-derived KEK | **blocked** — Credential Services pending activation |
| MCSP storage | **blocked** — no client exists to call |

### Gating the vault behind a Moca credential

A remote agent — an Animoca Mind — can query the vault over HTTP only if it presents
a valid credential *and* has been granted access locally. Both gates must agree, and
the effective scopes are their intersection: an over-broad credential cannot exceed
the local grant, and a generous grant does nothing without a valid credential.

```bash
vault grant --mind <mind-id> --scopes tweets.read --days 1
vault serve --http --port 8787          # loopback only; tunnel to it deliberately
vault revoke --mind <mind-id>           # instant, offline, tears down live sessions
```

**Why the credential is an SD-JWT-VC and not an AIR credential proper.** It cannot be
one. An AIR-issued VC is encrypted to the holder's public key and stored in DStorage;
no issuance endpoint ever returns it, and verifying one means `AirService.verifyCredential`
— a browser iframe flow requiring the holder's live session and their consent to
decrypt. A headless Mind can neither retrieve, decrypt, nor present that. So what a
Mind actually sends is an SD-JWT-VC signed by the same whitelisted AIR partner key,
which this server verifies with `jose` against the issuer's published JWKS. That
credential's `vct` is self-asserted rather than registered in the AIR dashboard: it is
cryptographically real, but AIR's own verifier programs will not consume it. A parallel
dashboard-issued VC can serve as the network-recognised record of a grant; it plays no
part in per-request authorization.

**The credential is a bearer token, and that is the weak point.** The issuer's `cnf`
key binding is a TODO, and a Mind has no secret store — the credential transits the
conversation transcript and is persisted to long-term memory. Anyone who reads that
transcript has the granted access until expiry. Challenge-response with the agent key
cannot fix this, because the Mind cannot hold a private key: signing with a key that
lives in a transcript is signing with a public secret. The mitigations are blast-radius
reduction, not prevention — short expiry, instant local revocation, minimal scopes
(`vault grant` refuses `dms.read` without an explicit override), loopback binding with
a tunnel in front, and every call attributed in `audit.log`. Putting a second,
independent secret at the tunnel (a Cloudflare Access service token) is strongly
advised: a public URL guarded only by a token designed to appear in an LLM transcript
is not a security boundary.

Failures are distinguishable on purpose — `credential_expired` means re-issue,
`credential_issuer` means something is impersonating your issuer, `grant_missing` means
the credential is fine but you never granted it. Revocation checks **fail closed**, so
an unreachable issuer denies access rather than assuming validity.

**Two revocation paths, and they are not equivalent.** `vault revoke` is local: it needs
nothing to be reachable, takes effect immediately, and tears down sessions already open.
Revoking at the issuer (`POST /admin/revoke-sd-jwt`) is the durable record, but a
successful check is cached for 60s (`VAULT_REVOCATION_TTL_MS`), so it takes up to that
long to stop a *new* session from a credential just used, and it does not touch live
sessions at all. Reach for `vault revoke` when it matters; use issuer revocation to make
it permanent.

### Issuing a credential

With [air-issuer-service](../air-issuer-service) running (Postgres up, migrations applied):

```bash
curl -X POST http://127.0.0.1:3000/admin/issue-sd-jwt \
  -H 'content-type: application/json' -H "x-admin-api-key: $ADMIN_API_KEY" \
  -d '{"schemaId":"adam-id-access-v1","holderDID":"did:air:...",
       "mindId":"<mind-id>","scopes":["tweets.read"],"label":"Adam (Hello Minds)"}'
```

Returns `{credential, credentialId, nonce, expiresAt}`. Unlike `/issue-vc`, this hands the
credential back rather than encrypting it to the holder and pushing it to DStorage —
necessary because the holder here is headless and could never decrypt it.

Verify the whole loop against a live issuer with `npm run smoke:issuer`.

### The two credentials, and why both exist

| | runtime credential | dashboard credential |
|---|---|---|
| format | SD-JWT-VC, `adam-id-access-v1` | iden3 `XDataAccess`, BJJSignature2021 |
| where it lives | presented as a bearer header | encrypted in Moca DStorage |
| who verifies it | this vault, server-side with `jose` | AIR verifier widget, Program `c29c50g0ltcs48yud0n1a2` |
| gate access? | **yes** | no |
| revocable by us? | yes, `POST /admin/revoke-sd-jwt` | see caveat below |

A Mind can only present the first. The second is network-recognised provenance that a
grant was made, issued with `npm run issue-air-credential`; nothing in the request path
reads it.

**Caveat on the dashboard credential's revocation.** Its `credentialStatus.id` points at
`https://issuer.staging.air3.com/credential-status/<nonce>` — derived from `ISSUER_ORIGIN`,
which must stay as Moca's host for partner auth to work. So the status URL embedded in that
credential is not ours to serve, and revoking it locally does not change what an AIR
verifier sees. Treat it as a record of issuance, not a control surface. Access is revoked by
`vault revoke` and by revoking the SD-JWT.

Two constraints worth knowing, both verified against `@mocanetwork/airkit@1.10.0`:

- **AIR Kit is browser-only.** `AirService` drives `HTMLIFrameElement`, so it cannot be imported
  into the Node MCP server. Anything needing it lives in
  [web/companion.html](web/companion.html); anchoring uses `viem` with a local key instead.
- **AIR Kit ships no storage API.** Grepping its `dist` for `mcsp|dstorage|storageProvider|uploadBlob|putObject`
  returns nothing. [src/storage/mcsp.ts](src/storage/mcsp.ts) therefore implements the interface
  and fails loudly listing what's missing, rather than shipping a guessed REST contract that
  would silently not work.

When Credential Services activate, `issueCredential` returns `cakPublicKey`; that becomes the
KEK and `rewrapAll` migrates the store without re-encrypting anything.

## Commands

```
vault ingest                    parse the archive into corpus/
vault index                     build the FTS5 index
vault seal [--skip-media]       encrypt into store/, anchor the root
     [--storage local|mcsp] [--anchor local|moca-testnet]
vault verify [--spot-checks N]  digests + Merkle root + real decryption
vault anchor [--anchor ...]     publish the current root
vault rebuild                   restore corpus + index from ciphertext
vault agent-key                 create/show the agent keypair
vault serve [--http] [--port N] MCP server over stdio, or credential-gated HTTP
vault doctor                    status of archive, corpus, key, storage, anchor

vault grants                    who may reach the vault remotely, and how far
vault grant --mind <id> --scopes a,b [--label L] [--days N] [--note "..."]
vault revoke --mind <id>        cut off a Mind immediately
```

Tests:

```
npm run smoke              stdio MCP end-to-end
npm run smoke:credential   every way a credential can be wrong
npm run smoke:http         the credential-gated HTTP path, offline
npm run smoke:all          all three
```

## Privacy

`.gitignore` excludes the archive, `corpus/`, `store/`, `*.db`, `audit.log` and `.env`. The
archive contains your email address, phone number, contact book, IP audit log and DMs — none of
it should reach git. Check with `git status` before committing.
