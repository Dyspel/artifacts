# Artifacts (prototype)

A versioned filesystem that speaks Git. Agent-first. Fork in a metadata write.

This is a **feasibility prototype**. It is not production software. It exists
to prove that the architectural claims of an Artifacts-style product — real
Git client interop, O(1) forks, a REST side-door — can be made to work
end-to-end in a day, not a quarter.

> If you want the *why*, read [ARCHITECTURE.md](./ARCHITECTURE.md). This file
> is the *what* — the surface, the numbers, and the commands. For wiring
> this into the [Dyspel collaborative AI IDE](https://github.com/dyspel),
> see [DYSPEL.md](./DYSPEL.md) — it covers the JWT handoff, the
> gitSyncService migration, and what's still open before production
> traffic. For a live view of what the server knows about itself —
> repos, forks, metrics — see [GUI.md](./GUI.md) (eframe/egui,
> Wayland-ready).

## What this is *not*, plainly

- **Not secure out of the box.** HTTP only, no TLS. Tokens travel in the
  URL (as git clients do) — if you run this over the public internet
  without TLS in front, you're broadcasting credentials. Put nginx /
  caddy / cloudflare-tunnel / any TLS terminator in front of the
  listener before exposing it. See [Security](#security-in-one-paragraph).
- **Not rate-limited.** The admin token has unlimited create / fork /
  delete. An insider with it can fill the disk and burn inodes. No
  quotas, no per-token caps, no audit log.
- **Not a drop-in for a multi-backend storage story.** `Storage` and
  `RefStore` are traits with one filesystem impl each. They're trait
  boundaries, not Spring-style pluggable backends — any real second impl
  of either depends on the git protocol layer going native (M1b-next),
  which hasn't happened yet. See [Design decisions](#design-decisions-worth-arguing-about).
- **Not tested against non-`git` clients.** The protocol work is
  delegated to `git upload-pack` / `git receive-pack` (for the
  expensive half) and to a small native pkt-line writer (for the v2
  capability advertisement). It should work with `libgit2`,
  `isomorphic-git`, `go-git`, `jgit` — all of them speak the same wire
  protocol — but the smoke test only exercises CLI `git`.

## Table of contents

- [Status](#status)
- [What's next](#whats-next)
- [Numbers we just measured](#numbers-we-just-measured)
- [Quickstart](#quickstart)
- [API reference](#api-reference)
- [Directory layout](#directory-layout)
- [How a fork works](#how-a-fork-works)
- [Development](#development)
- [Roadmap](#roadmap)
- [Design decisions worth arguing about](#design-decisions-worth-arguing-about)

## Status

**What works end-to-end today:**

| Feature                                                          | Status |
| ---------------------------------------------------------------- | ------ |
| `POST /v1/repos` — create empty repo, get `{ remote, token }`    | ✅     |
| `POST /v1/repos/:id/forks` — O(1) fork via `alternates`          | ✅     |
| `POST /v1/repos/:id/tokens` — mint additional scoped tokens      | ✅     |
| `DELETE /v1/repos/:id` — delete a repo                           | ✅     |
| `git clone https://x:$TOKEN@host/git/:id.git`                    | ✅     |
| `git push` / `git fetch` / `git pull`                            | ✅     |
| `git clone` of a fork — objects transparently via `alternates`   | ✅     |
| Per-repo token scoping (`read` vs `write`, enforced on push)     | ✅     |
| `readOnly: true` forks that reject pushes                        | ✅     |
| v1 + v2 git protocol (inherited from `git http-backend`)         | ✅     |
| `POST /v1/repos/:id/commits` — REST-side commits (no git client) | ✅     |
| CAS refs: 409 `ref_conflict` with `expected` + `current` fields  | ✅     |
| `RefStore` trait abstraction (FS-backed M0 impl)                 | ✅     |
| `Storage` trait abstraction (FS-backed M0 impl)                  | ✅     |
| `TokenStore` trait + SQLite persistence across restart           | ✅     |
| Tokens with TTL, revocation endpoint, SHA-256 hashed at rest     | ✅     |
| `git-http-backend` CGI removed — direct pack-handler shell-outs   | ✅     |
| Native v2 `info/refs` — no subprocess for the discovery request  | ✅     |
| JWT verification on REST (Dyspel-signed HS256 accepted)          | ✅     |
| Per-repo ownership + cross-user 403 enforcement                  | ✅     |
| Refuse non-loopback HTTP bind without `--allow-insecure`         | ✅     |
| Per-user repo-count quota (429 `quota_exceeded`)                 | ✅     |
| Per-subject token-bucket rate limiter (429 `rate_limited`)       | ✅     |
| Per-blob size cap on REST commits                                | ✅     |
| Prometheus `/metrics` endpoint (request counts, latencies, errors) | ✅   |
| `X-Request-Id` header roundtrip + structured per-request log     | ✅     |
| `GET /v1/admin/repos` list + `GET /v1/admin/repos/:id` detail    | ✅     |
| `artifacts-gui` Wayland/X11 visualizer (feature-gated)           | ✅     |

**Known not-yet:**

| Feature                                                          | Status |
| ---------------------------------------------------------------- | ------ |
| Native pack indexing via gix-pack (replaces `git unpack-objects` on push) | 🟡 M1b-3-gix |
| Chunked-KV / object-store `Storage` impl — `ObjectStore` trait scaffolded | 🟡 M2b |
| Multi-node distributed `RefStore` impl — trait + `MemRefStore` conformance ready, consensus log remains | 🟡 M3b |
| Per-token self-revocation, bulk rotate     | ✅ M4b |
| Account-level credentials + token listing  | 🟡 M4b-next |
| Webhooks (HMAC-signed) + Prometheus metrics | ✅ M6 |
| LFS, replication, PITR | 🟡 M6-other |

## What's next

**The CGI layer is gone (M1a).** `git-http-backend` was a wrapper — a
process that parsed CGI env vars and re-spawned `git upload-pack` or
`git receive-pack` internally. We now spawn the pack handlers directly,
which cut clone-latency p99 by ~27% and max by ~63%.

**The full v2 native protocol layer is in (M1b-1 / M1b-2 / M1b-3).**
`info/refs`, `command=ls-refs`, `command=fetch`, and `git-receive-pack`
are all served from in-process Rust — pkt-line + sideband framing,
ref enumeration off disk, ref CAS via the `RefStore` trait. The fetch
path's pack generation is fully native via `gix-pack` (M1b-2c). The
push path's pack indexing still calls `git unpack-objects --stdin` as
the sole remaining subprocess on the protocol hot path; that swap is
the next-logical commit (M1b-3-gix).

Remaining, in order:

1. **M1b-3-gix — native pack indexing via `gix-pack`.** The leaf
   subprocess on the push path. Same architectural shape as
   M1b-2c (which swapped `git pack-objects` for native gix-pack
   on the fetch side); the receive side gets the same treatment.
2. **M2b — chunked-KV `Storage` impl.** Second impl of the trait.
   `ObjectStore` trait scaffolded; full chunked-KV
   `Storage` lifecycle waits on M1b-3-gix so no production
   subprocess assumes a `<repo>/objects/` directory exists on disk.
3. **M3b — distributed `RefStore` impl.** `MemRefStore` + concurrent
   CAS conformance test landed; consensus log (openraft) + per-repo
   state machine + leader election + snapshot install remain.
4. **M4b-next — account-level credentials.** Token-subject column
   on the SQLite store + per-repo `GET /v1/repos/:id/tokens`
   listing. Self-revoke and bulk rotate already shipped.
5. **M6-deliver — durable webhook subscriptions + retries.**
   In-memory `MemRegistry` + best-effort delivery is in;
   SQLite-backed registry + retry-with-backoff + per-delivery
   metrics are the next slice.
6. **M6-other — LFS, replication, PITR.** Each is genuinely
   multi-week.

## Numbers we just measured

10,000 forks of a real 28 KB seed repo (30 files across `src/`, `docs/`,
`tests/`), parallelism 32, on this host's release build:

```
forks done in 3.52s (2837 forks/sec wall clock)
latency ms: p50=0.34  p95=0.63  p99=50.2  max=230.0
repos dir total:    2,308,837 bytes
source alone:          28,837 bytes
added by forks:     2,280,000 bytes  →  228 bytes/fork
(a full copy would have added ~288,370,000 bytes)
```

**228 bytes/fork vs ~28 KB/copy — ~126× less disk per fork.** After all
10,000 forks a random one clones cleanly and its working tree byte-matches
the source.

### Clone latency (sequential clones of a 28 KB seed repo)

Measured via `scripts/bench_clone.sh`:

|        | M0 (CGI) | M1a (direct) | M1b-1 (+ native v2 info/refs) |
| ------ | -------: | -----------: | ----------------------------: |
| p50    | 14.5 ms  | 13.4 ms      | 13.0 ms                       |
| p95    | 17.2 ms  | 14.9 ms      | 15.0 ms                       |
| p99    | 21.5 ms  | 15.6 ms      | 16.1 ms                       |
| max    | 45.8 ms  | 16.9 ms      | 17.9 ms                       |

M1a killed the CGI wrapper — that's where the big tail-latency win lives
(p99 −27%, max −63%). M1b-1 went native on the discovery response; a
small p50 nudge because that endpoint was the cheaper of the two git
subprocesses. The remaining M1b steps (native fetch / receive-pack via
gitoxide) hit the expensive half.

## Quickstart

**Requirements:** Rust stable (we've tested 1.75+) and `git` ≥ 2.30 on
`$PATH`. We invoke `git upload-pack` and `git receive-pack` directly for
smart-HTTP (no CGI wrapper, no git-http-backend dep).

Run the server:

```sh
cargo run --release -- serve \
    --data-dir ./data \
    --bind 127.0.0.1:8787 \
    --public-base-url http://127.0.0.1:8787
```

On startup the server prints an admin token to stderr. Use that token for
REST calls, or set `ARTIFACTS_ADMIN_TOKEN` to pin it.

Create a repo, clone it, push to it:

```sh
ADMIN="<admin token from stderr>"

# Create a repo. The response gives you a ready-to-clone URL.
curl -sS -X POST \
    -H "Authorization: Bearer $ADMIN" \
    http://127.0.0.1:8787/v1/repos
# → {"id":"abc...","remote":"http://x:TOKEN@127.0.0.1:8787/git/abc....git","token":"TOKEN"}

# Clone. The credentials are already in the URL, so no prompting.
git clone "http://x:TOKEN@127.0.0.1:8787/git/abc....git" ./work

cd work
echo "hi" > README.md
git add . && git commit -m "first"
git push -u origin main
```

Fork it:

```sh
curl -sS -X POST \
    -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' \
    -d '{"readOnly": false}' \
    "http://127.0.0.1:8787/v1/repos/abc.../forks"
# → {"id":"def...","remote":"http://x:TOKEN2@127.0.0.1:8787/git/def....git","token":"TOKEN2"}
```

Run the test suite:

```sh
cargo test                # unit tests
./tests/smoke.sh          # 7-step end-to-end: create / clone / push / fork / scopes
./scripts/bench_fork.sh   # fork benchmark (FORKS=10000 PARALLEL=64 by default)
```

## API reference

### Authentication

Two auth schemes, used for different paths.

| Scheme | Header | Used by | Carrying |
| ------ | ------ | ------- | -------- |
| Bearer | `Authorization: Bearer $ADMIN_TOKEN` | all `/v1/*` REST endpoints | the static admin token |
| Basic  | `Authorization: Basic base64(x:$TOKEN)` | all `/git/*` endpoints   | a per-repo token minted by the REST API |

For git endpoints, the expected way to pass the token is by embedding it in
the clone URL: `https://x:$TOKEN@host/git/$ID.git`. Git handles the HTTP
Basic handshake automatically from there, including the initial probe + 401
challenge dance.

### Health

`GET /v1/health` → `{"ok":true}` — no auth.

### Create repo

```
POST /v1/repos
Authorization: Bearer <admin>
Content-Type: application/json

{ "id": "optional-caller-supplied-id" }
```

Response:

```json
{
  "id": "n11g4bw6j4vwoy0ackf1ubv7",
  "remote": "http://x:8O3F6me...@127.0.0.1:8787/git/n11g4bw6j4vwoy0ackf1ubv7.git",
  "token": "8O3F6me..."
}
```

The returned token has **write** scope. If you don't pass an `id`, the
server generates a 24-character lowercase-alphanumeric one.

### Fork a repo

```
POST /v1/repos/:id/forks
Authorization: Bearer <admin>
Content-Type: application/json

{ "id": "optional-fork-id", "readOnly": false }
```

Response is the same shape as create. `readOnly: true` mints a read-only
token; any push to that fork will be rejected with 403. The fork itself is
still pushable — you can call `POST /tokens` later to mint a write token for
it.

Fork is O(1) in both time and disk (see [How a fork works](#how-a-fork-works)).

### Mint a token

```
POST /v1/repos/:id/tokens
Authorization: Bearer <admin>
Content-Type: application/json

{
  "scope": "read",
  "ttlSeconds": 3600          // optional; omit for no expiry
}
```

Scope is `"read"` or `"write"`. Response:

```json
{
  "token":    "...",
  "remote":   "http://x:...@host/git/...git",
  "expiresAt": 1734567890     // unix epoch seconds, null if no TTL
}
```

Tokens are stored as SHA-256 hashes in `<data-dir>/tokens.db` (SQLite).
A restart of the server does *not* invalidate them — this is the
whole point of M4's persistence layer.

### Revoke a token

```
POST /v1/tokens/revoke
Authorization: Bearer <admin>
Content-Type: application/json

{ "token": "<the raw token>" }
```

Response:

```json
{ "revoked": true }           // false = already revoked or unknown
```

Why POST with the token in the body instead of `DELETE /tokens/:token`?
Because paths land in access logs. Bodies don't. This keeps revoked
tokens out of log archives.

Revocation is idempotent. A second revoke of the same token returns
`{ "revoked": false }`.

### Delete a repo

```
DELETE /v1/repos/:id
Authorization: Bearer <admin>
```

Response: `{"ok":true}`. In the prototype this is a raw `rm -rf` on the
repo directory. Production needs soft-delete + alternates-aware GC so you
can't tombstone a repo that's still the object source for a live fork.

### Create a commit (no git client required)

```
POST /v1/repos/:id/commits
Authorization: Bearer <admin>
Content-Type: application/json

{
  "branch": "main",
  "parent": null,                        // or "abc123..." — CAS predicate
  "message": "update README",
  "author": { "name": "Agent", "email": "agent@example.com" },
  "changes": [
    { "op": "write",  "path": "README.md", "content": "# Hello\n" },
    { "op": "write",  "path": "img/logo.png", "contentBase64": "iVBORw0…", "mode": "100644" },
    { "op": "delete", "path": "old/thing.txt" }
  ]
}
```

Response:

```json
{
  "commit": "a1b2c3…",
  "tree":   "d4e5f6…",
  "branch": "main"
}
```

Semantics:

- `parent` is the **compare-and-swap predicate.** The commit is only
  applied if the branch currently points at `parent`. `null` means the
  branch must not yet exist (i.e. this is the initial commit / new branch).
- Changes are applied **in order** on top of `parent`'s tree. If the same
  path appears twice, the later write wins.
- `content` is UTF-8. `contentBase64` is arbitrary bytes. One or the other,
  not both. If neither is set, the file is written as empty.
- `mode` defaults to `100644` (regular file); `100755` is also accepted
  (executable).
- Paths must be relative, have no `..` or `.` components, and no empty
  path segments.

On CAS miss:

```
HTTP 409 Conflict

{
  "error": {
    "code": "ref_conflict",
    "message": "ref conflict on branch main",
    "branch": "main",
    "expected": "a1b2c3…",     // the SHA the caller thought was current
    "current":  "9f8e7d…"      // the SHA actually on the branch right now
  }
}
```

Clients should re-read, rebase their change set, and retry. The `current`
field lets them do that without a second round trip.

### Metrics

```
GET /metrics
```

Returns Prometheus text format (no auth). Scrape at whatever interval
your monitor prefers.

Exposed metrics:

| Name                                           | Kind      | Labels                   |
| ---------------------------------------------- | --------- | ------------------------ |
| `artifacts_requests_total`                     | counter   | `method`, `path`, `status` |
| `artifacts_request_duration_seconds`           | histogram | `method`, `path`         |
| `artifacts_rate_limited_total`                 | counter   | —                        |
| `artifacts_quota_exceeded_total`               | counter   | —                        |
| `artifacts_build_info`                         | gauge     | `version`                |

The `path` label is the **route template** (`/v1/repos/:id/tokens`),
not the concrete URI. Cardinality is bounded by the route table, not
by the number of repos created.

Histogram buckets are tuned for HTTP latency (1 ms through 10 s, 12
buckets). Good for percentile approximation up to p99-ish; if you
need finer resolution, tighten the bucket list in `src/metrics.rs`.

### Request IDs

Every response carries an `X-Request-Id: <id>` header. If the caller
supplied one on the request and it's well-formed (≤128 chars of
`[A-Za-z0-9_-]`), we echo it back; otherwise we generate a UUIDv4
(32-char hex). The id is attached to the per-request tracing span so
every log line the handler emits carries `request_id=<id>` as a
structured field — grep-friendly for incident debugging.

### Admin inspection (read-only)

```
GET /v1/admin/repos         →  [{ id, owner, createdAt, sourceId? }, ...]
GET /v1/admin/repos/:id     →  { …summary, sizeBytes, refs: [{ name, sha }] }
```

Both admin-only. `sourceId` is derived by reading the repo's
`objects/info/alternates` file, so forks are discoverable via the
admin list without a separate column. The list endpoint intentionally
omits size and ref walks (O(n_repos) each); those live on the detail
endpoint, which walks only the requested repo.

Powers [`artifacts-gui`](./GUI.md) — the Wayland/X11 live viewer — and
any other tooling that needs to browse server state out-of-band.

### Git endpoints

The standard smart-HTTP surface, exposed under `/git/:id.git/`:

```
GET  /git/:id.git/info/refs?service=git-upload-pack    # fetch/clone discovery
GET  /git/:id.git/info/refs?service=git-receive-pack   # push discovery
POST /git/:id.git/git-upload-pack                      # fetch/clone
POST /git/:id.git/git-receive-pack                     # push
```

You don't call these by hand — they exist for git clients. Auth is HTTP
Basic with the repo token; scope is enforced (`receive-pack` requires
`write`).

## Directory layout

```
artifacts/
├── Cargo.toml                 cargo manifest (single binary crate)
├── README.md                  this file
├── ARCHITECTURE.md            the three hard problems, prototype vs production
├── src/
│   ├── main.rs                CLI + server wiring (axum router)
│   ├── config.rs              runtime config (data dir, base URL, admin token)
│   ├── error.rs               error type + IntoResponse + WWW-Authenticate
│   ├── tokens.rs              in-memory token store, scopes
│   ├── auth.rs                Basic/Bearer extraction + authorization helpers
│   ├── tokens.rs              TokenStore trait + InMemory + SQLite impls
│   ├── refs.rs                RefStore trait + FsRefStore (CAS via update-ref)
│   ├── storage.rs             Storage trait + FsStorage (fork-via-alternates — THE CORE)
│   ├── smart_http.rs          direct shell-outs to git upload-pack / git receive-pack
│   ├── commits.rs             REST-side commits (POST /v1/repos/:id/commits)
│   ├── rest.rs                REST endpoints (create / fork / tokens / revoke / delete / admin)
│   └── bin/
│       └── artifacts-gui.rs   feature-gated: eframe/egui Wayland/X11 visualizer
├── tests/
│   └── smoke.sh               14-step end-to-end: create → clone → push → fork → scopes → REST commits → revoke → restart → JWT → quota → blob-cap → /metrics
└── scripts/
    ├── bench_fork.sh          10,000-fork benchmark; measures disk + latency
    └── bench_clone.sh         clone-latency benchmark; p50/p95/p99/max over N clones
```

Under `$DATA_DIR` at runtime:

```
data/
├── tokens.db                  SQLite — minted tokens (hashed), expiry, revocation
└── repos/
    ├── abc12...xy.git/        bare git repo (source)
    │   ├── HEAD
    │   ├── config
    │   ├── refs/heads/main    ← SHA-1 ref
    │   └── objects/…          ← loose + packed objects
    └── def34...z7.git/        bare git repo (fork)
        ├── HEAD
        ├── config
        ├── refs/heads/main    ← copy of source's ref at fork time
        └── objects/
            └── info/
                └── alternates ← points at ../../abc12...xy.git/objects
```

## How a fork works

A fork is seven file writes — no object copies, no git operations, no
network. Concretely:

1. Create `$DATA_DIR/repos/$FORK_ID.git/` and the three required
   subdirectories (`objects/info`, `objects/pack`, `refs/heads`, `refs/tags`).
2. Write `objects/info/alternates` containing the absolute path to the
   source's `objects/` directory. **This single file is the whole trick.**
   Any object reachable from the source is now reachable from the fork via
   git's native `alternates` mechanism.
3. Copy `HEAD` (a small text file: `ref: refs/heads/main`).
4. Write a minimal `config` (`bare = true` + HTTP enable flags).
5. Copy the source's `refs/` tree — tiny, since each ref is a text file
   with a single SHA.
6. Copy `packed-refs` if it exists.
7. Mint a token scoped to the fork id.

Empirically this is ~228 bytes on disk, regardless of how large the source
repo is. Contrast with a full copy, which would be O(object data).

This is how GitHub implements internal fork networks and has since ~2009.
`git gc`, `git repack`, `git fsck` all understand alternates natively.
`.git/objects/info/alternates` is built into git; we're not inventing new
semantics here.

## Security in one paragraph

Authentication is token-based. Per-repo tokens are minted by the admin
(via `Authorization: Bearer <admin>`), presented by clients as HTTP
Basic with username `x`, and stored as SHA-256 hashes in SQLite. The
admin-token compare is constant-time (`subtle::ConstantTimeEq`) to
prevent byte-at-a-time timing recovery. **That's the entire model.**
What's *missing*:

- **TLS.** The server listens HTTP. Run a TLS terminator in front.
- **Rate limiting.** None. The admin token can mint/delete unbounded.
- **Account-level auth.** One shared admin token. No revocation of
  the admin token except restarting the process with a new value.
- **Token introspection / audit.** Tokens can be revoked but there's
  no log of who revoked what when. No `GET /v1/tokens` listing.
- **Path-traversal hardening.** `repo_id` validation rejects slashes
  and path-escape characters; if a future change loosens the ruleset
  without updating `FsStorage::repo_path`, traversal becomes
  reachable. A `Path::components()` defensive check belongs on the
  repo_path helper.

A prototype for agents you trust talking to a backend you trust over
an internal / TLS-terminated link. Not a public service.

## Development

```sh
# Build
cargo build                 # debug
cargo build --release       # optimized, used by benchmarks

# Run
cargo run -- serve --data-dir ./data --bind 127.0.0.1:8787

# Test
cargo test                  # 64 unit tests (storage, smart-http, refs, commits, tokens, auth, jwt, ownership, rate-limit, request-id)
./tests/smoke.sh            # 14-step end-to-end integration test
./scripts/bench_fork.sh     # fork benchmark, knobs via env:
FORKS=100   PARALLEL=4  ./scripts/bench_fork.sh   # quick sanity run
FORKS=10000 PARALLEL=32 ./scripts/bench_fork.sh   # the headline test
KEEP=1 FORKS=5 ./scripts/bench_fork.sh            # keep data dir for poking

./scripts/bench_clone.sh    # clone-latency benchmark
CLONES=200 ./scripts/bench_clone.sh               # time 200 sequential clones
```

Logging is via `tracing`. Tune with `RUST_LOG`:

```sh
RUST_LOG=artifacts=debug,tower_http=info cargo run -- serve ...
```

## Roadmap

| Milestone | Status | Scope | Replaces |
| --------- | ------ | ----- | -------- |
| **M0**  | ✅ done | single-node prototype, smart-HTTP bridge, alternates-based forks | — |
| **M3a** | ✅ done | `RefStore` trait extracted; `FsRefStore` shells out to `update-ref` for CAS | direct ref writes |
| **M5**  | ✅ done | `POST /v1/repos/:id/commits` — REST-side commits with CAS, delete + write, 409 body on conflict | no serverless-friendly commit surface |
| **M2a** | ✅ done | `Storage` trait extracted; `FsStorage` is the sole impl. Handlers are now backend-neutral. | direct struct calls |
| **M4a** | ✅ done | `TokenStore` trait + SQLite-backed persistent store with TTL, revocation, hash-at-rest; `POST /v1/tokens/revoke` endpoint | in-memory token map |
| **M1a** | ✅ done | `git http-backend` CGI removed — direct `git upload-pack`/`git receive-pack` shell-outs. Clone p99 −27%, max −63%. | CGI wrapper + extra fork |
| **M1b-1** | ✅ done | Native v2 `info/refs` advertisement — discovery endpoint no longer spawns a subprocess when the client uses protocol v2 (almost all modern clients). | upload-pack `--advertise-refs` fork |
| **M1b-2a** | ✅ done | Native v2 `command=ls-refs` POST — refs read directly off disk (packed-refs + loose) by `RefStore::list`/`read_head`. No upload-pack subprocess on the discovery half. | upload-pack ls-refs fork |
| **M1b-2b** | ✅ done | Native v2 `command=fetch` POST — protocol layer + sideband-1 framing in-process; pack generation via `git pack-objects --stdout`. | upload-pack fetch fork |
| **M1b-2c** | ✅ done | Native pack generation via `gix-pack` (`rev_walk → count → entry::iter → bytes::FromEntriesIter`). The pack-objects subprocess is gone; remains as a fallback if the gix path errors. | pack-objects subprocess |
| **M1b-3**  | ✅ done | Native receive-pack — ref-update parsing + sideband-1 report-status framing in-process; native CAS via `RefStore`; `git unpack-objects --stdin` writes loose objects from the incoming pack. Native ref deletes (`push :branch`) included. | receive-pack subprocess |
| **M1b-3-gix** | 🟡 next | Replace `git unpack-objects` with `gix-pack`'s native pack indexing — same architectural seam as M1b-2c. | unpack-objects subprocess |
| **M2b**     | 🟡 | second `Storage` impl — objects chunked into a KV, matching the DO+SQLite shape. `ObjectStore` trait scaffolded; full impl unblocked once M1b-3-gix ships and the unpack-objects subprocess is gone. | bare repos on disk |
| **M3b**     | 🟡 | distributed `RefStore` impl (per-repo state machine / Raft / DO). `MemRefStore` + concurrent-CAS conformance suite landed; the consensus log itself (openraft etc.) is the remaining work. | single-node CAS |
| **M4b**     | ✅ done | Owner-scoped token self-revoke + bulk rotate (`POST /v1/repos/:id/tokens/rotate`). Account-level credentials (token-subject column + listing) is the remaining slice. | admin-only token management |
| **M6 — webhooks** | ✅ done | Outbound HTTP webhook delivery with HMAC-SHA256 signing. In-memory `MemRegistry`; SQLite-backed registry + delivery retries are the remaining slice. | — |
| **M6 — metrics**  | ✅ done | Prometheus `/metrics` with per-route counters + latency histograms + rate-limit / quota counters. | — |
| **M6 — other**    | 🟡 | LFS, replication, PITR — genuinely multi-week each. | — |

Each milestone is designed to land without breaking the API surface at the
edge. A caller written against M0 should keep working against M6 with no
code change — same `remote` URL shape, same REST bodies.

## Design decisions worth arguing about

**Q: The `Storage` / `RefStore` / `TokenStore` traits each have one impl.
How "abstract" are they, really?**

A: Honestly — for `Storage` and `RefStore`, less than earlier versions
of this README implied. `TokenStore` has genuine trait value (the
SQLite vs in-memory split matters for tests and for a future
account-service backend). For `Storage` and `RefStore`, the four
trait methods (create / fork / delete / exists) and the two trait
methods (read / cas_update) *are* clean boundaries — but the expensive
work (pack generation, object writes, ref-file updates) still goes
through `cfg.repos_dir().join("…git")` and/or shells out to `git`.
A non-FS impl of those traits would have to also replace the smart-HTTP
bridge and the commits plumbing, which means M1b-native is a hard
prerequisite for M2b/M3b, not an independent axis. The traits are
*a start*, not a drop-in boundary.

**Q: Why shell out to `git upload-pack` instead of writing the protocol
natively?**

A: Because `git upload-pack` *is* the git project's reference
implementation of the server side of the fetch protocol. Feeding the
HTTP body to its stdin and streaming its stdout back gives us bit-exact
protocol compatibility with every client — `git`, `libgit2`,
`isomorphic-git`, `go-git`, `jgit`, v0/v1/v2 — for free. M0 used
`git-http-backend` on top of this; M1a cut out that CGI wrapper; M1b
goes native via gitoxide. We're swapping out the protocol layer
incrementally as we earn the right to, not rewriting it up front.

**Q: Why not use `gitoxide` or `libgit2` from day one?**

A: Because doing it up front would have cost weeks and proved nothing
that isn't already proved. The goal of M0 was "can we fork 10,000 repos
in seconds, for bytes of disk?" — measurably, yes. Now that the
architecture holds up, M1b (native protocol) has something real sitting
underneath it.

**Q: Why trust `alternates` for production-grade fork networks?**

A: Because GitHub has run on exactly this mechanism for fifteen years, it's
part of the git reference implementation (not a wrapper trick), and all the
standard maintenance tools (`gc`, `repack`, `fsck`) understand it. The
failure mode we have to design for is "source repo is deleted while forks
still exist" — that's the alternates-aware GC we owe in M1/M2.

**Q: Why a single admin token instead of per-account auth?**

A: Because M0 is a single-node prototype. Multi-tenant auth is its own
meaningful design problem — short-lived creds, per-session scopes, key
rotation — and belongs in M4, not M0.

**Q: `POST /v1/repos/:id/commits` exists — how does it build commits without
a native git object writer?**

A: It shells out to git plumbing (`hash-object`, `update-index`,
`write-tree`, `commit-tree`, `update-ref`) against a per-request temp
index file. Ugly and slow compared to gitoxide, but it inherits git's own
semantics exactly — correct tree entry ordering, empty-tree convention,
delta-over-large-trees — in ~150 lines instead of ~1500. When M1 lands,
these subprocess calls become `gix::Repository::write_blob()` /
`write_object()` with no change to the REST surface. This was the right
tradeoff: deliver the agent-first story now, swap the implementation
later.

**Q: Tokens live in SQLite — why not a HashMap or Redis?**

A: SQLite is the smallest thing that gives us durability + WAL concurrency
+ column-level predicates (expiry and revocation are a `WHERE` clause, not
a sweep) with zero operational cost. A HashMap evaporates on restart,
which is genuinely broken UX for agent sessions that outlive a deploy.
Redis would add a network hop and an external daemon for a prototype
that's happy with file-backed durability. When multi-node arrives, this
moves to a real issuer service — which is M4b and already has the trait
carved out.

**Q: Why SHA-256 the tokens in the db when the server is already behind
HTTPS and admin auth?**

A: Defense in depth. Anyone who exfiltrates `tokens.db` (backup tape, a
dev laptop, an accidental git check-in) gets hashes, not tokens. The hash
is two lines and zero runtime cost — free belt-and-suspenders. If we ever
add a breach-notification path, "the DB leaked but no tokens were
compromised" is a much better sentence than the alternative.

**Q: The 10,000-fork bench shows p99 = 50 ms. Isn't that bad?**

A: That number was measured against the M0 CGI path. Fork itself is
~230 µs on disk — sub-millisecond. The tail was the `git-http-backend`
process fork that some fork requests incidentally triggered (they
shouldn't — forks are REST-only — but the historical bench had
process-fork noise in its tail because of the way it was structured).
M1a cleared out the CGI layer; M1b removes the last subprocess. We
expect the fork-bench tail to flatten further against M1a, and to look
like the storage hot path alone after M1b.

**Q: Does it work with isomorphic-git, go-git, jgit?**

A: It should — we don't implement the protocol ourselves; `git http-backend`
does. Any client that interoperates with a stock git HTTP server should
work. The smoke test exercises cli-`git`; extending it to other clients is
on the to-do list.

## License

Apache-2.0 (same as most of the Rust ecosystem; change at will).
