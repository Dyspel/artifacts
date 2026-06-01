# Artifacts (prototype)

A versioned filesystem that speaks Git. Agent-first. Fork in a metadata write.

This is a **feasibility prototype**, not production software. It exists to
prove that the architectural claims of an Artifacts-style product — real Git
client interop, O(1) forks, a REST side-door for agents — hold up end-to-end,
and to make the path to a production system concrete.

> The *why* is in [ARCHITECTURE.md](./ARCHITECTURE.md). This file is the
> *what*: the surface, the numbers, the commands. For wiring into the
> [Dyspel collaborative AI IDE](https://github.com/dyspel) (JWT handoff,
> gitSyncService migration) see [DYSPEL.md](./DYSPEL.md). For the live
> server visualizer see [GUI.md](./GUI.md). Security disclosure policy is in
> [SECURITY.md](./SECURITY.md).

## Read this first (what it is *not*)

- **Plaintext by default; TLS opt-in.** The server speaks HTTP unless you pass
  `--tls-cert` + `--tls-key` (rustls terminates in-process). Tokens travel in
  the URL, as git clients send them — without TLS on the wire (in-process or
  via an external terminator) you're broadcasting credentials. A bind-safety
  check refuses to start in the worst case (non-loopback bind + no TLS + no
  `https://` public URL) unless `--allow-insecure` is set.
- **Admin is break-glass.** The static admin Bearer token bypasses per-subject
  rate limits and per-user quotas. An insider holding it can fill the disk.
  Every mutating call is recorded in a tamper-evident audit log (below) — that
  is the after-the-fact control, not prevention.
- **Single-node.** `Storage`/`RefStore`/`ObjectStore` are trait boundaries with
  filesystem + SQLite impls, but there is no distributed ref consensus yet
  (that's M3b). Running two processes against one data dir is unsupported.
- **Exercised against CLI `git`.** The wire protocol is implemented natively
  (gitoxide) and *should* interoperate with any client that speaks
  smart-HTTP v0/v1/v2 — `libgit2`, `isomorphic-git`, `go-git`, `jgit` — but the
  test suite drives stock `git`.

## Table of contents

- [Status](#status)
- [Architecture in one screen](#architecture-in-one-screen)
- [Measured numbers](#measured-numbers)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [API reference](#api-reference)
- [How a fork works](#how-a-fork-works)
- [Security](#security)
- [Directory layout](#directory-layout)
- [Development](#development)
- [Deployment](#deployment)
- [Roadmap](#roadmap)
- [Design decisions worth arguing about](#design-decisions-worth-arguing-about)

## Status

The git wire protocol is served **natively** (gitoxide), not by shelling out to
`git http-backend` or `git upload-pack`/`receive-pack`. `git` is still required
on `$PATH` for three narrow jobs: the default push pack-indexer
(`git unpack-objects`), the connectivity check and GC reachability walk
(`git rev-list`), and a subprocess protocol fallback when the native path is
disabled. REST-side commits are built in-process with `gix` (no plumbing
subprocesses, no temp index dirs).

**Working end-to-end today:**

| Area | What works |
| --- | --- |
| Git client interop | `clone` / `push` / `fetch` / `pull` over smart-HTTP v0/v1/v2, served from in-process Rust (pkt-line parsing, sideband framing, ref CAS, `gix-pack` fetch generation). Per-repo token scope (`read`/`write`) enforced on push; `readOnly` forks reject pushes. |
| O(1) forks | `POST /v1/repos/:id/forks` — ~228 bytes/fork via `objects/info/alternates`, independent of source size. Clone of a fork resolves objects transparently. |
| REST commits | `POST /v1/repos/:id/commits` — build a commit with no git client (write/delete changes, base64 blobs), CAS on the parent SHA, `409 ref_conflict` carrying `expected`+`current`. Built via `gix::Repository::write_blob`/`edit_tree`/`write_object`. |
| Reads & collab | `GET` `/tree` · `/blob` · `/diff` · `/notes` · `/refs` · `/commits` (log) · repo detail; `POST /merge` (fast-forward + three-way); `GET /v1/events` (SSE commit/fork/status stream). |
| Tokens | Mint (scoped, optional TTL), list, revoke, per-repo bulk rotate. SHA-256-hashed at rest in SQLite; survive restart. Constant-time admin compare. |
| Identity | Static admin Bearer + optional Dyspel-signed HS256 JWT (`aud`/`iss` pinnable). Per-repo ownership with cross-user 403. |
| Webhooks | HMAC-SHA256-signed delivery with a **durable SQLite outbox** (enqueue → poll → deliver, exponential backoff, finalized-row retention prune). Secrets AES-256-GCM-sealed at rest under an env-pinnable, rotatable master key. |
| Admin | List/detail repos; alternates-aware GC (preview + run, plus a periodic sweep); persistent audit log (filter/paginate, cheap totals, SHA-256 hash-chain verify); in-process rotation of the admin token, JWT signing secret, and webhook master key. |
| Hardening | Connectivity check before any ref advances (no ref points at a missing object); pack-parser allocation caps (decompression-bomb + oversized-delta guard); fsync of objects before the ref CAS; per-route body caps; per-request timeout; typed DB errors (SQLITE_BUSY → 503 + `Retry-After`); 5xx bodies redacted to `"internal"`. |
| Ops | Prometheus `/metrics`, `X-Request-Id` round-trip, OTLP trace export, graceful drain (readiness-flip → drain → exit), `r2d2` SQLite pools with per-store gauges, forward-only schema migrator, online backup/restore, multi-stage Dockerfile + hardened systemd unit + single-replica k8s manifests. |

**Not yet:**

- **Distributed `RefStore` (M3b).** `MemRefStore` + a concurrent-CAS conformance
  suite exist; the consensus log (per-repo state machine / Raft) is the work.
- **LFS, cross-region replication, point-in-time restore (M6-other).** Each is
  genuinely multi-week.

## Architecture in one screen

Three hard problems, and where each stands:

1. **Forks must be cheap.** Solved with git's native `alternates` — a fork is a
   directory + a one-line pointer file + a ref copy. ~228 bytes regardless of
   source size. This is how GitHub has run fork networks since ~2009; `gc`,
   `repack`, and `fsck` all understand it.
2. **The wire protocol must be exactly git's.** Served natively via gitoxide:
   `info/refs` advertisement, v2 `ls-refs`/`fetch`, and `receive-pack`
   (ref-update parsing, sideband report-status, CAS through `RefStore`) all run
   in-process. Fetch packs are generated with `gix-pack`. The push pack-indexer
   defaults to `git unpack-objects` (a bench showed `gix-pack`'s indexer is
   ~4× slower on small pushes); the native indexer is opt-in via
   `ARTIFACTS_NATIVE_INDEX_PACK=1` so a future no-filesystem backend has a path.
3. **Storage must be swappable toward a chunked KV.** `Storage`, `RefStore`,
   and `ObjectStore` are traits. `ObjectStore` has three impls — `FsObjectStore`
   (atomic tmp+rename+fsync), `MemObjectStore`, and `SqliteObjectStore` (the
   KV-shaped target) — behind one conformance suite. The hand-rolled pack parser
   (`src/native_pack/parse.rs`) resolves Direct/REF_DELTA/OFS_DELTA against the
   KV with no filesystem touch.

## Measured numbers

Captured on a release build during the protocol-nativization work. Re-run any
of them with the scripts under `scripts/`.

**Forks** — 10,000 forks of a 28 KB seed repo (30 files), parallelism 32:

```
forks done in 3.52s (2837 forks/sec wall clock)
latency ms: p50=0.34  p95=0.63  p99=50.2  max=230.0
added by forks: 2,280,000 bytes  →  228 bytes/fork
(a full copy would have added ~288,370,000 bytes — ~126× more)
```

**Clone latency** (sequential, 28 KB seed, `scripts/bench_clone.sh`, 200 iters):

|     | M0 (CGI) | direct subprocess | + native v2 info/refs | + gix-pack fetch (current) |
| --- | -------: | ----------------: | --------------------: | -------------------------: |
| p50 | 14.5 ms  | 13.4 ms           | 13.0 ms               | **10.4 ms**                |
| p99 | 21.5 ms  | 15.6 ms           | 16.1 ms               | **12.8 ms**                |
| max | 45.8 ms  | 16.9 ms           | 17.9 ms               | **13.2 ms**                |

Killing the CGI wrapper took the big tail-latency win (p99 −27%, max −63%);
native `gix-pack` fetch generation took another p50 −22%.

**Push latency** (sequential small commit, `scripts/bench_push.sh`, 200 iters):

|     | all-subprocess (legacy) | native protocol + subprocess pack-indexing (current) |
| --- | ----------------------: | ---------------------------------------------------: |
| p50 | 14.7 ms                 | **12.1 ms**                                          |
| p99 | 18.2 ms                 | **14.1 ms**                                          |

**Concurrent fan-in** (`scripts/bench_concurrent.sh`, N=32):

|      | 32 concurrent clones | 32 concurrent pushes |
| ---- | -------------------: | -------------------: |
| p99  | 108.8 ms             | 53.3 ms              |
| tput | 288 ops/s            | 572 ops/s            |

The `r2d2` pool (max 8 connections/store) doesn't saturate at this fan-in;
`artifacts_sqlite_pool_in_use` returns to 0 by the post-bench scrape.

## Quickstart

**Requirements:** Rust 1.88 (pinned via `rust-toolchain.toml`) and `git` ≥ 2.30
on `$PATH`.

```sh
cargo run --release -- serve \
    --data-dir ./data \
    --bind 127.0.0.1:8787 \
    --public-base-url http://127.0.0.1:8787
```

On startup the server prints an admin token to stderr (or pin it with
`ARTIFACTS_ADMIN_TOKEN`). Then:

```sh
ADMIN="<admin token from stderr>"

# Create a repo — the response gives a ready-to-clone URL with creds embedded.
curl -sS -X POST -H "Authorization: Bearer $ADMIN" \
    http://127.0.0.1:8787/v1/repos
# → {"id":"abc…","remote":"http://x:TOKEN@127.0.0.1:8787/git/abc….git","token":"TOKEN"}

git clone "http://x:TOKEN@127.0.0.1:8787/git/abc….git" ./work
cd work && echo hi > README.md && git add . && git commit -m first && git push -u origin main

# Fork it (O(1)).
curl -sS -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
    -d '{"readOnly": false}' \
    "http://127.0.0.1:8787/v1/repos/abc…/forks"
```

## Configuration

All flags accept an env var (shown) and have sane defaults; the server runs with
none of them set.

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--data-dir` | `./data` | Entire mutable surface (repos + SQLite DBs). |
| `--bind` | `127.0.0.1:8787` | Listen address. |
| `--public-base-url` | `http://127.0.0.1:8787` | Base for generated clone URLs. |
| `--admin-token` / `ARTIFACTS_ADMIN_TOKEN` | generated | Static admin Bearer; printed to stderr if unset. |
| `--jwt-secret` / `ARTIFACTS_JWT_SECRET` | off | HS256 secret; enables JWT auth on REST. |
| `--jwt-expected-aud` / `…_AUD`, `--jwt-expected-iss` / `…_ISS` | off | Pin JWT `aud`/`iss` (set these when sharing the secret across services). |
| `--max-repos-per-user` / `…_MAX_REPOS_PER_USER` | 100 | Per-user repo quota (admin exempt). |
| `--max-commit-blob-bytes` / `…_MAX_COMMIT_BLOB_BYTES` | 8 MiB | Per-file cap on REST commits. |
| `--max-repo-bytes` / `…_MAX_REPO_BYTES` | 0 (off) | Per-repo on-disk byte quota. |
| `--rest-body-limit-bytes` / `…_REST_BODY_LIMIT_BYTES` | 1 MiB | Body cap on `/v1/*`. |
| `--git-body-limit-bytes` / `…_GIT_BODY_LIMIT_BYTES` | 2 GiB | Body cap on `/git/*`. |
| `--request-timeout-secs` / `…_REQUEST_TIMEOUT_SECS` | 300 | Per-request timeout (0 = off; not recommended). |
| `--tls-cert` / `…_TLS_CERT`, `--tls-key` / `…_TLS_KEY` | off | In-process rustls termination. |
| `--allow-insecure` | off | Permit non-loopback HTTP bind. |
| `--audit-retention-days` / `…_AUDIT_RETENTION_DAYS` | 90 | Audit-log prune window (0 = keep forever). |
| `--webhook-delivery-retention-days` / `…_WEBHOOK_DELIVERY_RETENTION_DAYS` | 30 | Finalized webhook-delivery prune window. |
| `--gc-interval-secs` / `…_GC_INTERVAL_SECS` | 86400 | Periodic GC sweep cadence (0 = off). |
| `--gc-min-object-age-secs` / `…_GC_MIN_OBJECT_AGE_SECS` | 7200 | GC anti-race: skip loose objects younger than this. |
| `--shutdown-timeout-secs` / `…_SHUTDOWN_TIMEOUT_SECS` | 30 | Graceful-drain budget. |
| `--shutdown-drain-delay-secs` / `…_SHUTDOWN_DRAIN_DELAY_SECS` | 5 | Readiness-503 hold-off before drain. |
| `--readiness-write-check` / `…_READINESS_WRITE_CHECK` | true | Exercise each store's write path in `/health/ready`. |
| `--otlp-endpoint` / `…_OTLP_ENDPOINT` | off | OTLP/gRPC trace export. |

Other env knobs: `ARTIFACTS_WEBHOOK_KEY` (base64 32-byte master key),
`ARTIFACTS_WEBHOOK_DB` (registry path), `ARTIFACTS_SQLITE_POOL_SIZE` (pool max),
`ARTIFACTS_NATIVE_INDEX_PACK=1` (opt into the native pack indexer),
`ARTIFACTS_DISABLE_NATIVE=1` (force the subprocess protocol fallback, for A/B).

## API reference

### Authentication

| Scheme | Header | Used by | Carries |
| --- | --- | --- | --- |
| Bearer | `Authorization: Bearer <admin-or-jwt>` | `/v1/*` REST | admin token, or a Dyspel HS256 JWT |
| Basic | `Authorization: Basic base64(x:<token>)` | `/git/*` | a per-repo token from the REST API |

Git endpoints expect the token in the clone URL (`https://x:TOKEN@host/git/ID.git`);
git does the Basic handshake from there.

### Endpoint map

**Health & metrics** (no auth)
- `GET /v1/health` → `{"ok":true}` — liveness.
- `GET /v1/health/ready` — readiness; probes the SQLite stores (and their write
  path when enabled). Returns 503 on failure or while draining
  (`{"ok":false,"draining":true}`).
- `GET /metrics` — Prometheus text.

**Repos & forks** (admin or owner JWT)
- `POST /v1/repos` — create; returns `{id, remote, token}` (write-scoped token).
- `GET /v1/repos` — list (admin: all; JWT: owned), `?limit=&offset=`, `X-Total-Count`.
- `GET /v1/repos/:id` — detail (size, refs).
- `POST /v1/repos/:id/forks` — O(1) fork; `{readOnly?, id?}`.
- `DELETE /v1/repos/:id` — refuses with `409 fork_dependency` if forks live;
  `?force=true` orphans them; `?cascade=true` deletes the subtree deepest-first.

**Tokens**
- `POST /v1/repos/:id/tokens` — mint `{scope:"read"|"write", ttlSeconds?}`.
- `GET /v1/repos/:id/tokens` — list (metadata only, never the secret).
- `POST /v1/repos/:id/tokens/rotate` — revoke + reissue this repo's tokens.
- `POST /v1/tokens/revoke` — `{token}` in the body (keeps tokens out of access
  logs); idempotent.

**Commits, reads & collaboration**
- `POST /v1/repos/:id/commits` — build a commit; `parent` is the CAS predicate
  (`null` = new branch), `changes[]` are ordered `write`/`delete` ops with
  `content` (UTF-8) or `contentBase64`. CAS miss → `409 ref_conflict` with
  `expected`+`current`.
- `GET /v1/repos/:id/commits` — log.
- `POST /v1/repos/:id/merge` — fast-forward or three-way; `409 merge_conflict`
  lists conflicting paths.
- `GET /v1/repos/:id/{tree,blob,diff,notes,refs}` — read trees, blobs
  (`<commit>:<path>`), diffs, git notes, and the ref list.
- `GET /v1/events` — Server-Sent Events stream of commit/fork/status events.

**Webhooks** (admin or owner)
- `POST /v1/repos/:id/webhooks` — `{url, secret?, events?}` (empty `events` = all
  kinds). Deliveries are HMAC-SHA256-signed and retried from a durable outbox.
- `GET /v1/repos/:id/webhooks`, `DELETE /v1/repos/:id/webhooks/:hook_id`.

**Admin** (admin only; JWT → 403)
- `GET /v1/admin/repos`, `GET /v1/admin/repos/:id`.
- `GET /v1/admin/repos/:id/gc-preview`, `POST /v1/admin/repos/:id/gc?minAgeSecs=`
  — alternates-network-aware unreachable-loose-object sweep (preview is
  read-only; run deletes objects older than `minAgeSecs`, default 7200).
- `GET /v1/admin/audit` (`?since=&until=&event=&actor=&repoId=&limit=&offset=`),
  `GET /v1/admin/audit/stats` (cheap totals), `GET /v1/admin/audit/verify-chain`
  (recompute the SHA-256 row-hash chain; reports the first tampered row id).
- `POST /v1/admin/token/rotate`, `POST /v1/admin/jwt-key/rotate`,
  `POST /v1/admin/webhook-key/rotate` — in-process secret rotation; each returns
  the new secret and emits an audit event (no secret bytes in the event).

**Git** (Basic auth, repo token; scope enforced)
- `GET /git/:id.git/info/refs?service=git-{upload,receive}-pack`
- `POST /git/:id.git/git-{upload,receive}-pack`

### Audit log

Every mutating endpoint writes a row to `<data-dir>/audit.db` (in addition to a
live `tracing!(target:"audit")` event). Rows are SHA-256 hash-chained — a
tampered or deleted row breaks the chain at its successor, and
`verify-chain` names the offending id. Process boundaries are bracketed by
`server.start` / `server.shutdown` events (a `start` with no matching
`shutdown` means SIGKILL or crash). Writes are best-effort: a SQLite hiccup logs
a warning but never fails the underlying mutation.

### Metrics

Prometheus text at `GET /metrics`. The `path` label is the route template
(`/v1/repos/:id/tokens`), so cardinality is bounded by the route table, not by
repo count.

| Metric | Kind | Labels |
| --- | --- | --- |
| `artifacts_requests_total` | counter | `method`,`path`,`status` |
| `artifacts_request_duration_seconds` | histogram | `method`,`path` |
| `artifacts_object_reads_total`, `artifacts_object_read_duration_seconds` | counter, histogram | `backend`,`outcome` |
| `artifacts_rate_limited_total`, `artifacts_quota_exceeded_total`, `artifacts_repo_byte_quota_exceeded_total` | counter | — |
| `artifacts_audit_events_total` | counter | `event` |
| `artifacts_webhook_deliveries_total` | counter | `kind`,`outcome` |
| `artifacts_webhook_events_dropped_total` | counter | — (event-bus lag) |
| `artifacts_tokens_active_total`, `artifacts_webhooks_active_total`, `artifacts_repos_total`, `artifacts_audit_events_stored_total` | gauge | — |
| `artifacts_sqlite_lock_wait_seconds` | histogram | `store` |
| `artifacts_sqlite_pool_size` / `_pool_in_use` | gauge | `store` |
| `artifacts_build_info` | gauge | `version` |

## How a fork works

A fork is a handful of file writes — no object copies, no git invocation, no
network:

1. Create `repos/<fork-id>.git/` with `objects/{info,pack}` + `refs/{heads,tags}`.
2. Write `objects/info/alternates` pointing at the source's `objects/` dir.
   **This one file is the whole trick** — every object reachable from the source
   is now reachable from the fork via git's native alternates mechanism.
3. Copy `HEAD`, write a minimal bare `config`, copy the source's `refs/` tree
   (and `packed-refs` if present).
4. Mint a token scoped to the fork.

~228 bytes on disk regardless of source size. `gc`/`repack`/`fsck` all
understand alternates, so this is not a wrapper trick — it's how the git
reference implementation models shared object stores.

## Security

See [SECURITY.md](./SECURITY.md) for the disclosure policy and threat model.
In brief:

- **Tokens** are SHA-256-hashed in SQLite (DB exfil yields hashes, not tokens);
  presented as HTTP Basic; admin/JWT compares are constant-time
  (`subtle::ConstantTimeEq`).
- **JWT** verification pins HS256 (no `alg=none`/confusion), requires `exp`,
  honors `nbf`, and pins `aud`/`iss` when configured.
- **Path traversal** has two lines of defense: `validate_repo_id` rejects
  slashes/dots at ingress, and `FsStorage::repo_path` re-checks every joined
  path's components.
- **Push integrity:** a connectivity walk runs before any ref advances, so a
  thin/truncated/partial push can never leave a ref pointing at a missing
  object; objects are fsync'd before the ref CAS.
- **Resource bounds:** the pack parser caps per-entry output and rejects
  oversized delta targets (decompression-bomb guard); per-route body caps and a
  per-request timeout bound memory and connection-hold; non-busy SQLite errors
  are redacted to a 500, `SQLITE_BUSY` maps to 503 + `Retry-After`.
- **Webhook secrets** are AES-256-GCM-sealed at rest (fresh per-row nonce) under
  a master key from `ARTIFACTS_WEBHOOK_KEY` or `<data-dir>/webhook-key.bin`
  (0600), rotatable in-process.
- **Secrets rotate** in-process: admin token, JWT signing secret, webhook master
  key — each invalidates the prior value on the next request.

Still open: a real KMS-backed webhook-secret path (the at-rest encryption is
done; KMS unwrap-per-delivery is the refinement).

## Directory layout

```
src/
├── lib.rs / main.rs        library root + thin clap→serve bin shim
├── app.rs                  server bring-up: router, layers, shutdown, bg tasks
├── config.rs / error.rs    runtime config; error type + IntoResponse (5xx redaction, DB→503)
├── auth.rs / jwt.rs        Basic/Bearer extraction; HS256 verification
├── ids.rs                  validated newtypes: RepoId / Oid / RefName / Subject / Token
├── storage.rs              Storage trait + FsStorage (fork-via-alternates — THE CORE)
├── refs.rs                 RefStore trait + FsRefStore (CAS) + MemRefStore
├── object_store/           ObjectStore trait + Fs/Mem/SQLite impls + conformance suite
├── tokens.rs / ownership.rs / audit.rs   SQLite-backed stores (+ hash-chain in audit)
├── db_migrate.rs           forward-only migrator + r2d2 pool + store-boilerplate macro
├── smart_http.rs           native git_handler + connectivity gate + subprocess fallback
├── git_wire/ pkt_line.rs   v2 ls-refs/fetch + push parsers; pkt-line codec
├── native_pack(/parse.rs)  hand-rolled pack parser + delta engine (bounded allocations)
├── git_cmd.rs              the single seam for spawning `git`
├── commits.rs / merge.rs   REST commits via gix; fast-forward + three-way merge
├── reads/                  tree / blob / diff / notes / refs / log read APIs
├── gc.rs                   alternates-aware reachability sweep (+ periodic actor)
├── events.rs / webhooks.rs in-process EventBus + SSE; webhook registry + durable outbox
├── secrets.rs              AES-256-GCM master key (env + file resolver)
├── metrics.rs / request_id.rs / rate_limit.rs / ip_rate_limit.rs   observability + limits
├── rest.rs + rest/         RestState + repos/tokens/webhooks/admin/health handlers
└── bin/artifacts-gui/      feature-gated eframe/egui live viewer
tests/   integration_smoke.rs (spawns the binary; clone/push/fork/merge/SSE/restart)
         backup_restore_roundtrip.rs
fuzz/    pkt_line + git_proto cargo-fuzz targets
deploy/  Dockerfile + systemd unit + k8s manifests
scripts/ bench_{fork,clone,push,concurrent}.sh + backup.sh / restore.sh
```

Under `$DATA_DIR`: `tokens.db` (tokens + ownership, separate namespaces),
`audit.db`, `webhooks.db`, `webhook-key.bin` (0600), and `repos/<id>.git/` bare
repos (forks carry an `objects/info/alternates` pointer).

## Development

```sh
cargo build --release             # benchmarks use the release build

cargo test                        # 754 lib tests + 2 doctests + integration
cargo test --all-features         # + GUI unit tests
cargo test --doc                  # runnable doc examples (e.g. src/ids.rs)
./tests/smoke.sh                  # → cargo test --test integration_smoke

# Coverage: ~94% line coverage (cargo-tarpaulin). The server is driven
# in-process by the e2e_* integration binaries so it's instrumented;
# see docs/COVERAGE.md for the measurement command, methodology, and a
# per-line accounting of the deliberately-uncovered residual.

# Lints: enforced as a hard gate in CI.
cargo fmt --check
cargo clippy --all-targets -- -D warnings   # pedantic + nursery + unsafe discipline
cargo deny check                            # advisories / bans / licenses / sources
cargo machete                               # unused-dependency guard

# Benchmarks
./scripts/bench_fork.sh           # FORKS / PARALLEL knobs
./scripts/bench_{clone,push,concurrent}.sh

# Backup / restore (online; restore needs the server stopped)
./scripts/backup.sh  <data-dir>  <backup-dir>
./scripts/restore.sh <backup-dir> <data-dir>

# Fuzz (nightly + cargo-fuzz)
cd fuzz && cargo +nightly fuzz run pkt_line --max-total-time=60
```

Lint policy lives in one place — the `[lints]` table in `Cargo.toml` — and
applies to the library, both binaries, tests, and benches: `clippy::pedantic`
and `clippy::nursery` (warn, with a documented allow-list for deliberate
exceptions), `unreachable_pub`, `unsafe_op_in_unsafe_fn`, and the
undocumented-unsafe-block guards. Formatting is pinned by `rustfmt.toml`. Logs
are `tracing`; tune with `RUST_LOG` (e.g. `RUST_LOG=artifacts=debug`).

## Deployment

Runtime artifacts live under [`deploy/`](./deploy/) — multi-stage `Dockerfile`
(debian-slim, `git` on PATH, non-root UID 10001), a hardened systemd unit
(`NoNewPrivileges`, `ProtectSystem=strict`, `SystemCallFilter`,
`MemoryDenyWriteExecute`) with a companion env file, and single-replica k8s
manifests (Deployment + Service + RWO PVC, `strategy: Recreate` so a rollout
can't deadlock two pods on one volume; probes pinned to `/v1/health/ready` and
`/v1/health`). The `--data-dir` is the entire mutable surface and must be a
PVC. Single-replica until M3b. See [`deploy/README.md`](./deploy/README.md).

## Roadmap

| Milestone | Status | Scope |
| --- | --- | --- |
| M0 | ✅ | Single-node prototype; smart-HTTP bridge; alternates forks. |
| M1a–M1b | ✅ | Protocol nativization: CGI removed, then native v2 `info/refs`/`ls-refs`/`fetch` (gix-pack) + `receive-pack` (CAS, sideband, deletes). |
| M1b-3-gix | 🟡 opt-in | Native pack indexer (`gix-pack`); default stays `git unpack-objects` (~4× faster on small pushes). |
| M2a / M2b | ✅ | `Storage` trait; then `ObjectStore` trait + Fs/Mem/SQLite impls + conformance + hand-rolled pack/delta resolver. |
| M3a | ✅ | `RefStore` trait + `FsRefStore` CAS. |
| M3b | 🟡 | Distributed `RefStore` — `MemRefStore` + concurrent-CAS suite done; consensus log remains. |
| M4a / M4b | ✅ | `TokenStore` (SQLite, TTL, revoke, hash-at-rest); owner-scoped self-revoke + bulk rotate; in-process admin/JWT-key rotation. |
| M5 | ✅ | REST commits (CAS, write/delete, 409 body) via gix. |
| M6 | ✅ | Webhooks (HMAC, durable SQLite outbox, retries, sealed secrets); Prometheus metrics; audit log + hash-chain; OTLP. |
| M6-other | 🟡 | LFS, replication, PITR. |

Each milestone lands without breaking the edge API — a caller written against
M0 keeps working: same `remote` URL shape, same REST bodies.

## Design decisions worth arguing about

**The traits each have a real impl — how abstract are they?** `TokenStore`,
`ObjectStore`, and `RefStore` earn their keep (the SQLite-vs-Mem split drives
tests; `ObjectStore` has three real impls behind one conformance suite).
`Storage` is thinner — object/ref I/O still resolves through `repos_dir()` — so
it's a clean *boundary*, not yet a drop-in backend. Honest framing: the traits
are how M3b/M6 land without churning the edge, not a claim that a second backend
is plug-and-play today.

**Why gitoxide for the protocol instead of `git http-backend`?** M0 used the CGI
wrapper to get bit-exact compatibility for free; once the architecture held up,
the protocol was nativized incrementally (gitoxide) — each step earned against a
benchmark rather than rewritten up front. `git` remains only for the narrow jobs
where its plumbing is still the fastest correct option (`unpack-objects`,
`rev-list`).

**Why is REST-commit built with `gix` and not git plumbing?** It started as a
chain of `hash-object`/`write-tree`/`commit-tree` subprocesses against a temp
index — correct but slow. It now uses `gix::Repository::write_blob`/`edit_tree`/
`write_object` in-process, same REST surface, no temp dirs.

**Why default to `git unpack-objects` for push indexing?** A bench showed
`gix-pack`'s `Bundle::write_to_directory` is ~4× slower than `git
unpack-objects` on the small packs an interactive push generates (gix has fixed
per-call setup cost). The native indexer stays wired behind
`ARTIFACTS_NATIVE_INDEX_PACK=1` for a future no-filesystem backend.

**Why SQLite for tokens/ownership/audit/webhooks?** Smallest thing giving
durability + WAL reader concurrency + column predicates (expiry/revocation are a
`WHERE` clause, not a sweep) at zero operational cost. A HashMap evaporates on
restart — broken UX for agent sessions that outlive a deploy. Multi-node moves
this to a real issuer service (the trait is already carved out).

**Why hash the tokens when the server is behind TLS + admin auth?** Defense in
depth — exfiltrating `tokens.db` yields hashes, not tokens, for two lines and
zero runtime cost.

## License

[Apache-2.0](./LICENSE).
