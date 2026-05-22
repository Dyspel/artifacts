# Architecture

## The three hard problems

Everything else is conventional server work. The three problems that make
Artifacts interesting are:

1. **Speak git, exactly.** Real clients — `git`, `libgit2`, `isomorphic-git`,
   `go-git`, `jgit`, and the two protocol versions (v1 and v2), with all the
   corner cases (shallow, partial, thin packs, delta chains, ref advertising,
   agent capability strings) — have to work. There is no "mostly compatible"
   with git: either your server passes `git clone` bit-for-bit or it doesn't.
2. **Forks are metadata.** A fork is a new name for an existing DAG. If the
   fork endpoint copies object data, the product's headline claim ("10,000
   forks from a known-good starting point") is a lie.
3. **Refs are the consistency boundary.** Every `git push` is a
   compare-and-swap on `refs/heads/<branch>`. That CAS must be strongly
   consistent, per-repo, or you lose writes under concurrency. Everything
   else (objects, packs, acls) can eventually-consistent its way through
   life. Refs cannot.

If these three are right, a production system is a matter of scaling and
polish. If any one is wrong, no amount of scaling saves it.

### Where they stand today

| Problem | Status |
| ------- | ------ |
| #1 Speak git, exactly | ✅ Native v2 protocol layer in Rust — pkt-line parsing, ls-refs, fetch (via `gix-pack`), receive-pack (with optional `gix-pack`-driven indexing). `git http-backend` CGI gone since M1a; the last subprocess on the protocol path is the upload-pack/receive-pack fallback, which is invocation-equivalent to native gix and stays only because the bench shows it's faster for small pushes. |
| #2 Forks are metadata | ✅ Fork-via-alternates measured at ~228 bytes per fork. The 10,000-fork benchmark holds. |
| #3 Refs are the consistency boundary | 🟡 `RefStore` trait is in place; `FsRefStore` provides single-node CAS via `update-ref` (or rename-into-place inside the trait). Multi-node consensus (M3b: openraft + per-repo state machine) is the only major architectural milestone still ahead. |

## What the trait abstractions actually buy us

The codebase has four trait boundaries that the rest of the system depends
on. Their utility today vs. their full multi-backend story:

- **`TokenStore`** — genuine. The SQLite-backed (with `r2d2_sqlite` pool) impl
  can be swapped for an account-service HTTP client without touching REST
  handlers or git-auth code. The in-memory test impl is real too.
- **`OwnershipStore`** — genuine. Per-user repo quota enforcement + admin
  listing all live behind this; same SQLite/Mem split.
- **`ObjectStore`** — *two real backends*. `FsObjectStore` (atomic
  tmp+rename, the production default) and `SqliteObjectStore` (KV-shaped,
  designed for a DurableObject+SQLite production target). The trait
  exercises four production paths: GC enumeration/deletion, REST-commit
  parent-exists, native receive-pack writes, and blob-read. The Sqlite impl
  resolves packs through a hand-rolled parser + delta engine
  (`src/native_pack/parse.rs`) — no filesystem touch on the push path.
- **`RefStore`** — single-backend (`FsRefStore`) production-side, plus
  `MemRefStore` for tests + concurrent-CAS conformance. The distributed
  impl (openraft-backed, M3b) is the remaining work.
- **`Storage`** — partial abstraction. Trait methods (create / fork /
  delete / exists) are correct surfaces, but `FsStorage` is the only impl
  and the smart-HTTP layer reaches around it via `cfg.repos_dir()` for some
  paths. A non-FS `Storage` impl is genuinely useful only after M3b lands,
  because the protocol layer's I/O still bottoms out at a real on-disk
  git repo for some operations.

So three of the five (`TokenStore`, `OwnershipStore`, `ObjectStore`) are
real abstractions with multiple impls in tree. `RefStore` is half there
(one production backend + one test backend; the distributed backend is the
roadmap's last 🟡). `Storage` is mostly cosmetic until M3b removes the
remaining FS coupling.

## Prototype shape

```
git clone https://x:$TOKEN@host/git/:id.git
       │
       ▼
  axum router  ── auth middleware ──► Basic/Bearer, r2d2-pooled SQLite TokenStore
       │                              JWT verification (rotatable via /v1/admin/jwt-key/rotate)
       │
       │  GET  /git/:id.git/info/refs?service=…    — native v2 advertisement
       │  POST /git/:id.git/git-upload-pack         — native v2 ls-refs + fetch;
       │                                              gix-pack for pack generation
       │  POST /git/:id.git/git-receive-pack        — native ref-update parsing +
       │                                              sideband-1 report; pack indexing
       │                                              via `git unpack-objects`
       │                                              (default) or gix-pack (opt-in)
       │
       │  POST /v1/repos                            — REST-only surface
       │  POST /v1/repos/:id/commits                — REST-side commits via gix
       │                                              (Repository::write_blob +
       │                                               edit_tree + write_object)
       │  POST /v1/repos/:id/merge                  — server-side three-way merge
       │  GET  /v1/events                           — SSE event stream
       │  GET  /metrics                             — Prometheus
       │
       ▼
  storage trait layer
       │
       ├── FsStorage           — bare git repos under $DATA_DIR/repos/{id}.git
       ├── FsRefStore          — refs/heads/*; CAS via O_EXCL + rename
       ├── FsObjectStore       — atomic tmp+rename writes
       ├── SqliteObjectStore   — KV-shaped; reads/writes/exists/ingest_pack
       │                        all sync against rusqlite + r2d2
       └── SqliteTokenStore/OwnershipStore/AuditStore/WebhookRegistry
                              — separate .db files, all r2d2-pooled
       │
       ▼
  $DATA_DIR/
    ├── repos/
    │   ├── abc12...xy.git/                    bare git repo (source)
    │   └── def34...z7.git/                    bare git repo (fork)
    │       └── objects/info/alternates → ../abc12...xy.git/objects
    ├── tokens.db          (tokens + ownership; separate namespaces)
    ├── audit.db           (hash-chained audit log)
    ├── webhooks.db        (subscriptions + AES-256-GCM-sealed secrets)
    ├── webhook-key.bin    (32-byte master key, 0600)
    └── jwt-key.bin        (rotatable JWT signing secret, 0600)
```

### Why we let git's reference implementation handle the protocol initially

Because `git upload-pack` / `git receive-pack` *are* the git project's
reference implementations. Feeding the HTTP body to their stdin and
streaming stdout back gave us bit-exact protocol compatibility with every
client — `git`, `libgit2`, `isomorphic-git`, `go-git`, `jgit` — for free
from day one. M0 used `git-http-backend` (the CGI wrapper) on top of
that; M1a cut out the wrapper; M1b went native (gitoxide) for everything
except the leaf pack-handling subprocess. We swapped out the protocol
layer incrementally as we earned the right to, not rewriting it up
front — and the M1b-2c bench shows the native pack-generation path is
~22 % faster on p50 than the subprocess it replaced.

### Why `alternates` for forks

`.git/objects/info/alternates` is git's own mechanism for sharing object
databases across repos. Write one file, fork done. `git gc` and friends
respect alternates. This is how GitHub's internal "fork network" (a.k.a.
`network.git`) has worked for fifteen years. It's correct, fast, and
costs no new code. The alternative — copying all objects — defeats the
entire product.

### Why single-node refs for M0

Git already stores refs correctly on a single machine with atomic rename
semantics. The single-node `FsRefStore` is observationally consistent for
a single deployment. M3b — openraft + per-repo state machine — replaces
it with a distributed CAS for multi-node deployments; the trait surface
doesn't change, so every caller of `cas_update` keeps working.

## Production shape

```
        ┌─── Git smart-HTTP (native gitoxide) ◄── auth ◄── TLS term ◄── Ingress
        │
        ├──► Object store     content-addressed, chunked
        │                     (SqliteObjectStore-on-DurableObject for the
        │                      hot path; S3/R2 for cold storage)
        │
        ├──► Refs store       distributed CAS, per-repo state machine
        │                     (RaftRefStore — openraft, M3b)
        │
        └──► Metadata DBs     tokens / ownership / audit / webhooks
                              (SQLite today; conventional RDBMS at scale)

        ┌─── REST API (for non-git callers) ◄── auth ◄── TLS term ◄── Ingress
        │
        └── same three backends as above

        ┌─── Observability
        │
        ├── /metrics    Prometheus exposition
        ├── OTLP        gRPC to a collector when --otlp-endpoint set
        └── /v1/admin/audit  hash-chained, queryable, persisted
```

The M0→M3b path in [README.md](./README.md) walks this one piece at a
time, keeping an end-to-end working system at every step. The remaining
gap to this picture is the consensus log under `RefStore` — everything
else (object store, observability, identity rotation, audit, backup) is
already in tree.

## What we are not building

- **A hosted git UI.** No web view of a repo, no PR review, no issues, no
  CI. This is an infrastructure product, not GitHub. The Wayland/X11
  `artifacts-gui` is an *operator* tool (live view of server state), not
  a user-facing product surface.
- **Branch protection / policy as code.** No required reviewers, no
  status checks, no protected branches. Those are human-workflow features;
  this is an agent product. Branch-name validation enforces git's own
  reference-format rules, no more.
- **LFS in this milestone.** LFS is a separate protocol bolted onto git;
  it's the headline remaining item under M6-other. The pack-indexing
  layer is ready for it (ObjectStore-shaped storage backend), but the
  LFS endpoints + pointer-file walking aren't here yet.
- **Arbitrary merge semantics.** Server-side merge does fast-forward +
  three-way-clean + three-way-conflict (the same shape any git server
  could compute); anything fancier (recursive strategies, rerere, hooks)
  is the client's job, or the agent's.

## What the 10,000-fork test actually measures

The fork benchmark in `scripts/bench_fork.sh` is a feasibility-critical
test. It proves:

1. Fork latency is bounded by metadata write cost, not object copy cost.
2. Disk usage is ~flat after the 10,000 forks (growth is only new inodes
   and a handful of bytes per fork for the alternates file and refs).
3. Clones of the forks succeed and resolve objects through alternates.

If any of those three fail, the architecture is wrong and the rest of the
system doesn't matter. The headline number — 228 bytes per fork, ~126×
less disk than full copies — is what carries the product story.

`scripts/bench_concurrent.sh` is the newer companion: 32 parallel clones
+ 32 parallel pushes against the same server, surfacing fan-in p99 the
single-client benches can't. The r2d2 pool (8 connections per store) +
the gix-native REST commits keep that p99 well-behaved at this fan-in
level — see the *Numbers we just measured* section in the README for the
current numbers on this host.

## Where we are now

After A1–B4 + C1–C4 + D1–D4, the prototype is meaningfully
production-quality for a single-tenant deployment:

- **Deployable**: Dockerfile (multi-stage, non-root), hardened systemd
  unit, single-replica k8s manifests (`Recreate` strategy because the
  PVC is RWO until M3b lands).
- **Operable**: Prometheus `/metrics`, opt-in OTLP tracing, Grafana
  starter dashboard, alertmanager rules for the obvious SLO violations,
  hash-chained audit log, rotatable admin/JWT/webhook-master keys,
  online backup + restore + round-trip test.
- **Correct under load**: r2d2_sqlite pool replaces the per-store
  serialized `Arc<Mutex<Connection>>`; the concurrent-load bench
  reports p99 well under 100 ms at 32-way fan-in.
- **Hands-off pack ingest**: `SqliteObjectStore::ingest_pack` resolves
  Direct + REF_DELTA + OFS_DELTA against the KV directly via a
  hand-rolled pack parser. The chunked-KV "no filesystem" purity
  claim holds.
- **CI-gated**: GitHub Actions runs fmt/clippy/test on every PR;
  nightly + manual `cargo-fuzz` against the `pkt_line` and
  `git_wire::proto` parsers.

The one architectural milestone left is M3b — multi-node consensus
under `RefStore`. The roadmap's M6-other (LFS, replication beyond
Raft, point-in-time recovery) is genuinely multi-week each and not
session-shaped. Everything else is run-it-in-production + iterate-on-
what-breaks.
