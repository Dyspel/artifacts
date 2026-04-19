# Artifacts (prototype)

A versioned filesystem that speaks Git. Agent-first. Fork in a metadata write.

This is a **feasibility prototype**. It is not production software. It exists
to prove that the architectural claims of an Artifacts-style product — real
Git client interop, O(1) forks, a REST side-door — can be made to work
end-to-end in a day, not a quarter.

> If you want the *why*, read [ARCHITECTURE.md](./ARCHITECTURE.md). This file
> is the *what* — the surface, the numbers, and the commands.

## Table of contents

- [Status](#status)
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

**Known not-yet:**

| Feature                                                          | Status |
| ---------------------------------------------------------------- | ------ |
| Native git implementation (replace `git http-backend` shell-out) | 🟡 M1  |
| Pluggable object store (chunked KV / S3)                         | 🟡 M2  |
| Strongly-consistent multi-node refs store with CAS               | 🟡 M3  |
| Production-grade auth (short-lived creds, revocation)            | 🟡 M4  |
| REST-side commits (for serverless, no git client)                | 🟡 M5  |
| LFS, replication, PITR, webhooks, metrics                        | 🟡 M6  |

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

The p99 tail (~50 ms) is almost entirely process-fork overhead in
`git http-backend`. M1 eliminates the CGI boundary and flattens the tail.

## Quickstart

**Requirements:** Rust stable (we've tested 1.75+), `git` ≥ 2.30, and the
`git-http-backend` CGI (ships with git; on Debian/Ubuntu it's in `git-core`
at `/usr/lib/git-core/git-http-backend`).

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

{ "scope": "read" }
```

Scope is `"read"` or `"write"`. Response:

```json
{
  "token": "...",
  "remote": "http://x:...@host/git/...git"
}
```

### Delete a repo

```
DELETE /v1/repos/:id
Authorization: Bearer <admin>
```

Response: `{"ok":true}`. In the prototype this is a raw `rm -rf` on the
repo directory. Production needs soft-delete + alternates-aware GC so you
can't tombstone a repo that's still the object source for a live fork.

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
├── Cargo.toml                 cargo manifest (single binary crate, M0)
├── README.md                  this file
├── ARCHITECTURE.md            the three hard problems, prototype vs production
├── src/
│   ├── main.rs                CLI + server wiring (axum router)
│   ├── config.rs              runtime config (data dir, base URL, admin token)
│   ├── error.rs               error type + IntoResponse + WWW-Authenticate
│   ├── tokens.rs              in-memory token store, scopes
│   ├── auth.rs                Basic/Bearer extraction + authorization helpers
│   ├── storage.rs             bare-repo storage, fork-via-alternates (THE CORE)
│   ├── smart_http.rs          CGI bridge to git-http-backend
│   └── rest.rs                REST endpoints (create / fork / tokens / delete)
├── tests/
│   └── smoke.sh               7-step end-to-end: create → clone → push → fork → scopes
└── scripts/
    └── bench_fork.sh          10,000-fork benchmark; measures disk + latency
```

Under `$DATA_DIR` at runtime:

```
data/
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

## Development

```sh
# Build
cargo build                 # debug
cargo build --release       # optimized, used by benchmarks

# Run
cargo run -- serve --data-dir ./data --bind 127.0.0.1:8787

# Test
cargo test                  # unit tests (4 currently: storage + smart-http)
./tests/smoke.sh            # end-to-end integration test
./scripts/bench_fork.sh     # fork benchmark, knobs via env:
FORKS=100   PARALLEL=4  ./scripts/bench_fork.sh   # quick sanity run
FORKS=10000 PARALLEL=32 ./scripts/bench_fork.sh   # the headline test
KEEP=1 FORKS=5 ./scripts/bench_fork.sh            # keep data dir for poking
```

Logging is via `tracing`. Tune with `RUST_LOG`:

```sh
RUST_LOG=artifacts=debug,tower_http=info cargo run -- serve ...
```

## Roadmap

| Milestone | Scope | Replaces |
| --------- | ----- | -------- |
| **M0** (this) | single-node prototype, `git http-backend` CGI, in-memory tokens | — |
| **M1** | native smart-HTTP via `gitoxide`; no CGI boundary | `git http-backend`, fork-per-request |
| **M2** | pluggable `Storage` trait: `FsStorage` + `ChunkedStorage` (objects in KV/S3, matching DO+SQLite shape) | bare repos on disk |
| **M3** | first-class refs store with CAS semantics, per-repo state machine | git's filesystem refs |
| **M4** | real auth: short-lived, scoped, revocable tokens; issuer separate from the data plane | in-memory token map |
| **M5** | REST-side commits (`POST /v1/repos/:id/commits`) so serverless callers don't need a git client | — |
| **M6** | replication, snapshots, PITR, LFS, webhooks, metrics | — |

Each milestone is designed to land without breaking the API surface at the
edge. A caller written against M0 should keep working against M6 with no
code change — same `remote` URL shape, same REST bodies.

## Design decisions worth arguing about

**Q: Why shell out to `git http-backend`? That's a process fork per request.**

A: For M0, because it is the canonical, git-project-maintained reference
implementation of the server side of smart-HTTP. Correctness is free. The
trade is p99 latency (process fork dominates), which we swap out in M1 when
we move to `gitoxide`. Getting the architectural shape right (fork-as-
metadata, refs-as-CAS) first, and optimizing the protocol path second, is
the right order.

**Q: Why not use `gitoxide` or `libgit2` from day one?**

A: We will, in M1. Doing it in M0 would have cost days and proved nothing
that's not already proved. The goal of M0 is feasibility: can we fork 10,000
repos in seconds, for bytes of disk? Yes, measurably. Move on.

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

**Q: Why isn't there a `POST /v1/repos/:id/commits` endpoint (server-side
commits for no-git-client callers)?**

A: That's listed as M5. It requires writing blob/tree/commit objects directly
into the object store, which in turn requires a first-class git object
writer. We're waiting on the `gitoxide` swap (M1) to avoid writing one from
scratch just to throw it away.

**Q: Does it work with isomorphic-git, go-git, jgit?**

A: It should — we don't implement the protocol ourselves; `git http-backend`
does. Any client that interoperates with a stock git HTTP server should
work. The smoke test exercises cli-`git`; extending it to other clients is
on the to-do list.

## License

Apache-2.0 (same as most of the Rust ecosystem; change at will).
