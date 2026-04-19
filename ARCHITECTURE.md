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

M0 answered #1 (shell out to `git http-backend`, guaranteed correct) and
#2 (fork-via-alternates, measured). M3a extracts the CAS boundary — #3 —
into a trait so the swap to a distributed ref store is a drop-in later.
The single-node `FsRefStore` delegates to `git update-ref`, which gives us
file-system CAS today; a future multi-node impl backed by a state machine
per repo is a local code change that doesn't reach out to the handlers.

## Prototype shape

```
git clone https://x:$TOKEN@host/git/:id.git
       │
       ▼
  axum  ── auth middleware ──► basic/bearer, in-memory token map
       │
       │  GET  /git/:id.git/info/refs?service=git-upload-pack
       │  POST /git/:id.git/git-upload-pack
       │  POST /git/:id.git/git-receive-pack
       │
       ▼
  smart-HTTP bridge
       │
       │  exec(/usr/lib/git-core/git-http-backend) as CGI
       │  stdin  = request body
       │  stdout = response body
       │  env    = { GIT_PROJECT_ROOT=$DATA_DIR/repos,
       │             GIT_HTTP_EXPORT_ALL=1,
       │             PATH_INFO, REQUEST_METHOD, QUERY_STRING,
       │             CONTENT_TYPE }
       │
       ▼
  bare repos on disk: $DATA_DIR/repos/{id}.git
       │
       └── forks: $DATA_DIR/repos/{fork_id}.git
                  └── objects/info/alternates → {source_id}.git/objects
```

### Why `git http-backend` for M0

Because it is the reference implementation of the server side of smart-HTTP,
maintained by the git project itself. Correctness is free. We trade a process
fork per request for confidence that every client works end-to-end from day
one. The cost is real — fork/exec is expensive, and there is no way to stream
packs out of a chunked object store through a CGI boundary — but it's the
right *prototype* shape. M1 replaces it with native code.

### Why `alternates` for forks

`.git/objects/info/alternates` is git's own mechanism for sharing object
databases across repos. Write one file, fork done. `git gc` and friends
respect alternates. This is how GitHub's internal "fork network" (a.k.a.
"network.git") has worked for fifteen years. It's correct, fast, and costs
no new code.

The alternative — copying all objects — defeats the entire product.

### Why single-node refs for M0

Git already stores refs correctly on a single machine with atomic rename
semantics. A separate ref store is only useful once we're multi-node. For a
prototype running on one box, it would be ceremony with no payoff.

## Production shape

```
        ┌──────── Git smart-HTTP (native, gitoxide)  ◄── auth  ◄── TLS term
        │
        ├──► Object store     content-addressed, chunked
        │                     (SQLite-in-DO for hot path, R2 for cold)
        │
        ├──► Refs store       per-repo state machine with CAS
        │                     (DurableObject or Raft group)
        │
        └──► Metadata DB      repos, tokens, acls, quotas
                              (conventional RDBMS)

        ┌──────── REST API (for non-git callers)  ◄── auth  ◄── TLS term
        │
        └── same three backends as above
```

The M0→M1→M2 path in [README.md](./README.md) walks this one piece at a
time, keeping an end-to-end working system at every step.

## What we are not building

- **A hosted git UI.** No web view of a repo, no PR review, no issues, no CI.
  This is an infrastructure product, not GitHub.
- **Arbitrary merge semantics.** The server accepts pushes and rejects
  non-fast-forwards the same way any git server does. Merge is the client's
  job, or the agent's.
- **LFS in M0.** LFS is a separate protocol bolted onto git; we'll add it
  once the core is stable.
- **Policy as code.** No branch protection rules, no required reviewers, no
  status checks. Those are human-workflow features; this is an agent product.

## What the 10,000-fork test actually measures

The fork benchmark in `scripts/bench_fork.sh` is a feasibility-critical test.
It proves:

1. Fork latency is bounded by metadata write cost, not object copy cost.
2. Disk usage is ~flat after the 10,000 forks (growth is only new inodes and
   a handful of bytes per fork for the alternates file and refs).
3. Clones of the forks succeed and resolve objects through alternates.

If any of those three fail, the architecture is wrong and the rest of the
system doesn't matter. Everything else (auth, replication, observability) is
engineering in the small compared to this.
