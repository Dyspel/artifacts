# Integrating Artifacts into Dyspel

This document describes how to run Artifacts as the versioned-filesystem
backend for the Dyspel collaborative AI IDE. It assumes you have read
[README.md](./README.md) for the API surface and [ARCHITECTURE.md](./ARCHITECTURE.md)
for the design rationale.

Scope: what's actually wired up today. See the "Still open" section at
the bottom for the things this prototype does not yet solve and would
need before production Dyspel traffic.

## The story in one paragraph

Dyspel already has `backend/services/lite/gitSyncService.js` managing
local bare repos and per-user worktrees, with `proposalService.js` on
top for PR-like proposals and `aiConflictResolver.js` for AI-assisted
merges. Artifacts slots in **underneath** that layer: it replaces the
"bare repo on local disk" concern with a network-accessible versioned
filesystem that speaks git. Everything Dyspel does today (proposals,
conflict resolution, UI) stays; only the storage layer moves.

```
  Dyspel backend
  ├── routes/lite/sync.js          (unchanged)
  ├── services/lite/
  │   ├── proposalService.js       (unchanged)
  │   ├── aiConflictResolver.js    (unchanged)
  │   └── gitSyncService.js        (rewritten to call Artifacts HTTP)
  │                    │
  │                    │  HTTPS
  │                    ▼
  └──────►  Artifacts (this repo)
              - per-repo bare git storage
              - fork via alternates (O(1))
              - auth via Dyspel-signed JWTs
              - REST + git smart-HTTP
```

## Auth handoff

Artifacts accepts the JWT Dyspel already signs. No new credential
exchange, no extra service.

1. Dyspel signs JWTs the same way it does today:

   ```js
   // backend/routes/lite/auth.js, unchanged
   const token = jwt.sign(
     { userId: user.id, email: user.email, tier: 'lite' },
     liteConfig.jwt.secret,
     { expiresIn: liteConfig.jwt.expiresIn }
   );
   ```

2. Start Artifacts with the same secret Dyspel uses:

   ```sh
   ARTIFACTS_JWT_SECRET="$LITE_JWT_SECRET" \
   ARTIFACTS_ADMIN_TOKEN="$ARTIFACTS_ADMIN_TOKEN" \
     artifacts serve \
       --data-dir /var/lib/artifacts \
       --bind 127.0.0.1:8787 \
       --public-base-url https://artifacts.dyspel.internal
   ```

3. The Dyspel backend forwards the user's JWT as the `Authorization:
   Bearer <jwt>` header on REST calls. Artifacts verifies the signature
   (HS256), reads `userId`, and derives a `Principal::User { subject }`
   from it.

   Every REST endpoint that touches an existing repo (`POST /forks`,
   `POST /tokens`, `POST /commits`, `DELETE /repo`) is ownership-scoped:
   only the user who created the repo (or the admin token) can touch
   it. Cross-user access returns 403.

### Admin vs user credentials

| Caller                                 | Credential                 | Allowed to do                          |
| -------------------------------------- | -------------------------- | -------------------------------------- |
| Dyspel backend on behalf of a user     | user's JWT                 | create/fork/mint/commit/delete their own repos |
| Dyspel backend on behalf of the system | `ARTIFACTS_ADMIN_TOKEN`    | anything, on any repo                  |
| An agent running inside a container    | per-repo token (git Basic) | clone/push according to scope, that repo only |

An agent never sees the user's JWT. Dyspel mints a per-repo token on
the user's behalf (using the user's JWT) and hands *that* to the agent.
Agents can only ever reach one repo with one scope; compromise
containment is the trait boundary, not the JWT lifetime.

## gitSyncService migration sketch

The current service manages bare repos on local disk:

```js
// Before (simplified)
class GitSyncService {
  getBareRepoPath(projectId) { return path.join(ROOT, `${projectId}.git`); }
  getUserWorkspacePath(projectId, userId) { return path.join(ROOT, 'wt', projectId, userId); }

  async createProject(projectId) {
    await exec(`git init --bare ${this.getBareRepoPath(projectId)}`);
  }

  async pushChanges(projectId, userId, branch) {
    // git ops in the user's worktree
  }
  // ...
}
```

After Artifacts, the service becomes a thin HTTP client:

```js
// After (simplified)
class GitSyncService {
  constructor({ artifactsUrl, adminToken }) {
    this.url = artifactsUrl;
    this.admin = adminToken;
  }

  // Called when a project is created. Uses admin so the system
  // acts on behalf of the platform; the `ownerJwt` captures which
  // user the repo belongs to.
  async createProject(projectId, ownerJwt) {
    const r = await fetch(`${this.url}/v1/repos`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerJwt}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: projectId }),
    });
    if (!r.ok) throw new Error(`artifacts create failed: ${r.status}`);
    return r.json(); // { id, remote, token }
  }

  // User's git client / agent gets this URL to clone from.
  async getUserCloneUrl(projectId, userJwt, scope /* 'read' | 'write' */) {
    const r = await fetch(`${this.url}/v1/repos/${projectId}/tokens`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${userJwt}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ scope, ttlSeconds: 3600 }),
    });
    if (!r.ok) throw new Error(`artifacts mint-token failed: ${r.status}`);
    return (await r.json()).remote; // https://x:TOKEN@host/git/<id>.git
  }

  // Server-side commit from a proposal or AI-generated change set —
  // no git client needed.
  async commit(projectId, userJwt, { branch, parent, message, changes }) {
    const r = await fetch(`${this.url}/v1/repos/${projectId}/commits`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${userJwt}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ branch, parent, message, changes }),
    });
    if (r.status === 409) throw new RefConflictError(await r.json());
    if (!r.ok) throw new Error(`artifacts commit failed: ${r.status}`);
    return r.json(); // { commit, tree, branch }
  }

  // ...
}
```

The `proposalService` and `aiConflictResolver` on top are unchanged —
they call `gitSyncService.commit()` / `pushChanges()` / etc., which now
go over HTTP instead of shelling out locally.

## Project-ID → Repo-ID mapping

Keep the mapping in Dyspel's DB, not in Artifacts. Artifacts doesn't
need to know about "projects"; it stores repos by id, and it's Dyspel's
job to know which project in the UI corresponds to which artifacts repo.

Simplest shape: use the Dyspel project id directly as the artifacts
repo id (passed as `{ "id": projectId }` when creating).

This has two properties:
- Dyspel never needs a separate lookup table. The URL path and the
  REST id are the same string.
- A Dyspel-project-delete that fails halfway through leaves an
  orphaned artifacts repo; garbage collection is a Dyspel-level
  concern (run a job that lists orphans in Artifacts against the
  project table in the Dyspel DB).

If Dyspel ever has to support "renames that don't rewrite the repo
id," or "one project with multiple Git repos," a separate mapping
table replaces the shortcut without breaking anything.

## Forks and templates

Dyspel's "new project from template" feature becomes a fork call:

```js
async createFromTemplate(templateProjectId, newProjectId, userJwt) {
  const r = await fetch(
    `${this.url}/v1/repos/${templateProjectId}/forks`,
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${userJwt}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: newProjectId, readOnly: false }),
    },
  );
  return r.json();
}
```

The fork is O(1) in storage — 228 bytes regardless of template size.
The resulting repo is owned by the caller (the user opening the
template); the template itself is unchanged.

**Ownership caveat:** a user can only fork a template they own. For
platform-wide templates (a "React starter" everyone can use), the
admin account owns them, and the initial fork has to go through the
admin token or a Dyspel backend service that proxies it. Per-user
fork-of-admin-repo support is a small extension of the trait — a
grants table — and belongs in the grants/sharing feature, not M0.

## Collaboration branches

Current Dyspel model: each user gets a per-user branch in the bare
repo; the proposal service merges user branches back to main. That
maps cleanly onto Artifacts:

- One Artifacts repo per project.
- Branches named `users/<userId>` per user.
- Proposals are commits on those branches.
- `aiConflictResolver` fetches the conflicting files via git and
  pushes a resolution commit.

Nothing about Artifacts needs to know this is the model. It's
branches in a git repo.

What the migration *does* need to enforce: bounded branch count per
repo. Without a cap, a leaky "create ephemeral branch" in the agent
loop can grow refs/ forever. Either Dyspel caps it (preferred — Dyspel
knows which branches are live), or Artifacts grows a per-repo
branch-count limit. M0 has neither; add it in M4b alongside quotas.

## Session lifecycle

When a Dyspel session ends (logout, expire, explicit close):

1. Dyspel revokes all the per-repo tokens it minted for that session.
   Current shape: call `POST /v1/tokens/revoke` for each. Future:
   `POST /v1/tokens/revoke-by-subject` to revoke everything for a user
   in one call. That batch endpoint is trivial — just an SQL
   `UPDATE ... WHERE repo_id IN (SELECT id FROM repos WHERE owner_subject=?)`
   — and should land before any production traffic.

2. The agent containers hosting the session are torn down (Dyspel
   already does this). They had per-repo tokens that no longer work.

3. The repos themselves persist — sessions end, projects don't.

## Deployment recipe

```
┌────────────────────────────────────────────┐
│  caddy / nginx / cloudflared               │  TLS terminator
│  listening on 443                          │  public internet
│  artifacts.dyspel.example.com ──────┐      │
└─────────────────────────────────────┼──────┘
                                      │  HTTP on loopback
                                      ▼
┌────────────────────────────────────────────┐
│  artifacts serve                           │  single process
│   --bind 127.0.0.1:8787                    │
│   --public-base-url https://artifacts.dyspel.example.com
│   --data-dir /var/lib/artifacts            │
│   (ARTIFACTS_JWT_SECRET from env)          │
│   (ARTIFACTS_ADMIN_TOKEN from env)         │
└────────────────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────┐
│  /var/lib/artifacts/                       │
│    tokens.db       (SQLite: tokens + repos)│
│    repos/          (bare git repos)        │
└────────────────────────────────────────────┘
```

The TLS terminator is non-negotiable: Artifacts refuses to start on a
non-loopback bind with an `http://` public URL unless `--allow-insecure`
is passed. Tokens travel in the clear otherwise.

## Still open — production blockers this guide does not close

The commits this guide references cover "single-user dogfooding" plus
the basic abuse-bounding and observability needed before letting a
small cohort in. Before public / multi-tenant traffic, you still need:

- **Backups.** `tokens.db` + `repos/` on one disk. A host-failure-level
  event loses work. Minimum: nightly tar + rsync to object storage,
  documented restore procedure.
- **Observability.** Prometheus metrics on ops/s + latency per endpoint;
  structured logs with request IDs; OTel traces so Dyspel can correlate
  client session → artifacts request.
- **GC + alternates-aware delete.** Fork network keeps source objects
  alive forever. Need a mark-and-sweep that respects alternates.
- **Concurrency on the fork path.** Concurrent push-to-source during
  a fork captures a torn ref snapshot. Atomic `packed-refs` snapshot
  under a per-repo lock.
- **Native git protocol (M1b).** The subprocess-per-request model has a
  hard ~15 ms floor on clone; at 10k concurrent IDE sessions that's
  a real wall. See the roadmap in README.md.

See the response in chat for the full priority-ordered list with effort
estimates; this guide is the "what's wired today" half.

## What's wired today (changelog)

| Feature                                                | In main since |
| ------------------------------------------------------ | ------------- |
| JWT verification (HS256, Dyspel claim shape)           | Prod-1        |
| Per-repo ownership + 403 on cross-user access          | Prod-2        |
| Refuse non-loopback HTTP bind without `--allow-insecure` | Prod-3        |
| Per-user repo-count quota (`max_repos_per_user`)       | Prod-5        |
| Per-subject token-bucket rate limiter                  | Prod-6        |
| Per-blob size cap on REST commits                      | Prod-7        |
| Prometheus `/metrics` endpoint                         | Prod-9        |
| X-Request-Id roundtrip + structured request logs       | Prod-10       |

### Tuning knobs

For a Dyspel deploy, override the defaults:

```sh
ARTIFACTS_ADMIN_TOKEN=...                              # from secrets
ARTIFACTS_JWT_SECRET="$LITE_JWT_SECRET"                # same as Dyspel
ARTIFACTS_MAX_REPOS_PER_USER=1000                      # well above any real user
ARTIFACTS_MAX_COMMIT_BLOB_BYTES=$((8 * 1024 * 1024))   # 8 MB, the default
artifacts serve \
  --data-dir /var/lib/artifacts \
  --bind 127.0.0.1:8787 \
  --public-base-url https://artifacts.dyspel.example.com
```

The rate-limit budgets are compile-time constants in
`src/rate_limit.rs` (20 burst / 10 per min for create, 120 burst / 2
per sec for token, 600 burst / 10 per sec for commit). If Dyspel
needs different shapes per tier (e.g., Lite vs Pro), promote those
to configurable values — a small change.
