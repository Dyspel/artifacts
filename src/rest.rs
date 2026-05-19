//! REST endpoints for creating repos, forking, and minting tokens.
//!
//! Shape modeled loosely on the Cloudflare Artifacts public API so callers
//! written for that surface can be adapted with a URL change.
//!
//! Handlers live in concern-scoped submodules and are re-exported from
//! this file so `crate::rest::name` continues to work for the router:
//!
//! - [`repos`]    — create / fork / delete / list
//! - [`tokens`]   — mint / list / revoke / rotate
//! - [`webhooks`] — create / list / delete
//! - [`admin`]    — `/v1/admin/*` inspection + maintenance
//! - [`health`]   — `/v1/health` + `/v1/health/ready`
//!
//! Shared cross-handler types (`RestState`, the admin summary shapes,
//! the pagination query) and small fs helpers (`list_refs`, `dir_size`,
//! `cascade_delete_order`) stay in this file because more than one
//! submodule depends on them.

pub mod admin;
pub mod health;
pub mod repos;
pub mod tokens;
pub mod webhooks;

use crate::{
    auth::authorize_rest,
    config::Config,
    error::{Error, Result},
    ownership::OwnershipStore,
    rate_limit::RateLimiter,
    refs::RefStore,
    storage::Storage,
    tokens::TokenStore,
};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// Re-exports so existing `crate::rest::name` imports (main.rs router,
// other handler modules) keep working after the split.
pub use admin::{
    admin_audit_stats, admin_gc_preview, admin_gc_run, admin_get_repo,
    admin_list_audit, admin_list_repos, admin_rotate_token,
    admin_rotate_webhook_key, admin_verify_audit_chain,
};
pub use health::{health, health_ready};
pub use repos::{create_repo, delete_repo, fork_repo, list_repos};
pub use tokens::{mint_token, list_tokens, revoke_token, rotate_tokens};
pub use webhooks::{create_webhook, delete_webhook, list_webhooks};

/// Data plane: every store/cache that holds repo content or metadata.
/// Grouped so a handler that only reads/writes repos can depend on
/// `DataState` rather than the full `RestState`.
#[derive(Clone)]
pub struct DataState {
    /// Repo lifecycle backend. M0 ships `FsStorage`; future impls
    /// (chunked KV, object-store-backed) drop in behind the same trait.
    pub storage: Arc<dyn Storage>,
    /// Who-owns-what. Populated by `create_repo` / `fork_repo`, read
    /// by the ownership-enforcing handlers (anything that mutates or
    /// mints credentials for an existing repo).
    pub ownership: Arc<dyn OwnershipStore>,
    /// Ref CAS backend. M0 ships `FsRefStore`; M3-proper swaps in a
    /// distributed impl without touching any handler.
    pub refs: Arc<dyn RefStore>,
    /// Object-store backend for loose-object reads / writes / list /
    /// delete + the blob-read endpoint.
    pub objects: Arc<dyn crate::object_store::ObjectStore>,
    /// Memoizes `objects/info/alternates` → `source_id` resolution.
    pub alternates_cache: Arc<crate::alternates_cache::AlternatesCache>,
}

/// Authentication-adjacent state. Handlers that mint, list, revoke,
/// or rate-limit on per-principal credentials depend on this.
#[derive(Clone)]
pub struct AuthnState {
    pub tokens: Arc<dyn TokenStore>,
    /// Token-bucket rate limiter, keyed by `(subject, class)`. Admin
    /// bypasses. Enforced per handler so that expensive vs cheap
    /// endpoints draw from separate classes.
    pub rate_limit: Arc<RateLimiter>,
}

/// Observability + event-bus state. Audit log, webhook registry,
/// in-process event bus.
#[derive(Clone)]
pub struct ObservState {
    /// Durable audit log. Mirrors the live `tracing!(target: "audit")`
    /// stream into SQLite so admin tooling can query history after
    /// the fact. Best-effort — a SQLite hiccup logs but never fails
    /// the underlying mutation.
    pub audit: Arc<dyn crate::audit::AuditStore>,
    /// In-process fan-out for commit / fork / status events. Lossy
    /// by design — slow subscribers get a Lagged error instead of
    /// blocking the bus.
    pub events: crate::events::EventBus,
    /// Webhook subscriptions registry. In-memory `MemRegistry` today;
    /// SQLite-backed when subscriptions need to survive a restart.
    pub webhooks: Arc<dyn crate::webhooks::WebhookRegistry>,
    /// Path to the on-disk webhook master key file. `None` for
    /// env-var-only deployments. `admin_rotate_webhook_key` rewrites
    /// it post-rotation so a restart picks up the new key.
    pub webhook_key_path: Option<std::path::PathBuf>,
}

/// Process-level runtime signals. Today just the readiness drain
/// flag; a future config-reload trigger or shutdown-deadline tracker
/// would land here.
#[derive(Clone)]
pub struct RuntimeState {
    /// Set to `true` once a SIGTERM/SIGINT has been received, before
    /// the axum-server graceful drain begins. The readiness probe
    /// short-circuits to 503 when this is set, so an orchestrator
    /// can pull the process out of rotation *before* it stops
    /// accepting new connections.
    pub draining: Arc<std::sync::atomic::AtomicBool>,
}

/// Top-level state injected into every REST handler via
/// `State<RestState>`. The four sub-states group related backends so
/// future handlers can depend on a focused slice (e.g.
/// `State<ObservState>`) rather than the whole bag.
#[derive(Clone)]
pub struct RestState {
    pub cfg: Arc<Config>,
    pub data: DataState,
    pub authn: AuthnState,
    pub observ: ObservState,
    pub runtime: RuntimeState,
}

#[derive(Debug, Serialize)]
pub struct RepoHandle {
    pub id: String,
    pub remote: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct AdminRepoSummary {
    pub id: String,
    /// `None` for admin-created repos.
    pub owner: Option<String>,
    /// Unix epoch seconds.
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    /// ID of the repo this is a fork of, if any — derived from reading
    /// `objects/info/alternates`.
    #[serde(rename = "sourceId", skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdminRepoDetail {
    #[serde(flatten)]
    pub summary: AdminRepoSummary,
    /// Size on disk in bytes. Walks the repo dir so not free — only
    /// populated on the single-repo endpoint.
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    pub refs: Vec<RefEntry>,
}

#[derive(Debug, Serialize)]
pub struct RefEntry {
    pub name: String,
    pub sha: String,
}

/// Pagination query shared by `GET /v1/repos` (user-scoped) and
/// `GET /v1/admin/repos` (admin-scoped). Both fields are optional;
/// missing fields fall back to `LIST_REPOS_DEFAULT_LIMIT` / `0`.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct ListReposQuery {
    /// Page size. Server-capped at `LIST_REPOS_MAX_LIMIT` (5000);
    /// default 1000. High enough that realistic prototype-stage callers
    /// (the GUI poller, the smoke harness) hit it implicitly — the cap
    /// is a safety bound on a previously-unbounded endpoint, not a
    /// behaviour change for current users.
    pub limit: Option<u32>,
    /// Number of rows to skip (in `created_at DESC` order). Use the
    /// `X-Total-Count` response header to know when to stop paging.
    pub offset: Option<u32>,
}

pub(crate) const LIST_REPOS_DEFAULT_LIMIT: u32 = 1000;
pub(crate) const LIST_REPOS_MAX_LIMIT: u32 = 5000;

pub(crate) fn remote_url(cfg: &Config, id: &str, token: &str) -> String {
    // https://x:TOKEN@host/git/:id.git — the form git clients parse natively.
    let base = cfg.public_base_url.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("https://") {
        format!("https://x:{token}@{rest}/git/{id}.git")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("http://x:{token}@{rest}/git/{id}.git")
    } else {
        format!("{base}/git/{id}.git") // unusual; caller will need to set creds themselves
    }
}

pub(crate) fn require_admin(state: &RestState, headers: &HeaderMap) -> Result<()> {
    let principal = authorize_rest(
        headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    if !matches!(principal, crate::auth::Principal::Admin) {
        return Err(Error::Forbidden("admin inspection endpoints require admin auth"));
    }
    Ok(())
}

/// BFS the dependent-fork tree rooted at `id` and return the
/// deletion order: dependents before dependencies. Iterative impl
/// (no recursion) so a deeply chained fork tree can't blow the
/// stack. Linear in the size of the dependent set — typically tiny.
pub(crate) fn cascade_delete_order(
    repos_dir: &std::path::Path,
    id: &str,
    cache: &crate::alternates_cache::AlternatesCache,
) -> Result<Vec<String>> {
    use std::collections::HashSet;
    // Levels: the seed is at depth 0; its forks at depth 1; their
    // forks at depth 2; etc. We delete from the deepest level back
    // to depth 0, so a child never sees its parent disappear before
    // it does.
    let mut levels: Vec<Vec<String>> = vec![vec![id.to_string()]];
    let mut seen: HashSet<String> = std::iter::once(id.to_string()).collect();
    loop {
        let last = levels.last().cloned().unwrap_or_default();
        let mut next: Vec<String> = Vec::new();
        for repo in &last {
            for child in crate::reads::list_forks_of(repos_dir, repo, cache)? {
                if seen.insert(child.clone()) {
                    next.push(child);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        levels.push(next);
    }
    let mut out = Vec::with_capacity(seen.len());
    for level in levels.into_iter().rev() {
        out.extend(level);
    }
    Ok(out)
}

/// List refs in a bare repo by recursively reading `refs/`. Only uses
/// the fs — no subprocess — so it's fast enough to include on the detail
/// endpoint.
pub(crate) fn list_refs(repo_path: &std::path::Path) -> std::io::Result<Vec<RefEntry>> {
    let mut out = Vec::new();
    walk_refs(&repo_path.join("refs"), "refs", &mut out)?;
    // Also read packed-refs (git consolidates refs here on gc).
    let packed = repo_path.join("packed-refs");
    if packed.exists() {
        let content = std::fs::read_to_string(&packed)?;
        for line in content.lines() {
            // Skip comments and peeled-ref lines (start with '^').
            if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
                continue;
            }
            if let Some((sha, name)) = line.split_once(' ') {
                // packed-refs can duplicate loose refs; dedupe by name.
                if out.iter().any(|r| r.name == name) {
                    continue;
                }
                out.push(RefEntry {
                    name: name.to_string(),
                    sha: sha.to_string(),
                });
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn walk_refs(
    dir: &std::path::Path,
    prefix: &str,
    out: &mut Vec<RefEntry>,
) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let full = format!("{prefix}/{name}");
        if path.is_dir() {
            walk_refs(&path, &full, out)?;
        } else if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let sha = content.trim().to_string();
                if !sha.is_empty() {
                    out.push(RefEntry { name: full, sha });
                }
            }
        }
    }
    Ok(())
}

/// Recursive dir-size. Not cached; a full walk. Only called from the
/// detail endpoint, so cost is bounded to one repo at a time.
pub(crate) fn dir_size(path: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        for entry in std::fs::read_dir(&p)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                total += entry.metadata()?.len();
            }
        }
    }
    Ok(total)
}

// `source_id` (parent repo) resolution lives in `crate::alternates_cache`
// so it can memoize across admin-list polls. Handlers call
// `state.data.alternates_cache.lookup(...)` instead of reading the file
// directly.

// alternates → source_id resolution is tested in
// `crate::alternates_cache::tests`. No duplicate coverage here.

// Health-readiness tests live alongside the handler in `health.rs`.
