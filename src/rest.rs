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
    admin_audit_stats, admin_gc_preview, admin_gc_run, admin_get_repo, admin_list_audit,
    admin_list_repos, admin_rotate_jwt_key, admin_rotate_token, admin_rotate_webhook_key,
    admin_verify_audit_chain,
};
pub use health::{health, health_ready};
pub use repos::{create_repo, delete_repo, fork_repo, list_repos};
pub use tokens::{list_tokens, mint_token, revoke_token, rotate_tokens};
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
    /// Durable delivery outbox — `Some` only for the SQLite backend.
    /// When present, handlers enqueue webhook deliveries at publish time
    /// (via `webhooks::publish_event`) so a broadcast lag can't drop
    /// them; `None` (MemRegistry) falls back to the bus dispatcher's
    /// direct dispatch.
    pub webhook_outbox: Option<Arc<dyn crate::webhooks::DeliveryOutbox>>,
    /// Path to the on-disk webhook master key file. `None` for
    /// env-var-only deployments. `admin_rotate_webhook_key` rewrites
    /// it post-rotation so a restart picks up the new key.
    pub webhook_key_path: Option<std::path::PathBuf>,
    /// Path to the on-disk JWT signing secret. `None` when the
    /// secret was env-pinned (`ARTIFACTS_JWT_SECRET` set) — in that
    /// case the rotate endpoint still rotates the in-memory cell but
    /// doesn't touch disk; the operator must update the env var out
    /// of band before the process restarts.
    pub jwt_key_path: Option<std::path::PathBuf>,
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
    pub token: crate::ids::Token,
}

#[derive(Debug, Serialize)]
pub struct AdminRepoSummary {
    pub id: crate::ids::RepoId,
    /// `None` for admin-created repos.
    pub owner: Option<crate::ids::Subject>,
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

pub(crate) fn remote_url(cfg: &Config, id: &str, token: &crate::ids::Token) -> String {
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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    if !matches!(principal, crate::auth::Principal::Admin) {
        return Err(Error::Forbidden(
            "admin inspection endpoints require admin auth",
        ));
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

fn walk_refs(dir: &std::path::Path, prefix: &str, out: &mut Vec<RefEntry>) -> std::io::Result<()> {
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

#[cfg(test)]
mod router_tests {
    //! In-process `oneshot` router tests for the repos / tokens / admin
    //! HTTP surfaces. The integration smoke drives these out-of-process
    //! (invisible to in-process coverage); these exercise auth, 404, and
    //! owner/admin-enforcement branches through the real handlers.
    use super::{
        admin_gc_preview, admin_list_repos, create_repo, list_repos, mint_token, AuthnState,
        DataState, ObservState, RestState, RuntimeState,
    };
    use crate::merge::merge_branches;
    use crate::reads::get_blob;
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use std::sync::{atomic::AtomicBool, Arc};
    use tower::ServiceExt;

    const ADMIN: &str = "admin-token-for-rest-router-tests-01234567";
    const JWT_SECRET: &str = "rest-router-test-secret";

    fn build_state(dir: &std::path::Path) -> RestState {
        let data_dir = dir.to_path_buf();
        let storage = crate::storage::FsStorage::new(data_dir.join("repos")).unwrap();
        let cfg = crate::config::Config::new(
            data_dir.clone(),
            "http://localhost".to_string(),
            ADMIN.to_string(),
            Some(JWT_SECRET.to_string()),
            None,
            None,
            100,
            1 << 20,
            1 << 30,
            false,
        );
        RestState {
            cfg: Arc::new(cfg),
            data: DataState {
                storage: Arc::new(storage),
                ownership: Arc::new(
                    crate::ownership::SqliteOwnershipStore::open(&data_dir.join("own.db")).unwrap(),
                ),
                refs: Arc::new(crate::refs::MemRefStore::new()),
                objects: Arc::new(crate::object_store::MemObjectStore::new()),
                alternates_cache: Arc::new(crate::alternates_cache::AlternatesCache::new()),
            },
            authn: AuthnState {
                tokens: Arc::new(
                    crate::tokens::SqliteTokenStore::open(&data_dir.join("tok.db")).unwrap(),
                ),
                rate_limit: Arc::new(crate::rate_limit::RateLimiter::with_defaults()),
            },
            observ: ObservState {
                audit: Arc::new(crate::audit::NoopAuditStore),
                events: crate::events::EventBus::new(),
                webhooks: Arc::new(crate::webhooks::MemRegistry::new()),
                webhook_outbox: None,
                webhook_key_path: None,
                jwt_key_path: None,
            },
            runtime: RuntimeState {
                draining: Arc::new(AtomicBool::new(false)),
            },
        }
    }

    fn app(dir: &std::path::Path) -> Router {
        Router::new()
            .route("/v1/repos", post(create_repo).get(list_repos))
            .route("/v1/repos/:id/tokens", post(mint_token))
            .route("/v1/repos/:id/merge", post(merge_branches))
            .route("/v1/repos/:id/blob", get(get_blob))
            .route("/v1/admin/repos", get(admin_list_repos))
            .route("/v1/admin/repos/:id/gc-preview", get(admin_gc_preview))
            .with_state(build_state(dir))
    }

    fn user_jwt(subject: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        #[derive(serde::Serialize)]
        struct Claims {
            sub: String,
            exp: usize,
        }
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + 3600;
        encode(
            &Header::default(),
            &Claims {
                sub: subject.to_string(),
                exp,
            },
            &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
        )
        .unwrap()
    }

    fn req(method: &str, uri: &str, bearer: Option<&str>, body: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(t) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        b.body(body.map_or_else(Body::empty, |s| Body::from(s.to_string())))
            .unwrap()
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn create_repo_requires_auth() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        let (status, _) = send(&app, req("POST", "/v1/repos", None, Some("{}"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_create_then_list_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        let (status, body) = send(&app, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["id"].as_str().is_some());
        assert!(body["token"].as_str().is_some());
        let (status, body) = send(&app, req("GET", "/v1/repos", Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().map(|a| a.len()), Some(1));
    }

    #[tokio::test]
    async fn mint_token_on_missing_repo_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        let (status, _) = send(
            &app,
            req(
                "POST",
                "/v1/repos/no-such-repo/tokens",
                Some(ADMIN),
                Some(r#"{"scope":"read"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn mint_token_requires_auth() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        let (status, _) = send(
            &app,
            req(
                "POST",
                "/v1/repos/whatever-repo/tokens",
                None,
                Some(r#"{"scope":"read"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_repos_forbidden_for_jwt_user() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        let jwt = user_jwt("mallory");
        let (status, _) = send(&app, req("GET", "/v1/admin/repos", Some(&jwt), None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // …and admin succeeds.
        let (status, body) = send(&app, req("GET", "/v1/admin/repos", Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_array());
    }

    #[tokio::test]
    async fn admin_gc_preview_on_missing_repo_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        let (status, _) = send(
            &app,
            req(
                "GET",
                "/v1/admin/repos/no-such-repo/gc-preview",
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn merge_on_missing_repo_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        let (status, _) = send(
            &app,
            req(
                "POST",
                "/v1/repos/no-such-repo/merge",
                Some(ADMIN),
                Some(r#"{"sourceBranch":"feature","targetBranch":"main"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn merge_with_invalid_branch_is_400() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        // Create a repo so the merge handler reaches branch validation.
        let (status, body) = send(&app, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        assert_eq!(status, StatusCode::OK);
        let id = body["id"].as_str().unwrap();
        // A branch name with a space is rejected before any git work.
        let (status, _) = send(
            &app,
            req(
                "POST",
                &format!("/v1/repos/{id}/merge"),
                Some(ADMIN),
                Some(r#"{"sourceBranch":"bad branch","targetBranch":"main"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn blob_on_missing_repo_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let app = app(tmp.path());
        let (status, _) = send(
            &app,
            req(
                "GET",
                "/v1/repos/no-such-repo/blob?ref=HEAD&path=README.md",
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
