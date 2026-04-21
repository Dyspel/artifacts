//! REST endpoints for creating repos, forking, and minting tokens.
//!
//! Shape modeled loosely on the Cloudflare Artifacts public API so callers
//! written for that surface can be adapted with a URL change.

use crate::{
    auth::authorize_rest,
    config::Config,
    error::{Error, Result},
    ownership::{check_repo_quota, enforce_owner, OwnershipStore},
    rate_limit::{Class, RateLimiter},
    refs::RefStore,
    storage::{new_repo_id, Storage},
    tokens::{Scope, TokenStore},
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct RestState {
    pub cfg: Arc<Config>,
    /// Repo lifecycle backend. M0 ships `FsStorage`; future impls
    /// (chunked KV, object-store-backed) drop in behind the same trait.
    pub storage: Arc<dyn Storage>,
    pub tokens: Arc<dyn TokenStore>,
    /// Who-owns-what. Populated by `create_repo` / `fork_repo`, read by
    /// the ownership-enforcing handlers (anything that mutates or mints
    /// credentials for an existing repo).
    pub ownership: Arc<dyn OwnershipStore>,
    /// Ref CAS backend. M0 ships `FsRefStore`; M3-proper swaps in a
    /// distributed impl without touching any handler.
    pub refs: Arc<dyn RefStore>,
    /// Token-bucket rate limiter, keyed by `(subject, class)`. Admin
    /// bypasses. Enforced per handler by the handler itself so that
    /// expensive vs cheap endpoints draw from separate classes.
    pub rate_limit: Arc<RateLimiter>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct CreateRepoBody {
    /// Optional caller-supplied id. If omitted we generate one.
    pub id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RepoHandle {
    pub id: String,
    pub remote: String,
    pub token: String,
}

fn remote_url(cfg: &Config, id: &str, token: &str) -> String {
    // https://x:TOKEN@host/git/:id.git — the form git clients parse natively.
    let base = cfg.public_base_url.trim_end_matches('/');
    // Insert credentials into the URL.
    if let Some(rest) = base.strip_prefix("https://") {
        format!("https://x:{token}@{rest}/git/{id}.git")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("http://x:{token}@{rest}/git/{id}.git")
    } else {
        format!("{base}/git/{id}.git") // unusual; caller will need to set creds themselves
    }
}

/// POST /v1/repos
///
/// Creates an empty repo owned by the caller. If the caller is `Admin`
/// the owner is recorded as `NULL` (admin-owned); if the caller is a
/// user, their JWT subject becomes the owner for all subsequent
/// access checks.
pub async fn create_repo(
    State(state): State<RestState>,
    headers: HeaderMap,
    body: Option<Json<CreateRepoBody>>,
) -> Result<Json<RepoHandle>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token,
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Create)?;
    check_repo_quota(
        &*state.ownership,
        &principal,
        state.cfg.max_repos_per_user,
    )
    .await?;
    let id = body
        .and_then(|Json(b)| b.id)
        .unwrap_or_else(new_repo_id);
    state.storage.create(&id)?;
    // Record ownership *before* minting the token so a crash between the
    // two leaves a repo we can identify the owner of.
    state
        .ownership
        .record_owner(&id, principal.subject())
        .await?;
    let token = state.tokens.mint(&id, Scope::Write, None).await?;
    let remote = remote_url(&state.cfg, &id, &token);
    Ok(Json(RepoHandle { id, remote, token }))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct ForkBody {
    pub id: Option<String>,
    #[serde(rename = "readOnly")]
    pub read_only: bool,
}

/// POST /v1/repos/:id/forks
///
/// Forking requires read access to the source (enforced as ownership, so
/// only the source's owner — or admin — can fork). The fork itself is
/// owned by the caller; this lets a user fork their own template into a
/// personal workspace, but prevents arbitrary users from cloning each
/// other's repos via this endpoint.
pub async fn fork_repo(
    State(state): State<RestState>,
    Path(source_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ForkBody>>,
) -> Result<Json<RepoHandle>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token,
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Create)?;
    if !state.storage.exists(&source_id) {
        return Err(Error::RepoNotFound(source_id));
    }
    enforce_owner(&*state.ownership, &principal, &source_id).await?;
    // Quota applies to forks too — the point is to bound a single
    // user's footprint regardless of whether the repos came from
    // create or fork.
    check_repo_quota(
        &*state.ownership,
        &principal,
        state.cfg.max_repos_per_user,
    )
    .await?;
    let (fork_id, read_only) = body
        .map(|Json(b)| (b.id, b.read_only))
        .unwrap_or((None, false));
    let fork_id = fork_id.unwrap_or_else(new_repo_id);
    state.storage.fork(&source_id, &fork_id)?;
    state
        .ownership
        .record_owner(&fork_id, principal.subject())
        .await?;
    let scope = if read_only { Scope::Read } else { Scope::Write };
    let token = state.tokens.mint(&fork_id, scope, None).await?;
    let remote = remote_url(&state.cfg, &fork_id, &token);
    Ok(Json(RepoHandle { id: fork_id, remote, token }))
}

#[derive(Debug, Deserialize)]
pub struct MintTokenBody {
    pub scope: Scope,
    /// Optional lifetime in seconds. `None` means never expires.
    #[serde(default, rename = "ttlSeconds")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct TokenMinted {
    pub token: String,
    pub remote: String,
    /// Unix epoch seconds. `null` if the token doesn't expire.
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<u64>,
}

/// POST /v1/repos/:id/tokens
pub async fn mint_token(
    State(state): State<RestState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MintTokenBody>,
) -> Result<Json<TokenMinted>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token,
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Token)?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.ownership, &principal, &id).await?;
    let ttl = body.ttl_seconds.map(std::time::Duration::from_secs);
    let token = state.tokens.mint(&id, body.scope, ttl).await?;
    let remote = remote_url(&state.cfg, &id, &token);
    let expires_at = ttl.map(|d| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|now| now.as_secs() + d.as_secs())
            .unwrap_or(0)
    });
    Ok(Json(TokenMinted { token, remote, expires_at }))
}

#[derive(Debug, Deserialize)]
pub struct RevokeBody {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub revoked: bool,
}

/// POST /v1/tokens/revoke
///
/// Takes the token in the request body so it doesn't get captured in
/// access logs, URL history, or any other place URL paths usually land.
///
/// **Admin-only for now.** To let a `User` revoke only their own
/// tokens, we'd need the `TokenStore` to expose "what repo is this
/// token bound to" so we could `enforce_owner` against that. That's a
/// trait extension and belongs in M4b alongside `GET /v1/tokens`
/// listing. Until then, non-admin callers get 403.
pub async fn revoke_token(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(body): Json<RevokeBody>,
) -> Result<Json<RevokeResponse>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token,
        state.cfg.jwt_secret.as_deref(),
    )?;
    if !matches!(principal, crate::auth::Principal::Admin) {
        return Err(Error::Forbidden("token revocation is admin-only"));
    }
    // Admin-only; rate-limit skipped (admin is exempt anyway). Left
    // here as a no-op call for symmetry with the other handlers.
    state.rate_limit.check(&principal, Class::Token)?;
    let revoked = state.tokens.revoke(&body.token).await?;
    Ok(Json(RevokeResponse { revoked }))
}

/// DELETE /v1/repos/:id
pub async fn delete_repo(
    State(state): State<RestState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token,
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Default)?;
    enforce_owner(&*state.ownership, &principal, &id).await?;
    state.storage.delete(&id)?;
    state.ownership.delete(&id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /v1/health
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

/// `GET /v1/repos`
///
/// User-facing repo listing. Scoped by who's asking:
///   - `Admin` → every repo the server knows about.
///   - `User { subject }` → only repos that user owns.
///
/// Kept separate from `/v1/admin/repos` (which is Admin-only and serves
/// the operator-facing GUI) because the auth model differs: this endpoint
/// exists so a user's Fleet view can list their own repos without the
/// backend proxying each request with the admin token. Admin callers get
/// the same response shape as a convenience for tooling.
///
/// Response shape intentionally matches `AdminRepoSummary` so clients
/// that already parse `/v1/admin/repos` don't need a second parser.
pub async fn list_repos(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminRepoSummary>>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token,
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, crate::rate_limit::Class::Default)?;

    let rows = match &principal {
        crate::auth::Principal::Admin => state.ownership.list_all().await?,
        crate::auth::Principal::User { subject } => {
            state.ownership.list_by_owner(subject).await?
        }
    };
    let repos_dir = state.cfg.repos_dir();
    let summaries = rows
        .into_iter()
        .map(|r| AdminRepoSummary {
            source_id: read_alternates_source(&repos_dir, &r.id),
            id: r.id,
            owner: r.owner,
            created_at: r.created_at,
        })
        .collect();
    Ok(Json(summaries))
}

// ──────────────────────────────────────────────────────────────────────
// Admin read-only inspection surface
//
// These endpoints are admin-only (JWT principals get 403) and live under
// `/v1/admin/*` to make the separation obvious at the URL level. They
// power the artifacts-gui visualizer, and anyone else who needs to browse
// the server's state out-of-band.
// ──────────────────────────────────────────────────────────────────────

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

/// `GET /v1/admin/repos`
///
/// Returns every repo the server knows about. Expensive bits (disk size,
/// ref list) are deliberately left off this list endpoint so it stays
/// cheap even with thousands of repos — those live on the single-repo
/// detail endpoint.
pub async fn admin_list_repos(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminRepoSummary>>> {
    require_admin(&state, &headers)?;
    state.rate_limit.check(
        &crate::auth::Principal::Admin, // rate-limit is a no-op for admin; kept for symmetry
        crate::rate_limit::Class::Default,
    )?;

    let rows = state.ownership.list_all().await?;
    let repos_dir = state.cfg.repos_dir();
    let summaries = rows
        .into_iter()
        .map(|r| AdminRepoSummary {
            source_id: read_alternates_source(&repos_dir, &r.id),
            id: r.id,
            owner: r.owner,
            created_at: r.created_at,
        })
        .collect();
    Ok(Json(summaries))
}

/// `GET /v1/admin/repos/:id`
///
/// Full detail for one repo: base summary + refs + size-on-disk. The
/// size walk is only done here (not in the list endpoint) because it
/// requires reading the repo's full directory tree.
pub async fn admin_get_repo(
    State(state): State<RestState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AdminRepoDetail>> {
    require_admin(&state, &headers)?;
    state.rate_limit.check(
        &crate::auth::Principal::Admin,
        crate::rate_limit::Class::Default,
    )?;

    // One PK lookup — gives us both the owner and the created_at
    // without scanning the whole repos table.
    let Some(row) = state.ownership.get_row(&id).await? else {
        return Err(Error::RepoNotFound(id));
    };

    let repos_dir = state.cfg.repos_dir();
    let repo_path = repos_dir.join(format!("{id}.git"));
    if !repo_path.is_dir() {
        // Metadata says the repo exists but the directory is gone —
        // treat as missing at the HTTP layer.
        return Err(Error::RepoNotFound(id));
    }

    let refs = list_refs(&repo_path).unwrap_or_default();
    let size_bytes = dir_size(&repo_path).unwrap_or(0);

    Ok(Json(AdminRepoDetail {
        summary: AdminRepoSummary {
            source_id: read_alternates_source(&repos_dir, &id),
            id,
            owner: row.owner,
            created_at: row.created_at,
        },
        size_bytes,
        refs,
    }))
}

/// Helper: reject non-admin principals with 403.
fn require_admin(state: &RestState, headers: &HeaderMap) -> Result<()> {
    let principal = authorize_rest(
        headers,
        &state.cfg.admin_token,
        state.cfg.jwt_secret.as_deref(),
    )?;
    if !matches!(principal, crate::auth::Principal::Admin) {
        return Err(Error::Forbidden("admin inspection endpoints require admin auth"));
    }
    Ok(())
}

/// Derive the `source_id` (parent repo) by reading `objects/info/alternates`.
/// Returns `None` if the file doesn't exist (repo is a root, not a fork)
/// or if its contents don't match our alternates-shape.
fn read_alternates_source(repos_dir: &std::path::Path, repo_id: &str) -> Option<String> {
    let p = repos_dir.join(format!("{repo_id}.git/objects/info/alternates"));
    let s = std::fs::read_to_string(p).ok()?;
    // Content we wrote is `<repos_dir>/<source_id>.git/objects\n`. Try to
    // parse that back. If it doesn't match (e.g., someone hand-edited),
    // fall through to None rather than guessing.
    let trimmed = s.trim();
    let prefix = format!("{}/", repos_dir.display());
    let rest = trimmed.strip_prefix(&prefix)?;
    let source_id = rest.strip_suffix(".git/objects")?;
    // Defensive: make sure the computed id doesn't contain path separators,
    // which would mean the alternates file points somewhere unexpected.
    if source_id.contains('/') || source_id.contains('\\') {
        return None;
    }
    Some(source_id.to_string())
}

/// List refs in a bare repo by recursively reading `refs/`. Only uses
/// the fs — no subprocess — so it's fast enough to include on the detail
/// endpoint.
fn list_refs(repo_path: &std::path::Path) -> std::io::Result<Vec<RefEntry>> {
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
fn dir_size(path: &std::path::Path) -> std::io::Result<u64> {
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
