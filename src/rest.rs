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
    /// In-process fan-out for commit / fork / status events. Populated
    /// by the mutating handlers (commit, merge, fork, create). Consumed
    /// by the SSE endpoint in events.rs and (through there) by the
    /// backend BFF's live-stream bridge. Lossy by design — slow
    /// subscribers get a Lagged error instead of blocking the bus.
    pub events: crate::events::EventBus,
    /// Memoizes `objects/info/alternates` → `source_id` resolution.
    /// Populated lazily on first admin-list / admin-detail call; keyed
    /// by repo_id, invalidated on mtime change (and on delete).
    pub alternates_cache: Arc<crate::alternates_cache::AlternatesCache>,
    /// Webhook subscriptions registry. In-memory `MemRegistry` today;
    /// SQLite-backed when subscriptions need to survive a restart.
    pub webhooks: Arc<dyn crate::webhooks::WebhookRegistry>,
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
        &state.cfg.admin_token(),
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
    let token = state
        .tokens
        .mint(&id, Scope::Write, None, principal.subject())
        .await?;
    let remote = remote_url(&state.cfg, &id, &token);
    tracing::info!(
        target: "audit",
        event = "repo.create",
        actor = principal.audit_label(),
        repo_id = %id,
    );
    // Emit a status transition so subscribers pick up brand-new repos
    // without polling. "unknown → idle" matches the repo's initial
    // state in the Fleet UI's RepoStatus enum.
    state.events.publish(crate::events::Event::status(&id, "unknown", "idle"));
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
        &state.cfg.admin_token(),
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
    let token = state
        .tokens
        .mint(&fork_id, scope, None, principal.subject())
        .await?;
    let remote = remote_url(&state.cfg, &fork_id, &token);
    tracing::info!(
        target: "audit",
        event = "repo.fork",
        actor = principal.audit_label(),
        source_id = %source_id,
        repo_id = %fork_id,
        read_only,
    );
    state.events.publish(crate::events::Event::fork(&source_id, &fork_id));
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
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Token)?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.ownership, &principal, &id).await?;
    let ttl = body.ttl_seconds.map(std::time::Duration::from_secs);
    let token = state
        .tokens
        .mint(&id, body.scope, ttl, principal.subject())
        .await?;
    let remote = remote_url(&state.cfg, &id, &token);
    let expires_at = ttl.map(|d| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|now| now.as_secs() + d.as_secs())
            .unwrap_or(0)
    });
    tracing::info!(
        target: "audit",
        event = "token.mint",
        actor = principal.audit_label(),
        repo_id = %id,
        scope = ?body.scope,
        ttl_seconds = ?body.ttl_seconds,
    );
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
/// Authorization (M4b): admins always pass. Non-admins (JWT user) may
/// revoke a token iff they own the repo that token is bound to — i.e.
/// they could have minted it themselves. This is the "I think my
/// repo's token leaked, kill it" path that previously required an
/// admin to do.
pub async fn revoke_token(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(body): Json<RevokeBody>,
) -> Result<Json<RevokeResponse>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Token)?;

    // Resolve the token's bound repo for the audit log + the
    // ownership check. Admins skip the ownership check but we
    // still want the audit field populated; for a stale-or-fake
    // token there's nothing to bind to so log "unknown".
    let target_repo: Option<String> = state
        .tokens
        .lookup(&body.token)
        .await
        .ok()
        .flatten()
        .map(|rec| rec.repo_id.clone());

    if !matches!(principal, crate::auth::Principal::Admin) {
        // Look up the token's bound repo and require ownership. Any
        // failure to resolve the token (unknown / expired / already
        // revoked) is reported as a 403 rather than a 404, because the
        // alternative leaks "this token doesn't exist" to anyone with
        // a JWT — slight oracle for token-fishing.
        let repo_id = target_repo
            .as_deref()
            .ok_or(Error::Forbidden("not your token"))?;
        enforce_owner(&*state.ownership, &principal, repo_id).await?;
    }

    let revoked = state.tokens.revoke(&body.token).await?;
    tracing::info!(
        target: "audit",
        event = "token.revoke",
        actor = principal.audit_label(),
        repo_id = target_repo.as_deref().unwrap_or("unknown"),
        revoked,
    );
    Ok(Json(RevokeResponse { revoked }))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct RotateTokenBody {
    /// Scope for the freshly-minted replacement token. Defaults to
    /// `write` to mirror the create-repo / fork mint defaults — the
    /// most useful scope for an interactive client recovering after a
    /// suspected token leak.
    pub scope: Option<Scope>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RotateTokenResponse {
    /// How many tokens for this repo were marked revoked. Useful for
    /// surfacing "rotated 3 tokens" in CLI output / audit logs.
    pub revoked: u64,
    /// The fresh token, the same way `mint_token` would surface it.
    /// Caller stores it — we never hold the raw form server-side.
    pub token: String,
    pub remote: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookBody {
    pub url: String,
    /// HMAC-SHA256 secret. Optional — subscribers behind a private
    /// network might not bother. The server stores it verbatim
    /// today (no DB to hash against); when subscriptions persist we
    /// should hash on the way in.
    pub secret: Option<String>,
    /// Empty list means "all event kinds for this repo". Otherwise
    /// only events whose `kind` matches one of these are delivered.
    #[serde(default)]
    pub events: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookCreated {
    pub id: String,
}

/// POST /v1/repos/:id/webhooks
pub async fn create_webhook(
    State(state): State<RestState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CreateWebhookBody>,
) -> Result<Json<WebhookCreated>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Token)?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.ownership, &principal, &id).await?;
    let hook_id = state.webhooks.add(crate::webhooks::Subscription {
        id: String::new(),
        repo_id: id,
        url: body.url,
        secret: body.secret,
        events: body.events,
    });
    Ok(Json(WebhookCreated { id: hook_id }))
}

/// GET /v1/repos/:id/webhooks
pub async fn list_webhooks(
    State(state): State<RestState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::webhooks::Subscription>>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.ownership, &principal, &id).await?;
    Ok(Json(state.webhooks.list(&id)))
}

/// DELETE /v1/repos/:id/webhooks/:hook_id
pub async fn delete_webhook(
    State(state): State<RestState>,
    Path((id, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.ownership, &principal, &id).await?;
    let removed = state.webhooks.remove(&id, &hook_id);
    Ok(Json(serde_json::json!({ "removed": removed })))
}

/// GET /v1/repos/:id/tokens
///
/// Lists every live token bound to the repo. Admin sees all; a repo
/// owner sees their own (filtered by JWT subject). Returns
/// `TokenSummary` rows — never the raw token. The id field is the
/// SHA-256 hex of the token, truncated to 16 chars: stable, useful
/// for cross-referencing with `revoke`, but not enough to use as
/// auth.
pub async fn list_tokens(
    State(state): State<RestState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::tokens::TokenSummary>>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.ownership, &principal, &id).await?;
    let subject_filter = match &principal {
        // Admins see every row; users see rows they minted.
        crate::auth::Principal::Admin => None,
        crate::auth::Principal::User { subject } => Some(subject.as_str()),
    };
    let rows = state.tokens.list_for_repo(&id, subject_filter).await?;
    Ok(Json(rows))
}

/// POST /v1/repos/:id/tokens/rotate
///
/// Atomic-ish "kill-everything-and-re-mint" for a repo's tokens.
/// Useful when a token leaks: the caller doesn't have to enumerate
/// individual tokens to kill, and they get a fresh one in one round
/// trip.
///
/// "Atomic-ish" because there's a tiny window between the bulk
/// revoke and the new mint where a request authorized by an
/// already-validated cached token could still succeed; given each
/// request re-validates against the SQLite store on every call,
/// that window is on the order of the time between two SQL
/// statements (microseconds). For a stronger guarantee we'd run
/// both in one transaction — TokenStore doesn't expose that
/// today, and at our qps it's not necessary.
pub async fn rotate_tokens(
    State(state): State<RestState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RotateTokenBody>,
) -> Result<Json<RotateTokenResponse>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Token)?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.ownership, &principal, &id).await?;

    let revoked = state.tokens.revoke_all_for_repo(&id).await?;
    let scope = body.scope.unwrap_or(Scope::Write);
    let ttl = body.ttl_seconds.map(std::time::Duration::from_secs);
    let token = state
        .tokens
        .mint(&id, scope, ttl, principal.subject())
        .await?;
    let remote = remote_url(&state.cfg, &id, &token);
    tracing::info!(
        target: "audit",
        event = "token.rotate",
        actor = principal.audit_label(),
        repo_id = %id,
        revoked,
        scope = ?scope,
    );
    Ok(Json(RotateTokenResponse {
        revoked,
        token,
        remote,
    }))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct DeleteRepoQuery {
    /// Override the alternates-dependency safety check. Without this,
    /// deleting a repo that other forks depend on returns 409. With
    /// `force=true` the delete proceeds — forks are left with broken
    /// alternates pointers, which is sometimes what an admin wants
    /// (e.g. cleaning up after an experiment) but should never be the
    /// default. Logged as WARN whenever it fires.
    ///
    /// Mutually exclusive with `cascade=true`. Force is the
    /// structured override ("yes I know I'm orphaning forks"); cascade
    /// is the structured cleanup ("delete me and every dependent").
    pub force: Option<bool>,
    /// Delete this repo *and* every transitive fork of it. Walks the
    /// dependent network deepest-first so no repo is briefly orphaned
    /// mid-cascade. Mutually exclusive with `force=true`. Returns
    /// the list of all deleted IDs in the response body.
    pub cascade: Option<bool>,
}

/// DELETE /v1/repos/:id
pub async fn delete_repo(
    State(state): State<RestState>,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<DeleteRepoQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Default)?;
    enforce_owner(&*state.ownership, &principal, &id).await?;

    let force = q.force.unwrap_or(false);
    let cascade = q.cascade.unwrap_or(false);
    if force && cascade {
        return Err(Error::BadRequest(
            "force and cascade are mutually exclusive — pick one".to_string(),
        ));
    }

    if cascade {
        // BFS the dependent network so we know every repo that has
        // to go. Then delete deepest-first: child before parent,
        // so no repo is briefly orphaned with a dangling alternates
        // pointer mid-cascade.
        let order = cascade_delete_order(
            &state.cfg.repos_dir(),
            &id,
            &state.alternates_cache,
        )?;
        // Re-check ownership for every dependent before we touch
        // anything. enforce_owner on the root passed; without this
        // the cascade could let a user delete repos they don't
        // own just because a fork chain happens to pass through
        // their repo. Admin bypasses (Principal::Admin's
        // enforce_owner is a no-op).
        for dep in &order {
            if dep != &id {
                enforce_owner(&*state.ownership, &principal, dep).await?;
            }
        }
        let mut deleted = Vec::with_capacity(order.len());
        for dep in &order {
            state.storage.delete(dep)?;
            state.ownership.delete(dep).await?;
            state.alternates_cache.invalidate(dep);
            deleted.push(dep.clone());
        }
        tracing::info!(
            target: "audit",
            event = "repo.delete",
            actor = principal.audit_label(),
            repo_id = %id,
            mode = "cascade",
            count = deleted.len(),
            deleted = ?deleted,
        );
        return Ok(Json(serde_json::json!({
            "ok": true,
            "deleted": deleted,
        })));
    }

    // Refuse to delete a repo other forks depend on via alternates.
    // The fork count is small (one stat() per repo) so no need to
    // gate behind a flag — every delete pays the cost.
    let forks = crate::reads::list_forks_of(
        &state.cfg.repos_dir(),
        &id,
        &state.alternates_cache,
    )?;
    if !forks.is_empty() {
        if force {
            tracing::warn!(
                repo = %id,
                fork_count = forks.len(),
                forks = ?forks,
                "delete with force=true; forks will be orphaned",
            );
        } else {
            return Err(Error::ForkDependency {
                repo_id: id,
                forks,
            });
        }
    }

    state.storage.delete(&id)?;
    state.ownership.delete(&id).await?;
    // Drop the cached source_id entry so the repo_id isn't stuck as
    // a stale hit if a future repo ever reuses the same id.
    state.alternates_cache.invalidate(&id);
    tracing::info!(
        target: "audit",
        event = "repo.delete",
        actor = principal.audit_label(),
        repo_id = %id,
        mode = if force { "force" } else { "default" },
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// BFS the dependent-fork tree rooted at `id` and return the
/// deletion order: dependents before dependencies. Iterative impl
/// (no recursion) so a deeply chained fork tree can't blow the
/// stack. Linear in the size of the dependent set — typically tiny.
fn cascade_delete_order(
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
        &state.cfg.admin_token(),
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
            source_id: state.alternates_cache.lookup(&repos_dir, &r.id),
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
            source_id: state.alternates_cache.lookup(&repos_dir, &r.id),
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
            source_id: state.alternates_cache.lookup(&repos_dir, &id),
            id,
            owner: row.owner,
            created_at: row.created_at,
        },
        size_bytes,
        refs,
    }))
}

/// Helper: reject non-admin principals with 403.
/// GET /v1/admin/repos/:id/gc-preview
///
/// Read-only reachability accounting for the analyzed repo's loose
/// objects, alternates-aware. See `crate::gc` for the algorithm.
/// Admin-only because it walks the alternates network and runs a
/// `git rev-list` per member — not something a per-user JWT should
/// be able to trigger on arbitrary other users' repos.
pub async fn admin_gc_preview(
    State(state): State<RestState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<crate::gc::GcPreview>> {
    require_admin(&state, &headers)?;
    state.rate_limit.check(
        &crate::auth::Principal::Admin,
        crate::rate_limit::Class::Default,
    )?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    let preview = crate::gc::preview(
        &state.cfg.repos_dir(),
        &id,
        &state.alternates_cache,
    )?;
    Ok(Json(preview))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct GcRunQuery {
    /// Minimum age (in seconds) of a loose object before gc will
    /// delete it. Defaults to 7200 (2 hours) — conservative, mirrors
    /// `git gc`'s spirit of refusing to prune objects that might
    /// belong to an in-flight write. Pass `min_age_secs=0` to
    /// disable the guard (useful in tests / one-shot cleanups
    /// where you know nothing is in flight).
    #[serde(rename = "minAgeSecs")]
    pub min_age_secs: Option<u64>,
}

/// POST /v1/admin/repos/:id/gc
///
/// Run a real GC pass on the repo. Returns the same shape as
/// preview plus actual deletion counts. Admin-only.
pub async fn admin_gc_run(
    State(state): State<RestState>,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<GcRunQuery>,
    headers: HeaderMap,
) -> Result<Json<crate::gc::GcResult>> {
    require_admin(&state, &headers)?;
    state.rate_limit.check(
        &crate::auth::Principal::Admin,
        crate::rate_limit::Class::Default,
    )?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    let result = crate::gc::run(
        &state.cfg.repos_dir(),
        &id,
        &state.alternates_cache,
        q.min_age_secs.unwrap_or(7200),
    )?;
    Ok(Json(result))
}

#[derive(Debug, Serialize)]
pub struct AdminTokenRotateResponse {
    /// The fresh admin token. Caller stores it; we don't keep a
    /// plaintext copy server-side beyond the in-memory `Config`
    /// cell that future requests authorize against.
    pub token: String,
}

/// `POST /v1/admin/token/rotate`
///
/// Generates a new process-wide admin token, atomically swaps the
/// in-memory cell, and returns the new token. The previous admin
/// token stops working on subsequent requests. Admin-only — JWT
/// principals get 403 from `require_admin`.
///
/// The audit event records that rotation happened but never the
/// token bytes (the old one is being invalidated and the new one
/// returns in the response body — no audit field needs them).
///
/// This is the in-process counterpart to restarting the server
/// with a different `ARTIFACTS_ADMIN_TOKEN`. Use it after a
/// suspected leak, before walking away from a shared session, or
/// any time the previous holder shouldn't keep speaking for
/// every user.
pub async fn admin_rotate_token(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<AdminTokenRotateResponse>> {
    require_admin(&state, &headers)?;
    let new = crate::random_admin_token();
    state.cfg.rotate_admin_token(new.clone());
    tracing::info!(
        target: "audit",
        event = "admin.token.rotate",
        actor = "admin",
    );
    Ok(Json(AdminTokenRotateResponse { token: new }))
}

fn require_admin(state: &RestState, headers: &HeaderMap) -> Result<()> {
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

// `source_id` (parent repo) resolution lives in `crate::alternates_cache`
// so it can memoize across admin-list polls. Handlers call
// `state.alternates_cache.lookup(...)` instead of reading the file
// directly.

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

// alternates → source_id resolution is tested in
// `crate::alternates_cache::tests`. No duplicate coverage here.
