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
    response::{IntoResponse, Response},
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
    /// Durable audit log. Mirrors the live `tracing!(target: "audit")`
    /// stream into SQLite so admin tooling can query history after the
    /// fact. Writes are best-effort — a SQLite hiccup logs a warning
    /// but never fails the underlying mutation.
    pub audit: Arc<dyn crate::audit::AuditStore>,
    /// Path to the on-disk webhook master key file, when one is in
    /// use. `None` for env-var-only deployments. The
    /// `admin_rotate_webhook_key` handler updates this file (if set)
    /// after a successful rotation so a restart picks up the new key.
    pub webhook_key_path: Option<std::path::PathBuf>,
    /// Object-store backend for loose-object reads / writes / list /
    /// delete. M2b's first production-routing landing — `gc` goes
    /// through this trait now. A future chunked-KV backend swaps
    /// in by satisfying the same trait.
    pub objects: Arc<dyn crate::object_store::ObjectStore>,
    /// Set to `true` once a SIGTERM/SIGINT has been received, before
    /// the axum-server graceful drain begins. The readiness probe
    /// short-circuits to 503 when this is set, so an orchestrator
    /// (k8s, systemd) sees the process leave the load-balancer pool
    /// *before* it stops accepting new connections. Without this the
    /// orchestrator could route a fresh request onto a process that's
    /// about to refuse it at the TCP level. Cheap relaxed atomic load
    /// per probe — readiness is hit at most every couple of seconds.
    pub draining: Arc<std::sync::atomic::AtomicBool>,
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
    crate::audit::record(
        &*state.audit,
        "repo.create",
        principal.audit_label(),
        Some(&id),
        serde_json::json!({}),
        None,
    )
    .await;
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
    crate::audit::record(
        &*state.audit,
        "repo.fork",
        principal.audit_label(),
        Some(&fork_id),
        serde_json::json!({ "source_id": source_id, "read_only": read_only }),
        None,
    )
    .await;
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
    crate::audit::record(
        &*state.audit,
        "token.mint",
        principal.audit_label(),
        Some(&id),
        serde_json::json!({
            "scope": format!("{:?}", body.scope),
            "ttl_seconds": body.ttl_seconds,
        }),
        None,
    )
    .await;
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
    crate::audit::record(
        &*state.audit,
        "token.revoke",
        principal.audit_label(),
        target_repo.as_deref(),
        serde_json::json!({ "revoked": revoked }),
        None,
    )
    .await;
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
    crate::audit::record(
        &*state.audit,
        "token.rotate",
        principal.audit_label(),
        Some(&id),
        serde_json::json!({
            "revoked": revoked,
            "scope": format!("{:?}", scope),
        }),
        None,
    )
    .await;
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
        crate::audit::record(
            &*state.audit,
            "repo.delete",
            principal.audit_label(),
            Some(&id),
            serde_json::json!({
                "mode": "cascade",
                "count": deleted.len(),
                "deleted": deleted,
            }),
            None,
        )
        .await;
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
    let mode = if force { "force" } else { "default" };
    crate::audit::record(
        &*state.audit,
        "repo.delete",
        principal.audit_label(),
        Some(&id),
        serde_json::json!({ "mode": mode }),
        None,
    )
    .await;
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

/// `GET /v1/health/ready`
///
/// Readiness probe — distinct from `/v1/health` (the cheap liveness
/// probe). Exercises the SQLite stores so k8s / systemd / load
/// balancers catch a server that's running but can't actually serve
/// traffic (DB file unreadable, schema drift, disk full, …).
///
/// Returns 200 with `{ok:true, components:{tokens:"ok", audit:"ok",
/// ownership:"ok"}}` when every store responds. Returns 503 with
/// `ok:false` and the failing component(s) flagged when any store
/// errors out — k8s then refuses to route traffic to the pod.
///
/// Each component check has a 1-second deadline. Slow-but-not-broken
/// stores fail closed rather than blocking the probe; an indefinitely
/// hung probe is worse than one that flags a problem and lets the
/// orchestrator decide.
///
/// No auth — same as `/v1/health`. Probe traffic shouldn't need
/// credentials.
pub async fn health_ready(
    State(state): State<RestState>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    if let Some(resp) = drain_response_if_draining(&state.draining) {
        return resp;
    }
    probe_stores(&*state.tokens, &*state.audit, &*state.ownership).await
}

/// Pure helper: short-circuit readiness with `503 + {draining: true}`
/// when the shared drain flag is set. Returning `Some` skips the
/// store probes entirely so a draining process responds fast even
/// if the stores are themselves under load. Lifted out of
/// `health_ready` so the contract is unit-testable without
/// constructing a full `RestState`.
pub(crate) fn drain_response_if_draining(
    draining: &std::sync::atomic::AtomicBool,
) -> Option<(axum::http::StatusCode, Json<serde_json::Value>)> {
    use std::sync::atomic::Ordering;
    if draining.load(Ordering::Relaxed) {
        Some((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "draining": true,
            })),
        ))
    } else {
        None
    }
}

/// Run the store-health probes that back the readiness response.
/// Each probe runs against a 1s deadline so a stuck SQLite write
/// doesn't make the response itself stuck. Lifted out of
/// `health_ready` so it can be unit-tested with stub stores
/// without standing up a full `RestState`.
async fn probe_stores(
    tokens: &dyn TokenStore,
    audit: &dyn crate::audit::AuditStore,
    ownership: &dyn OwnershipStore,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    use axum::http::StatusCode;
    use std::time::Duration;
    let deadline = Duration::from_secs(1);
    // Cheap query that hits the tokens table — `lookup` of a known-
    // missing token returns Ok(None) and proves the store can read.
    let tokens_ok = matches!(
        tokio::time::timeout(deadline, tokens.lookup("__health_ready_probe__")).await,
        Ok(Ok(_))
    );
    let audit_ok = matches!(
        tokio::time::timeout(deadline, audit.count()).await,
        Ok(Ok(_))
    );
    // Same cheap-COUNT(*) shape as the audit probe — proves the
    // ownership SQLite file is readable. Every mutation-on-existing-
    // repo handler reads this store via `enforce_owner`, so a broken
    // ownership store causes user-visible 500s while tokens/audit
    // could still answer; including it here closes that gap.
    let ownership_ok = matches!(
        tokio::time::timeout(deadline, ownership.count_all()).await,
        Ok(Ok(_))
    );
    let all_ok = tokens_ok && audit_ok && ownership_ok;
    let body = serde_json::json!({
        "ok": all_ok,
        "components": {
            "tokens":    if tokens_ok    { "ok" } else { "fail" },
            "audit":     if audit_ok     { "ok" } else { "fail" },
            "ownership": if ownership_ok { "ok" } else { "fail" },
        }
    });
    let status = if all_ok {
        StatusCode::OK
    } else {
        tracing::warn!(
            tokens_ok, audit_ok, ownership_ok,
            "/v1/health/ready failing — orchestrator should refuse traffic"
        );
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body))
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
    axum::extract::Query(q): axum::extract::Query<ListReposQuery>,
    headers: HeaderMap,
) -> Result<Response> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, crate::rate_limit::Class::Default)?;

    let limit = q
        .limit
        .unwrap_or(LIST_REPOS_DEFAULT_LIMIT)
        .min(LIST_REPOS_MAX_LIMIT);
    let offset = q.offset.unwrap_or(0);

    let (rows, total) = match &principal {
        crate::auth::Principal::Admin => (
            state.ownership.list_paginated(limit, offset).await?,
            state.ownership.count_all().await?,
        ),
        crate::auth::Principal::User { subject } => (
            state
                .ownership
                .list_paginated_by_owner(subject, limit, offset)
                .await?,
            state.ownership.count_by_owner(subject).await?,
        ),
    };

    if offset == 0 && total > limit as u64 {
        tracing::warn!(
            total,
            limit,
            "/v1/repos returned a truncated page; caller should paginate via ?offset=",
        );
    }

    let repos_dir = state.cfg.repos_dir();
    let summaries: Vec<AdminRepoSummary> = rows
        .into_iter()
        .map(|r| AdminRepoSummary {
            source_id: state.alternates_cache.lookup(&repos_dir, &r.id),
            id: r.id,
            owner: r.owner,
            created_at: r.created_at,
        })
        .collect();

    let body = Json(summaries).into_response();
    let (mut parts, body) = body.into_parts();
    parts.headers.insert(
        axum::http::HeaderName::from_static("x-total-count"),
        axum::http::HeaderValue::from_str(&total.to_string())
            .expect("u64 decimal fits in a header value"),
    );
    Ok(Response::from_parts(parts, body))
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

const LIST_REPOS_DEFAULT_LIMIT: u32 = 1000;
const LIST_REPOS_MAX_LIMIT: u32 = 5000;

/// `GET /v1/admin/repos`
///
/// Returns the repos the server knows about. Expensive bits (disk size,
/// ref list) are deliberately left off this list endpoint so it stays
/// cheap even with thousands of repos — those live on the single-repo
/// detail endpoint.
///
/// Pagination: `?limit=N&offset=M`. Default limit is
/// [`LIST_REPOS_DEFAULT_LIMIT`], hard-capped at
/// [`LIST_REPOS_MAX_LIMIT`]. The total row count is returned in
/// the `X-Total-Count` response header so callers can tell whether
/// they need to fetch more pages.
pub async fn admin_list_repos(
    State(state): State<RestState>,
    axum::extract::Query(q): axum::extract::Query<ListReposQuery>,
    headers: HeaderMap,
) -> Result<Response> {
    require_admin(&state, &headers)?;
    state.rate_limit.check(
        &crate::auth::Principal::Admin, // rate-limit is a no-op for admin; kept for symmetry
        crate::rate_limit::Class::Default,
    )?;

    let limit = q
        .limit
        .unwrap_or(LIST_REPOS_DEFAULT_LIMIT)
        .min(LIST_REPOS_MAX_LIMIT);
    let offset = q.offset.unwrap_or(0);

    let total = state.ownership.count_all().await?;
    let rows = state.ownership.list_paginated(limit, offset).await?;

    // Operational signal: if a caller hit the cap without paging,
    // they're probably truncating silently — log it once per request.
    if offset == 0 && total > limit as u64 {
        tracing::warn!(
            total,
            limit,
            "/v1/admin/repos returned a truncated page; caller should paginate via ?offset=",
        );
    }

    let repos_dir = state.cfg.repos_dir();
    let summaries: Vec<AdminRepoSummary> = rows
        .into_iter()
        .map(|r| AdminRepoSummary {
            source_id: state.alternates_cache.lookup(&repos_dir, &r.id),
            id: r.id,
            owner: r.owner,
            created_at: r.created_at,
        })
        .collect();

    let body = Json(summaries).into_response();
    let (mut parts, body) = body.into_parts();
    parts.headers.insert(
        axum::http::HeaderName::from_static("x-total-count"),
        axum::http::HeaderValue::from_str(&total.to_string())
            .expect("u64 decimal fits in a header value"),
    );
    Ok(Response::from_parts(parts, body))
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
        &*state.objects,
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
        &*state.objects,
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
    crate::audit::record(
        &*state.audit,
        "admin.token.rotate",
        "admin",
        None,
        serde_json::json!({}),
        None,
    )
    .await;
    Ok(Json(AdminTokenRotateResponse { token: new }))
}

#[derive(Debug, Serialize)]
pub struct AdminWebhookKeyRotateResponse {
    /// Number of rows re-encrypted under the new key. Legacy
    /// plaintext rows (secret_nonce IS NULL) are skipped, so this
    /// can be lower than the total subscription count.
    pub rotated: u64,
    /// The freshly-generated 32-byte AES-256 key, base64-encoded.
    /// Caller must persist this — if the server restarts before the
    /// new key is in `ARTIFACTS_WEBHOOK_KEY` env or the on-disk key
    /// file, every encrypted webhook row becomes unreadable.
    pub key: String,
}

/// `POST /v1/admin/webhook-key/rotate`
///
/// Generates a fresh AES-256 master key, re-encrypts every webhook
/// secret in the SQLite registry under it (in a single transaction
/// — partial failure rolls back), atomically swaps the in-memory
/// key, and returns the new key in the response body.
///
/// If the deployment uses the on-disk key file
/// (`<data-dir>/webhook-key.bin`) the file is rewritten with the new
/// key (0600 perms preserved) so a restart picks up the new value.
/// Env-var deployments must update `ARTIFACTS_WEBHOOK_KEY` out of
/// band — the response body is the only place the new key surfaces.
///
/// Admin-only. JWT principals get 403. Emits an
/// `admin.webhook_key.rotate` audit event with the rotated row
/// count (no key bytes in the event).
///
/// In-memory `MemRegistry` deployments accept the call but the
/// trait's default `rotate_master_key` is a no-op (returns 0); the
/// new key is still generated and returned for parity with the
/// SQLite path.
pub async fn admin_rotate_webhook_key(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<AdminWebhookKeyRotateResponse>> {
    require_admin(&state, &headers)?;
    let new_key = Arc::new(crate::secrets::MasterKey::random());
    let new_key_b64 = new_key.to_base64();

    let rotated = state.webhooks.rotate_master_key(new_key.clone())?;

    // Update the on-disk key file (if one is in use) so a restart
    // loads the new key. Failure here is best-effort logged — the
    // in-memory swap already succeeded, and the response body
    // surfaces the key so the operator can persist it manually if
    // we couldn't.
    if let Some(path) = state.webhook_key_path.as_deref() {
        if let Err(e) = std::fs::write(path, &new_key_b64) {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "webhook key file rewrite failed; persist `key` from response manually",
            );
        }
    }

    crate::audit::record(
        &*state.audit,
        "admin.webhook_key.rotate",
        "admin",
        None,
        serde_json::json!({ "rotated": rotated }),
        None,
    )
    .await;

    Ok(Json(AdminWebhookKeyRotateResponse {
        rotated,
        key: new_key_b64,
    }))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct AdminAuditQuery {
    /// Unix epoch seconds. Lower bound (inclusive).
    pub since: Option<i64>,
    /// Unix epoch seconds. Upper bound (inclusive).
    pub until: Option<i64>,
    /// Filter by event kind, e.g. `repo.create`, `token.mint`.
    pub event: Option<String>,
    /// Filter by actor — `admin` or a JWT subject.
    pub actor: Option<String>,
    /// Filter by repo id — only events scoped to a single repo
    /// (admin.token.rotate has no repo and won't match).
    #[serde(rename = "repoId")]
    pub repo_id: Option<String>,
    /// Page size. Server-capped at 1000.
    pub limit: Option<u32>,
    /// Number of newest-first rows to skip. Symmetric with
    /// `/v1/admin/repos?offset=`. Use this to walk historical
    /// pages without growing the `limit` past the cap.
    pub offset: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AdminAuditStats {
    /// Total rows in the audit_events table. Includes events that
    /// will be pruned at the next retention sweep — there's no
    /// pre-prune view because the prune is a delete (gone is gone).
    pub count: u64,
}

/// `GET /v1/admin/audit/stats`
///
/// Returns the cheap-to-compute totals admin tooling wants without
/// having to paginate through `/v1/admin/audit`. SQLite computes
/// this with an indexed `SELECT COUNT(*)` — constant-time. Admin-only.
pub async fn admin_audit_stats(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<AdminAuditStats>> {
    require_admin(&state, &headers)?;
    let count = state.audit.count().await?;
    Ok(Json(AdminAuditStats { count }))
}

/// `GET /v1/admin/audit`
///
/// Returns the persisted audit log, filtered by query params.
/// Newest-first ordering. Admin-only — JWT principals get 403.
///
/// Filters compose with AND. Default page size is 100, hard-capped
/// at 1000. Events past the cap require pagination via `until` —
/// take the oldest `ts` from the previous page and pass it as
/// `until` on the next request.
pub async fn admin_list_audit(
    State(state): State<RestState>,
    axum::extract::Query(q): axum::extract::Query<AdminAuditQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::audit::AuditEvent>>> {
    require_admin(&state, &headers)?;
    let rows = state
        .audit
        .list(crate::audit::AuditQuery {
            since_ts: q.since,
            until_ts: q.until,
            event: q.event,
            actor: q.actor,
            repo_id: q.repo_id,
            limit: q.limit,
            offset: q.offset,
        })
        .await?;
    Ok(Json(rows))
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

#[cfg(test)]
mod health_ready_tests {
    //! Pin the readiness-probe contract:
    //!   - drain flag short-circuits to 503 + `{draining: true}`,
    //!     skipping the store probes entirely
    //!   - probe-store success → 200 + `{ok: true, components: ...}`
    //!   - one failing store → 503 + that component flagged `fail`
    //!
    //! The smoke test exercises this against a real server, but the
    //! contract is small enough that pinning it as a unit test
    //! catches refactor regressions earlier than a 30s smoke run.
    use super::*;
    use crate::audit::{AuditEvent, AuditQuery, AuditStore, NoopAuditStore};
    use crate::error::{Error, Result};
    use crate::ownership::{OwnershipStore, RepoRow};
    use crate::tokens::{Scope, TokenRecord, TokenStore};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// Minimal `TokenStore` whose `lookup` outcome is configurable.
    /// Every other trait method either has a default impl or panics
    /// (we never exercise them from `health_ready`).
    struct StubTokenStore {
        lookup_succeeds: bool,
    }

    #[async_trait]
    impl TokenStore for StubTokenStore {
        async fn mint(&self, _: &str, _: Scope, _: Option<Duration>, _: Option<&str>) -> Result<String> {
            unreachable!("health_ready does not mint")
        }
        async fn lookup(&self, _: &str) -> Result<Option<TokenRecord>> {
            if self.lookup_succeeds {
                Ok(None)
            } else {
                Err(Error::Other(anyhow::anyhow!("simulated tokens-store failure")))
            }
        }
        async fn revoke(&self, _: &str) -> Result<bool> {
            unreachable!("health_ready does not revoke")
        }
    }

    /// `AuditStore` whose `count` returns Err. Pairs with
    /// `NoopAuditStore` (which returns Ok(0)) to cover both paths.
    struct FailingAuditStore;

    #[async_trait]
    impl AuditStore for FailingAuditStore {
        async fn record(&self, _: AuditEvent) -> Result<()> {
            Ok(())
        }
        async fn list(&self, _: AuditQuery) -> Result<Vec<AuditEvent>> {
            Ok(Vec::new())
        }
        async fn count(&self) -> Result<u64> {
            Err(Error::Other(anyhow::anyhow!("simulated audit-store failure")))
        }
        async fn prune_older_than(&self, _: i64) -> Result<u64> {
            Ok(0)
        }
    }

    /// `OwnershipStore` whose `count_all` outcome is configurable.
    /// Other methods panic — `health_ready` only ever calls `count_all`.
    struct StubOwnershipStore {
        count_succeeds: bool,
    }

    #[async_trait]
    impl OwnershipStore for StubOwnershipStore {
        async fn record_owner(&self, _: &str, _: Option<&str>) -> Result<()> {
            unreachable!("health_ready does not record")
        }
        async fn get_owner(&self, _: &str) -> Result<Option<Option<String>>> {
            unreachable!("health_ready does not get_owner")
        }
        async fn delete(&self, _: &str) -> Result<()> {
            unreachable!("health_ready does not delete")
        }
        async fn count_by_owner(&self, _: &str) -> Result<u64> {
            unreachable!("health_ready does not count_by_owner")
        }
        async fn list_all(&self) -> Result<Vec<RepoRow>> {
            unreachable!("health_ready does not list_all")
        }
        async fn count_all(&self) -> Result<u64> {
            if self.count_succeeds {
                Ok(0)
            } else {
                Err(Error::Other(anyhow::anyhow!(
                    "simulated ownership-store failure"
                )))
            }
        }
        async fn list_by_owner(&self, _: &str) -> Result<Vec<RepoRow>> {
            unreachable!("health_ready does not list_by_owner")
        }
        async fn get_row(&self, _: &str) -> Result<Option<RepoRow>> {
            unreachable!("health_ready does not get_row")
        }
    }

    #[test]
    fn drain_response_returns_none_when_flag_clear() {
        let flag = AtomicBool::new(false);
        assert!(drain_response_if_draining(&flag).is_none());
    }

    #[test]
    fn drain_response_short_circuits_when_flag_set() {
        let flag = AtomicBool::new(true);
        let (status, body) =
            drain_response_if_draining(&flag).expect("expected Some response");
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        // Body must include `draining: true` so a caller can
        // distinguish "we're shutting down" from "stores are wedged."
        assert_eq!(body.0["draining"], serde_json::json!(true));
        assert_eq!(body.0["ok"], serde_json::json!(false));
    }

    #[test]
    fn drain_response_load_uses_relaxed_ordering_correctly() {
        // Belt-and-braces: a flag that flips between two reads
        // resolves consistently within one call. Not a stress test —
        // just verifies a basic store-then-load cycle, since the
        // production code uses Relaxed ordering and this is the
        // invariant we rely on.
        let flag = AtomicBool::new(false);
        flag.store(true, Ordering::Relaxed);
        assert!(drain_response_if_draining(&flag).is_some());
        flag.store(false, Ordering::Relaxed);
        assert!(drain_response_if_draining(&flag).is_none());
    }

    #[tokio::test]
    async fn probe_stores_returns_200_when_all_ok() {
        let tokens = StubTokenStore { lookup_succeeds: true };
        let audit = NoopAuditStore;
        let ownership = StubOwnershipStore { count_succeeds: true };
        let (status, body) = probe_stores(&tokens, &audit, &ownership).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body.0["ok"], serde_json::json!(true));
        assert_eq!(body.0["components"]["tokens"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["audit"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["ownership"], serde_json::json!("ok"));
    }

    #[tokio::test]
    async fn probe_stores_returns_503_when_tokens_fails() {
        let tokens = StubTokenStore { lookup_succeeds: false };
        let audit = NoopAuditStore;
        let ownership = StubOwnershipStore { count_succeeds: true };
        let (status, body) = probe_stores(&tokens, &audit, &ownership).await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["ok"], serde_json::json!(false));
        assert_eq!(body.0["components"]["tokens"], serde_json::json!("fail"));
        assert_eq!(body.0["components"]["audit"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["ownership"], serde_json::json!("ok"));
    }

    #[tokio::test]
    async fn probe_stores_returns_503_when_audit_fails() {
        let tokens = StubTokenStore { lookup_succeeds: true };
        let audit = FailingAuditStore;
        let ownership = StubOwnershipStore { count_succeeds: true };
        let (status, body) = probe_stores(&tokens, &audit, &ownership).await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["ok"], serde_json::json!(false));
        assert_eq!(body.0["components"]["tokens"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["audit"], serde_json::json!("fail"));
        assert_eq!(body.0["components"]["ownership"], serde_json::json!("ok"));
    }

    #[tokio::test]
    async fn probe_stores_returns_503_when_ownership_fails() {
        let tokens = StubTokenStore { lookup_succeeds: true };
        let audit = NoopAuditStore;
        let ownership = StubOwnershipStore { count_succeeds: false };
        let (status, body) = probe_stores(&tokens, &audit, &ownership).await;
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["ok"], serde_json::json!(false));
        assert_eq!(body.0["components"]["tokens"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["audit"], serde_json::json!("ok"));
        assert_eq!(body.0["components"]["ownership"], serde_json::json!("fail"));
    }
}
