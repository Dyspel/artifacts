//! REST endpoints for creating repos, forking, and minting tokens.
//!
//! Shape modeled loosely on the Cloudflare Artifacts public API so callers
//! written for that surface can be adapted with a URL change.

use crate::{
    auth::authorize_admin,
    config::Config,
    error::{Error, Result},
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
    /// Ref CAS backend. M0 ships `FsRefStore`; M3-proper swaps in a
    /// distributed impl without touching any handler.
    pub refs: Arc<dyn RefStore>,
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
pub async fn create_repo(
    State(state): State<RestState>,
    headers: HeaderMap,
    body: Option<Json<CreateRepoBody>>,
) -> Result<Json<RepoHandle>> {
    authorize_admin(&headers, &state.cfg.admin_token)?;
    let id = body
        .and_then(|Json(b)| b.id)
        .unwrap_or_else(new_repo_id);
    state.storage.create(&id)?;
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
pub async fn fork_repo(
    State(state): State<RestState>,
    Path(source_id): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ForkBody>>,
) -> Result<Json<RepoHandle>> {
    authorize_admin(&headers, &state.cfg.admin_token)?;
    if !state.storage.exists(&source_id) {
        return Err(Error::RepoNotFound(source_id));
    }
    let (fork_id, read_only) = body
        .map(|Json(b)| (b.id, b.read_only))
        .unwrap_or((None, false));
    let fork_id = fork_id.unwrap_or_else(new_repo_id);
    state.storage.fork(&source_id, &fork_id)?;
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
    authorize_admin(&headers, &state.cfg.admin_token)?;
    if !state.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
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
pub async fn revoke_token(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(body): Json<RevokeBody>,
) -> Result<Json<RevokeResponse>> {
    authorize_admin(&headers, &state.cfg.admin_token)?;
    let revoked = state.tokens.revoke(&body.token).await?;
    Ok(Json(RevokeResponse { revoked }))
}

/// DELETE /v1/repos/:id
pub async fn delete_repo(
    State(state): State<RestState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    authorize_admin(&headers, &state.cfg.admin_token)?;
    state.storage.delete(&id)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /v1/health
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}
