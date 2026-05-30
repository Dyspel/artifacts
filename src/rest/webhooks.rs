//! Webhook subscription endpoints: create / list / delete.
//!
//! Owner-scoped (admin always passes; users must own the repo). The
//! registry itself is `state.observ.webhooks` — `MemRegistry` or
//! `SqliteWebhookRegistry` depending on deployment shape.

use super::RestState;
use crate::{
    auth::authorize_rest,
    error::{Error, Result},
    ownership::enforce_owner,
    rate_limit::Class,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    state.authn.rate_limit.check(&principal, Class::Token)?;
    if !state.data.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.data.ownership, &principal, &id).await?;
    let hook_id = state.observ.webhooks.add(crate::webhooks::Subscription {
        id: String::new(),
        repo_id: id,
        url: body.url,
        secret: body.secret,
        events: body.events,
    })?;
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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    if !state.data.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.data.ownership, &principal, &id).await?;
    Ok(Json(state.observ.webhooks.list(&id)?))
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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    if !state.data.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.data.ownership, &principal, &id).await?;
    let removed = state.observ.webhooks.remove(&id, &hook_id)?;
    Ok(Json(serde_json::json!({ "removed": removed })))
}
