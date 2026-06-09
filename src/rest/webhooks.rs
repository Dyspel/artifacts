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
    /// HMAC-SHA256 signing secret. Optional — subscribers behind a
    /// trusted network might not bother. Persisted sealed with
    /// AES-256-GCM by `SqliteWebhookRegistry` (it must stay recoverable
    /// to sign deliveries, so it's encrypted, not hashed); held in
    /// memory by `MemRegistry`.
    pub secret: Option<String>,
    /// Empty list means "all event kinds for this repo". Otherwise
    /// only events whose `kind` matches one of these are delivered.
    /// Typed as `EventKind`, so a misspelled kind (`"comit"`) is a 400
    /// at creation rather than a subscription that silently never fires.
    #[serde(default)]
    pub events: Vec<crate::events::EventKind>,
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
    let id_typed = crate::ids::RepoId::try_from(id.as_str())?;
    if !state.data.storage.exists(&id_typed) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.data.ownership, &principal, &id).await?;
    // SSRF guard: a tenant-supplied URL the server will POST to. Reject
    // non-http(s) schemes and (unless explicitly allowed) private /
    // loopback / link-local IP literals before persisting it.
    crate::webhooks::validate_webhook_url(&body.url, state.cfg.webhook_allow_private_targets())?;
    let hook_id = state.observ.webhooks.add(crate::webhooks::Subscription {
        id: String::new(),
        repo_id: id_typed,
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
    let id_typed = crate::ids::RepoId::try_from(id.as_str())?;
    if !state.data.storage.exists(&id_typed) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.data.ownership, &principal, &id).await?;
    Ok(Json(state.observ.webhooks.list(&id_typed)?))
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
    let id_typed = crate::ids::RepoId::try_from(id.as_str())?;
    if !state.data.storage.exists(&id_typed) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.data.ownership, &principal, &id).await?;
    let removed = state.observ.webhooks.remove(&id_typed, &hook_id)?;
    Ok(Json(serde_json::json!({ "removed": removed })))
}

#[cfg(test)]
mod tests {
    //! In-process router tests for the webhook HTTP surface. These drive
    //! the real handlers through an `axum::Router` via `oneshot` (no
    //! socket, no spawned server), so the auth / owner-enforcement /
    //! 404 / body-deserialization / registry wiring is exercised AND
    //! visible to in-process coverage — the integration smoke spawns the
    //! server out-of-process, which the line counter can't see, and it
    //! never touches `/webhooks` at all.
    use super::{create_webhook, delete_webhook, list_webhooks};
    use crate::rest::{AuthnState, DataState, ObservState, RestState, RuntimeState};
    use crate::storage::Storage as _;
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::{delete, post},
        Router,
    };
    use std::sync::{atomic::AtomicBool, Arc};
    use tower::ServiceExt;

    const ADMIN: &str = "admin-token-for-router-tests-0123456789";
    const JWT_SECRET: &str = "rest-webhook-router-test-secret";
    const REPO: &str = "webhook-router-repo";

    /// Build a `Router` over the three webhook routes with a fully-wired
    /// `RestState`: a real `FsStorage` (with `REPO` created so
    /// `exists()` is true), SQLite ownership/token stores on a tempdir,
    /// in-memory refs/objects/webhooks, and a `NoopAuditStore`. The repo
    /// is intentionally left *unregistered* in ownership, so a non-admin
    /// principal hits the "admin-owned or unregistered" 403 branch.
    fn build_app() -> (tempfile::TempDir, Router) {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let storage = crate::storage::FsStorage::new(data_dir.join("repos")).unwrap();
        storage
            .create(&crate::ids::RepoId::try_from(REPO).unwrap())
            .unwrap();

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
        let state = RestState {
            cfg: Arc::new(cfg),
            data: DataState {
                storage: Arc::new(storage),
                ownership: Arc::new(
                    crate::ownership::SqliteOwnershipStore::open(&data_dir.join("ownership.db"))
                        .unwrap(),
                ),
                refs: Arc::new(crate::refs::MemRefStore::new()),
                objects: Arc::new(crate::object_store::MemObjectStore::new()),
                alternates_cache: Arc::new(crate::alternates_cache::AlternatesCache::new()),
            },
            authn: AuthnState {
                tokens: Arc::new(
                    crate::tokens::SqliteTokenStore::open(&data_dir.join("tokens.db")).unwrap(),
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
        };
        let app = Router::new()
            .route(
                "/v1/repos/:id/webhooks",
                post(create_webhook).get(list_webhooks),
            )
            .route("/v1/repos/:id/webhooks/:hook_id", delete(delete_webhook))
            .with_state(state);
        (tmp, app)
    }

    /// Mint an HS256 JWT (sub + exp) signed with the test secret, so
    /// `authorize_rest` resolves it to `Principal::User { subject }`.
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

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
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

    const BODY: &str = r#"{"url":"http://hook.invalid/x","events":["commit"]}"#;

    #[tokio::test]
    async fn create_without_auth_is_401() {
        let (_t, app) = build_app();
        let (status, _) = send(
            &app,
            req(
                "POST",
                &format!("/v1/repos/{REPO}/webhooks"),
                None,
                Some(BODY),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_on_missing_repo_is_404() {
        let (_t, app) = build_app();
        let (status, _) = send(
            &app,
            req(
                "POST",
                "/v1/repos/no-such-repo-here/webhooks",
                Some(ADMIN),
                Some(BODY),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn non_owner_user_is_403() {
        // REPO has no ownership record, so a non-admin principal must be
        // refused even though the repo exists and they're authenticated.
        let (_t, app) = build_app();
        let jwt = user_jwt("mallory");
        let (status, _) = send(
            &app,
            req(
                "GET",
                &format!("/v1/repos/{REPO}/webhooks"),
                Some(&jwt),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_create_list_delete_round_trip() {
        let (_t, app) = build_app();
        let base = format!("/v1/repos/{REPO}/webhooks");

        // Create.
        let (status, body) = send(&app, req("POST", &base, Some(ADMIN), Some(BODY))).await;
        assert_eq!(status, StatusCode::OK);
        let hook_id = body["id"].as_str().expect("created id").to_string();
        assert!(!hook_id.is_empty());

        // List shows exactly the one we created.
        let (status, body) = send(&app, req("GET", &base, Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        let arr = body.as_array().expect("list is an array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["url"], "http://hook.invalid/x");

        // Delete it → removed: true.
        let del = format!("{base}/{hook_id}");
        let (status, body) = send(&app, req("DELETE", &del, Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["removed"], true);

        // Deleting again → removed: false (idempotent).
        let (status, body) = send(&app, req("DELETE", &del, Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["removed"], false);

        // List is empty again.
        let (status, body) = send(&app, req("GET", &base, Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn create_rejects_ssrf_target() {
        // A loopback IP-literal target must be refused by default
        // (build_app's Config leaves webhook_allow_private_targets =
        // false). Admin auth, repo exists — the only thing that fails
        // is the SSRF guard → 400.
        let (_t, app) = build_app();
        let (status, _) = send(
            &app,
            req(
                "POST",
                &format!("/v1/repos/{REPO}/webhooks"),
                Some(ADMIN),
                Some(r#"{"url":"http://169.254.169.254/latest/meta-data","events":["commit"]}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "metadata SSRF must be 400");

        let (status, _) = send(
            &app,
            req(
                "POST",
                &format!("/v1/repos/{REPO}/webhooks"),
                Some(ADMIN),
                Some(r#"{"url":"http://127.0.0.1:9000/hook","events":["commit"]}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "loopback SSRF must be 400");
    }

    #[test]
    fn create_body_rejects_unknown_event_kind() {
        // The N3 win: a misspelled kind fails to deserialize, so the
        // subscription is rejected at creation rather than silently
        // never matching any event.
        let ok = serde_json::from_str::<super::CreateWebhookBody>(
            r#"{"url":"http://x.invalid","events":["commit","fork"]}"#,
        );
        assert!(ok.is_ok(), "valid kinds must parse");
        let bad = serde_json::from_str::<super::CreateWebhookBody>(
            r#"{"url":"http://x.invalid","events":["comit"]}"#,
        );
        assert!(bad.is_err(), "a typo'd kind must be rejected, not dropped");
    }
}
