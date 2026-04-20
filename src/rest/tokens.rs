//! Per-repo token endpoints: mint, list, revoke, rotate.
//!
//! All four are owner-scoped (admin always passes; users must own the
//! repo). The store itself lives in `state.authn.tokens`.

use super::{remote_url, RestState};
use crate::{
    auth::authorize_rest,
    error::{Error, Result},
    ownership::enforce_owner,
    rate_limit::Class,
    tokens::Scope,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct MintTokenBody {
    pub scope: Scope,
    /// Optional lifetime in seconds. `None` means never expires.
    #[serde(default, rename = "ttlSeconds")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct TokenMinted {
    pub token: crate::ids::Token,
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
    let ttl = body.ttl_seconds.map(std::time::Duration::from_secs);
    let subject_typed = match principal.subject() {
        Some(s) => Some(crate::ids::Subject::try_from(s)?),
        None => None,
    };
    let token = state
        .authn
        .tokens
        .mint(&id_typed, body.scope, ttl, subject_typed.as_ref())
        .await?;
    let remote = remote_url(&state.cfg, &id, &token);
    let expires_at = ttl.map(|d| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|now| now.as_secs() + d.as_secs())
            .unwrap_or(0)
    });
    crate::audit::record(
        &*state.observ.audit,
        "token.mint",
        principal.audit_label(),
        Some(&id_typed),
        serde_json::json!({
            "scope": format!("{:?}", body.scope),
            "ttl_seconds": body.ttl_seconds,
        }),
        None,
    )
    .await;
    Ok(Json(TokenMinted {
        token,
        remote,
        expires_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RevokeBody {
    /// The token to revoke. Validated at decode time (1–256 graphic
    /// ASCII chars per `Token::try_from`); a malformed value becomes
    /// a 400 with the field path.
    pub token: crate::ids::Token,
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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    state.authn.rate_limit.check(&principal, Class::Token)?;

    // Resolve the token's bound repo for the audit log + the
    // ownership check. Admins skip the ownership check but we
    // still want the audit field populated; for a stale-or-fake
    // token there's nothing to bind to so log "unknown".
    let target_repo: Option<crate::ids::RepoId> = state
        .authn
        .tokens
        .lookup(&body.token)
        .await
        .ok()
        .flatten()
        .map(|rec| rec.repo_id);

    if !matches!(principal, crate::auth::Principal::Admin) {
        // Look up the token's bound repo and require ownership. Any
        // failure to resolve the token (unknown / expired / already
        // revoked) is reported as a 403 rather than a 404, because the
        // alternative leaks "this token doesn't exist" to anyone with
        // a JWT — slight oracle for token-fishing.
        let repo_id = target_repo
            .as_ref()
            .ok_or(Error::Forbidden("not your token"))?;
        enforce_owner(&*state.data.ownership, &principal, repo_id.as_str()).await?;
    }

    let revoked = state.authn.tokens.revoke(&body.token).await?;
    crate::audit::record(
        &*state.observ.audit,
        "token.revoke",
        principal.audit_label(),
        target_repo.as_ref(),
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
    pub token: crate::ids::Token,
    pub remote: String,
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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    let id_typed = crate::ids::RepoId::try_from(id.as_str())?;
    if !state.data.storage.exists(&id_typed) {
        return Err(Error::RepoNotFound(id));
    }
    enforce_owner(&*state.data.ownership, &principal, &id).await?;
    let subject_filter_typed = match &principal {
        crate::auth::Principal::Admin => None,
        crate::auth::Principal::User { subject } => {
            Some(crate::ids::Subject::try_from(subject.as_str())?)
        },
    };
    let rows = state
        .authn
        .tokens
        .list_for_repo(&id_typed, subject_filter_typed.as_ref())
        .await?;
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

    let subject_typed = match principal.subject() {
        Some(s) => Some(crate::ids::Subject::try_from(s)?),
        None => None,
    };
    let revoked = state.authn.tokens.revoke_all_for_repo(&id_typed).await?;
    let scope = body.scope.unwrap_or(Scope::Write);
    let ttl = body.ttl_seconds.map(std::time::Duration::from_secs);
    let token = state
        .authn
        .tokens
        .mint(&id_typed, scope, ttl, subject_typed.as_ref())
        .await?;
    let remote = remote_url(&state.cfg, &id, &token);
    crate::audit::record(
        &*state.observ.audit,
        "token.rotate",
        principal.audit_label(),
        Some(&id_typed),
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

#[cfg(test)]
mod tests {
    use super::super::{
        create_repo, fork_repo, list_tokens, mint_token, revoke_token, rotate_tokens, AuthnState,
        DataState, ObservState, RestState, RuntimeState,
    };
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::post,
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
            .route("/v1/repos", post(create_repo))
            .route("/v1/repos/:id/forks", post(fork_repo))
            .route("/v1/repos/:id/tokens", post(mint_token).get(list_tokens))
            .route("/v1/repos/:id/tokens/rotate", post(rotate_tokens))
            .route("/v1/tokens/revoke", post(revoke_token))
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

    async fn send(app: &Router, r: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.clone().oneshot(r).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    // ── mint_token ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mint_token_admin_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        let (status, tok) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{id}/tokens"),
                Some(ADMIN),
                Some(r#"{"scope":"read"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(tok["token"].as_str().is_some());
        assert!(tok["remote"].as_str().is_some());
        assert!(tok["expiresAt"].is_null());
    }

    #[tokio::test]
    async fn mint_token_jwt_owner_subject_path() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt = user_jwt("alice");
        // alice creates repo.
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(&jwt), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        // alice mints a token → 200 with subject path exercised.
        let (status, tok) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{id}/tokens"),
                Some(&jwt),
                Some(r#"{"scope":"write"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(tok["token"].as_str().is_some());
    }

    #[tokio::test]
    async fn mint_token_non_owner_is_403() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt_alice = user_jwt("alice");
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(&jwt_alice), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        // bob tries to mint → 403.
        let jwt_bob = user_jwt("bob");
        let (status, _) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{id}/tokens"),
                Some(&jwt_bob),
                Some(r#"{"scope":"read"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mint_token_missing_repo_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(
            &a,
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
    async fn mint_token_bad_scope_is_422() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        // "admin" is not a valid Scope → axum JSON extractor should 422.
        let (status, _) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{id}/tokens"),
                Some(ADMIN),
                Some(r#"{"scope":"admin"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn mint_token_with_ttl_has_expires_at() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        let (status, tok) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{id}/tokens"),
                Some(ADMIN),
                Some(r#"{"scope":"read","ttlSeconds":3600}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(tok["expiresAt"].is_number());
    }

    // ── list_tokens ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_tokens_owner_sees_own_tokens() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt = user_jwt("alice");
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(&jwt), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        let (status, list) = send(
            &a,
            req("GET", &format!("/v1/repos/{id}/tokens"), Some(&jwt), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(list.is_array());
    }

    #[tokio::test]
    async fn list_tokens_non_owner_is_403() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt_alice = user_jwt("alice");
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(&jwt_alice), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        let jwt_bob = user_jwt("bob");
        let (status, _) = send(
            &a,
            req(
                "GET",
                &format!("/v1/repos/{id}/tokens"),
                Some(&jwt_bob),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // ── revoke_token ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn revoke_token_existing_returns_revoked_true() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        // Mint a token to revoke.
        let (_, tok_body) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{id}/tokens"),
                Some(ADMIN),
                Some(r#"{"scope":"read"}"#),
            ),
        )
        .await;
        let token_val = tok_body["token"].as_str().unwrap().to_string();
        let revoke_body = format!(r#"{{"token":"{token_val}"}}"#);
        let (status, resp) = send(
            &a,
            req("POST", "/v1/tokens/revoke", Some(ADMIN), Some(&revoke_body)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["revoked"], true);
    }

    #[tokio::test]
    async fn revoke_token_unknown_token_returns_revoked_false() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        // A token that was never minted → revoked: false.
        let (status, resp) = send(
            &a,
            req(
                "POST",
                "/v1/tokens/revoke",
                Some(ADMIN),
                Some(r#"{"token":"aaaa-bbbb-cccc-dddd-eeee"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp["revoked"], false);
    }

    // ── rotate_tokens ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn rotate_tokens_owner_gets_fresh_token() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt = user_jwt("alice");
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(&jwt), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        let (status, resp) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{id}/tokens/rotate"),
                Some(&jwt),
                Some("{}"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(resp["token"].as_str().is_some());
        assert!(resp["revoked"].is_number());
    }

    #[tokio::test]
    async fn rotate_tokens_with_optional_scope_field() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        let (status, resp) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{id}/tokens/rotate"),
                Some(ADMIN),
                Some(r#"{"scope":"read"}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(resp["token"].as_str().is_some());
    }

    #[tokio::test]
    async fn rotate_tokens_missing_repo_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(
            &a,
            req(
                "POST",
                "/v1/repos/no-such-repo/tokens/rotate",
                Some(ADMIN),
                Some("{}"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
