//! Admin-only inspection + maintenance endpoints.
//!
//! Every handler here calls [`require_admin`] first — JWT principals
//! get 403. Routes are mounted at `/v1/admin/*` so the separation is
//! obvious at the URL level.

use super::{
    dir_size, list_refs, require_admin, AdminRepoDetail, AdminRepoSummary, ListReposQuery,
    RestState, LIST_REPOS_DEFAULT_LIMIT, LIST_REPOS_MAX_LIMIT,
};
use crate::error::{Error, Result};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    state.authn.rate_limit.check(
        &crate::auth::Principal::Admin,
        crate::rate_limit::Class::Default,
    )?;

    let limit = q
        .limit
        .unwrap_or(LIST_REPOS_DEFAULT_LIMIT)
        .min(LIST_REPOS_MAX_LIMIT);
    let offset = q.offset.unwrap_or(0);

    let total = state.data.ownership.count_all().await?;
    let rows = state.data.ownership.list_paginated(limit, offset).await?;

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
            source_id: state
                .data
                .alternates_cache
                .lookup(&repos_dir, r.id.as_str()),
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
    state.authn.rate_limit.check(
        &crate::auth::Principal::Admin,
        crate::rate_limit::Class::Default,
    )?;

    let id_typed = crate::ids::RepoId::try_from(id.as_str())?;
    let Some(row) = state.data.ownership.get_row(&id_typed).await? else {
        return Err(Error::RepoNotFound(id));
    };

    let repos_dir = state.cfg.repos_dir();
    let repo_path = repos_dir.join(format!("{id}.git"));
    if !repo_path.is_dir() {
        return Err(Error::RepoNotFound(id));
    }

    let refs = list_refs(&repo_path).unwrap_or_default();
    let size_bytes = dir_size(&repo_path).unwrap_or(0);

    Ok(Json(AdminRepoDetail {
        summary: AdminRepoSummary {
            source_id: state.data.alternates_cache.lookup(&repos_dir, &id),
            id: id_typed,
            owner: row.owner,
            created_at: row.created_at,
        },
        size_bytes,
        refs,
    }))
}

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
    state.authn.rate_limit.check(
        &crate::auth::Principal::Admin,
        crate::rate_limit::Class::Default,
    )?;
    let id_typed = crate::ids::RepoId::try_from(id.as_str())?;
    if !state.data.storage.exists(&id_typed) {
        return Err(Error::RepoNotFound(id));
    }
    // GC preview walks the alternates network and runs a `git rev-list`
    // per member — seconds on a large repo. Offload to a blocking
    // worker so it doesn't stall a tokio runtime thread (the periodic
    // sweep already does this; the admin endpoint must too).
    let repos_dir = state.cfg.repos_dir();
    let cache = state.data.alternates_cache.clone();
    let objects = state.data.objects.clone();
    let preview = crate::blocking::run_blocking("admin_gc_preview", move || {
        crate::gc::preview(&repos_dir, &id, &cache, &*objects)
    })
    .await?;
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
    state.authn.rate_limit.check(
        &crate::auth::Principal::Admin,
        crate::rate_limit::Class::Default,
    )?;
    let id_typed = crate::ids::RepoId::try_from(id.as_str())?;
    if !state.data.storage.exists(&id_typed) {
        return Err(Error::RepoNotFound(id));
    }
    // A full GC pass (reachability walk + per-object unlink) can run
    // for seconds-to-minutes; keep it off the runtime threads.
    let repos_dir = state.cfg.repos_dir();
    let cache = state.data.alternates_cache.clone();
    let objects = state.data.objects.clone();
    let min_age_secs = q.min_age_secs.unwrap_or(7200);
    let result = crate::blocking::run_blocking("admin_gc_run", move || {
        crate::gc::run(&repos_dir, &id, &cache, min_age_secs, &*objects)
    })
    .await?;
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
/// Generates a fresh admin token, swaps it into the running
/// `Config`'s in-memory cell, and returns it in the response. After
/// this call returns, the previous admin token no longer authorizes
/// anything; the new one does. No restart required.
///
/// Admin-only. JWT principals get 403. Emits an `admin.token.rotate`
/// audit event (without the actual token bytes — the caller already
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
        &*state.observ.audit,
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
pub struct AdminJwtKeyRotateResponse {
    /// The freshly-generated JWT signing secret, base64-url-encoded
    /// (no padding). 32 bytes of entropy. Caller must persist this
    /// — if the server restarts before either the env var is
    /// updated or the on-disk `<data-dir>/jwt-key.bin` is replaced,
    /// every JWT minted under the previous key stops authorizing.
    pub key: String,
    /// True if the rotation persisted the new key to disk (i.e.
    /// `<data-dir>/jwt-key.bin` was rewritten). False for env-pinned
    /// deployments — the response body is the only place the new
    /// key surfaces.
    pub persisted: bool,
}

/// `POST /v1/admin/jwt-key/rotate`
///
/// Generates a fresh 32-byte HS256 secret, swaps the in-memory cell
/// in `Config`, persists to `<data-dir>/jwt-key.bin` (0600) when the
/// deployment is file-backed, and returns the new key. Mirrors the
/// admin-token rotation pattern — the previous secret stops
/// authorizing any JWT on the next request, no restart required.
///
/// Use this after a suspected leak of the JWT signing secret. Every
/// JWT minted under the old secret instantly fails verification;
/// fresh JWTs must be signed under the new secret. Coordinate with
/// the identity provider (Dyspel backend etc.) — both sides need
/// the new value to keep accepting tokens.
///
/// Admin-only. JWT principals get 403 (which is the only sane
/// answer: a JWT user rotating the JWT key would lock themselves
/// out mid-flight). Emits an `admin.jwt_key.rotate` audit event
/// with `{persisted: bool}` — no key bytes in the event.
pub async fn admin_rotate_jwt_key(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<AdminJwtKeyRotateResponse>> {
    require_admin(&state, &headers)?;
    let new_key = {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use rand::Rng;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    };
    state.cfg.rotate_jwt_secret(Some(new_key.clone()));

    let persisted = if let Some(path) = state.observ.jwt_key_path.as_deref() {
        // 0600 perms on POSIX; on Windows the OpenOptions mode flag is
        // ignored but the file still gets the user's default ACL,
        // which is roughly equivalent for single-user deployments.
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(path).and_then(|mut f| {
            use std::io::Write;
            f.write_all(new_key.as_bytes())
        }) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "jwt key file rewrite failed; persist `key` from response manually",
                );
                false
            },
        }
    } else {
        false
    };

    crate::audit::record(
        &*state.observ.audit,
        "admin.jwt_key.rotate",
        "admin",
        None,
        serde_json::json!({ "persisted": persisted }),
        None,
    )
    .await;

    Ok(Json(AdminJwtKeyRotateResponse {
        key: new_key,
        persisted,
    }))
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

    let rotated = state.observ.webhooks.rotate_master_key(new_key.clone())?;

    if let Some(path) = state.observ.webhook_key_path.as_deref() {
        if let Err(e) = std::fs::write(path, &new_key_b64) {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "webhook key file rewrite failed; persist `key` from response manually",
            );
        }
    }

    crate::audit::record(
        &*state.observ.audit,
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
    let count = state.observ.audit.count().await?;
    Ok(Json(AdminAuditStats { count }))
}

/// `GET /v1/admin/audit/verify-chain`
///
/// Walk the audit-log hash chain and recompute every row's hash.
/// Returns `{verified: N}` on success — the count of chained rows
/// whose stored hash matched. Returns 500 with a descriptive error
/// on the first mismatch (post-hoc tampering of the SQLite file by
/// anyone with shell access to the data dir).
///
/// Admin-only. Cost is one full scan over `audit_events`; safe to
/// call from compliance tooling on demand.
pub async fn admin_verify_audit_chain(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<crate::audit::ChainVerifyOk>> {
    require_admin(&state, &headers)?;
    let ok = state.observ.audit.verify_chain().await?;
    Ok(Json(ok))
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
        .observ
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

#[cfg(test)]
mod tests {
    use super::super::{
        admin_audit_stats, admin_gc_preview, admin_gc_run, admin_get_repo, admin_list_audit,
        admin_list_repos, admin_rotate_jwt_key, admin_rotate_token, admin_rotate_webhook_key,
        admin_verify_audit_chain, create_repo, fork_repo, AuthnState, DataState, ObservState,
        RestState, RuntimeState,
    };
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
            .route("/v1/repos", post(create_repo))
            .route("/v1/repos/:id/forks", post(fork_repo))
            .route("/v1/admin/repos", get(admin_list_repos))
            .route("/v1/admin/repos/:id", get(admin_get_repo))
            .route("/v1/admin/repos/:id/gc-preview", get(admin_gc_preview))
            .route("/v1/admin/repos/:id/gc", post(admin_gc_run))
            .route("/v1/admin/token/rotate", post(admin_rotate_token))
            .route("/v1/admin/jwt-key/rotate", post(admin_rotate_jwt_key))
            .route(
                "/v1/admin/webhook-key/rotate",
                post(admin_rotate_webhook_key),
            )
            .route("/v1/admin/audit", get(admin_list_audit))
            .route("/v1/admin/audit/stats", get(admin_audit_stats))
            .route(
                "/v1/admin/audit/verify-chain",
                get(admin_verify_audit_chain),
            )
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

    // ── admin_list_audit ──────────────────────────────────────────────────

    #[tokio::test]
    async fn admin_list_audit_no_auth_is_401() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(&a, req("GET", "/v1/admin/audit", None, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_list_audit_jwt_user_is_403() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt = user_jwt("alice");
        let (status, _) = send(&a, req("GET", "/v1/admin/audit", Some(&jwt), None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_list_audit_with_query_params_returns_200() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        // Exercise every supported query param to hit the filter branches.
        let (status, body) = send(
            &a,
            req(
                "GET",
                "/v1/admin/audit?event=repo.create&actor=admin&repoId=some-repo&since=0&until=9999999999&limit=5&offset=0",
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_array());
    }

    // ── admin_audit_stats ─────────────────────────────────────────────────

    #[tokio::test]
    async fn admin_audit_stats_no_auth_is_401() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(&a, req("GET", "/v1/admin/audit/stats", None, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_audit_stats_jwt_user_is_403() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt = user_jwt("alice");
        let (status, _) = send(&a, req("GET", "/v1/admin/audit/stats", Some(&jwt), None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_audit_stats_admin_returns_count() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, body) = send(&a, req("GET", "/v1/admin/audit/stats", Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["count"].is_number());
    }

    // ── admin_verify_audit_chain ──────────────────────────────────────────

    #[tokio::test]
    async fn admin_verify_audit_chain_no_auth_is_401() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(&a, req("GET", "/v1/admin/audit/verify-chain", None, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_verify_audit_chain_admin_returns_verified_count() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, body) = send(
            &a,
            req("GET", "/v1/admin/audit/verify-chain", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["verified"].is_number());
    }

    // ── admin_get_repo ────────────────────────────────────────────────────

    #[tokio::test]
    async fn admin_get_repo_missing_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(
            &a,
            req("GET", "/v1/admin/repos/no-such-repo", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_get_repo_existing_returns_detail() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        // Create a repo so there is something to fetch.
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        let (status, detail) = send(
            &a,
            req("GET", &format!("/v1/admin/repos/{id}"), Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(detail["id"], id);
        assert!(detail["sizeBytes"].is_number());
    }

    #[tokio::test]
    async fn admin_get_repo_no_auth_is_401() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(&a, req("GET", "/v1/admin/repos/any-repo", None, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ── admin_gc_preview / admin_gc_run ───────────────────────────────────

    #[tokio::test]
    async fn admin_gc_preview_missing_repo_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(
            &a,
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
    async fn admin_gc_preview_existing_repo_returns_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        let (status, _) = send(
            &a,
            req(
                "GET",
                &format!("/v1/admin/repos/{id}/gc-preview"),
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_gc_run_missing_repo_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(
            &a,
            req("POST", "/v1/admin/repos/no-such-repo/gc", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_gc_run_existing_repo_returns_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        // Pass minAgeSecs=0 so no age-gating, no objects exist anyway.
        let (status, _) = send(
            &a,
            req(
                "POST",
                &format!("/v1/admin/repos/{id}/gc?minAgeSecs=0"),
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // ── admin_rotate_token ────────────────────────────────────────────────

    #[tokio::test]
    async fn admin_rotate_token_no_auth_is_401() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(&a, req("POST", "/v1/admin/token/rotate", None, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_rotate_token_jwt_user_is_403() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt = user_jwt("alice");
        let (status, _) = send(&a, req("POST", "/v1/admin/token/rotate", Some(&jwt), None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_rotate_token_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, body) =
            send(&a, req("POST", "/v1/admin/token/rotate", Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["token"].as_str().is_some());
    }

    // ── admin_rotate_jwt_key ──────────────────────────────────────────────

    #[tokio::test]
    async fn admin_rotate_jwt_key_no_auth_is_401() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(&a, req("POST", "/v1/admin/jwt-key/rotate", None, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_rotate_jwt_key_jwt_user_is_403() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt = user_jwt("alice");
        let (status, _) = send(
            &a,
            req("POST", "/v1/admin/jwt-key/rotate", Some(&jwt), None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_rotate_jwt_key_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, body) = send(
            &a,
            req("POST", "/v1/admin/jwt-key/rotate", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["key"].as_str().is_some());
        // Not file-backed in tests → persisted == false.
        assert_eq!(body["persisted"], false);
    }

    // ── admin_rotate_webhook_key ──────────────────────────────────────────

    #[tokio::test]
    async fn admin_rotate_webhook_key_no_auth_is_401() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(&a, req("POST", "/v1/admin/webhook-key/rotate", None, None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_rotate_webhook_key_jwt_user_is_403() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt = user_jwt("alice");
        let (status, _) = send(
            &a,
            req("POST", "/v1/admin/webhook-key/rotate", Some(&jwt), None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_rotate_webhook_key_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, body) = send(
            &a,
            req("POST", "/v1/admin/webhook-key/rotate", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["key"].as_str().is_some());
        assert!(body["rotated"].is_number());
    }

    // ── admin_list_repos pagination ───────────────────────────────────────

    #[tokio::test]
    async fn admin_list_repos_pagination() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        // Create two repos.
        send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        // limit=1 offset=0 → one result.
        let (status, body) = send(
            &a,
            req("GET", "/v1/admin/repos?limit=1&offset=0", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().map(|a| a.len()), Some(1));
        // offset=1 → second result.
        let (status, body2) = send(
            &a,
            req("GET", "/v1/admin/repos?limit=1&offset=1", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body2.as_array().map(|a| a.len()), Some(1));
        // The two pages should have different ids.
        assert_ne!(body[0]["id"], body2[0]["id"]);
    }

    // ── admin_get_repo: ownership row exists but git dir missing ─────────────

    /// Cover line 109: the row exists in the ownership store but the git
    /// directory is absent from disk (e.g. deleted out-of-band). The
    /// handler must return 404 without panicking.
    #[tokio::test]
    async fn admin_get_repo_row_exists_but_git_dir_missing_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        // Create a repo so the ownership row exists.
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        // Remove the git directory from disk without going through the API.
        let repos_dir = tmp.path().join("repos");
        let git_dir = repos_dir.join(format!("{id}.git"));
        std::fs::remove_dir_all(&git_dir).unwrap();
        // Now the ownership row exists but the on-disk repo does not.
        let (status, _) = send(
            &a,
            req("GET", &format!("/v1/admin/repos/{id}"), Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── admin_rotate_jwt_key: file-backed path ────────────────────────────

    /// Cover lines 293-311: when `jwt_key_path` is set, the handler writes
    /// the new key to that file and returns `persisted: true`.
    #[tokio::test]
    async fn admin_rotate_jwt_key_file_backed_persists_and_returns_true() {
        let tmp = tempfile::tempdir().unwrap();
        // Build a state with jwt_key_path pointing at a file we control.
        let jwt_key_file = tmp.path().join("jwt-key.bin");
        std::fs::write(&jwt_key_file, "initial-key").unwrap();
        let data_dir = tmp.path().to_path_buf();
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
        let state = RestState {
            cfg: std::sync::Arc::new(cfg),
            data: DataState {
                storage: std::sync::Arc::new(storage),
                ownership: std::sync::Arc::new(
                    crate::ownership::SqliteOwnershipStore::open(&data_dir.join("own.db")).unwrap(),
                ),
                refs: std::sync::Arc::new(crate::refs::MemRefStore::new()),
                objects: std::sync::Arc::new(crate::object_store::MemObjectStore::new()),
                alternates_cache: std::sync::Arc::new(
                    crate::alternates_cache::AlternatesCache::new(),
                ),
            },
            authn: AuthnState {
                tokens: std::sync::Arc::new(
                    crate::tokens::SqliteTokenStore::open(&data_dir.join("tok.db")).unwrap(),
                ),
                rate_limit: std::sync::Arc::new(crate::rate_limit::RateLimiter::with_defaults()),
            },
            observ: ObservState {
                audit: std::sync::Arc::new(crate::audit::NoopAuditStore),
                events: crate::events::EventBus::new(),
                webhooks: std::sync::Arc::new(crate::webhooks::MemRegistry::new()),
                webhook_outbox: None,
                webhook_key_path: None,
                jwt_key_path: Some(jwt_key_file.clone()),
            },
            runtime: RuntimeState {
                draining: std::sync::Arc::new(AtomicBool::new(false)),
            },
        };
        let a = Router::new()
            .route(
                "/v1/admin/jwt-key/rotate",
                axum::routing::post(super::super::admin_rotate_jwt_key),
            )
            .with_state(state);
        let req_val = req("POST", "/v1/admin/jwt-key/rotate", Some(ADMIN), None);
        let (status, body) = send(&a, req_val).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["key"].as_str().is_some());
        // With a valid writable path, persisted must be true.
        assert_eq!(
            body["persisted"], true,
            "file-backed rotation must return persisted=true"
        );
        // The file on disk must now contain the new key.
        let on_disk = std::fs::read_to_string(&jwt_key_file).unwrap();
        assert_eq!(on_disk, body["key"].as_str().unwrap());
    }

    /// Cover lines 305-311: when the jwt_key_path exists but points to a
    /// non-writable location, the handler logs and returns `persisted: false`
    /// (best-effort; doesn't fail the request).
    #[tokio::test]
    async fn admin_rotate_jwt_key_file_write_fails_returns_persisted_false() {
        let tmp = tempfile::tempdir().unwrap();
        // Point jwt_key_path at a path whose parent does not exist.
        let bad_path = tmp.path().join("no-such-dir").join("jwt-key.bin");
        let data_dir = tmp.path().to_path_buf();
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
        let state = RestState {
            cfg: std::sync::Arc::new(cfg),
            data: DataState {
                storage: std::sync::Arc::new(storage),
                ownership: std::sync::Arc::new(
                    crate::ownership::SqliteOwnershipStore::open(&data_dir.join("own.db")).unwrap(),
                ),
                refs: std::sync::Arc::new(crate::refs::MemRefStore::new()),
                objects: std::sync::Arc::new(crate::object_store::MemObjectStore::new()),
                alternates_cache: std::sync::Arc::new(
                    crate::alternates_cache::AlternatesCache::new(),
                ),
            },
            authn: AuthnState {
                tokens: std::sync::Arc::new(
                    crate::tokens::SqliteTokenStore::open(&data_dir.join("tok.db")).unwrap(),
                ),
                rate_limit: std::sync::Arc::new(crate::rate_limit::RateLimiter::with_defaults()),
            },
            observ: ObservState {
                audit: std::sync::Arc::new(crate::audit::NoopAuditStore),
                events: crate::events::EventBus::new(),
                webhooks: std::sync::Arc::new(crate::webhooks::MemRegistry::new()),
                webhook_outbox: None,
                webhook_key_path: None,
                jwt_key_path: Some(bad_path),
            },
            runtime: RuntimeState {
                draining: std::sync::Arc::new(AtomicBool::new(false)),
            },
        };
        let a = Router::new()
            .route(
                "/v1/admin/jwt-key/rotate",
                axum::routing::post(super::super::admin_rotate_jwt_key),
            )
            .with_state(state);
        let req_val = req("POST", "/v1/admin/jwt-key/rotate", Some(ADMIN), None);
        let (status, body) = send(&a, req_val).await;
        assert_eq!(status, StatusCode::OK);
        // File write fails → persisted=false, but the request itself succeeds.
        assert_eq!(
            body["persisted"], false,
            "failed file write must return persisted=false, not an error response"
        );
        assert!(body["key"].as_str().is_some());
    }

    // ── admin_rotate_webhook_key: file write error path ──────────────────────

    /// Cover lines 379-385: webhook_key_path is set but the write fails
    /// (parent directory missing). Handler must log-warn and succeed, not
    /// return an error to the caller.
    #[tokio::test]
    async fn admin_rotate_webhook_key_file_write_fails_still_returns_200() {
        let tmp = tempfile::tempdir().unwrap();
        let bad_path = tmp.path().join("no-such-dir").join("wh-key.bin");
        let data_dir = tmp.path().to_path_buf();
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
        let state = RestState {
            cfg: std::sync::Arc::new(cfg),
            data: DataState {
                storage: std::sync::Arc::new(storage),
                ownership: std::sync::Arc::new(
                    crate::ownership::SqliteOwnershipStore::open(&data_dir.join("own.db")).unwrap(),
                ),
                refs: std::sync::Arc::new(crate::refs::MemRefStore::new()),
                objects: std::sync::Arc::new(crate::object_store::MemObjectStore::new()),
                alternates_cache: std::sync::Arc::new(
                    crate::alternates_cache::AlternatesCache::new(),
                ),
            },
            authn: AuthnState {
                tokens: std::sync::Arc::new(
                    crate::tokens::SqliteTokenStore::open(&data_dir.join("tok.db")).unwrap(),
                ),
                rate_limit: std::sync::Arc::new(crate::rate_limit::RateLimiter::with_defaults()),
            },
            observ: ObservState {
                audit: std::sync::Arc::new(crate::audit::NoopAuditStore),
                events: crate::events::EventBus::new(),
                webhooks: std::sync::Arc::new(crate::webhooks::MemRegistry::new()),
                webhook_outbox: None,
                webhook_key_path: Some(bad_path),
                jwt_key_path: None,
            },
            runtime: RuntimeState {
                draining: std::sync::Arc::new(AtomicBool::new(false)),
            },
        };
        let a = Router::new()
            .route(
                "/v1/admin/webhook-key/rotate",
                axum::routing::post(super::super::admin_rotate_webhook_key),
            )
            .with_state(state);
        let req_val = req("POST", "/v1/admin/webhook-key/rotate", Some(ADMIN), None);
        let (status, body) = send(&a, req_val).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["key"].as_str().is_some());
    }

    // ── audit endpoints with real SqliteAuditStore (non-empty rows) ──────────

    /// Build a RestState whose `observ.audit` is a real `SqliteAuditStore`
    /// seeded with events so the list/stats/verify-chain endpoints exercise
    /// the non-empty response-shaping paths (lines 293-330, 379-380 hint
    /// at the list path in audit; the real gap is the list branch that
    /// iterates over returned rows).
    fn build_state_with_sqlite_audit(dir: &std::path::Path) -> RestState {
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
            cfg: std::sync::Arc::new(cfg),
            data: DataState {
                storage: std::sync::Arc::new(storage),
                ownership: std::sync::Arc::new(
                    crate::ownership::SqliteOwnershipStore::open(&data_dir.join("own.db")).unwrap(),
                ),
                refs: std::sync::Arc::new(crate::refs::MemRefStore::new()),
                objects: std::sync::Arc::new(crate::object_store::MemObjectStore::new()),
                alternates_cache: std::sync::Arc::new(
                    crate::alternates_cache::AlternatesCache::new(),
                ),
            },
            authn: AuthnState {
                tokens: std::sync::Arc::new(
                    crate::tokens::SqliteTokenStore::open(&data_dir.join("tok.db")).unwrap(),
                ),
                rate_limit: std::sync::Arc::new(crate::rate_limit::RateLimiter::with_defaults()),
            },
            observ: ObservState {
                audit: std::sync::Arc::new(
                    crate::audit::SqliteAuditStore::open(&data_dir.join("audit.db")).unwrap(),
                ),
                events: crate::events::EventBus::new(),
                webhooks: std::sync::Arc::new(crate::webhooks::MemRegistry::new()),
                webhook_outbox: None,
                webhook_key_path: None,
                jwt_key_path: None,
            },
            runtime: RuntimeState {
                draining: std::sync::Arc::new(AtomicBool::new(false)),
            },
        }
    }

    fn audit_app(dir: &std::path::Path) -> Router {
        Router::new()
            .route("/v1/admin/audit", get(admin_list_audit))
            .route("/v1/admin/audit/stats", get(admin_audit_stats))
            .route(
                "/v1/admin/audit/verify-chain",
                get(admin_verify_audit_chain),
            )
            .with_state(build_state_with_sqlite_audit(dir))
    }

    /// Seed the store with events, then assert the list endpoint returns them.
    #[tokio::test]
    async fn admin_list_audit_with_real_store_returns_rows() {
        let tmp = tempfile::tempdir().unwrap();
        // Seed the store directly before building the app so the rows are there.
        {
            let store = crate::audit::SqliteAuditStore::open(&tmp.path().join("audit.db")).unwrap();
            crate::audit::record(
                &store,
                "repo.create",
                "admin",
                None,
                serde_json::json!({}),
                None,
            )
            .await;
            crate::audit::record(
                &store,
                "token.mint",
                "alice",
                None,
                serde_json::json!({}),
                Some("req-1".into()),
            )
            .await;
        }
        let a = audit_app(tmp.path());
        let (status, body) = send(&a, req("GET", "/v1/admin/audit", Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        let arr = body.as_array().expect("expected array");
        assert_eq!(arr.len(), 2, "both inserted events must appear");
    }

    /// stats endpoint with a real store: count must equal inserted rows.
    #[tokio::test]
    async fn admin_audit_stats_with_real_store_returns_correct_count() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let store = crate::audit::SqliteAuditStore::open(&tmp.path().join("audit.db")).unwrap();
            for i in 0..5u32 {
                crate::audit::record(
                    &store,
                    &format!("e{i}"),
                    "admin",
                    None,
                    serde_json::json!({}),
                    None,
                )
                .await;
            }
        }
        let a = audit_app(tmp.path());
        let (status, body) = send(&a, req("GET", "/v1/admin/audit/stats", Some(ADMIN), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], serde_json::json!(5u64));
    }

    /// verify-chain with a real store and real chained rows.
    #[tokio::test]
    async fn admin_verify_chain_with_real_store_returns_nonzero_verified() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let store = crate::audit::SqliteAuditStore::open(&tmp.path().join("audit.db")).unwrap();
            for i in 0..3u32 {
                crate::audit::record(
                    &store,
                    &format!("e{i}"),
                    "admin",
                    None,
                    serde_json::json!({}),
                    None,
                )
                .await;
            }
        }
        let a = audit_app(tmp.path());
        let (status, body) = send(
            &a,
            req("GET", "/v1/admin/audit/verify-chain", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["verified"],
            serde_json::json!(3u64),
            "verify-chain must count all 3 chained rows"
        );
    }

    /// list endpoint with filters exercised against a real store.
    #[tokio::test]
    async fn admin_list_audit_real_store_with_filters() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let store = crate::audit::SqliteAuditStore::open(&tmp.path().join("audit.db")).unwrap();
            crate::audit::record(
                &store,
                "repo.create",
                "admin",
                None,
                serde_json::json!({}),
                None,
            )
            .await;
            crate::audit::record(
                &store,
                "token.mint",
                "alice",
                None,
                serde_json::json!({}),
                None,
            )
            .await;
        }
        let a = audit_app(tmp.path());
        // Filter by event=repo.create: only one row.
        let (status, body) = send(
            &a,
            req(
                "GET",
                "/v1/admin/audit?event=repo.create&actor=admin",
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["event"], "repo.create");
    }
}
