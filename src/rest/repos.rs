//! Repo lifecycle endpoints: create, fork, delete, list.

use super::{
    remote_url, AdminRepoSummary, ListReposQuery, RepoHandle, RestState, LIST_REPOS_DEFAULT_LIMIT,
    LIST_REPOS_MAX_LIMIT,
};
use crate::{
    auth::authorize_rest,
    error::{Error, Result},
    ownership::{check_repo_quota, enforce_owner},
    rate_limit::Class,
    storage::new_repo_id,
    tokens::Scope,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct CreateRepoBody {
    /// Optional caller-supplied id. If omitted we generate one.
    /// `RepoId`'s Deserialize impl enforces the same `[a-z0-9_-]{4..=64}`
    /// rule `validate_repo_id` enforces, so a bad value becomes a 400
    /// at decode time with the field path.
    pub id: Option<crate::ids::RepoId>,
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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    state.authn.rate_limit.check(&principal, Class::Create)?;
    check_repo_quota(
        &*state.data.ownership,
        &principal,
        state.cfg.max_repos_per_user,
    )
    .await?;
    // body.id is already a validated RepoId (serde checked) or None.
    // If absent, generate via new_repo_id — also valid by construction.
    let id_typed = body.and_then(|Json(b)| b.id).unwrap_or_else(|| {
        crate::ids::RepoId::try_from(new_repo_id().as_str())
            .expect("new_repo_id() output satisfies the RepoId contract")
    });
    let id_str = id_typed.as_str().to_owned();
    state.data.storage.create(&id_typed)?;
    // Record ownership *before* minting the token so a crash between the
    // two leaves a repo we can identify the owner of.
    let owner_typed = match principal.subject() {
        Some(s) => Some(crate::ids::Subject::try_from(s)?),
        None => None,
    };
    state
        .data
        .ownership
        .record_owner(&id_typed, owner_typed.as_ref())
        .await?;
    let token = state
        .authn
        .tokens
        .mint(&id_typed, Scope::Write, None, owner_typed.as_ref())
        .await?;
    let remote = remote_url(&state.cfg, &id_str, &token);
    crate::audit::record(
        &*state.observ.audit,
        "repo.create",
        principal.audit_label(),
        Some(&id_typed),
        serde_json::json!({}),
        None,
    )
    .await;
    // Emit a status transition so subscribers pick up brand-new repos
    // without polling. "unknown → idle" matches the repo's initial
    // state in the Fleet UI's RepoStatus enum.
    crate::webhooks::publish_event(
        &state.observ.events,
        state.observ.webhook_outbox.as_deref(),
        crate::events::Event::status(&id_str, "unknown", "idle"),
    );
    Ok(Json(RepoHandle {
        id: id_str,
        remote,
        token,
    }))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct ForkBody {
    /// Optional caller-supplied id for the fork. Validated at decode
    /// time (see `RepoId`); a malformed value becomes a 400.
    pub id: Option<crate::ids::RepoId>,
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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    state.authn.rate_limit.check(&principal, Class::Create)?;
    let source_id_typed = crate::ids::RepoId::try_from(source_id.as_str())?;
    if !state.data.storage.exists(&source_id_typed) {
        return Err(Error::RepoNotFound(source_id));
    }
    enforce_owner(&*state.data.ownership, &principal, &source_id).await?;
    check_repo_quota(
        &*state.data.ownership,
        &principal,
        state.cfg.max_repos_per_user,
    )
    .await?;
    let (fork_id_opt, read_only) = body
        .map(|Json(b)| (b.id, b.read_only))
        .unwrap_or((None, false));
    let fork_id_typed = fork_id_opt.unwrap_or_else(|| {
        crate::ids::RepoId::try_from(new_repo_id().as_str())
            .expect("new_repo_id() output satisfies the RepoId contract")
    });
    let fork_id_str = fork_id_typed.as_str().to_owned();
    state.data.storage.fork(&source_id_typed, &fork_id_typed)?;
    let owner_typed = match principal.subject() {
        Some(s) => Some(crate::ids::Subject::try_from(s)?),
        None => None,
    };
    state
        .data
        .ownership
        .record_owner(&fork_id_typed, owner_typed.as_ref())
        .await?;
    let scope = if read_only { Scope::Read } else { Scope::Write };
    let token = state
        .authn
        .tokens
        .mint(&fork_id_typed, scope, None, owner_typed.as_ref())
        .await?;
    let remote = remote_url(&state.cfg, &fork_id_str, &token);
    crate::audit::record(
        &*state.observ.audit,
        "repo.fork",
        principal.audit_label(),
        Some(&fork_id_typed),
        serde_json::json!({ "source_id": source_id, "read_only": read_only }),
        None,
    )
    .await;
    crate::webhooks::publish_event(
        &state.observ.events,
        state.observ.webhook_outbox.as_deref(),
        crate::events::Event::fork(&source_id, &fork_id_str),
    );
    Ok(Json(RepoHandle {
        id: fork_id_str,
        remote,
        token,
    }))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct DeleteRepoQuery {
    /// Allow deletion even if other repos depend on this one via
    /// `objects/info/alternates`. Without this flag a delete that
    /// would orphan a fork's object graph fails with 409.
    pub force: Option<bool>,
    /// If set, also delete every fork that depends on this repo
    /// (transitively). Mutually exclusive with `force=true` — pick
    /// "delete the chain together" or "orphan deliberately", not both.
    /// The response body returns
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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    state.authn.rate_limit.check(&principal, Class::Default)?;
    enforce_owner(&*state.data.ownership, &principal, &id).await?;
    let id_typed = crate::ids::RepoId::try_from(id.as_str())?;

    let force = q.force.unwrap_or(false);
    let cascade = q.cascade.unwrap_or(false);
    if force && cascade {
        return Err(Error::BadRequest(
            "force and cascade are mutually exclusive — pick one".to_string(),
        ));
    }

    if cascade {
        let order =
            super::cascade_delete_order(&state.cfg.repos_dir(), &id, &state.data.alternates_cache)?;
        for dep in &order {
            if dep != &id {
                enforce_owner(&*state.data.ownership, &principal, dep).await?;
            }
        }
        let mut deleted = Vec::with_capacity(order.len());
        for dep in &order {
            let dep_typed = crate::ids::RepoId::try_from(dep.as_str())?;
            // `delete` is `remove_dir_all` of a bare repo — potentially
            // large and fully blocking. Keep it off the runtime thread.
            let storage = state.data.storage.clone();
            let dep_for_delete = dep_typed.clone();
            crate::blocking::run_blocking("repo_delete_cascade", move || {
                storage.delete(&dep_for_delete)
            })
            .await?;
            state.data.ownership.delete(&dep_typed).await?;
            state.data.alternates_cache.invalidate(dep);
            deleted.push(dep.clone());
        }
        crate::audit::record(
            &*state.observ.audit,
            "repo.delete",
            principal.audit_label(),
            Some(&id_typed),
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

    let forks =
        crate::reads::list_forks_of(&state.cfg.repos_dir(), &id, &state.data.alternates_cache)?;
    if !forks.is_empty() {
        if force {
            tracing::warn!(
                repo = %id,
                fork_count = forks.len(),
                forks = ?forks,
                "delete with force=true; forks will be orphaned",
            );
        } else {
            return Err(Error::ForkDependency { repo_id: id, forks });
        }
    }

    // `remove_dir_all` of the bare repo — blocking, possibly large.
    let storage = state.data.storage.clone();
    let id_for_delete = id_typed.clone();
    crate::blocking::run_blocking("repo_delete", move || storage.delete(&id_for_delete)).await?;
    state.data.ownership.delete(&id_typed).await?;
    state.data.alternates_cache.invalidate(&id);
    let mode = if force { "force" } else { "default" };
    crate::audit::record(
        &*state.observ.audit,
        "repo.delete",
        principal.audit_label(),
        Some(&id_typed),
        serde_json::json!({ "mode": mode }),
        None,
    )
    .await;
    Ok(Json(serde_json::json!({ "ok": true })))
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
        state.cfg.jwt_secret().as_deref(),
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    state
        .authn
        .rate_limit
        .check(&principal, crate::rate_limit::Class::Default)?;

    let limit = q
        .limit
        .unwrap_or(LIST_REPOS_DEFAULT_LIMIT)
        .min(LIST_REPOS_MAX_LIMIT);
    let offset = q.offset.unwrap_or(0);

    let (rows, total) = match &principal {
        crate::auth::Principal::Admin => (
            state.data.ownership.list_paginated(limit, offset).await?,
            state.data.ownership.count_all().await?,
        ),
        crate::auth::Principal::User { subject } => {
            let subject_typed = crate::ids::Subject::try_from(subject.as_str())?;
            (
                state
                    .data
                    .ownership
                    .list_paginated_by_owner(&subject_typed, limit, offset)
                    .await?,
                state.data.ownership.count_by_owner(&subject_typed).await?,
            )
        },
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

#[cfg(test)]
mod tests {
    use super::super::{
        create_repo, delete_repo, fork_repo, list_repos, AuthnState, DataState, ObservState,
        RestState, RuntimeState,
    };
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        routing::{delete, post},
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
            .route("/v1/repos/:id", delete(delete_repo))
            .route("/v1/repos/:id/forks", post(fork_repo))
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

    // ── create_repo ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_repo_as_admin_records_null_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        assert_eq!(status, StatusCode::OK);
        let id = body["id"].as_str().unwrap().to_string();
        // List as admin → owner should be null (admin-owned).
        let (_, list) = send(&a, req("GET", "/v1/repos", Some(ADMIN), None)).await;
        let entry = list
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()
            .clone();
        assert!(entry["owner"].is_null());
    }

    #[tokio::test]
    async fn create_repo_as_jwt_user_records_subject_as_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt = user_jwt("alice");
        let (status, body) = send(&a, req("POST", "/v1/repos", Some(&jwt), Some("{}"))).await;
        assert_eq!(status, StatusCode::OK);
        let id = body["id"].as_str().unwrap().to_string();
        // Listing as alice → one repo with owner == "alice".
        let (_, list) = send(&a, req("GET", "/v1/repos", Some(&jwt), None)).await;
        let entry = list
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()
            .clone();
        assert_eq!(entry["owner"], "alice");
    }

    // ── list_repos pagination + owner scoping ─────────────────────────────

    #[tokio::test]
    async fn list_repos_pagination() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let (status, page0) = send(
            &a,
            req("GET", "/v1/repos?limit=1&offset=0", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page0.as_array().map(|a| a.len()), Some(1));

        let (status, page1) = send(
            &a,
            req("GET", "/v1/repos?limit=1&offset=1", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page1.as_array().map(|a| a.len()), Some(1));
        assert_ne!(page0[0]["id"], page1[0]["id"]);
    }

    #[tokio::test]
    async fn list_repos_owner_scoping() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let jwt_alice = user_jwt("alice");
        let jwt_bob = user_jwt("bob");
        // alice creates one repo, bob creates one.
        let (_, alice_body) =
            send(&a, req("POST", "/v1/repos", Some(&jwt_alice), Some("{}"))).await;
        let alice_id = alice_body["id"].as_str().unwrap().to_string();
        send(&a, req("POST", "/v1/repos", Some(&jwt_bob), Some("{}"))).await;

        // Alice sees only her repo.
        let (status, list) = send(&a, req("GET", "/v1/repos", Some(&jwt_alice), None)).await;
        assert_eq!(status, StatusCode::OK);
        let arr = list.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], alice_id);
    }

    // ── fork_repo ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn fork_repo_writable_sets_write_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let src = body["id"].as_str().unwrap().to_string();
        let (status, fork_body) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{src}/forks"),
                Some(ADMIN),
                Some(r#"{"readOnly":false}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(fork_body["id"].as_str().is_some());
        assert!(fork_body["token"].as_str().is_some());
    }

    #[tokio::test]
    async fn fork_repo_read_only_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let src = body["id"].as_str().unwrap().to_string();
        let (status, fork_body) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{src}/forks"),
                Some(ADMIN),
                Some(r#"{"readOnly":true}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(fork_body["id"].as_str().is_some());
    }

    #[tokio::test]
    async fn fork_repo_missing_source_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(
            &a,
            req(
                "POST",
                "/v1/repos/no-such-repo/forks",
                Some(ADMIN),
                Some("{}"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn fork_repo_non_owner_jwt_is_403() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        // alice creates a repo.
        let jwt_alice = user_jwt("alice");
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(&jwt_alice), Some("{}"))).await;
        let src = body["id"].as_str().unwrap().to_string();
        // bob tries to fork it → 403.
        let jwt_bob = user_jwt("bob");
        let (status, _) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{src}/forks"),
                Some(&jwt_bob),
                Some("{}"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // ── delete_repo ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_repo_missing_is_404() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (status, _) = send(
            &a,
            req("DELETE", "/v1/repos/no-such-repo", Some(ADMIN), None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_repo_with_dependent_fork_without_force_is_409() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, parent_body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let parent_id = parent_body["id"].as_str().unwrap().to_string();
        // Fork the parent.
        send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{parent_id}/forks"),
                Some(ADMIN),
                Some("{}"),
            ),
        )
        .await;
        // Delete without force → 409 fork_dependency.
        let (status, body) = send(
            &a,
            req(
                "DELETE",
                &format!("/v1/repos/{parent_id}"),
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "fork_dependency");
    }

    #[tokio::test]
    async fn delete_repo_with_force_orphans_fork_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, parent_body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let parent_id = parent_body["id"].as_str().unwrap().to_string();
        // Fork the parent.
        send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{parent_id}/forks"),
                Some(ADMIN),
                Some("{}"),
            ),
        )
        .await;
        // Delete with force=true → 200.
        let (status, body) = send(
            &a,
            req(
                "DELETE",
                &format!("/v1/repos/{parent_id}?force=true"),
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
    }

    #[tokio::test]
    async fn delete_repo_cascade_deletes_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        // Create parent.
        let (_, parent_body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let parent_id = parent_body["id"].as_str().unwrap().to_string();
        // Fork the parent (dependent fork).
        let (_, fork_body) = send(
            &a,
            req(
                "POST",
                &format!("/v1/repos/{parent_id}/forks"),
                Some(ADMIN),
                Some("{}"),
            ),
        )
        .await;
        let fork_id = fork_body["id"].as_str().unwrap().to_string();
        // cascade=true deletes both parent and fork.
        let (status, body) = send(
            &a,
            req(
                "DELETE",
                &format!("/v1/repos/{parent_id}?cascade=true"),
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let deleted = body["deleted"].as_array().unwrap();
        assert!(deleted.iter().any(|v| v == &parent_id));
        assert!(deleted.iter().any(|v| v == &fork_id));
    }

    #[tokio::test]
    async fn delete_repo_force_and_cascade_is_400() {
        let tmp = tempfile::tempdir().unwrap();
        let a = app(tmp.path());
        let (_, body) = send(&a, req("POST", "/v1/repos", Some(ADMIN), Some("{}"))).await;
        let id = body["id"].as_str().unwrap().to_string();
        let (status, err) = send(
            &a,
            req(
                "DELETE",
                &format!("/v1/repos/{id}?force=true&cascade=true"),
                Some(ADMIN),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(err["error"]["code"], "bad_request");
    }
}
