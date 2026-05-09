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
    state.data.storage.create(&id_str)?;
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
        Some(&id_str),
        serde_json::json!({}),
        None,
    )
    .await;
    // Emit a status transition so subscribers pick up brand-new repos
    // without polling. "unknown → idle" matches the repo's initial
    // state in the Fleet UI's RepoStatus enum.
    state
        .observ
        .events
        .publish(crate::events::Event::status(&id_str, "unknown", "idle"));
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
    if !state.data.storage.exists(&source_id) {
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
    state.data.storage.fork(&source_id, &fork_id_str)?;
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
        Some(&fork_id_str),
        serde_json::json!({ "source_id": source_id, "read_only": read_only }),
        None,
    )
    .await;
    state
        .observ
        .events
        .publish(crate::events::Event::fork(&source_id, &fork_id_str));
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
            state.data.storage.delete(dep)?;
            let dep_typed = crate::ids::RepoId::try_from(dep.as_str())?;
            state.data.ownership.delete(&dep_typed).await?;
            state.data.alternates_cache.invalidate(dep);
            deleted.push(dep.clone());
        }
        crate::audit::record(
            &*state.observ.audit,
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

    state.data.storage.delete(&id)?;
    let id_typed = crate::ids::RepoId::try_from(id.as_str())?;
    state.data.ownership.delete(&id_typed).await?;
    state.data.alternates_cache.invalidate(&id);
    let mode = if force { "force" } else { "default" };
    crate::audit::record(
        &*state.observ.audit,
        "repo.delete",
        principal.audit_label(),
        Some(&id),
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
