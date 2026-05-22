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
            source_id: state.data.alternates_cache.lookup(&repos_dir, &r.id),
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

    let Some(row) = state.data.ownership.get_row(&id).await? else {
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
            id,
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
    if !state.data.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    let preview = crate::gc::preview(
        &state.cfg.repos_dir(),
        &id,
        &state.data.alternates_cache,
        &*state.data.objects,
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
    state.authn.rate_limit.check(
        &crate::auth::Principal::Admin,
        crate::rate_limit::Class::Default,
    )?;
    if !state.data.storage.exists(&id) {
        return Err(Error::RepoNotFound(id));
    }
    let result = crate::gc::run(
        &state.cfg.repos_dir(),
        &id,
        &state.data.alternates_cache,
        q.min_age_secs.unwrap_or(7200),
        &*state.data.objects,
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
            }
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
