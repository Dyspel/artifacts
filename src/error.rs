//! The crate's error type and its HTTP-response contract.
//!
//! [`Error`] is the single enum every fallible operation returns (via
//! the [`Result`] alias), and its [`IntoResponse`] impl is the
//! authoritative map from error to HTTP status + JSON body. Two
//! invariants are worth knowing before touching this module:
//!
//! - **5xx bodies are redacted.** Server-error variants log their full
//!   `Display` chain via `tracing::error!` but emit only
//!   `{"error":{"code":"internal","message":"internal"}}` on the wire,
//!   so filesystem paths, gix internals, and `anyhow` context never
//!   leak to a caller. 4xx variants keep their (user-input-shaped)
//!   message because it's already safe to echo.
//! - **Typed causes are preserved where they change behavior.**
//!   [`Error::Db`] keeps the underlying `rusqlite::Error` as its
//!   `source()`, which lets a transient busy/locked database map to a
//!   503 + `Retry-After` instead of an opaque 500.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("repository not found: {0}")]
    RepoNotFound(String),

    #[error("repository already exists: {0}")]
    RepoExists(String),

    #[error("invalid repo id: {0}")]
    InvalidRepoId(String),

    #[error("unauthorized")]
    Unauthorized,

    /// Same as Unauthorized, but emits `WWW-Authenticate: Basic realm="..."`
    /// so git clients know to retry with credentials from the URL. Git will
    /// otherwise give up after the first 401.
    #[error("unauthorized")]
    UnauthorizedBasic,

    #[error("forbidden: {0}")]
    Forbidden(&'static str),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("ref conflict on branch {branch}")]
    RefConflict {
        branch: String,
        expected: Option<crate::ids::Oid>,
        current: Option<crate::ids::Oid>,
    },

    #[error("merge conflict on branch {target_branch} ({} path{})", conflict_paths.len(), if conflict_paths.len() == 1 { "" } else { "s" })]
    MergeConflict {
        target_branch: String,
        source_branch: String,
        conflict_paths: Vec<String>,
    },

    #[error("repo {repo_id} has {} dependent fork{}", forks.len(), if forks.len() == 1 { "" } else { "s" })]
    ForkDependency {
        /// The repo that was the target of the delete.
        repo_id: String,
        /// IDs of repos whose alternates source is `repo_id`. Deleting
        /// `repo_id` would orphan their object storage, so the delete
        /// is refused unless the caller passes `?force=true`.
        forks: Vec<String>,
    },

    #[error("repo quota exceeded for {subject} (limit: {limit})")]
    QuotaExceeded { subject: String, limit: u64 },

    #[error("repo {repo_id} byte quota exceeded ({bytes_used} ≥ {limit})")]
    RepoByteQuotaExceeded {
        repo_id: String,
        bytes_used: u64,
        limit: u64,
    },

    #[error("rate limited; retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Pack-parser failure. Covers everything the hand-rolled
    /// `native_pack::parse` family rejects: short headers, wrong
    /// magic, unknown object kinds, zlib errors, delta-resolution
    /// failures. Previously every site produced `Error::Other(anyhow!())`
    /// with the same shape — one variant centralizes the category
    /// without losing any per-site detail since the String carries it.
    #[error("pack parse: {0}")]
    PackParse(String),

    /// gix operation failure. Wraps the common
    /// `repo.find_object(...)` / `repo.write_blob(...)` / `gix::open(...)`
    /// error sites. Each call site formats the operation + path/oid
    /// context into the String; the variant just names the category
    /// so a 5xx with `"code":"gix"` is recognizable in logs.
    #[error("gix: {0}")]
    GixError(String),

    /// A SQLite operation failed. Unlike the other backend errors this
    /// keeps the underlying `rusqlite::Error` as its `source()` (via
    /// `#[from]`) rather than flattening it into a `String`/`anyhow`,
    /// so callers and tests can inspect the cause and the response layer
    /// can tell a transient busy/locked database (→ 503 + Retry-After)
    /// apart from a genuine internal failure (→ 500).
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// True when a SQLite failure is transient (the database was
    /// momentarily busy or locked under concurrent writers) and the
    /// client should retry rather than treat it as a hard error.
    fn is_retryable_db(&self) -> bool {
        matches!(
            self,
            Error::Db(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                )
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::Other(anyhow::Error::from(e))
    }
}

impl From<r2d2::Error> for Error {
    fn from(e: r2d2::Error) -> Self {
        Error::Other(anyhow::Error::from(e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Other(anyhow::Error::from(e))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Other(anyhow::Error::from(e))
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(e: aes_gcm::Error) -> Self {
        // aes_gcm::Error is a unit struct with no Display detail, so
        // anyhow::Error::from would yield a useless message. Wrap
        // with a hard-coded context line — every caller that goes
        // through `?` here knows it's an AES seal/unseal failure.
        Error::Other(anyhow::anyhow!("aes-gcm operation failed: {e}"))
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Error::RepoNotFound(_) => (StatusCode::NOT_FOUND, "repo_not_found"),
            Error::RepoExists(_) => (StatusCode::CONFLICT, "repo_exists"),
            Error::InvalidRepoId(_) => (StatusCode::BAD_REQUEST, "invalid_repo_id"),
            Error::Unauthorized | Error::UnauthorizedBasic => {
                (StatusCode::UNAUTHORIZED, "unauthorized")
            },
            Error::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            Error::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Error::QuotaExceeded { subject, limit } => {
                // 429 with a dedicated code so clients can tell
                // "you've hit your quota" apart from "you're being
                // rate-limited." Includes the limit so the client UI
                // can surface it.
                metrics::counter!("artifacts_quota_exceeded_total").increment(1);
                let body = Json(json!({
                    "error": {
                        "code": "quota_exceeded",
                        "message": format!("repo quota exceeded for {subject}"),
                        "subject": subject,
                        "limit": limit,
                    }
                }));
                return (StatusCode::TOO_MANY_REQUESTS, body).into_response();
            },
            Error::RepoByteQuotaExceeded {
                repo_id,
                bytes_used,
                limit,
            } => {
                // 413 Payload Too Large — the next push/commit would
                // exceed the per-repo byte quota. Distinct counter from
                // the per-user repo-count quota (`quota_exceeded`) so
                // dashboards can chart them separately.
                metrics::counter!("artifacts_repo_byte_quota_exceeded_total").increment(1);
                let body = Json(json!({
                    "error": {
                        "code": "repo_byte_quota_exceeded",
                        "message": format!("repo {repo_id} byte quota exceeded ({bytes_used} >= {limit})"),
                        "repoId": repo_id,
                        "bytesUsed": bytes_used,
                        "limit": limit,
                    }
                }));
                return (StatusCode::PAYLOAD_TOO_LARGE, body).into_response();
            },
            Error::RateLimited { retry_after_secs } => {
                // 429 + Retry-After. Distinct `code` from `quota_exceeded`
                // so clients retry (rate-limited is transient) vs. surface
                // an error (quota is persistent).
                metrics::counter!("artifacts_rate_limited_total").increment(1);
                let body = Json(json!({
                    "error": {
                        "code": "rate_limited",
                        "message": format!("rate limited; retry after {retry_after_secs}s"),
                        "retryAfter": retry_after_secs,
                    }
                }));
                let mut resp = (StatusCode::TOO_MANY_REQUESTS, body).into_response();
                if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                    resp.headers_mut().insert(header::RETRY_AFTER, v);
                }
                return resp;
            },
            Error::RefConflict {
                branch,
                expected,
                current,
            } => {
                // Dedicated 409 with the current + expected SHAs so callers
                // can re-read and retry without a second round trip.
                let body = Json(json!({
                    "error": {
                        "code": "ref_conflict",
                        "message": format!("ref conflict on branch {branch}"),
                        "branch": branch,
                        "expected": expected,
                        "current": current,
                    }
                }));
                return (StatusCode::CONFLICT, body).into_response();
            },
            Error::ForkDependency { repo_id, forks } => {
                // 409 with the dependent fork ids so callers can decide
                // whether to delete those first or re-issue with
                // ?force=true. Mirrors the shape of MergeConflict /
                // RefConflict — explicit code + structured payload.
                let body = Json(json!({
                    "error": {
                        "code": "fork_dependency",
                        "message": format!(
                            "repo {repo_id} has {} dependent fork{}",
                            forks.len(),
                            if forks.len() == 1 { "" } else { "s" },
                        ),
                        "repoId": repo_id,
                        "forks": forks,
                    }
                }));
                return (StatusCode::CONFLICT, body).into_response();
            },
            Error::MergeConflict {
                target_branch,
                source_branch,
                conflict_paths,
            } => {
                // 409 with the paths that failed to merge so the caller can
                // surface them directly in a UI or resolve server-side by
                // re-issuing with explicit content.
                let body = Json(json!({
                    "error": {
                        "code": "merge_conflict",
                        "message": format!(
                            "merge conflict: {} → {} ({} conflicting path{})",
                            source_branch,
                            target_branch,
                            conflict_paths.len(),
                            if conflict_paths.len() == 1 { "" } else { "s" },
                        ),
                        "sourceBranch": source_branch,
                        "targetBranch": target_branch,
                        "conflicts": conflict_paths,
                    }
                }));
                return (StatusCode::CONFLICT, body).into_response();
            },
            Error::PackParse(_) => {
                // 400 — the pack body the client sent didn't parse.
                // Distinct code so dashboards can chart bad-push rates
                // separately from genuine 5xxs.
                tracing::warn!(error = %self, "pack parse failure");
                (StatusCode::BAD_REQUEST, "pack_parse")
            },
            Error::Db(_) if self.is_retryable_db() => {
                // Transient: the database was busy/locked under concurrent
                // writers. A 503 + Retry-After tells the client to back
                // off and retry rather than surfacing a hard 500. The
                // cause stays in logs, not on the wire.
                tracing::warn!(error = %self, "database busy/locked; advising retry");
                let body = Json(json!({
                    "error": {
                        "code": "db_busy",
                        "message": "database temporarily busy, retry shortly",
                    }
                }));
                let mut resp = (StatusCode::SERVICE_UNAVAILABLE, body).into_response();
                resp.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return resp;
            },
            Error::Io(_) | Error::Other(_) | Error::GixError(_) | Error::Db(_) => {
                tracing::error!(error = %self, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            },
        };
        // 5xx responses MUST NOT echo the underlying Display chain to
        // the wire. The chain leaks file paths (Io), anyhow `.context()`
        // strings (Other), and gix internals (GixError) — enough to
        // help an attacker probe filesystem layout or feature flags.
        // The full Display already went to `tracing::error!` above, so
        // operators see the detail in logs while the wire surface stays
        // opaque. 4xx responses keep their Display text because the
        // content is already user-input-shaped (echoed repo ids, pack
        // parse messages bounded by the parser's vocabulary, etc.).
        let message = if status.is_server_error() {
            "internal".to_string()
        } else {
            self.to_string()
        };
        let body = Json(json!({ "error": { "code": code, "message": message } }));
        let mut resp = (status, body).into_response();
        if matches!(self, Error::UnauthorizedBasic) {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"artifacts\""),
            );
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    //! Pin the HTTP-response shapes that clients depend on. These are
    //! public contracts — `code` strings, response status, custom
    //! headers — so a refactor that quietly renames `rate_limited` →
    //! `RATE_LIMITED` or drops Retry-After breaks every caller. Smoke
    //! catches them eventually; unit-pinning catches them in cargo test.
    use super::*;

    async fn body_json(resp: Response) -> serde_json::Value {
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut headers = serde_json::Map::new();
        for (k, val) in &parts.headers {
            headers.insert(k.as_str().to_string(), json!(val.to_str().unwrap_or("")));
        }
        json!({
            "status": parts.status.as_u16(),
            "body": v,
            "headers": serde_json::Value::Object(headers),
        })
    }

    #[tokio::test]
    async fn rate_limited_emits_429_and_retry_after_header() {
        let resp = Error::RateLimited {
            retry_after_secs: 30,
        }
        .into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 429);
        assert_eq!(v["headers"]["retry-after"], "30");
        assert_eq!(v["body"]["error"]["code"], "rate_limited");
        assert_eq!(v["body"]["error"]["retryAfter"], 30);
    }

    #[tokio::test]
    async fn db_busy_emits_503_with_retry_after() {
        // A transient SQLITE_BUSY (result code 5) must surface as a
        // 503 + Retry-After so the client backs off and retries, not a
        // hard 500.
        let busy = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(5), None);
        let resp = Error::from(busy).into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 503);
        assert_eq!(v["headers"]["retry-after"], "1");
        assert_eq!(v["body"]["error"]["code"], "db_busy");
    }

    #[tokio::test]
    async fn db_non_transient_emits_redacted_500() {
        // A non-busy SQLite error is a genuine internal failure: 500
        // with the body redacted to "internal" (the cause goes to logs).
        let resp = Error::from(rusqlite::Error::QueryReturnedNoRows).into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 500);
        assert_eq!(v["body"]["error"]["code"], "internal");
        assert_eq!(v["body"]["error"]["message"], "internal");
    }

    #[test]
    fn db_error_preserves_rusqlite_source() {
        // Unlike GixError(String)/PackParse(String), Error::Db keeps the
        // typed cause reachable via std::error::Error::source().
        use std::error::Error as _;
        let err = Error::from(rusqlite::Error::QueryReturnedNoRows);
        let src = err.source().expect("Db must expose its source");
        assert!(
            src.downcast_ref::<rusqlite::Error>().is_some(),
            "source must downcast back to rusqlite::Error"
        );
    }

    #[tokio::test]
    async fn quota_exceeded_emits_429_with_limit_in_body() {
        let resp = Error::QuotaExceeded {
            subject: "alice".to_string(),
            limit: 100,
        }
        .into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 429);
        // Distinct `code` from rate_limited so clients can branch:
        // quota is persistent, rate-limit is transient.
        assert_eq!(v["body"]["error"]["code"], "quota_exceeded");
        assert_eq!(v["body"]["error"]["subject"], "alice");
        assert_eq!(v["body"]["error"]["limit"], 100);
        assert!(v["headers"].get("retry-after").is_none());
    }

    #[tokio::test]
    async fn ref_conflict_emits_409_with_expected_and_current() {
        let aaaa = crate::ids::Oid::try_from("a".repeat(40).as_str()).unwrap();
        let bbbb = crate::ids::Oid::try_from("b".repeat(40).as_str()).unwrap();
        let resp = Error::RefConflict {
            branch: "main".to_string(),
            expected: Some(aaaa.clone()),
            current: Some(bbbb.clone()),
        }
        .into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 409);
        assert_eq!(v["body"]["error"]["code"], "ref_conflict");
        assert_eq!(v["body"]["error"]["branch"], "main");
        assert_eq!(v["body"]["error"]["expected"], aaaa.as_str());
        assert_eq!(v["body"]["error"]["current"], bbbb.as_str());
    }

    #[tokio::test]
    async fn fork_dependency_emits_409_with_dependent_fork_ids() {
        let resp = Error::ForkDependency {
            repo_id: "r1".to_string(),
            forks: vec!["f1".to_string(), "f2".to_string()],
        }
        .into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 409);
        assert_eq!(v["body"]["error"]["code"], "fork_dependency");
        assert_eq!(v["body"]["error"]["repoId"], "r1");
        assert_eq!(v["body"]["error"]["forks"], json!(["f1", "f2"]));
    }

    #[tokio::test]
    async fn unauthorized_basic_emits_www_authenticate_header() {
        let resp = Error::UnauthorizedBasic.into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 401);
        // Critical for git clients — without this header git gives up
        // after the first 401 instead of retrying with URL credentials.
        assert_eq!(
            v["headers"]["www-authenticate"],
            "Basic realm=\"artifacts\""
        );
    }

    #[tokio::test]
    async fn unauthorized_omits_www_authenticate_header() {
        // The non-Basic variant must NOT emit WWW-Authenticate; clients
        // that get 401 without the header know it isn't a git-style
        // challenge and won't retry. The split between the two variants
        // is the contract — pin it.
        let resp = Error::Unauthorized.into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 401);
        assert!(v["headers"].get("www-authenticate").is_none());
    }

    #[tokio::test]
    async fn other_returns_500_with_internal_code_and_redacted_message() {
        // The underlying anyhow chain ("boom" + any added context)
        // must NOT reach the wire — operators see it in tracing::error
        // logs, callers see only "internal".
        let resp = Error::Other(anyhow::anyhow!("boom: secret /etc/shadow")).into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 500);
        assert_eq!(v["body"]["error"]["code"], "internal");
        assert_eq!(v["body"]["error"]["message"], "internal");
        // Belt-and-suspenders: the leaky bits must not be in the body
        // anywhere, including any future fields we might add.
        let serialized = serde_json::to_string(&v["body"]).unwrap();
        assert!(
            !serialized.contains("boom") && !serialized.contains("shadow"),
            "5xx body must not contain underlying error detail: {serialized}"
        );
    }

    #[tokio::test]
    async fn io_returns_500_with_internal_code_and_redacted_message() {
        // An Io error typically wraps a path; that path must not
        // reach the wire on a 5xx.
        let inner = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found: /var/secret/passwords.db",
        );
        let resp = Error::Io(inner).into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 500);
        assert_eq!(v["body"]["error"]["code"], "internal");
        assert_eq!(v["body"]["error"]["message"], "internal");
        let serialized = serde_json::to_string(&v["body"]).unwrap();
        assert!(
            !serialized.contains("/var/secret") && !serialized.contains("passwords.db"),
            "Io 5xx body must not contain the leaked path: {serialized}"
        );
    }

    #[tokio::test]
    async fn gix_returns_500_with_internal_code_and_redacted_message() {
        // GixError wraps a String that call sites build from gix
        // internals (pack offsets, ODB paths, oid lookups). The wire
        // must say only "internal".
        let resp =
            Error::GixError("find_object(deadbeef): odb at /data/repos/r1.git missing".to_string())
                .into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 500);
        assert_eq!(v["body"]["error"]["code"], "internal");
        assert_eq!(v["body"]["error"]["message"], "internal");
        let serialized = serde_json::to_string(&v["body"]).unwrap();
        assert!(
            !serialized.contains("/data/repos") && !serialized.contains("deadbeef"),
            "GixError 5xx body must not contain gix internals: {serialized}"
        );
    }

    #[tokio::test]
    async fn pack_parse_returns_400_and_keeps_user_facing_message() {
        // 4xx variants are NOT redacted — their Display is already
        // user-input-shaped and aids debugging at the callsite. Pin
        // that PackParse keeps its message so the redaction logic
        // doesn't over-broaden by status family.
        let resp = Error::PackParse("expected PACK magic, got DEAD".to_string()).into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 400);
        assert_eq!(v["body"]["error"]["code"], "pack_parse");
        assert!(
            v["body"]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("expected PACK magic"),
            "4xx message must surface the user-input-shaped detail"
        );
    }

    #[tokio::test]
    async fn bad_request_keeps_user_facing_message() {
        // Same property as pack_parse — BadRequest is the other
        // common 4xx that lets callers know what they sent wrong.
        let resp = Error::BadRequest("missing field: branch".to_string()).into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 400);
        assert_eq!(v["body"]["error"]["code"], "bad_request");
        assert_eq!(
            v["body"]["error"]["message"].as_str().unwrap(),
            "bad request: missing field: branch"
        );
    }
}
