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
        expected: Option<String>,
        current: Option<String>,
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

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::Other(anyhow::Error::from(e))
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
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
            }
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
            }
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
            }
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
            }
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
            }
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
            }
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
            }
            Error::Io(_) | Error::Other(_) => {
                tracing::error!(error = %self, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let body = Json(json!({ "error": { "code": code, "message": self.to_string() } }));
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
        for (k, val) in parts.headers.iter() {
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
        let resp = Error::RefConflict {
            branch: "main".to_string(),
            expected: Some("aaaa".to_string()),
            current: Some("bbbb".to_string()),
        }
        .into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 409);
        assert_eq!(v["body"]["error"]["code"], "ref_conflict");
        assert_eq!(v["body"]["error"]["branch"], "main");
        assert_eq!(v["body"]["error"]["expected"], "aaaa");
        assert_eq!(v["body"]["error"]["current"], "bbbb");
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
    async fn other_returns_500_with_internal_code() {
        let resp = Error::Other(anyhow::anyhow!("boom")).into_response();
        let v = body_json(resp).await;
        assert_eq!(v["status"], 500);
        assert_eq!(v["body"]["error"]["code"], "internal");
    }
}
