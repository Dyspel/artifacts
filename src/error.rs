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

    #[error("repo quota exceeded for {subject} (limit: {limit})")]
    QuotaExceeded { subject: String, limit: u64 },

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
            Error::RefConflict { branch, expected, current } => {
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
