//! Auth for the HTTP surface.
//!
//! Two schemes coexist:
//!
//! **Git endpoints** (`/git/:id.git/*`) — HTTP Basic with username `x`
//! and a repo-scoped token as the password. Matches how git clients embed
//! tokens in `https://x:TOKEN@host/...` URLs. The token is looked up via
//! `TokenStore` and carries a `(repo_id, scope)` binding.
//!
//! **REST endpoints** (`/v1/*`) — `Authorization: Bearer <token>`. The
//! bearer can be one of two things:
//!
//! - The process-wide **admin token** (CLI-provided or auto-generated
//!   at startup). Grants `Principal::Admin`, which bypasses ownership
//!   checks. Meant for bootstrap, CLI tooling, and anywhere that needs
//!   to speak for every user.
//! - A **JWT** signed with the configured JWT secret (see `crate::jwt`).
//!   Grants `Principal::User { subject }`, and ownership-scoped REST
//!   ops only succeed when `subject` matches the repo's recorded owner.
//!
//! The JWT path is off when no `--jwt-secret` is configured — callers
//! must use the admin token in that mode. This is the "single-user
//! prototype" default and keeps the auth surface tiny until Dyspel (or
//! whoever else) is actually integrated.

use crate::{
    error::{Error, Result},
    tokens::{Scope, TokenRecord, TokenStore},
};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::STANDARD, Engine};
use subtle::ConstantTimeEq;

/// Who the server thinks is making a request. The result of authorizing
/// a REST call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// The process-wide admin. No ownership check applies.
    Admin,
    /// A user authenticated via JWT. Identified by the verified subject.
    User { subject: String },
}

impl Principal {
    /// The subject string to record as the owner when a user creates a
    /// new repo. `Admin` has no meaningful subject — callers that want
    /// an owner field must use a JWT path. Returns `None` for admin.
    pub fn subject(&self) -> Option<&str> {
        match self {
            Principal::Admin => None,
            Principal::User { subject } => Some(subject),
        }
    }

    /// Stable label suitable for an audit-log `actor=…` field.
    /// Always emits something usable: the literal `"admin"` for
    /// the bootstrap principal, the JWT subject for users. Never
    /// returns the bytes of an actual token (we never have one
    /// in hand at this layer — by the time `Principal` exists
    /// the secret has already been consumed by `authorize_rest`).
    pub fn audit_label(&self) -> &str {
        match self {
            Principal::Admin => "admin",
            Principal::User { subject } => subject,
        }
    }
}

/// Extract and decode an HTTP Basic token from request headers. Returns the
/// raw token (password half). Missing or malformed headers ->
/// UnauthorizedBasic (triggers the WWW-Authenticate challenge that git
/// clients need to resend their credentials).
pub fn basic_token(headers: &HeaderMap) -> Result<String> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(Error::UnauthorizedBasic)?
        .to_str()
        .map_err(|_| Error::UnauthorizedBasic)?;
    let b64 = value
        .strip_prefix("Basic ")
        .ok_or(Error::UnauthorizedBasic)?;
    let decoded = STANDARD.decode(b64).map_err(|_| Error::UnauthorizedBasic)?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| Error::UnauthorizedBasic)?;
    // username:password — we accept any username; the password is the token.
    let (_user, pass) = decoded.split_once(':').ok_or(Error::UnauthorizedBasic)?;
    Ok(pass.to_string())
}

/// Authorize a git request for `repo_id` at `required` scope.
///
/// `async` because `TokenStore::lookup` is async (see tokens module for
/// why). `.await` is cheap in the common path; the only real I/O is the
/// SQLite row read in `SqliteTokenStore`, which takes microseconds.
pub async fn authorize_git(
    tokens: &dyn TokenStore,
    headers: &HeaderMap,
    repo_id: &str,
    required: Scope,
) -> Result<TokenRecord> {
    let token = basic_token(headers)?;
    let record = tokens
        .lookup(&token)
        .await?
        .ok_or(Error::UnauthorizedBasic)?;
    if record.repo_id != repo_id {
        return Err(Error::Forbidden("token not valid for this repo"));
    }
    if required == Scope::Write && record.scope != Scope::Write {
        return Err(Error::Forbidden("token is read-only"));
    }
    Ok(record)
}

/// Authorize a REST request. Returns the resolved `Principal`.
///
/// The header is `Authorization: Bearer <token>`. The bearer is tried in
/// order:
///
/// 1. **Admin token.** If it matches the configured admin token (constant-
///    time compare via `subtle::ConstantTimeEq`), the principal is
///    `Admin`. A naive `!=` on `&str` short-circuits and leaks byte-at-a-
///    time timing; the `ct_eq` version doesn't.
/// 2. **JWT.** If a JWT secret is configured, we verify the token as an
///    HS256 JWT (see `crate::jwt`). On success, the verified subject is
///    the principal.
///
/// Either path producing success returns `Ok`. Neither path matching is
/// `Error::Unauthorized`. We deliberately try admin-first so that a
/// well-known operational token keeps working even if a JWT misconfig
/// breaks the JWT path.
///
/// Length-gating the admin compare leaks the admin token's length, but
/// that length is already printed to stderr on startup — not a secret.
pub fn authorize_rest(
    headers: &HeaderMap,
    admin_token: &str,
    jwt_secret: Option<&str>,
) -> Result<Principal> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(Error::Unauthorized)?
        .to_str()
        .map_err(|_| Error::Unauthorized)?;
    let presented = value.strip_prefix("Bearer ").ok_or(Error::Unauthorized)?;

    // Admin path: constant-time compare, with length-gating so ct_eq
    // doesn't immediately fail on length mismatch.
    if presented.len() == admin_token.len()
        && presented
            .as_bytes()
            .ct_eq(admin_token.as_bytes())
            .unwrap_u8()
            == 1
    {
        return Ok(Principal::Admin);
    }

    // JWT path: only enabled when a secret was configured at startup.
    if let Some(secret) = jwt_secret {
        if let Ok(claims) = crate::jwt::verify(secret, presented) {
            if let Some(sub) = claims.subject() {
                return Ok(Principal::User {
                    subject: sub.to_string(),
                });
            }
        }
    }

    Err(Error::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn headers(auth: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = auth {
            h.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn sign_jwt(secret: &str, subject_key: &str, subject_value: &str) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({ subject_key: subject_value, "exp": exp }),
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn admin_token_yields_admin_principal() {
        let p = authorize_rest(&headers(Some("Bearer sekret")), "sekret", None).unwrap();
        assert_eq!(p, Principal::Admin);
    }

    #[test]
    fn valid_jwt_yields_user_principal() {
        let jwt = sign_jwt("shared-secret", "userId", "u-42");
        let p = authorize_rest(
            &headers(Some(&format!("Bearer {jwt}"))),
            "admin-tok",
            Some("shared-secret"),
        )
        .unwrap();
        assert_eq!(
            p,
            Principal::User {
                subject: "u-42".to_string()
            }
        );
    }

    #[test]
    fn jwt_disabled_when_no_secret() {
        let jwt = sign_jwt("shared-secret", "userId", "u-42");
        // A valid JWT should NOT authorize when the server has no secret
        // configured — otherwise an attacker who knows what secret the
        // Dyspel instance uses could bypass by turning off our --jwt-secret.
        let r = authorize_rest(&headers(Some(&format!("Bearer {jwt}"))), "admin-tok", None);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn jwt_wrong_secret_rejects() {
        let jwt = sign_jwt("real-secret", "userId", "u");
        let r = authorize_rest(
            &headers(Some(&format!("Bearer {jwt}"))),
            "admin-tok",
            Some("wrong-secret"),
        );
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn missing_header_rejects() {
        let r = authorize_rest(&headers(None), "sekret", None);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn wrong_scheme_rejects() {
        // A git-client-style Basic credential should not authorize REST,
        // even if the password half matches the admin token.
        let b64 = STANDARD.encode("x:sekret");
        let r = authorize_rest(&headers(Some(&format!("Basic {b64}"))), "sekret", None);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn wrong_admin_token_rejects() {
        let r = authorize_rest(&headers(Some("Bearer wrong")), "right", None);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn admin_length_mismatch_rejects() {
        assert!(matches!(
            authorize_rest(&headers(Some("Bearer short")), "much-longer-token", None),
            Err(Error::Unauthorized)
        ));
    }
}
