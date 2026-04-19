//! Auth for git endpoints: HTTP Basic with username `x` and the token as the
//! password, matching how clients embed tokens in `https://x:TOKEN@host/...`
//! URLs.
//!
//! Auth for REST endpoints: a single static admin token for M0. M4 replaces
//! this with scoped account credentials.

use crate::{
    error::{Error, Result},
    tokens::{Scope, TokenRecord, TokenStore},
};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::STANDARD, Engine};
use subtle::ConstantTimeEq;

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
    let b64 = value.strip_prefix("Basic ").ok_or(Error::UnauthorizedBasic)?;
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

/// Authorize a REST admin request. Single shared admin token via bearer.
///
/// The comparison is constant-time in the length of the expected token:
/// `subtle::ConstantTimeEq` returns `Choice(0)` or `Choice(1)` without
/// short-circuiting on the first mismatching byte. A naive `!=` on
/// `&str` would leak how many leading bytes an attacker got right,
/// letting them recover the token byte-by-byte over many requests.
///
/// Length is still observable via timing (longer input takes marginally
/// longer to hash/compare), but that just leaks *roughly how long* the
/// admin token is, which isn't load-bearing — the entropy is still in
/// the bytes themselves.
pub fn authorize_admin(headers: &HeaderMap, admin_token: &str) -> Result<()> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(Error::Unauthorized)?
        .to_str()
        .map_err(|_| Error::Unauthorized)?;
    let presented = value
        .strip_prefix("Bearer ")
        .ok_or(Error::Unauthorized)?;

    // ConstantTimeEq requires the slices to be the same length, otherwise
    // it returns Choice(0) immediately. We check length first to give a
    // deterministic fail on short/long inputs; the length check itself is
    // not secret-dependent (the admin token length is known to anyone who
    // reads the server's startup log), so no timing concern there.
    if presented.len() != admin_token.len() {
        return Err(Error::Unauthorized);
    }
    if presented.as_bytes().ct_eq(admin_token.as_bytes()).unwrap_u8() != 1 {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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

    #[test]
    fn authorize_admin_accepts_correct_bearer() {
        assert!(authorize_admin(&headers(Some("Bearer sekret")), "sekret").is_ok());
    }

    #[test]
    fn authorize_admin_rejects_missing_header() {
        let r = authorize_admin(&headers(None), "sekret");
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn authorize_admin_rejects_wrong_scheme() {
        // Git-style Basic with token-as-password should not authorize admin.
        let b64 = STANDARD.encode("x:sekret");
        let r = authorize_admin(
            &headers(Some(&format!("Basic {b64}"))),
            "sekret",
        );
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn authorize_admin_rejects_wrong_token() {
        let r = authorize_admin(&headers(Some("Bearer wrong")), "right");
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn authorize_admin_rejects_different_length() {
        // Ensure the length check returns Unauthorized (not some odd
        // success path) for an input shorter/longer than the expected.
        assert!(matches!(
            authorize_admin(&headers(Some("Bearer shorter")), "long-admin-token"),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            authorize_admin(&headers(Some("Bearer very-much-longer")), "short"),
            Err(Error::Unauthorized)
        ));
    }
}
