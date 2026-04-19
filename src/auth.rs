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
pub fn authorize_git(
    tokens: &dyn TokenStore,
    headers: &HeaderMap,
    repo_id: &str,
    required: Scope,
) -> Result<TokenRecord> {
    let token = basic_token(headers)?;
    let record = tokens
        .lookup(&token)?
        .ok_or(Error::UnauthorizedBasic)?;
    if record.repo_id != repo_id {
        return Err(Error::Forbidden("token not valid for this repo"));
    }
    if required == Scope::Write && record.scope != Scope::Write {
        return Err(Error::Forbidden("token is read-only"));
    }
    Ok(record)
}

/// Authorize a REST admin request. M0: single shared admin token via bearer.
pub fn authorize_admin(headers: &HeaderMap, admin_token: &str) -> Result<()> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(Error::Unauthorized)?
        .to_str()
        .map_err(|_| Error::Unauthorized)?;
    let presented = value
        .strip_prefix("Bearer ")
        .ok_or(Error::Unauthorized)?;
    if presented != admin_token {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
