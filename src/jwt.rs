//! JWT verification for Dyspel-signed (or compatible) bearer tokens.
//!
//! Dyspel issues tokens via `jsonwebtoken` (Node) with HS256 and claim
//! shape `{ userId, email, tier, iat, exp }`. We accept the same shape
//! here so Artifacts can run as a backend for Dyspel without an
//! additional credential-exchange hop.
//!
//! ## What we validate
//!
//! - Signature (HS256 via shared secret from `--jwt-secret` /
//!   `ARTIFACTS_JWT_SECRET`).
//! - `exp` — required; we deliberately reject tokens without expiry so a
//!   leaked admin-scope JWT has a bounded lifetime.
//! - Subject — accepted from either `userId` (Dyspel convention) or the
//!   standard `sub` claim. At least one must be present.
//!
//! Everything else — `email`, `tier`, `iat`, custom claims — is ignored
//! at this layer. Ownership checks happen later using only the subject.
//!
//! ## What we don't do
//!
//! - **No JWKS / no public-key rotation.** Pure shared-secret HS256 for
//!   the prototype. Swapping to RS256 + a JWKS endpoint is a localized
//!   change inside this module plus a config shape tweak, and is what a
//!   real multi-service deployment would want.
//! - **No audience check.** If Dyspel ever issues JWTs for other
//!   services using the same secret, those would incorrectly validate
//!   here. For a single-tenant prototype that shares a secret between
//!   two services this is acceptable; for anything more, add `aud` and
//!   require it.

use crate::error::{Error, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// A deserialized, *verified* Dyspel JWT.
///
/// The public API is `subject()` — everything else is intentionally
/// internal so downstream code can't accidentally trust an unverified
/// field.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    /// Dyspel's preferred subject claim.
    #[serde(default, rename = "userId")]
    user_id: Option<String>,

    /// Standard-JWT subject claim. Accepted as a fallback so tokens
    /// issued by services that follow RFC 7519 conventions work too.
    #[serde(default)]
    sub: Option<String>,
}

impl Claims {
    /// Return the subject string that identifies *who* this token speaks
    /// for. Used as the owner-principal downstream.
    pub fn subject(&self) -> Option<&str> {
        self.user_id.as_deref().or(self.sub.as_deref())
    }
}

/// Verify an HS256 JWT against `secret`. Returns the decoded claims on
/// success. Any failure — bad signature, expired, missing subject — is
/// collapsed into `Error::Unauthorized` so the error surface doesn't
/// leak *why* it failed.
pub fn verify(secret: &str, token: &str) -> Result<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    // Require `exp`. jsonwebtoken's default already validates exp when
    // present, but it doesn't *require* the claim to be set. We do.
    validation.set_required_spec_claims(&["exp"]);
    // We don't check `aud`, `iss`, or `nbf` — Dyspel doesn't set them.
    // This means we'd happily accept a JWT that was issued for some
    // *other* service using the same secret. Acceptable for a
    // single-secret prototype; documented in the module header.
    validation.validate_aud = false;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| Error::Unauthorized)?;

    // Must have *something* we can identify the caller by.
    if data.claims.subject().is_none() {
        return Err(Error::Unauthorized);
    }
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sign(secret: &str, payload: serde_json::Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &payload,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn future_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    #[test]
    fn accepts_valid_dyspel_shape() {
        let tok = sign(
            "sec",
            json!({ "userId": "u-42", "email": "a@b", "tier": "lite", "exp": future_ts() }),
        );
        let claims = verify("sec", &tok).unwrap();
        assert_eq!(claims.subject(), Some("u-42"));
    }

    #[test]
    fn accepts_standard_sub_claim() {
        let tok = sign("sec", json!({ "sub": "u-17", "exp": future_ts() }));
        let claims = verify("sec", &tok).unwrap();
        assert_eq!(claims.subject(), Some("u-17"));
    }

    #[test]
    fn prefers_userId_over_sub() {
        let tok = sign(
            "sec",
            json!({ "userId": "primary", "sub": "fallback", "exp": future_ts() }),
        );
        let claims = verify("sec", &tok).unwrap();
        assert_eq!(claims.subject(), Some("primary"));
    }

    #[test]
    fn rejects_wrong_secret() {
        let tok = sign("right", json!({ "userId": "u", "exp": future_ts() }));
        let r = verify("wrong", &tok);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn rejects_expired() {
        // jsonwebtoken's default Validation applies a 60s leeway on `exp`
        // — a 60-second-old token is still considered valid. Go well
        // past that (1 hour) so the rejection is unambiguous, regardless
        // of clock skew in CI.
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;
        let tok = sign("sec", json!({ "userId": "u", "exp": past }));
        let r = verify("sec", &tok);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn rejects_missing_exp() {
        // No `exp` claim at all — we require one so a leaked token has a
        // bounded lifetime.
        let tok = sign("sec", json!({ "userId": "u" }));
        let r = verify("sec", &tok);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn rejects_no_subject() {
        // exp present, but no userId or sub — we can't identify the caller.
        let tok = sign("sec", json!({ "email": "a@b", "exp": future_ts() }));
        let r = verify("sec", &tok);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn rejects_malformed_token() {
        assert!(matches!(verify("sec", "not-a-jwt"), Err(Error::Unauthorized)));
    }
}
