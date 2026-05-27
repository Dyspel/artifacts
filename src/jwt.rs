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
//! - Algorithm allow-list — `Validation::new(Algorithm::HS256)` seeds
//!   `algorithms` with `[HS256]`. `jsonwebtoken` v9 has no
//!   `Algorithm::None` variant at all (tokens claiming `alg: none`
//!   fail to decode), and the decode path rejects any algorithm not
//!   in the allow-list, so asymmetric-via-HMAC confusion isn't
//!   possible against this configuration.
//! - `exp` — required; we deliberately reject tokens without expiry so a
//!   leaked admin-scope JWT has a bounded lifetime.
//! - `nbf` — when present, the token must already be valid. The default
//!   60-second leeway covers clock skew between issuer and verifier.
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
//! - **No audience or issuer check by default.** When `--jwt-expected-aud`
//!   / `--jwt-expected-iss` are unset, any JWT verifying against the
//!   shared secret authorizes — including JWTs originally issued for a
//!   sibling service that shares the secret. K2 added the per-deploy
//!   strict-mode flags: setting either pins the corresponding claim,
//!   rejecting tokens whose `aud` / `iss` doesn't match (and rejecting
//!   tokens missing the claim altogether). Production deployments that
//!   share a JWT secret across services SHOULD set both.

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

/// Verify an HS256 JWT against `secret`, optionally enforcing
/// audience / issuer claims. Returns the decoded claims on success.
/// Any failure — bad signature, expired, wrong aud, wrong iss,
/// missing subject — is collapsed into `Error::Unauthorized` so the
/// error surface doesn't leak *why* it failed.
///
/// `expected_aud` / `expected_iss`: when `Some`, the corresponding
/// claim is REQUIRED to be present in the token AND must equal the
/// configured value. When `None`, the claim is not inspected (legacy
/// mode — see module-header note).
pub fn verify(
    secret: &str,
    token: &str,
    expected_aud: Option<&str>,
    expected_iss: Option<&str>,
) -> Result<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    // Require `exp`. jsonwebtoken's default already validates exp when
    // present, but it doesn't *require* the claim to be set. We do.
    let mut required: Vec<&str> = vec!["exp"];
    // Honor `nbf` when the issuer set it. Default is off in
    // jsonwebtoken; we enable so a delayed-issue token can't authorize
    // before its declared start. The 60s default leeway absorbs clock
    // skew, same as for `exp`. We do not *require* `nbf` (Dyspel
    // doesn't set it) — only validate when present.
    validation.validate_nbf = true;
    // Audience: when expected_aud is set we require the claim, populate
    // the allow-set, and let jsonwebtoken's validator do the compare.
    // When unset we explicitly disable validate_aud — without this,
    // jsonwebtoken's `validate_aud = true` default would require an
    // `aud` claim that the legacy Dyspel-shape token doesn't carry.
    match expected_aud {
        Some(aud) => {
            validation.set_audience(&[aud]);
            required.push("aud");
        }
        None => validation.validate_aud = false,
    }
    // Issuer: same shape. set_issuer populates the allow-set; we add
    // `iss` to required-claims so a token without one is rejected.
    if let Some(iss) = expected_iss {
        validation.set_issuer(&[iss]);
        required.push("iss");
    }
    validation.set_required_spec_claims(&required);

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
        let claims = verify("sec", &tok, None, None).unwrap();
        assert_eq!(claims.subject(), Some("u-42"));
    }

    #[test]
    fn accepts_standard_sub_claim() {
        let tok = sign("sec", json!({ "sub": "u-17", "exp": future_ts() }));
        let claims = verify("sec", &tok, None, None).unwrap();
        assert_eq!(claims.subject(), Some("u-17"));
    }

    #[test]
    fn prefers_user_id_over_sub() {
        let tok = sign(
            "sec",
            json!({ "userId": "primary", "sub": "fallback", "exp": future_ts() }),
        );
        let claims = verify("sec", &tok, None, None).unwrap();
        assert_eq!(claims.subject(), Some("primary"));
    }

    #[test]
    fn rejects_wrong_secret() {
        let tok = sign("right", json!({ "userId": "u", "exp": future_ts() }));
        let r = verify("wrong", &tok, None, None);
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
        let r = verify("sec", &tok, None, None);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn rejects_missing_exp() {
        // No `exp` claim at all — we require one so a leaked token has a
        // bounded lifetime.
        let tok = sign("sec", json!({ "userId": "u" }));
        let r = verify("sec", &tok, None, None);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn rejects_no_subject() {
        // exp present, but no userId or sub — we can't identify the caller.
        let tok = sign("sec", json!({ "email": "a@b", "exp": future_ts() }));
        let r = verify("sec", &tok, None, None);
        assert!(matches!(r, Err(Error::Unauthorized)));
    }

    #[test]
    fn rejects_malformed_token() {
        assert!(matches!(
            verify("sec", "not-a-jwt", None, None),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn rejects_nbf_in_the_future() {
        // `nbf` (not-before) well outside the 60s leeway window must
        // reject. Confirms validate_nbf is honored — without it
        // jsonwebtoken would ignore the claim entirely.
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let tok = sign(
            "sec",
            json!({ "userId": "u", "exp": future_ts(), "nbf": future }),
        );
        assert!(matches!(
            verify("sec", &tok, None, None),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn accepts_nbf_in_the_past() {
        // `nbf` already elapsed — token is currently valid. Pin the
        // happy path so a stricter future Validation default doesn't
        // silently break tokens that set nbf for legitimate reasons.
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60;
        let tok = sign(
            "sec",
            json!({ "userId": "u", "exp": future_ts(), "nbf": past }),
        );
        let claims = verify("sec", &tok, None, None).unwrap();
        assert_eq!(claims.subject(), Some("u"));
    }

    #[test]
    fn rejects_token_signed_with_different_family_algorithm() {
        // The Validation allow-list is `[HS256]`. A token whose header
        // claims `alg: HS512` must not authorize even if we somehow had
        // a matching key — different algorithm = reject. This pins the
        // "no algorithm confusion" property at runtime; the jsonwebtoken
        // crate has no `Algorithm::None` variant at all, so the more
        // dangerous "downgrade to none" attack isn't representable.
        let header = Header::new(Algorithm::HS512);
        let tok = encode(
            &header,
            &json!({ "userId": "u", "exp": future_ts() }),
            &EncodingKey::from_secret(b"sec"),
        )
        .unwrap();
        assert!(matches!(
            verify("sec", &tok, None, None),
            Err(Error::Unauthorized)
        ));
    }

    // K2 — audience strict-mode triple.

    #[test]
    fn aud_set_matching_aud_accepts() {
        let tok = sign(
            "sec",
            json!({ "userId": "u", "aud": "artifacts", "exp": future_ts() }),
        );
        let claims = verify("sec", &tok, Some("artifacts"), None).unwrap();
        assert_eq!(claims.subject(), Some("u"));
    }

    #[test]
    fn aud_set_wrong_aud_rejects() {
        let tok = sign(
            "sec",
            json!({ "userId": "u", "aud": "some-other-service", "exp": future_ts() }),
        );
        assert!(matches!(
            verify("sec", &tok, Some("artifacts"), None),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn aud_set_missing_aud_rejects() {
        // Token has no `aud` claim at all — strict mode must reject
        // rather than silently accepting it.
        let tok = sign("sec", json!({ "userId": "u", "exp": future_ts() }));
        assert!(matches!(
            verify("sec", &tok, Some("artifacts"), None),
            Err(Error::Unauthorized)
        ));
    }

    // K2 — issuer strict-mode triple.

    #[test]
    fn iss_set_matching_iss_accepts() {
        let tok = sign(
            "sec",
            json!({ "userId": "u", "iss": "dyspel", "exp": future_ts() }),
        );
        let claims = verify("sec", &tok, None, Some("dyspel")).unwrap();
        assert_eq!(claims.subject(), Some("u"));
    }

    #[test]
    fn iss_set_wrong_iss_rejects() {
        let tok = sign(
            "sec",
            json!({ "userId": "u", "iss": "other-issuer", "exp": future_ts() }),
        );
        assert!(matches!(
            verify("sec", &tok, None, Some("dyspel")),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn iss_set_missing_iss_rejects() {
        let tok = sign("sec", json!({ "userId": "u", "exp": future_ts() }));
        assert!(matches!(
            verify("sec", &tok, None, Some("dyspel")),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn aud_and_iss_both_set_both_match_accepts() {
        // Combined-strict-mode sanity: production deployments that
        // share a JWT secret across services SHOULD set both.
        let tok = sign(
            "sec",
            json!({
                "userId": "u",
                "aud": "artifacts",
                "iss": "dyspel",
                "exp": future_ts(),
            }),
        );
        let claims = verify("sec", &tok, Some("artifacts"), Some("dyspel")).unwrap();
        assert_eq!(claims.subject(), Some("u"));
    }

    #[test]
    fn aud_and_iss_unset_legacy_token_accepts() {
        // Pin the "no breakage" property explicitly: when neither
        // strict-mode flag is set, a token without aud/iss (the
        // current Dyspel shape) still authorizes. Without this test
        // a future bump to jsonwebtoken that flips a default would
        // silently break every existing deployment.
        let tok = sign("sec", json!({ "userId": "u", "exp": future_ts() }));
        let claims = verify("sec", &tok, None, None).unwrap();
        assert_eq!(claims.subject(), Some("u"));
    }
}
