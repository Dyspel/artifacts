//! Newtype wrappers for the five stringly-typed identifiers that
//! used to flow through the codebase as bare `&str` / `String`.
//!
//! Every storage trait method (`ObjectStore::read_loose`,
//! `RefStore::cas_update`, `TokenStore::mint`, …) previously took
//! parameters like `(repo_id: &str, oid: &str, …)` — easy to swap
//! at the call site, no compile-time check that the argument that
//! looks like a SHA-1 actually is one. The brutal-assessment
//! identified this as the biggest single divergence from
//! library-quality Rust (Arkworks-tier libraries parameterize
//! types, never the string form).
//!
//! Each type here:
//!
//! - Wraps a `String`. Heap allocation is the same cost as the
//!   pre-existing `String` parameters; the win is at the type
//!   system, not the runtime.
//! - Validates at construction via `TryFrom<&str>` / `TryFrom<String>`,
//!   returning [`crate::error::Error::BadRequest`] on invalid input.
//! - Implements `AsRef<str>`, `Display`, `Debug`, `Clone`, `PartialEq`,
//!   `Eq`, `Hash` so the migration is mostly drop-in at call sites:
//!   pass `&repo_id` where `&str` used to fit (the `AsRef<str>` impl
//!   covers the ergonomics).
//! - Implements `serde::Serialize` / `serde::Deserialize` via the
//!   transparent wrapper form — the JSON shape over REST stays a
//!   bare string, no breaking change to existing clients.
//!
//! ## Migration boundary
//!
//! The REST handlers in `src/rest/*.rs` keep receiving `String`
//! from axum's `AxumPath` / JSON body extractors (axum's
//! extraction API isn't easy to plumb through `TryFrom`), and
//! convert at the top of each handler:
//!
//! ```ignore
//! let repo_id = RepoId::try_from(repo_id_str)
//!     .map_err(|_| Error::InvalidRepoId(repo_id_str.clone()))?;
//! ```
//!
//! Trait surfaces from there inward use `&RepoId`, `&Oid`, etc.
//! Inside an impl that needs the raw `&str` (e.g., to pass into
//! a SQL parameter), call `.as_str()` or `.as_ref()`.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// A repository identifier. Validated to match the same constraints
/// `crate::storage::validate_repo_id` enforces: 1–63 chars of
/// `[A-Za-z0-9_-]`, no path separators, no leading dash, no `.git`
/// suffix collisions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoId(String);

impl RepoId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume self, return the inner String. Useful when handing
    /// the id to a callee that owns the storage (SQL bindings,
    /// path-join construction, …).
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for RepoId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RepoId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl TryFrom<&str> for RepoId {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        crate::storage::validate_repo_id(s)?;
        Ok(Self(s.to_string()))
    }
}

impl TryFrom<String> for RepoId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        crate::storage::validate_repo_id(&s)?;
        Ok(Self(s))
    }
}

/// A git object id — exactly 40 lowercase hex characters (SHA-1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Oid(String);

impl Oid {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Oid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl TryFrom<&str> for Oid {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        if s.len() == 40
            && s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            Ok(Self(s.to_string()))
        } else {
            Err(Error::BadRequest(format!("invalid oid: {s:?}")))
        }
    }
}

impl TryFrom<String> for Oid {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::try_from(s.as_str())
    }
}

/// A git ref name (`refs/heads/main`, `refs/tags/v1`, `HEAD`, …).
/// Validated against git's check-ref-format rules — no whitespace,
/// no `..`, no `@{`, no control characters, components separated by
/// `/` with no empty parts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RefName(String);

impl RefName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }

    /// True iff `self` starts with the given prefix, treating the
    /// underlying string as bytes (matches git's
    /// `ref-prefix`-filter shape).
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.0.starts_with(prefix)
    }
}

impl AsRef<str> for RefName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RefName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

fn valid_ref_name(s: &str) -> bool {
    // Allow HEAD as a special case; otherwise enforce a structure
    // compatible with both `refs/heads/...` and `refs/tags/...`,
    // matching what `git check-ref-format` accepts for the part
    // after `refs/`.
    if s == "HEAD" {
        return true;
    }
    if s.is_empty()
        || s.starts_with('/')
        || s.ends_with('/')
        || s.ends_with('.')
        || s.contains("//")
        || s.contains("..")
        || s.contains("@{")
        || s.contains('\\')
    {
        return false;
    }
    if s.chars().any(|c| {
        let u = c as u32;
        u < 0x20 || u == 0x7f || matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[')
    }) {
        return false;
    }
    for part in s.split('/') {
        if part.is_empty() || part.starts_with('.') || part.ends_with(".lock") {
            return false;
        }
    }
    true
}

impl TryFrom<&str> for RefName {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        if valid_ref_name(s) {
            Ok(Self(s.to_string()))
        } else {
            Err(Error::BadRequest(format!("invalid ref name: {s:?}")))
        }
    }
}

impl TryFrom<String> for RefName {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::try_from(s.as_str())
    }
}

/// An opaque API token (admin, per-repo, or webhook). Validated as
/// non-empty + printable ASCII + ≤ 256 chars so the audit log + URL
/// embedding never see garbage.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Token(String);

impl Token {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// `Debug` redacts the body so a stray println! / tracing field
/// can't leak the token. Use `Display` only at the wire boundary
/// where revealing it is the explicit intent.
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token(<{}-char redacted>)", self.0.len())
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl TryFrom<&str> for Token {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        if s.is_empty() || s.len() > 256 {
            return Err(Error::BadRequest(format!(
                "invalid token: length {} (must be 1..=256)",
                s.len()
            )));
        }
        if !s.chars().all(|c| c.is_ascii_graphic()) {
            return Err(Error::BadRequest("invalid token: non-graphic bytes".into()));
        }
        Ok(Self(s.to_string()))
    }
}

impl TryFrom<String> for Token {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::try_from(s.as_str())
    }
}

/// A JWT subject (`userId` claim). Validated as non-empty + no NUL +
/// ≤ 256 chars; everything else is allowed because the issuing
/// identity provider has its own conventions we don't want to
/// second-guess.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Subject(String);

impl Subject {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for Subject {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl TryFrom<&str> for Subject {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        if s.is_empty() || s.len() > 256 || s.as_bytes().contains(&0) {
            return Err(Error::BadRequest("invalid subject".into()));
        }
        Ok(Self(s.to_string()))
    }
}

impl TryFrom<String> for Subject {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::try_from(s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_id_accepts_valid_ids() {
        // validate_repo_id allows: 4..=64 chars of [a-z0-9_-]. Upper
        // case + path separators + spaces fall under the wider
        // rejection set below.
        for s in ["abcd", "user_alpha-0", "abc123"] {
            assert!(RepoId::try_from(s).is_ok(), "expected {s:?} to be accepted");
        }
    }

    #[test]
    fn repo_id_rejects_path_traversal_and_slashes() {
        for s in [
            "", "..", "abc", "/foo", "foo/bar", "foo bar", "foo\0bar", "AaAaAa",
        ] {
            assert!(
                RepoId::try_from(s).is_err(),
                "expected {s:?} to be rejected"
            );
        }
    }

    #[test]
    fn oid_round_trips_canonical_form() {
        let s = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
        let oid = Oid::try_from(s).unwrap();
        assert_eq!(oid.as_str(), s);
        assert_eq!(format!("{oid}"), s);
    }

    #[test]
    fn oid_rejects_wrong_length_and_case() {
        for s in [
            "",
            "deadbeef",                                  // too short
            "4b825dc642cb6eb9a060e54bf8d69288fbee49044", // too long
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",  // non-hex
            "4B825DC642CB6EB9A060E54BF8D69288FBEE4904",  // uppercase
        ] {
            assert!(Oid::try_from(s).is_err(), "expected {s:?} to be rejected");
        }
    }

    #[test]
    fn ref_name_accepts_heads_tags_and_head() {
        for s in [
            "HEAD",
            "refs/heads/main",
            "refs/tags/v1",
            "refs/notes/agent",
        ] {
            assert!(
                RefName::try_from(s).is_ok(),
                "expected {s:?} to be accepted"
            );
        }
    }

    #[test]
    fn ref_name_rejects_git_invalid_forms() {
        for s in [
            "",
            "refs/heads/",
            "refs//heads",
            "refs/heads/..foo",
            "refs/heads/foo\nbar",
        ] {
            assert!(
                RefName::try_from(s).is_err(),
                "expected {s:?} to be rejected"
            );
        }
    }

    #[test]
    fn token_redacts_in_debug() {
        let t = Token::try_from("super-secret-token-xyz").unwrap();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("super-secret"));
        // Display still reveals (used at wire boundaries on purpose).
        assert_eq!(format!("{t}"), "super-secret-token-xyz");
    }

    #[test]
    fn token_rejects_garbage() {
        for s in ["", "with space", "with\tcontrol", &"x".repeat(257)] {
            assert!(Token::try_from(s).is_err(), "expected {s:?} to be rejected");
        }
    }

    #[test]
    fn subject_accepts_typical_jwt_subject_shapes() {
        for s in ["alice", "u-12345", "user:alice", "alice@example.com"] {
            assert!(
                Subject::try_from(s).is_ok(),
                "expected {s:?} to be accepted"
            );
        }
    }

    #[test]
    fn subject_rejects_empty_and_nul() {
        assert!(Subject::try_from("").is_err());
        assert!(Subject::try_from("alice\0bob").is_err());
    }

    #[test]
    fn newtypes_serialize_as_bare_strings() {
        // The transparent serde form keeps wire compatibility — a
        // RepoId in a JSON body is `"abc123"`, not `{"0":"abc123"}`.
        let repo = RepoId::try_from("abc123").unwrap();
        let json = serde_json::to_string(&repo).unwrap();
        assert_eq!(json, "\"abc123\"");
        let back: RepoId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, repo);
    }
}
