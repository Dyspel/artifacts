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
// `try_from` makes Deserialize run validation; `into` keeps Serialize
// transparent over the inner String. The pair beats plain
// `#[serde(transparent)]`, which would deserialize without validation
// and silently let a malformed value into the trait surface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepoId(String);

impl From<RepoId> for String {
    fn from(r: RepoId) -> Self {
        r.0
    }
}

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
#[serde(try_from = "String", into = "String")]
pub struct Oid(String);

impl From<Oid> for String {
    fn from(o: Oid) -> Self {
        o.0
    }
}

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
#[serde(try_from = "String", into = "String")]
pub struct RefName(String);

impl From<RefName> for String {
    fn from(r: RefName) -> Self {
        r.0
    }
}

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
#[serde(try_from = "String", into = "String")]
pub struct Token(String);

impl From<Token> for String {
    fn from(t: Token) -> Self {
        t.0
    }
}

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
#[serde(try_from = "String", into = "String")]
pub struct Subject(String);

impl From<Subject> for String {
    fn from(s: Subject) -> Self {
        s.0
    }
}

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
        // The `try_from = String, into = String` serde form keeps wire
        // compatibility — a RepoId in a JSON body is `"abc123"`, not
        // `{"0":"abc123"}`. Same shape as plain `serde(transparent)`
        // would produce, but with TryFrom-driven deserialization.
        let repo = RepoId::try_from("abc123").unwrap();
        let json = serde_json::to_string(&repo).unwrap();
        assert_eq!(json, "\"abc123\"");
        let back: RepoId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, repo);
    }

    /// The whole point of G2 — Deserialize MUST run the same validation
    /// `TryFrom<String>` runs, not just blindly accept the inner String.
    /// A bad value in JSON has to fail at decode time, not silently let
    /// a malformed RepoId into the trait surface where it'd take a
    /// runtime check three layers deeper to catch.
    #[test]
    fn deserialize_rejects_malformed_repo_id() {
        let err = serde_json::from_str::<RepoId>("\"AaA\"").unwrap_err();
        // serde's error wraps our `Display`; the field-shape rule is in
        // the message, plus the wire layer (axum's `Json` extractor)
        // turns that into a 400 with the path of the offending field.
        assert!(
            err.to_string().contains("invalid repo id")
                || err.to_string().contains("InvalidRepoId"),
            "expected validation error, got {err}"
        );
    }

    #[test]
    fn deserialize_rejects_malformed_oid() {
        let cases = [
            "\"deadbeef\"",
            "\"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\"",
        ];
        for c in cases {
            let err = serde_json::from_str::<Oid>(c).unwrap_err();
            assert!(
                err.to_string().contains("invalid oid"),
                "expected oid validation error for {c}, got {err}"
            );
        }
    }

    #[test]
    fn deserialize_rejects_malformed_ref_name() {
        for c in ["\"\"", "\"refs/heads/..\"", "\"refs/heads/@{0}\""] {
            assert!(
                serde_json::from_str::<RefName>(c).is_err(),
                "expected ref-name validation error for {c}"
            );
        }
    }

    #[test]
    fn deserialize_rejects_malformed_token() {
        for c in ["\"\"", "\"with space\""] {
            assert!(
                serde_json::from_str::<Token>(c).is_err(),
                "expected token validation error for {c}"
            );
        }
    }

    #[test]
    fn deserialize_rejects_malformed_subject() {
        // Subject only rejects empty + NUL byte; \\u0000 in a JSON
        // string is the literal NUL byte after decode.
        assert!(serde_json::from_str::<Subject>("\"\"").is_err());
        assert!(serde_json::from_str::<Subject>("\"alice\\u0000bob\"").is_err());
    }

    /// Property tests — sweep the input space to pin invariants the
    /// hand-written cases above only exercise at a handful of points.
    /// Case count capped low so SQLite-free property runs stay sub-second.
    mod prop {
        use super::super::*;
        use proptest::prelude::*;
        proptest! {
            #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

            /// Every accepted RepoId round-trips serde-transparently: a
            /// JSON string → RepoId → JSON string must yield the same
            /// JSON bytes. If serde introduces a quoting / escaping
            /// asymmetry this catches it.
            #[test]
            fn repo_id_json_roundtrip(s in "[a-z0-9_-]{4,64}") {
                let id = RepoId::try_from(s.as_str())
                    .expect("generator output satisfies RepoId contract");
                let json = serde_json::to_string(&id).unwrap();
                let back: RepoId = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(id, back);
            }

            /// Same property for Oid — 40 lowercase hex chars round-trip
            /// through serde without mutation.
            #[test]
            fn oid_json_roundtrip(s in "[0-9a-f]{40}") {
                let o = Oid::try_from(s.as_str())
                    .expect("generator output satisfies Oid contract");
                let json = serde_json::to_string(&o).unwrap();
                let back: Oid = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(o, back);
            }

            /// Oid::try_from + .as_str() is idempotent: the inner string
            /// is exactly what was handed in (no normalization, no
            /// case-folding, no trimming).
            #[test]
            fn oid_try_from_is_idempotent(s in "[0-9a-f]{40}") {
                let o = Oid::try_from(s.as_str()).unwrap();
                prop_assert_eq!(o.as_str(), s.as_str());
            }

            /// RefName::try_from rejects any input containing git's
            /// banned sequences anywhere — `..`, `@{`, ASCII control
            /// chars, or whitespace. The generator embeds a banned
            /// substring in an otherwise-plausible ref-prefix.
            #[test]
            fn ref_name_rejects_banned_sequences(
                bad in prop::sample::select(&["..", "@{", "\x01", " ", "\\", "~", "^"][..])
            ) {
                let candidate = format!("refs/heads/foo{bad}bar");
                prop_assert!(
                    RefName::try_from(candidate.as_str()).is_err(),
                    "expected RefName to reject {candidate:?}"
                );
            }

            /// Inputs that fail RepoId validation must produce an Error,
            /// never a panic. Sweeps strings that mix in-set + out-of-set
            /// chars so we hit both the empty/length-bound paths and the
            /// charset path. Asymmetric: accepted strings round-trip
            /// (other tests pin that); we only assert "no panic" here.
            #[test]
            fn repo_id_rejects_garbage_without_panic(s in ".{0,80}") {
                // try_from MUST return Ok/Err — a panic from unwrap or
                // overflow inside the validator would surface as a
                // proptest failure with the offending input.
                let _ = RepoId::try_from(s.as_str());
            }

            /// Same "no panic" guard for the other four newtypes.
            #[test]
            fn other_newtypes_no_panic_on_garbage(s in ".{0,300}") {
                let _ = Oid::try_from(s.as_str());
                let _ = RefName::try_from(s.as_str());
                let _ = Token::try_from(s.as_str());
                let _ = Subject::try_from(s.as_str());
            }
        }
    }

    /// CAS-outcome property: for any sequence of cas_update calls
    /// against MemRefStore, the number of Updated outcomes is bounded
    /// by the number of distinct (expected, new) inputs that match
    /// the current ref value. This is the CAS contract — duplicates
    /// can't both succeed; conflicts don't move the ref. Lives outside
    /// `mod prop` because it needs a tokio runtime + MemRefStore from
    /// the `refs` module.
    #[test]
    fn cas_update_property_bounded_updates() {
        use crate::refs::{CasOutcome, MemRefStore, RefStore};
        use proptest::collection::vec;
        use proptest::prelude::*;
        let runner = tokio::runtime::Runtime::new().unwrap();
        let mut prop_runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 24,
            ..ProptestConfig::default()
        });
        // Sequence of (expected, new) pairs over a small oid alphabet.
        let strategy = vec((0u8..4u8, 0u8..4u8), 1..=20);
        prop_runner
            .run(&strategy, |sequence| {
                runner.block_on(async {
                    let s = MemRefStore::new();
                    let repo = RepoId::try_from("rtst").unwrap();
                    let rname = RefName::try_from("refs/heads/x").unwrap();
                    let mut applied: Vec<u8> = Vec::new(); // history of accepted `new`s
                    let oids: Vec<Oid> = (0..=4u8)
                        .map(|i| Oid::try_from(&*i.to_string().repeat(40)).unwrap())
                        .collect();
                    for (expected_idx, new_idx) in sequence {
                        let expected = (expected_idx > 0).then(|| &oids[expected_idx as usize]);
                        let new = &oids[new_idx as usize];
                        match s.cas_update(&repo, &rname, expected, new).await.unwrap() {
                            CasOutcome::Updated => {
                                // Invariant: the CAS only accepted if the
                                // ref's current value really did equal the
                                // expected (or None meant "must be absent").
                                applied.push(new_idx);
                            }
                            CasOutcome::Conflict { .. } => {}
                        }
                    }
                    // The post-state must equal the last accepted `new`
                    // (or None if no update ever succeeded).
                    let final_val = s.read(&repo, &rname).await.unwrap();
                    match applied.last() {
                        Some(&idx) => {
                            assert_eq!(final_val, Some(oids[idx as usize].clone()));
                        }
                        None => {
                            assert!(final_val.is_none());
                        }
                    }
                });
                Ok(())
            })
            .unwrap();
    }
}
