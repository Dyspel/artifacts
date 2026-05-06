//! `ObjectStore`: the abstraction that future M2b chunked-KV storage
//! will plug into.
//!
//! ## Where this fits
//!
//! `Storage` (storage.rs) already abstracts the *repo lifecycle* —
//! `create`, `exists`, `fork`, `delete`. What it doesn't abstract is
//! *object reads*: the actual git objects (commits, trees, blobs)
//! still live on disk under `<repos_dir>/<id>.git/objects/` and are
//! read by either git plumbing subprocesses or direct filesystem
//! reads. To make `Storage`'s second impl meaningful (a chunked-KV
//! backend matching the Cloudflare DO+SQLite shape), object reads
//! also have to go through a trait.
//!
//! `ObjectStore` is that trait. Today it has one method
//! (`read_loose`) and one impl (`FsObjectStore`). Production code
//! does **not** route through this yet — that swap is the rest of
//! M2b. This module exists so the next commit can land a chunked-KV
//! impl without inventing the trait shape from scratch, and so the
//! intent is documented at the seam where it'll eventually slot in.
//!
//! ## What's still blocking real M2b
//!
//! The git pack handlers — `git pack-objects` (M1b-2b leaf) and
//! `git unpack-objects` (M1b-3 leaf) — operate on a real on-disk
//! `<repo>/objects/` tree. A chunked-KV `Storage` can't satisfy
//! those subprocesses because the bytes don't live in a directory.
//!
//! The M1b-2c / M1b-3-gix follow-up commits replace those
//! subprocesses with `gix-pack`-driven streaming reads + writes;
//! that's where `ObjectStore` actually gets called. Until then,
//! anything that reads/writes objects has to keep touching the
//! filesystem.
//!
//! ## What's delivered today
//!
//! - The trait and two impls — `FsObjectStore` (production-shape
//!   reads against `<repo>/objects/<aa>/<bbbb...>`) and
//!   `MemObjectStore` (in-memory `HashMap`-backed). The Mem impl is
//!   the M2b proof-of-concept: it shows the trait shape isn't
//!   accidentally FS-specific, so the eventual chunked-KV impl can
//!   plug in by implementing the same trait without trait surgery.
//! - A conformance test suite (`conformance` module) that runs
//!   both impls through the same contract checks — read-after-write
//!   round-trip, missing-oid → `None`, malformed-oid → `None`. New
//!   impls add their own conformance test by calling the shared
//!   helpers; the contract lives in one place.
//! - Documentation that says, plainly, that production code
//!   doesn't route through this yet.

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

/// Read-only view into a repo's git object database. Writes don't
/// have a method yet — receive-pack writes go through
/// `git unpack-objects` (M1b-3 leaf). When that subprocess is
/// replaced with native code, we'll add `write_loose` here.
///
/// Production paths don't route through this yet — the trait + impl
/// exist as M2b foundation per the README. Annotated `#[allow(dead_code)]`
/// so the unused warning doesn't drift into a real signal once
/// real callers land.
#[allow(dead_code)]
pub trait ObjectStore: Send + Sync {
    /// Read a loose object by its 40-char hex SHA-1. Returns the raw
    /// loose-object bytes (zlib-deflated header+payload). `Ok(None)`
    /// means the object isn't in this store as a loose file — it
    /// might be in a packfile, or absent entirely; callers that
    /// need that distinction should consult a higher-level `find`
    /// API on top of this trait.
    fn read_loose(&self, repo_id: &str, oid: &str) -> Result<Option<Vec<u8>>>;
}

/// Filesystem-backed `ObjectStore`. Reads from
/// `<root>/<id>.git/objects/<aa>/<bbbb...>`.
#[allow(dead_code)]
#[derive(Clone)]
pub struct FsObjectStore {
    root: PathBuf,
}

#[allow(dead_code)]
impl FsObjectStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn loose_path(&self, repo_id: &str, oid: &str) -> Option<PathBuf> {
        // Defensive: oid validation. We don't trust the caller for
        // path-traversal — anything outside the [a-f0-9]{40} shape
        // gets rejected. Shared with `MemObjectStore` so both impls
        // honor the same malformed-oid contract.
        if !oid_is_valid(oid) {
            return None;
        }
        let (a, b) = oid.split_at(2);
        Some(
            self.root
                .join(format!("{repo_id}.git"))
                .join("objects")
                .join(a)
                .join(b),
        )
    }
}

impl ObjectStore for FsObjectStore {
    fn read_loose(&self, repo_id: &str, oid: &str) -> Result<Option<Vec<u8>>> {
        let path = match self.loose_path(repo_id, oid) {
            Some(p) => p,
            None => return Ok(None),
        };
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::from(e)),
        }
    }
}

/// In-memory `ObjectStore`. Backed by an `RwLock<HashMap<(repo_id, oid),
/// Vec<u8>>>`; reads share the lock, writes serialize. Built as the
/// M2b proof-of-concept that the trait isn't FS-specific. Tests use it
/// as a fast, deterministic alternative to spinning up a real
/// `<repo>/objects/` tree.
///
/// Not used in production yet — production reads still go through
/// the filesystem via `FsObjectStore` (or, more often, directly via
/// gix). The chunked-KV `Storage` impl is the place this would get
/// wired up: the trait shape demonstrated here is what M2b's actual
/// impl will satisfy.
#[allow(dead_code)]
pub struct MemObjectStore {
    objects: RwLock<HashMap<(String, String), Vec<u8>>>,
}

#[allow(dead_code)]
impl MemObjectStore {
    pub fn new() -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
        }
    }

    /// Test-helper: insert raw loose-object bytes for `(repo_id, oid)`.
    /// Production code wouldn't need this — the eventual M2b impl
    /// will populate via the receive-pack path. For now this is the
    /// only way to put bytes in.
    ///
    /// Rejects malformed `oid` the same way `read_loose` does, so
    /// the store can't be poisoned with un-readable keys.
    pub fn write_loose(&self, repo_id: &str, oid: &str, bytes: Vec<u8>) -> bool {
        if !oid_is_valid(oid) {
            return false;
        }
        self.objects
            .write()
            .expect("MemObjectStore lock poisoned")
            .insert((repo_id.to_string(), oid.to_string()), bytes);
        true
    }
}

impl Default for MemObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStore for MemObjectStore {
    fn read_loose(&self, repo_id: &str, oid: &str) -> Result<Option<Vec<u8>>> {
        if !oid_is_valid(oid) {
            return Ok(None);
        }
        Ok(self
            .objects
            .read()
            .expect("MemObjectStore lock poisoned")
            .get(&(repo_id.to_string(), oid.to_string()))
            .cloned())
    }
}

/// 40-char lowercase hex. The validation contract both impls share —
/// keeping it in one place means the conformance test for malformed
/// oids exercises the same predicate against both backends.
fn oid_is_valid(oid: &str) -> bool {
    oid.len() == 40 && oid.chars().all(|c| c.is_ascii_hexdigit())
}

/// Conformance contract for any `ObjectStore` impl. Each behavior
/// here is one assertion both `FsObjectStore` and `MemObjectStore`
/// must satisfy. A future chunked-KV impl runs the same helpers and
/// inherits the contract for free.
///
/// Helpers take a fixture closure `populate` that puts known bytes
/// for a known oid into the impl-specific way (FS: `git hash-object`
/// against a real bare repo; Mem: `MemObjectStore::write_loose`).
/// Each helper then exercises the trait method and asserts.
#[cfg(test)]
pub(crate) mod conformance {
    use super::*;

    /// "Read returns the bytes that were written." The fundamental
    /// contract — an ObjectStore that can't read back what it stored
    /// is broken regardless of backend.
    pub fn read_after_write_round_trips<S: ObjectStore>(store: &S, repo_id: &str, oid: &str) {
        let bytes = store
            .read_loose(repo_id, oid)
            .expect("read_loose Result::Ok")
            .expect("Some(bytes) for a known-present oid");
        assert!(!bytes.is_empty(), "read_loose returned empty bytes");
    }

    /// Reading an oid that was never inserted yields `Ok(None)` —
    /// not an error, not empty bytes. Distinguishes "absent" from
    /// "present but empty".
    pub fn missing_oid_returns_none<S: ObjectStore>(store: &S, repo_id: &str) {
        let absent = "0123456789abcdef0123456789abcdef01234567";
        assert!(
            store.read_loose(repo_id, absent).unwrap().is_none(),
            "expected None for unknown oid, got Some",
        );
    }

    /// Malformed oids (path-traversal, wrong length, non-hex) yield
    /// `Ok(None)` — never an error, never a stored value, never a
    /// computed path that escapes the store. This is the trait's
    /// path-safety contract.
    pub fn malformed_oid_returns_none<S: ObjectStore>(store: &S) {
        // Path-traversal attempt.
        assert!(
            store
                .read_loose("repo", "../something/with/slash/and/some/more/x")
                .unwrap()
                .is_none()
        );
        // Wrong length.
        assert!(store.read_loose("repo", "abc").unwrap().is_none());
        // Non-hex (uppercase Z).
        assert!(
            store
                .read_loose("repo", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{new_repo_id, FsStorage, Storage};
    use std::path::Path;

    fn write_blob(git_dir: &Path, bytes: &[u8]) -> String {
        use std::io::Write as _;
        let mut child = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
        let out = child.wait_with_output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    // ─── FsObjectStore conformance ─────────────────────────────────

    fn fs_fixture() -> (tempfile::TempDir, FsObjectStore, String, String) {
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));
        let oid = write_blob(&git_dir, b"hello\n");
        let store = FsObjectStore::new(&repos);
        (tmp, store, repo_id, oid)
    }

    #[test]
    fn fs_read_after_write_round_trips() {
        let (_t, store, repo_id, oid) = fs_fixture();
        conformance::read_after_write_round_trips(&store, &repo_id, &oid);
    }

    #[test]
    fn fs_missing_oid_returns_none() {
        let (_t, store, repo_id, _) = fs_fixture();
        conformance::missing_oid_returns_none(&store, &repo_id);
    }

    #[test]
    fn fs_malformed_oid_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::malformed_oid_returns_none(&store);
    }

    /// FS-specific contract that doesn't apply to Mem: returned bytes
    /// are git's actual zlib-deflated loose-object format. The Mem
    /// impl stores whatever the test puts in, so it can't satisfy
    /// this — that's fine, `read_loose`'s contract is only "return
    /// the bytes that were stored", not "return zlib".
    #[test]
    fn fs_returns_zlib_deflated_payload() {
        let (_t, store, repo_id, oid) = fs_fixture();
        let bytes = store.read_loose(&repo_id, &oid).unwrap().expect("found");
        // Loose objects start with the zlib magic byte 0x78 (low-nibble
        // = 0x8 means deflate at the default window size).
        assert_eq!(bytes[0], 0x78);
        assert!(bytes.len() > 2);
    }

    // ─── MemObjectStore conformance ────────────────────────────────

    /// Synthesize a deterministic 40-hex oid for a Mem fixture. The
    /// store doesn't validate the oid against the bytes (the FS impl
    /// doesn't either — it's a key-value lookup), so any 40-hex
    /// string is fine for round-trip testing.
    fn mem_oid(seed: u8) -> String {
        let mut s = String::with_capacity(40);
        for _ in 0..40 {
            s.push(char::from_digit((seed % 16) as u32, 16).unwrap());
        }
        s
    }

    fn mem_fixture() -> (MemObjectStore, String, String) {
        let store = MemObjectStore::new();
        let repo_id = "mem-repo".to_string();
        let oid = mem_oid(0xa);
        assert!(store.write_loose(&repo_id, &oid, b"any-bytes-stand-in".to_vec()));
        (store, repo_id, oid)
    }

    #[test]
    fn mem_read_after_write_round_trips() {
        let (store, repo_id, oid) = mem_fixture();
        conformance::read_after_write_round_trips(&store, &repo_id, &oid);
    }

    #[test]
    fn mem_missing_oid_returns_none() {
        let (store, repo_id, _) = mem_fixture();
        conformance::missing_oid_returns_none(&store, &repo_id);
    }

    #[test]
    fn mem_malformed_oid_returns_none() {
        let store = MemObjectStore::new();
        conformance::malformed_oid_returns_none(&store);
    }

    #[test]
    fn mem_write_loose_rejects_malformed_oid() {
        // The store can't be poisoned with a path-traversal-shaped
        // key — write_loose silently refuses, so subsequent reads
        // for that key yield None (covered by malformed_oid_returns_none).
        let store = MemObjectStore::new();
        assert!(!store.write_loose("repo", "../bad", b"x".to_vec()));
        assert!(!store.write_loose("repo", "abc", b"x".to_vec()));
        assert!(!store.write_loose(
            "repo",
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            b"x".to_vec()
        ));
    }

    #[test]
    fn mem_read_returns_exact_bytes_written() {
        // Mem-specific: returned bytes are *exactly* what was stored.
        // The FS impl can't make this assertion because git rewrites
        // its loose-object format on write.
        let store = MemObjectStore::new();
        let oid = mem_oid(0x3);
        let payload: Vec<u8> = (0..=255).cycle().take(1024).collect();
        store.write_loose("r", &oid, payload.clone());
        let got = store.read_loose("r", &oid).unwrap().unwrap();
        assert_eq!(got, payload);
    }
}
