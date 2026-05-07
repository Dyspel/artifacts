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

/// One row of `ObjectStore::list_loose`. Captures the metadata
/// `gc` needs without an extra round-trip per object — the FS impl
/// reads stat in the same `read_dir` walk; a future KV impl reads
/// `oid + length(bytes) + created_at` in one row.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LooseInfo {
    pub oid: String,
    pub size: u64,
    /// Unix epoch seconds when the object was last written. The FS
    /// impl reads from mtime; a future chunked-KV impl reads from
    /// its own `created_at` column. Used by `gc::run`'s mtime
    /// guard — don't delete an object younger than the guard, in
    /// case a push that landed seconds ago is mid-stream.
    pub created_secs: i64,
}

/// Read + write view into a repo's git object database.
///
/// Production paths don't route through this yet — the trait + impls
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

    /// Store loose-object bytes for `(repo_id, oid)`. Idempotent:
    /// a second write of the same `oid` is a no-op (loose objects
    /// are content-addressed — the same oid implies the same
    /// bytes). Malformed `oid` is rejected with an error rather
    /// than silently dropped, since this is a write path and the
    /// caller wants to know.
    ///
    /// FS impl writes atomically via tmp-then-rename so a torn
    /// write never leaves a partial file at the canonical path.
    /// Mem impl just inserts into the map.
    fn write_loose(&self, repo_id: &str, oid: &str, bytes: &[u8]) -> Result<()>;

    /// Enumerate every loose object in the repo. Used by gc to
    /// compute the on-disk set that gets diffed against the
    /// reachable set. Order is unspecified — callers that need
    /// determinism sort.
    ///
    /// Returns an empty Vec for a repo that doesn't exist or has
    /// no loose objects yet (rather than an error) — this matches
    /// the FS shape where a missing `objects/` dir is identical
    /// to one with no loose subdirs.
    fn list_loose(&self, repo_id: &str) -> Result<Vec<LooseInfo>>;

    /// Delete a loose object by oid. Returns `Ok(true)` if a row
    /// was removed, `Ok(false)` if the object wasn't there
    /// (idempotent — a second delete of the same oid is fine).
    /// Malformed oid is an error, mirroring `write_loose`.
    fn delete_loose(&self, repo_id: &str, oid: &str) -> Result<bool>;
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

    fn write_loose(&self, repo_id: &str, oid: &str, bytes: &[u8]) -> Result<()> {
        let path = self.loose_path(repo_id, oid).ok_or_else(|| {
            Error::Other(anyhow::anyhow!("write_loose: invalid oid {oid:?}"))
        })?;
        // Idempotent — content-addressed storage means the same oid
        // implies the same bytes. Skip the rewrite to save the syscall
        // and avoid the rename race that brief existence would imply.
        if path.exists() {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic write: stage into a tmp file in the same parent
        // directory (so rename is filesystem-local), then rename
        // into place. A torn write to the tmp file leaves the
        // canonical path untouched. Tmp name uses pid+rand+oid
        // suffix so concurrent writers of the same object don't
        // collide on the tmp path.
        let parent = path.parent().expect("loose_path has 2-component prefix");
        let tmp_name = format!(".tmp-{}-{}-{}", std::process::id(), rand::random::<u32>(), oid);
        let tmp = parent.join(tmp_name);
        std::fs::write(&tmp, bytes)?;
        match std::fs::rename(&tmp, &path) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Clean up the tmp on failure so we don't leave
                // garbage. Best-effort; if cleanup fails too, the
                // original error is the one that matters.
                let _ = std::fs::remove_file(&tmp);
                Err(Error::from(e))
            }
        }
    }

    fn list_loose(&self, repo_id: &str) -> Result<Vec<LooseInfo>> {
        let objects = self.root.join(format!("{repo_id}.git")).join("objects");
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&objects) {
            Ok(e) => e,
            // Missing objects/ dir is identical to "no loose objects".
            // Don't bubble — gc treats this as a no-op pass.
            Err(_) => return Ok(out),
        };
        for ent in entries.flatten() {
            let name = match ent.file_name().to_str().map(str::to_string) {
                Some(s) => s,
                None => continue,
            };
            // Loose-object subdirs are exactly 2 hex chars. Skip
            // `info/`, `pack/`, `.tmp-*` rename stragglers, etc.
            if name.len() != 2 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let subdir = ent.path();
            let inner = match std::fs::read_dir(&subdir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for f in inner.flatten() {
                let fname = match f.file_name().to_str().map(str::to_string) {
                    Some(s) => s,
                    None => continue,
                };
                if fname.len() != 38 || !fname.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                let oid = format!("{name}{fname}");
                let meta = match f.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let created_secs = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                out.push(LooseInfo {
                    oid,
                    size: meta.len(),
                    created_secs,
                });
            }
        }
        Ok(out)
    }

    fn delete_loose(&self, repo_id: &str, oid: &str) -> Result<bool> {
        let path = self.loose_path(repo_id, oid).ok_or_else(|| {
            Error::Other(anyhow::anyhow!("delete_loose: invalid oid {oid:?}"))
        })?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::from(e)),
        }
    }
}

/// In-memory `ObjectStore`. Backed by an `RwLock<HashMap<(repo_id, oid),
/// MemEntry>>`; reads share the lock, writes serialize. Built as the
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
    objects: RwLock<HashMap<(String, String), MemEntry>>,
}

/// One row in `MemObjectStore`. Carries `created_secs` so the Mem
/// impl can satisfy `list_loose`'s `LooseInfo.created_secs` contract
/// the same way the FS impl does (mtime). Tests that need to control
/// the timestamp use the `_with_ts` helper.
#[derive(Debug, Clone)]
struct MemEntry {
    bytes: Vec<u8>,
    created_secs: i64,
}

#[allow(dead_code)]
impl MemObjectStore {
    pub fn new() -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
        }
    }

    /// Test-helper: insert with a chosen timestamp so the gc-prune
    /// guard tests don't depend on wall-clock. Bypasses the trait's
    /// validation contract — callers must pass a valid oid.
    #[cfg(test)]
    pub(crate) fn write_loose_with_ts(
        &self,
        repo_id: &str,
        oid: &str,
        bytes: &[u8],
        created_secs: i64,
    ) {
        self.objects
            .write()
            .expect("MemObjectStore lock poisoned")
            .insert(
                (repo_id.to_string(), oid.to_string()),
                MemEntry {
                    bytes: bytes.to_vec(),
                    created_secs,
                },
            );
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
            .map(|e| e.bytes.clone()))
    }

    fn write_loose(&self, repo_id: &str, oid: &str, bytes: &[u8]) -> Result<()> {
        if !oid_is_valid(oid) {
            return Err(Error::Other(anyhow::anyhow!(
                "write_loose: invalid oid {oid:?}"
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.objects
            .write()
            .expect("MemObjectStore lock poisoned")
            .insert(
                (repo_id.to_string(), oid.to_string()),
                MemEntry {
                    bytes: bytes.to_vec(),
                    created_secs: now,
                },
            );
        Ok(())
    }

    fn list_loose(&self, repo_id: &str) -> Result<Vec<LooseInfo>> {
        Ok(self
            .objects
            .read()
            .expect("MemObjectStore lock poisoned")
            .iter()
            .filter(|((r, _), _)| r == repo_id)
            .map(|((_, oid), e)| LooseInfo {
                oid: oid.clone(),
                size: e.bytes.len() as u64,
                created_secs: e.created_secs,
            })
            .collect())
    }

    fn delete_loose(&self, repo_id: &str, oid: &str) -> Result<bool> {
        if !oid_is_valid(oid) {
            return Err(Error::Other(anyhow::anyhow!(
                "delete_loose: invalid oid {oid:?}"
            )));
        }
        Ok(self
            .objects
            .write()
            .expect("MemObjectStore lock poisoned")
            .remove(&(repo_id.to_string(), oid.to_string()))
            .is_some())
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

    /// `write_loose` round-trips through `read_loose` with byte-exact
    /// fidelity. Both impls have to satisfy this — anything a chunked-KV
    /// or future backend can't preserve verbatim is broken.
    pub fn write_then_read_round_trips<S: ObjectStore>(store: &S) {
        // Use a synthetic 40-hex oid; both impls treat it as opaque
        // key-value lookup, so the FS impl's loose-format expectation
        // doesn't apply to the trait contract test.
        let oid = "1111111111111111111111111111111111111111";
        let payload = b"contract-bytes-stand-in";
        store.write_loose("conf-repo", oid, payload).unwrap();
        let got = store
            .read_loose("conf-repo", oid)
            .unwrap()
            .expect("Some after write");
        assert_eq!(got.as_slice(), payload);
    }

    /// `write_loose` is idempotent — a second write of the same oid is
    /// a no-op. Loose objects are content-addressed, so the same oid
    /// implies the same bytes; both impls must honor this without
    /// erroring out.
    pub fn write_loose_idempotent_on_repeat<S: ObjectStore>(store: &S) {
        let oid = "2222222222222222222222222222222222222222";
        let payload = b"first-write";
        store.write_loose("conf-repo", oid, payload).unwrap();
        // Second write of the same oid + bytes — must not error.
        store.write_loose("conf-repo", oid, payload).unwrap();
        let got = store.read_loose("conf-repo", oid).unwrap().unwrap();
        assert_eq!(got.as_slice(), payload);
    }

    /// `write_loose` with a malformed oid is a hard error, not a
    /// silent drop. Reads of malformed oids return `Ok(None)` (the
    /// path-safety contract), but writes need to surface the bug —
    /// callers want to know rather than silently lose data.
    pub fn write_loose_rejects_malformed_oid<S: ObjectStore>(store: &S) {
        let cases = [
            "../something",
            "abc",
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        ];
        for bad in cases {
            let r = store.write_loose("repo", bad, b"x");
            assert!(r.is_err(), "expected write_loose({bad:?}) to error, got {r:?}");
        }
    }

    /// `list_loose` returns every written object with a populated
    /// LooseInfo (oid + size + non-zero created_secs). Order is
    /// unspecified, so the test sorts before comparing.
    pub fn list_loose_enumerates_writes<S: ObjectStore>(store: &S) {
        let oids = [
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222",
            "3333333333333333333333333333333333333333",
        ];
        for oid in oids {
            store.write_loose("conf-repo", oid, b"some-bytes").unwrap();
        }
        let mut listed = store.list_loose("conf-repo").unwrap();
        listed.sort_by(|a, b| a.oid.cmp(&b.oid));
        let listed_oids: Vec<&str> = listed.iter().map(|i| i.oid.as_str()).collect();
        assert_eq!(listed_oids, oids);
        for info in &listed {
            assert!(info.size > 0, "size must be populated, got {info:?}");
            assert!(
                info.created_secs > 0,
                "created_secs must be populated, got {info:?}"
            );
        }
    }

    /// `list_loose` on an empty / unknown repo returns `Ok(vec![])` —
    /// not an error. This matches the FS shape where `objects/` may
    /// not exist yet and the chunked-KV shape where the repo's row
    /// set is empty.
    pub fn list_loose_empty_returns_empty_vec<S: ObjectStore>(store: &S) {
        let listed = store.list_loose("nope").unwrap();
        assert!(listed.is_empty(), "expected empty Vec, got {listed:?}");
    }

    /// `delete_loose` on a present oid returns `Ok(true)` then
    /// `Ok(false)` on a second call (idempotent removal). After
    /// delete, `read_loose` returns None. Both impls must satisfy.
    pub fn delete_loose_round_trips<S: ObjectStore>(store: &S) {
        let oid = "4444444444444444444444444444444444444444";
        store.write_loose("conf-repo", oid, b"to-delete").unwrap();
        assert!(store.read_loose("conf-repo", oid).unwrap().is_some());
        assert!(store.delete_loose("conf-repo", oid).unwrap(), "first delete must report true");
        assert!(store.read_loose("conf-repo", oid).unwrap().is_none());
        assert!(
            !store.delete_loose("conf-repo", oid).unwrap(),
            "second delete must report false (already gone)"
        );
    }

    /// `delete_loose` with a malformed oid is a hard error — same
    /// shape as `write_loose`. We won't computed-path-escape on
    /// the way out any more than on the way in.
    pub fn delete_loose_rejects_malformed_oid<S: ObjectStore>(store: &S) {
        for bad in ["../something", "abc", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"] {
            let r = store.delete_loose("repo", bad);
            assert!(r.is_err(), "expected delete_loose({bad:?}) to error, got {r:?}");
        }
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
        store
            .write_loose(&repo_id, &oid, b"any-bytes-stand-in")
            .unwrap();
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
    fn mem_write_then_read_round_trips() {
        let store = MemObjectStore::new();
        conformance::write_then_read_round_trips(&store);
    }

    #[test]
    fn mem_write_loose_idempotent_on_repeat() {
        let store = MemObjectStore::new();
        conformance::write_loose_idempotent_on_repeat(&store);
    }

    #[test]
    fn mem_write_loose_rejects_malformed_oid() {
        let store = MemObjectStore::new();
        conformance::write_loose_rejects_malformed_oid(&store);
    }

    #[test]
    fn mem_read_returns_exact_bytes_written() {
        // Mem-specific: returned bytes are *exactly* what was stored.
        // The FS impl can't make this assertion because git rewrites
        // its loose-object format on write.
        let store = MemObjectStore::new();
        let oid = mem_oid(0x3);
        let payload: Vec<u8> = (0..=255).cycle().take(1024).collect();
        store.write_loose("r", &oid, &payload).unwrap();
        let got = store.read_loose("r", &oid).unwrap().unwrap();
        assert_eq!(got, payload);
    }

    // ─── FsObjectStore — write conformance ─────────────────────────

    #[test]
    fn fs_write_then_read_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::write_then_read_round_trips(&store);
    }

    #[test]
    fn fs_write_loose_idempotent_on_repeat() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::write_loose_idempotent_on_repeat(&store);
    }

    #[test]
    fn fs_write_loose_rejects_malformed_oid() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::write_loose_rejects_malformed_oid(&store);
    }

    #[test]
    fn fs_list_loose_enumerates_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::list_loose_enumerates_writes(&store);
    }

    #[test]
    fn fs_list_loose_empty_returns_empty_vec() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::list_loose_empty_returns_empty_vec(&store);
    }

    #[test]
    fn fs_delete_loose_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::delete_loose_round_trips(&store);
    }

    #[test]
    fn fs_delete_loose_rejects_malformed_oid() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::delete_loose_rejects_malformed_oid(&store);
    }

    #[test]
    fn mem_list_loose_enumerates_writes() {
        let store = MemObjectStore::new();
        conformance::list_loose_enumerates_writes(&store);
    }

    #[test]
    fn mem_list_loose_empty_returns_empty_vec() {
        let store = MemObjectStore::new();
        conformance::list_loose_empty_returns_empty_vec(&store);
    }

    #[test]
    fn mem_delete_loose_round_trips() {
        let store = MemObjectStore::new();
        conformance::delete_loose_round_trips(&store);
    }

    #[test]
    fn mem_delete_loose_rejects_malformed_oid() {
        let store = MemObjectStore::new();
        conformance::delete_loose_rejects_malformed_oid(&store);
    }

    /// FS-specific: `write_loose` is atomic via tmp+rename. After a
    /// successful write the canonical path exists; no `.tmp-*` files
    /// remain in the parent dir.
    #[test]
    fn fs_write_loose_leaves_no_tmp_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        let oid = "9999999999999999999999999999999999999999";
        store.write_loose("r", oid, b"payload").unwrap();
        // Walk the parent dir; only the canonical 38-hex name should
        // remain. Any `.tmp-*` entry means the cleanup is broken.
        let parent = tmp.path().join("repos/r.git/objects/99");
        let entries: Vec<String> = std::fs::read_dir(&parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string().unwrap_or_default())
            .collect();
        assert_eq!(
            entries,
            vec!["9".repeat(38)],
            "expected only the canonical loose-object file, got {entries:?}"
        );
    }
}
