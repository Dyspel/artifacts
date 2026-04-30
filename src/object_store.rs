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
//! ## What this commit *does* deliver
//!
//! - The trait + the FS impl so the seam is named and tested.
//! - A minimal "round-trip a loose object" test that pins down
//!   the contract: returned bytes are the *raw zlib-compressed
//!   loose-object payload*, not the deflated content. Callers
//!   (gix-object) decode them.
//! - Documentation that says, plainly, that production code
//!   doesn't route through this yet.

use crate::error::{Error, Result};
use std::path::PathBuf;

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
        // gets rejected.
        if oid.len() != 40 || !oid.chars().all(|c| c.is_ascii_hexdigit()) {
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

    #[test]
    fn read_loose_returns_zlib_payload_for_existing_object() {
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));
        let oid = write_blob(&git_dir, b"hello\n");

        let store = FsObjectStore::new(&repos);
        let bytes = store.read_loose(&repo_id, &oid).unwrap().expect("found");
        // Loose objects start with the zlib magic byte 0x78 (low-nibble
        // = 0x8 means deflate at the default window size).
        assert_eq!(bytes[0], 0x78);
        // And a non-empty payload.
        assert!(bytes.len() > 2);
    }

    #[test]
    fn read_loose_returns_none_for_unknown_oid() {
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();

        let store = FsObjectStore::new(&repos);
        let absent = "0123456789abcdef0123456789abcdef01234567";
        assert!(store.read_loose(&repo_id, absent).unwrap().is_none());
    }

    #[test]
    fn read_loose_rejects_non_hex_oid() {
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let store = FsObjectStore::new(&repos);
        // Path-traversal attempt — we should never compute a path
        // for "../foo".
        assert!(
            store
                .read_loose("repo", "../something/with/slash/and/some/more/x")
                .unwrap()
                .is_none(),
        );
        // Wrong length.
        assert!(store.read_loose("repo", "abc").unwrap().is_none());
        // Non-hex.
        assert!(
            store
                .read_loose("repo", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
                .unwrap()
                .is_none()
        );
    }
}
