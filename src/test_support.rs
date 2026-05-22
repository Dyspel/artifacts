//! Shared test fixtures.
//!
//! Tests previously inlined the same `tempdir + FsStorage::new +
//! create + git_dir.join(...)` setup in five modules. Every new test
//! had to copy four lines and remember to assign `_d` to extend the
//! TempDir lifetime past the assertions. Centralizing means one place
//! to keep the path conventions consistent, and one place to fix when
//! a backend swap (e.g. M3b's RefStore) changes the construction
//! shape.
//!
//! The whole module is gated `#[cfg(test)]` so no production binary
//! ever references it.

use crate::refs::FsRefStore;
use crate::storage::{new_repo_id, FsStorage, Storage};
use std::path::PathBuf;
use tempfile::TempDir;

/// A fresh empty bare repo on disk. Returned together with the
/// `TempDir` so the caller can keep it alive past the assertions —
/// dropping the `TempDir` removes the directory.
///
/// Production code uses the same `FsStorage::new` + `create` path; the
/// only difference is the temp root.
pub struct TestRepo {
    /// Lifetime-anchor for the temp dir — held for its `Drop`,
    /// which cleans up the directory tree. Read by no test, which
    /// is exactly what we want: dropping `TestRepo` is what
    /// triggers cleanup, not a `tmp.close()` call. Allow the
    /// dead-field lint locally for this one false-positive.
    #[allow(dead_code)]
    tmp: TempDir,
    /// Container of `<repo_id>.git`, suitable for `FsRefStore::new`
    /// and `FsObjectStore::new`.
    pub repos_dir: PathBuf,
    pub repo_id: String,
    /// `<repos_dir>/<repo_id>.git` — what every git subprocess +
    /// `gix::open` call wants.
    pub git_dir: PathBuf,
}

impl Default for TestRepo {
    fn default() -> Self {
        Self::new()
    }
}

impl TestRepo {
    /// Construct a fresh, empty bare repo with a random id.
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repos_dir = tmp.path().join("repos");
        let storage = FsStorage::new(&repos_dir).expect("FsStorage::new");
        let repo_id = new_repo_id();
        storage.create(&repo_id).expect("create repo");
        let git_dir = repos_dir.join(format!("{repo_id}.git"));
        Self {
            tmp,
            repos_dir,
            repo_id,
            git_dir,
        }
    }

    /// `FsRefStore` rooted at the same `repos_dir`.
    pub fn fs_refs(&self) -> FsRefStore {
        FsRefStore::new(self.repos_dir.clone())
    }
}
