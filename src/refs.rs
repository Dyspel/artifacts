//! `RefStore`: the ref-level compare-and-swap abstraction.
//!
//! Refs are the single place in a git repo where concurrency lives. Every
//! push and every REST-side commit is, at the bottom, a `CAS(ref, expected,
//! new)`. If that CAS is wrong, two concurrent writers can tombstone each
//! other's commits and the repo silently loses data. If the CAS is right,
//! everything else in the system can be eventually-consistent.
//!
//! This module exists so that **the rest of the codebase never writes a ref
//! directly.** Everything goes through the trait, so when M3-proper swaps
//! filesystem refs for a distributed state machine (DurableObject, Raft
//! group, whatever), the callers don't change.
//!
//! The single concrete impl today — `FsRefStore` — shells out to
//! `git update-ref`, which on a single machine provides CAS via flock +
//! rename. That's correct for M0 and fine for any deployment that pins a
//! repo to a single node.

use crate::error::{Error, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// The 40-char SHA that `update-ref` interprets as "ref must not exist".
const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

/// Outcome of a CAS. We distinguish "update applied" from "lost the race"
/// because the latter is a normal, expected outcome in a concurrent system
/// — 409 Conflict at the HTTP layer, worth a retry, not a 5xx.
#[derive(Debug, PartialEq, Eq)]
pub enum CasOutcome {
    Updated,
    Conflict {
        /// The ref's current value, if we could read it back. Lets the
        /// caller return a useful 409 body without a second round trip.
        current: Option<String>,
    },
}

/// Strongly-consistent per-repo ref CAS. The trait is the whole interface.
#[async_trait]
pub trait RefStore: Send + Sync {
    /// Read a ref by full name (e.g. `refs/heads/main`). `None` = absent.
    async fn read(&self, repo_id: &str, ref_name: &str) -> Result<Option<String>>;

    /// Atomically set `ref_name` to `new_sha`.
    ///
    /// - If `expected` is `Some`, the update succeeds iff the current value
    ///   equals that SHA.
    /// - If `expected` is `None`, the update succeeds iff the ref does not
    ///   yet exist.
    async fn cas_update(
        &self,
        repo_id: &str,
        ref_name: &str,
        expected: Option<&str>,
        new_sha: &str,
    ) -> Result<CasOutcome>;
}

/// Filesystem-backed `RefStore` via `git update-ref`. Single-node only.
#[derive(Clone)]
pub struct FsRefStore {
    pub repos_dir: PathBuf,
}

impl FsRefStore {
    pub fn new(repos_dir: PathBuf) -> Self {
        Self { repos_dir }
    }

    fn repo_path(&self, repo_id: &str) -> PathBuf {
        self.repos_dir.join(format!("{repo_id}.git"))
    }
}

#[async_trait]
impl RefStore for FsRefStore {
    async fn read(&self, repo_id: &str, ref_name: &str) -> Result<Option<String>> {
        let git_dir = self.repo_path(repo_id);
        let (rc, stdout, _) = run_git(&git_dir, &["rev-parse", "--verify", ref_name]).await?;
        if rc != 0 {
            return Ok(None);
        }
        let s = String::from_utf8(stdout)?.trim().to_string();
        if s.is_empty() {
            Ok(None)
        } else {
            Ok(Some(s))
        }
    }

    async fn cas_update(
        &self,
        repo_id: &str,
        ref_name: &str,
        expected: Option<&str>,
        new_sha: &str,
    ) -> Result<CasOutcome> {
        let git_dir = self.repo_path(repo_id);
        let expected_arg = expected.unwrap_or(ZERO_SHA);
        let (rc, _, stderr) = run_git(
            &git_dir,
            &["update-ref", ref_name, new_sha, expected_arg],
        )
        .await?;
        if rc == 0 {
            return Ok(CasOutcome::Updated);
        }
        tracing::debug!(
            repo = %repo_id, ref_name = %ref_name,
            stderr = %String::from_utf8_lossy(&stderr),
            "update-ref non-zero; treating as conflict"
        );
        let current = self.read(repo_id, ref_name).await.ok().flatten();
        Ok(CasOutcome::Conflict { current })
    }
}

async fn run_git(git_dir: &Path, args: &[&str]) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut cmd = Command::new("git");
    cmd.arg("--git-dir").arg(git_dir).args(args);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
    let mut child = cmd.spawn().map_err(Error::from)?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut p) = child.stdout.take() {
        p.read_to_end(&mut stdout).await?;
    }
    if let Some(mut p) = child.stderr.take() {
        p.read_to_end(&mut stderr).await?;
    }
    let s = child.wait().await?;
    Ok((s.code().unwrap_or(-1), stdout, stderr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{new_repo_id, Storage};

    fn setup_repo() -> (PathBuf, String, FsRefStore) {
        let tmp = std::env::temp_dir().join(format!("refs-test-{}", new_repo_id()));
        let repos_dir = tmp.join("repos");
        let storage = Storage::new(&repos_dir).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let refs = FsRefStore::new(repos_dir);
        (tmp, repo_id, refs)
    }

    /// Write `bytes` as a blob into the given bare repo and return its SHA.
    /// Used to populate the object DB with writable targets so `update-ref`
    /// (which verifies the target exists) will accept our CAS updates.
    fn write_blob(git_dir: &Path, bytes: &[u8]) -> String {
        use std::io::Write as _;
        let mut child = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn git hash-object");
        child
            .stdin
            .as_mut()
            .expect("stdin piped")
            .write_all(bytes)
            .expect("write blob bytes");
        let out = child.wait_with_output().expect("wait hash-object");
        assert!(
            out.status.success(),
            "hash-object failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let s = String::from_utf8(out.stdout).unwrap().trim().to_string();
        assert_eq!(s.len(), 40, "expected 40-char sha, got {s:?}");
        s
    }

    #[tokio::test]
    async fn read_nonexistent_ref_returns_none() {
        let (_tmp, repo, refs) = setup_repo();
        let r = refs.read(&repo, "refs/heads/nope").await.unwrap();
        assert_eq!(r, None);
    }

    #[tokio::test]
    async fn cas_update_creates_ref_when_expected_none() {
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let sha = write_blob(&git_dir, b"hello");

        let out = refs.cas_update(&repo, "refs/test/t", None, &sha).await.unwrap();
        assert_eq!(out, CasOutcome::Updated);
        let r = refs.read(&repo, "refs/test/t").await.unwrap();
        assert_eq!(r.as_deref(), Some(sha.as_str()));
    }

    #[tokio::test]
    async fn cas_update_rejects_stale_expected() {
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let s1 = write_blob(&git_dir, b"one");
        let s2 = write_blob(&git_dir, b"two");
        let s3 = write_blob(&git_dir, b"three");

        // create
        assert_eq!(
            refs.cas_update(&repo, "refs/test/x", None, &s1).await.unwrap(),
            CasOutcome::Updated
        );
        // expected=s1 -> succeeds, now at s2
        assert_eq!(
            refs.cas_update(&repo, "refs/test/x", Some(&s1), &s2).await.unwrap(),
            CasOutcome::Updated
        );
        // expected=s1 (stale) -> conflict, current should be s2
        match refs.cas_update(&repo, "refs/test/x", Some(&s1), &s3).await.unwrap() {
            CasOutcome::Conflict { current } => {
                assert_eq!(current.as_deref(), Some(s2.as_str()));
            }
            other => panic!("wanted conflict, got {other:?}"),
        }
    }
}
