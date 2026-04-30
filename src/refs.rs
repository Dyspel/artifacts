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

/// One row in a ref-listing response (the kind ls-refs produces).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEntry {
    pub name: String,
    pub oid: String,
    /// For annotated tags: the OID the tag dereferences to. `None` for
    /// branches, lightweight tags, and (today) all our native enumerations
    /// — peel resolution requires reading the tag object, which the
    /// FS-native lister doesn't do yet. Filled in by the fallback path
    /// when the upload-pack subprocess produces it.
    pub peeled: Option<String>,
}

/// HEAD's three possible states. Distinguishing them is the whole job of
/// the v2 `unborn` capability — clients want to know whether HEAD points
/// at a real OID, at a not-yet-created branch (fresh repo), or at a
/// detached commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadState {
    /// `ref: refs/heads/main` and that ref resolves to an OID.
    Symbolic { target: String, oid: String },
    /// `ref: refs/heads/main` but the target has no commits yet.
    Unborn { target: String },
    /// HEAD is a raw OID (detached).
    Detached { oid: String },
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

    /// Atomically delete `ref_name`. The CAS variant prevents
    /// surprise-races: a delete that arrives after some other writer
    /// updated the ref reports `Conflict { current }` so the caller
    /// can return the wire-protocol "non-fast-forward" / "stale info"
    /// error instead of silently dropping the more-recent commit.
    ///
    /// `expected = None` means "delete unconditionally" — only
    /// callers that have already validated freshness elsewhere
    /// should pass this. The HTTP push path always has an expected
    /// (the OID the client thought the ref had), so it threads it
    /// through.
    ///
    /// Default impl errors so trait callers see a clear "this
    /// backend doesn't implement deletes" instead of silently
    /// no-op'ing. Concrete stores override.
    async fn cas_delete(
        &self,
        _repo_id: &str,
        _ref_name: &str,
        _expected: Option<&str>,
    ) -> Result<CasOutcome> {
        Err(Error::Other(anyhow::anyhow!(
            "RefStore::cas_delete not implemented for this backend"
        )))
    }

    /// Enumerate refs whose name starts with any of `prefixes`. An empty
    /// `prefixes` slice means "all refs". Order is unspecified — the
    /// caller (e.g. ls-refs) sorts as needed.
    ///
    /// Default impl errors; concrete stores override. We give a default
    /// rather than `unimplemented!()` so callers can detect "this store
    /// doesn't support enumeration" without a panic — useful for
    /// future stores that genuinely can't enumerate (e.g. a chunked KV
    /// without a secondary index).
    async fn list(&self, _repo_id: &str, _prefixes: &[String]) -> Result<Vec<RefEntry>> {
        Err(Error::Other(anyhow::anyhow!(
            "RefStore::list not implemented for this backend"
        )))
    }

    /// Read HEAD's symref/detached/unborn state. Default errors as above.
    async fn read_head(&self, _repo_id: &str) -> Result<HeadState> {
        Err(Error::Other(anyhow::anyhow!(
            "RefStore::read_head not implemented for this backend"
        )))
    }
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

    async fn list(&self, repo_id: &str, prefixes: &[String]) -> Result<Vec<RefEntry>> {
        let git_dir = self.repo_path(repo_id);
        let entries = enumerate_refs(&git_dir)?;
        if prefixes.is_empty() {
            return Ok(entries);
        }
        Ok(entries
            .into_iter()
            .filter(|e| prefixes.iter().any(|p| e.name.starts_with(p)))
            .collect())
    }

    async fn read_head(&self, repo_id: &str) -> Result<HeadState> {
        let git_dir = self.repo_path(repo_id);
        head_state(&git_dir)
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

    async fn cas_delete(
        &self,
        repo_id: &str,
        ref_name: &str,
        expected: Option<&str>,
    ) -> Result<CasOutcome> {
        let git_dir = self.repo_path(repo_id);
        // `git update-ref -d <ref> [old-sha]` deletes; with
        // expected, requires the ref to currently equal old-sha
        // (CAS). Without expected we pass no extra arg, which makes
        // git delete unconditionally.
        let (rc, _, stderr) = if let Some(exp) = expected {
            run_git(&git_dir, &["update-ref", "-d", ref_name, exp]).await?
        } else {
            run_git(&git_dir, &["update-ref", "-d", ref_name]).await?
        };
        if rc == 0 {
            return Ok(CasOutcome::Updated);
        }
        tracing::debug!(
            repo = %repo_id, ref_name = %ref_name,
            stderr = %String::from_utf8_lossy(&stderr),
            "update-ref -d non-zero; treating as conflict"
        );
        let current = self.read(repo_id, ref_name).await.ok().flatten();
        Ok(CasOutcome::Conflict { current })
    }
}

/// In-process `RefStore` impl backed by HashMaps under a Mutex.
///
/// Not wired into production today — held as M3b foundation per
/// the README. `#[allow(dead_code)]` on the type and its impls
/// keeps the unused warning off the trait scaffolding so a real
/// signal (e.g. a dead helper) isn't lost in the noise.
///
/// Why this exists (M3b foundation): the production `FsRefStore` shells
/// out to `git update-ref` for CAS — that's a single-node guarantee that
/// breaks the moment two `artifacts serve` processes share a repos dir.
/// Real distributed CAS belongs in a consensus log (Raft, in something
/// like `openraft`/`raft-rs`), which is multi-week work and not in scope
/// for this session.
///
/// What this *is* good for:
///   - tests (no fork+exec on every CAS makes test suites way faster);
///   - validating that the trait shape is sufficient for non-FS impls;
///   - a stand-in for the eventual replicated impl during integration
///     work — the two will be swap-in compatible.
///
/// What this is **NOT** good for:
///   - production. Loses all state on restart, and there's no
///     replication. A second process with its own MemRefStore can't see
///     these refs.
///
/// CAS is implemented as a check-and-update under a single per-store
/// Mutex. That's strict serializability, not just linearizability —
/// stronger than what `FsRefStore` gives you (which is per-ref flock).
/// Stronger is fine; tests don't notice.
#[allow(dead_code)]
pub struct MemRefStore {
    inner: std::sync::Mutex<MemState>,
}

#[allow(dead_code)]
#[derive(Default)]
struct MemState {
    /// `(repo_id, ref_name) -> oid`.
    refs: std::collections::HashMap<(String, String), String>,
    /// `repo_id -> head_state`. Defaults to the same `Unborn { target:
    /// "refs/heads/main" }` that `git init --bare --initial-branch=main`
    /// produces, so callers can treat MemRefStore as drop-in for a
    /// freshly-initialized FsRefStore.
    heads: std::collections::HashMap<String, HeadState>,
}

impl Default for MemRefStore {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl MemRefStore {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(MemState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemState> {
        // Poison recovery: we never violate an invariant under a panic
        // (a panic mid-CAS leaves the map in either the pre- or post-
        // state, both of which are valid). So treating the lock as
        // never-poisoned is safe.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[async_trait]
impl RefStore for MemRefStore {
    async fn read(&self, repo_id: &str, ref_name: &str) -> Result<Option<String>> {
        let g = self.lock();
        Ok(g.refs.get(&(repo_id.to_string(), ref_name.to_string())).cloned())
    }

    async fn cas_update(
        &self,
        repo_id: &str,
        ref_name: &str,
        expected: Option<&str>,
        new_sha: &str,
    ) -> Result<CasOutcome> {
        let mut g = self.lock();
        let key = (repo_id.to_string(), ref_name.to_string());
        let current = g.refs.get(&key).cloned();
        let matches = match (expected, current.as_deref()) {
            (None, None) => true,
            (Some(e), Some(c)) => e == c,
            _ => false,
        };
        if !matches {
            return Ok(CasOutcome::Conflict { current });
        }
        g.refs.insert(key, new_sha.to_string());
        Ok(CasOutcome::Updated)
    }

    async fn list(&self, repo_id: &str, prefixes: &[String]) -> Result<Vec<RefEntry>> {
        let g = self.lock();
        let mut out: Vec<RefEntry> = g
            .refs
            .iter()
            .filter(|((r, _), _)| r == repo_id)
            .filter(|((_, name), _)| {
                prefixes.is_empty() || prefixes.iter().any(|p| name.starts_with(p))
            })
            .map(|((_, name), oid)| RefEntry {
                name: name.clone(),
                oid: oid.clone(),
                peeled: None,
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn read_head(&self, repo_id: &str) -> Result<HeadState> {
        let g = self.lock();
        Ok(g.heads
            .get(repo_id)
            .cloned()
            .unwrap_or_else(|| HeadState::Unborn {
                target: "refs/heads/main".to_string(),
            }))
    }

    async fn cas_delete(
        &self,
        repo_id: &str,
        ref_name: &str,
        expected: Option<&str>,
    ) -> Result<CasOutcome> {
        let mut g = self.lock();
        let key = (repo_id.to_string(), ref_name.to_string());
        let current = g.refs.get(&key).cloned();
        let matches = match (expected, current.as_deref()) {
            (None, _) => true, // unconditional delete
            (Some(e), Some(c)) => e == c,
            (Some(_), None) => false,
        };
        if !matches {
            return Ok(CasOutcome::Conflict { current });
        }
        g.refs.remove(&key);
        Ok(CasOutcome::Updated)
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

/// Native ref enumeration. Reads `packed-refs` once (if present), then
/// walks the loose-ref tree under `refs/`. Loose refs override packed.
///
/// We deliberately do NOT shell out to `git for-each-ref` here — that's
/// the whole point of M1b-2a, killing the subprocess on the read path.
/// Loose ref files are 41 bytes each (40-hex + LF) and packed-refs is a
/// single bounded text file, so the disk cost is trivial compared to a
/// fork+exec.
///
/// We do NOT resolve peeled OIDs for annotated tags. That requires
/// reading the tag object out of the loose/packed object DB, which is
/// the kind of work `gix` is for and lands in M1b-2b. Modern git
/// clients tolerate missing peel annotations (will just fetch unpeeled).
fn enumerate_refs(git_dir: &Path) -> Result<Vec<RefEntry>> {
    use std::collections::HashMap;
    let mut by_name: HashMap<String, RefEntry> = HashMap::new();

    // packed-refs first.
    let packed = git_dir.join("packed-refs");
    if let Ok(text) = std::fs::read_to_string(&packed) {
        let mut last_name: Option<String> = None;
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // `^<sha>` is a peeled annotation for the previous ref —
            // git emits these for annotated tags. We attach to the
            // last seen ref.
            if let Some(peel) = line.strip_prefix('^') {
                if let Some(name) = &last_name {
                    if let Some(e) = by_name.get_mut(name) {
                        e.peeled = Some(peel.trim().to_string());
                    }
                }
                continue;
            }
            // `<sha> <name>`
            if let Some((sha, name)) = line.split_once(' ') {
                let entry = RefEntry {
                    name: name.to_string(),
                    oid: sha.to_string(),
                    peeled: None,
                };
                by_name.insert(entry.name.clone(), entry);
                last_name = Some(name.to_string());
            }
        }
    }

    // Loose refs override packed. Walk `refs/` recursively.
    let refs_dir = git_dir.join("refs");
    if refs_dir.is_dir() {
        let mut stack = vec![refs_dir.clone()];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for ent in entries.flatten() {
                let path = ent.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let s = match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let oid = s.trim().to_string();
                // 40-hex check; symbolic-ref files (`ref: ...`) under
                // refs/ are theoretically possible but not produced by
                // anything we run — skip them defensively.
                if oid.len() != 40 || !oid.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                let rel = match path.strip_prefix(git_dir) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                // Build the full ref name with forward slashes regardless
                // of platform. We control the format on creation, so
                // backslashes shouldn't appear, but be explicit.
                let name = rel
                    .components()
                    .filter_map(|c| c.as_os_str().to_str())
                    .collect::<Vec<_>>()
                    .join("/");
                by_name.insert(
                    name.clone(),
                    RefEntry {
                        name,
                        oid,
                        peeled: None,
                    },
                );
            }
        }
    }

    let mut out: Vec<RefEntry> = by_name.into_values().collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Native HEAD parser. HEAD is one of:
///   - `ref: refs/heads/main\n`  (symbolic — common case)
///   - `<40-hex>\n`              (detached — `git checkout <sha>`)
///
/// For the symbolic case we resolve the target by reading the loose ref
/// or packed-refs entry. If the target doesn't exist we report Unborn,
/// which the v2 ls-refs `unborn` capability lets us advertise to clients.
fn head_state(git_dir: &Path) -> Result<HeadState> {
    let head_path = git_dir.join("HEAD");
    let raw = std::fs::read_to_string(&head_path)?;
    let trimmed = raw.trim();
    if let Some(target) = trimmed.strip_prefix("ref: ") {
        let target = target.trim().to_string();
        // Try the loose ref file first.
        let loose = git_dir.join(&target);
        if let Ok(s) = std::fs::read_to_string(&loose) {
            let oid = s.trim().to_string();
            if oid.len() == 40 {
                return Ok(HeadState::Symbolic { target, oid });
            }
        }
        // Fall back to packed-refs.
        let packed = git_dir.join("packed-refs");
        if let Ok(text) = std::fs::read_to_string(&packed) {
            for line in text.lines() {
                if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
                    continue;
                }
                if let Some((sha, name)) = line.split_once(' ') {
                    if name == target {
                        return Ok(HeadState::Symbolic {
                            target,
                            oid: sha.to_string(),
                        });
                    }
                }
            }
        }
        Ok(HeadState::Unborn { target })
    } else if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(HeadState::Detached {
            oid: trimmed.to_string(),
        })
    } else {
        Err(Error::Other(anyhow::anyhow!(
            "unrecognized HEAD format: {trimmed:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{new_repo_id, FsStorage, Storage};

    fn setup_repo() -> (PathBuf, String, FsRefStore) {
        let tmp = std::env::temp_dir().join(format!("refs-test-{}", new_repo_id()));
        let repos_dir = tmp.join("repos");
        let storage = FsStorage::new(&repos_dir).unwrap();
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

    /// Conformance: any `RefStore` impl must satisfy the same CAS
    /// invariants. We exercise the in-memory impl here so the trait's
    /// expectations are explicit; when a future ReplicatedRefStore
    /// arrives, point it at the same suite.
    mod mem_conformance {
        use super::*;

        #[tokio::test]
        async fn cas_create_then_update_then_stale_conflicts() {
            let s = MemRefStore::new();
            // create
            assert_eq!(
                s.cas_update("r", "refs/heads/x", None, "0123456789012345678901234567890123456789").await.unwrap(),
                CasOutcome::Updated,
            );
            // update under matching expected
            assert_eq!(
                s.cas_update(
                    "r",
                    "refs/heads/x",
                    Some("0123456789012345678901234567890123456789"),
                    "abcabcabcabcabcabcabcabcabcabcabcabcabca",
                )
                .await
                .unwrap(),
                CasOutcome::Updated,
            );
            // stale expected → conflict, current returned
            match s
                .cas_update(
                    "r",
                    "refs/heads/x",
                    Some("0123456789012345678901234567890123456789"),
                    "ffffffffffffffffffffffffffffffffffffffff",
                )
                .await
                .unwrap()
            {
                CasOutcome::Conflict { current } => {
                    assert_eq!(
                        current.as_deref(),
                        Some("abcabcabcabcabcabcabcabcabcabcabcabcabca"),
                    );
                }
                other => panic!("expected Conflict, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn read_returns_none_for_missing_ref() {
            let s = MemRefStore::new();
            assert!(s.read("r", "refs/heads/nope").await.unwrap().is_none());
        }

        #[tokio::test]
        async fn read_head_defaults_to_unborn_main() {
            let s = MemRefStore::new();
            match s.read_head("r").await.unwrap() {
                HeadState::Unborn { target } => assert_eq!(target, "refs/heads/main"),
                other => panic!("expected Unborn, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn list_filters_by_prefix() {
            let s = MemRefStore::new();
            s.cas_update("r", "refs/heads/main", None, "0".repeat(40).as_str())
                .await
                .unwrap();
            s.cas_update("r", "refs/tags/v1", None, "0".repeat(40).as_str())
                .await
                .unwrap();
            let heads = s.list("r", &["refs/heads/".into()]).await.unwrap();
            assert_eq!(heads.len(), 1);
            assert_eq!(heads[0].name, "refs/heads/main");
        }

        #[tokio::test]
        async fn cas_delete_removes_when_expected_matches() {
            let s = MemRefStore::new();
            let oid = "0".repeat(40);
            s.cas_update("r", "refs/heads/x", None, &oid).await.unwrap();
            assert!(s.read("r", "refs/heads/x").await.unwrap().is_some());
            assert_eq!(
                s.cas_delete("r", "refs/heads/x", Some(&oid)).await.unwrap(),
                CasOutcome::Updated,
            );
            assert!(s.read("r", "refs/heads/x").await.unwrap().is_none());
        }

        #[tokio::test]
        async fn cas_delete_conflicts_when_expected_stale() {
            let s = MemRefStore::new();
            let oid_old = "0".repeat(40);
            let oid_new = "1".repeat(40);
            s.cas_update("r", "refs/heads/x", None, &oid_old).await.unwrap();
            s.cas_update("r", "refs/heads/x", Some(&oid_old), &oid_new).await.unwrap();
            // Try deleting with the stale oid — should conflict and
            // return current.
            match s.cas_delete("r", "refs/heads/x", Some(&oid_old)).await.unwrap() {
                CasOutcome::Conflict { current } => {
                    assert_eq!(current.as_deref(), Some(oid_new.as_str()));
                }
                other => panic!("expected Conflict, got {other:?}"),
            }
            // Ref is still present — delete didn't happen.
            assert!(s.read("r", "refs/heads/x").await.unwrap().is_some());
        }

        #[tokio::test]
        async fn cas_delete_unconditional_when_expected_none() {
            let s = MemRefStore::new();
            s.cas_update("r", "refs/heads/x", None, &"0".repeat(40))
                .await
                .unwrap();
            // expected=None bypasses the equality check.
            assert_eq!(
                s.cas_delete("r", "refs/heads/x", None).await.unwrap(),
                CasOutcome::Updated,
            );
            assert!(s.read("r", "refs/heads/x").await.unwrap().is_none());
        }

        #[tokio::test]
        async fn concurrent_cas_only_one_winner() {
            // Property test: if two writers race a create-from-None,
            // exactly one Updated and exactly one Conflict come out.
            // Repeated rounds shake out timing-dependent bugs.
            let s = std::sync::Arc::new(MemRefStore::new());
            for round in 0..50 {
                let s1 = s.clone();
                let s2 = s.clone();
                let oid_a = format!("a{:039}", round);
                let oid_b = format!("b{:039}", round);
                let ref_name = format!("refs/round/{round}");

                let h1 = tokio::spawn({
                    let r = ref_name.clone();
                    let oid = oid_a.clone();
                    async move {
                        s1.cas_update("r", &r, None, &oid).await.unwrap()
                    }
                });
                let h2 = tokio::spawn({
                    let r = ref_name.clone();
                    let oid = oid_b.clone();
                    async move {
                        s2.cas_update("r", &r, None, &oid).await.unwrap()
                    }
                });
                let r1 = h1.await.unwrap();
                let r2 = h2.await.unwrap();
                let updates = matches!(r1, CasOutcome::Updated) as u32
                    + matches!(r2, CasOutcome::Updated) as u32;
                let conflicts = matches!(r1, CasOutcome::Conflict { .. }) as u32
                    + matches!(r2, CasOutcome::Conflict { .. }) as u32;
                assert_eq!(updates, 1, "round {round} got {updates} updates");
                assert_eq!(conflicts, 1, "round {round} got {conflicts} conflicts");
            }
        }
    }

    #[tokio::test]
    async fn list_returns_refs_under_arbitrary_namespaces() {
        // Note: refs/heads/* requires commit targets via `update-ref`, so
        // we use refs/test/* and refs/tags/* (which accept any object) to
        // exercise enumeration without spinning up real commits.
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let s = write_blob(&git_dir, b"hello");
        refs.cas_update(&repo, "refs/test/a", None, &s)
            .await
            .unwrap();
        refs.cas_update(&repo, "refs/test/sub/b", None, &s)
            .await
            .unwrap();
        refs.cas_update(&repo, "refs/tags/v1", None, &s)
            .await
            .unwrap();

        let all = refs.list(&repo, &[]).await.unwrap();
        let names: Vec<&str> = all.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"refs/test/a"));
        assert!(names.contains(&"refs/test/sub/b"));
        assert!(names.contains(&"refs/tags/v1"));
        // Sorted lex.
        for w in all.windows(2) {
            assert!(w[0].name <= w[1].name, "list not sorted: {:?}", names);
        }
        // Filter by prefix.
        let only_test = refs
            .list(&repo, &["refs/test/".to_string()])
            .await
            .unwrap();
        assert!(only_test.iter().all(|e| e.name.starts_with("refs/test/")));
        assert_eq!(only_test.len(), 2);
    }

    #[tokio::test]
    async fn read_head_unborn_on_fresh_repo() {
        let (_tmp, repo, refs) = setup_repo();
        // git init --bare --initial-branch=main writes HEAD = ref: refs/heads/main
        // but the ref doesn't exist yet — that's "unborn".
        let st = refs.read_head(&repo).await.unwrap();
        match st {
            HeadState::Unborn { target } => assert_eq!(target, "refs/heads/main"),
            other => panic!("expected Unborn, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_head_symbolic_when_ref_resolved() {
        // Point HEAD at a non-heads namespace so we can write a blob-target
        // ref directly (update-ref enforces commit-targets only on
        // refs/heads/*). The resolution path is what's under test, not the
        // branch-shape-dance.
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let s = write_blob(&git_dir, b"hello");
        refs.cas_update(&repo, "refs/test/x", None, &s)
            .await
            .unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/test/x\n").unwrap();
        let st = refs.read_head(&repo).await.unwrap();
        match st {
            HeadState::Symbolic { target, oid } => {
                assert_eq!(target, "refs/test/x");
                assert_eq!(oid, s);
            }
            other => panic!("expected Symbolic, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_picks_up_packed_refs_and_loose_overrides() {
        // Hand-write a packed-refs file and a conflicting loose ref;
        // confirm enumerate_refs returns the loose value (loose wins
        // over packed per git's semantics).
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let s_packed = write_blob(&git_dir, b"packed");
        let s_loose = write_blob(&git_dir, b"loose");
        let packed_text = format!(
            "# pack-refs with: peeled\n{s_packed} refs/test/packed-only\n{s_packed} refs/test/conflict\n"
        );
        std::fs::write(git_dir.join("packed-refs"), packed_text).unwrap();
        // Loose conflict overrides the packed entry.
        std::fs::create_dir_all(git_dir.join("refs/test")).unwrap();
        std::fs::write(git_dir.join("refs/test/conflict"), format!("{s_loose}\n"))
            .unwrap();

        let all = refs.list(&repo, &[]).await.unwrap();
        let by_name: std::collections::HashMap<&str, &str> = all
            .iter()
            .map(|e| (e.name.as_str(), e.oid.as_str()))
            .collect();
        assert_eq!(by_name.get("refs/test/packed-only"), Some(&s_packed.as_str()));
        assert_eq!(by_name.get("refs/test/conflict"), Some(&s_loose.as_str()));
    }

    #[tokio::test]
    async fn list_attaches_peeled_oid_from_packed_refs() {
        // packed-refs uses `^<sha>` lines to annotate the previous ref
        // with a peeled OID for annotated tags. The native enumerator
        // must thread that through to RefEntry.peeled.
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let tag_oid = write_blob(&git_dir, b"tag-object");
        let peeled_oid = write_blob(&git_dir, b"peeled-target");
        let packed_text = format!(
            "# pack-refs with: peeled fully-peeled\n{tag_oid} refs/tags/annot\n^{peeled_oid}\n"
        );
        std::fs::write(git_dir.join("packed-refs"), packed_text).unwrap();
        let all = refs.list(&repo, &[]).await.unwrap();
        let entry = all
            .iter()
            .find(|e| e.name == "refs/tags/annot")
            .expect("annotated tag missing");
        assert_eq!(entry.oid, tag_oid);
        assert_eq!(entry.peeled.as_deref(), Some(peeled_oid.as_str()));
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
