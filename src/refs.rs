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
use crate::ids::{Oid, RefName, RepoId};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

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
        current: Option<Oid>,
    },
}

/// One row in a ref-listing response (the kind ls-refs produces).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEntry {
    pub name: RefName,
    pub oid: Oid,
    /// For annotated tags: the OID the tag dereferences to. `None` for
    /// branches, lightweight tags, and (today) all our native enumerations
    /// — peel resolution requires reading the tag object, which the
    /// FS-native lister doesn't do yet. Filled in by the fallback path
    /// when the upload-pack subprocess produces it.
    pub peeled: Option<Oid>,
}

/// HEAD's three possible states. Distinguishing them is the whole job of
/// the v2 `unborn` capability — clients want to know whether HEAD points
/// at a real OID, at a not-yet-created branch (fresh repo), or at a
/// detached commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadState {
    /// `ref: refs/heads/main` and that ref resolves to an OID.
    Symbolic { target: RefName, oid: Oid },
    /// `ref: refs/heads/main` but the target has no commits yet.
    Unborn { target: RefName },
    /// HEAD is a raw OID (detached).
    Detached { oid: Oid },
}

/// Strongly-consistent per-repo ref CAS. The trait is the whole interface.
#[async_trait]
pub trait RefStore: Send + Sync {
    /// Read a ref by full name (e.g. `refs/heads/main`). `None` = absent.
    async fn read(&self, repo_id: &RepoId, ref_name: &RefName) -> Result<Option<Oid>>;

    /// Atomically set `ref_name` to `new_sha`.
    ///
    /// - If `expected` is `Some`, the update succeeds iff the current value
    ///   equals that SHA.
    /// - If `expected` is `None`, the update succeeds iff the ref does not
    ///   yet exist.
    async fn cas_update(
        &self,
        repo_id: &RepoId,
        ref_name: &RefName,
        expected: Option<&Oid>,
        new_sha: &Oid,
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
        _repo_id: &RepoId,
        _ref_name: &RefName,
        _expected: Option<&Oid>,
    ) -> Result<CasOutcome> {
        Err(Error::Other(anyhow::anyhow!(
            "RefStore::cas_delete not implemented for this backend"
        )))
    }

    /// Enumerate refs whose name starts with any of `prefixes`. An empty
    /// `prefixes` slice means "all refs". Order is unspecified — the
    /// caller (e.g. ls-refs) sorts as needed.
    ///
    /// `prefixes` are free-form string prefixes (e.g. `"refs/heads/"`),
    /// not full `RefName`s — they don't have to satisfy the strict
    /// check-ref-format rules, so they stay as `String`.
    ///
    /// Default impl errors; concrete stores override. We give a default
    /// rather than `unimplemented!()` so callers can detect "this store
    /// doesn't support enumeration" without a panic — useful for
    /// future stores that genuinely can't enumerate (e.g. a chunked KV
    /// without a secondary index).
    async fn list(&self, _repo_id: &RepoId, _prefixes: &[String]) -> Result<Vec<RefEntry>> {
        Err(Error::Other(anyhow::anyhow!(
            "RefStore::list not implemented for this backend"
        )))
    }

    /// Read HEAD's symref/detached/unborn state. Default errors as above.
    async fn read_head(&self, _repo_id: &RepoId) -> Result<HeadState> {
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

    fn repo_path(&self, repo_id: &RepoId) -> PathBuf {
        self.repos_dir.join(format!("{repo_id}.git"))
    }
}

#[async_trait]
impl RefStore for FsRefStore {
    async fn read(&self, repo_id: &RepoId, ref_name: &RefName) -> Result<Option<Oid>> {
        let git_dir = self.repo_path(repo_id);
        let (rc, stdout, _) = crate::git_cmd::run_git(
            &git_dir,
            &["rev-parse", "--verify", ref_name.as_str()],
            &[],
            None,
        )
        .await?;
        if rc != 0 {
            return Ok(None);
        }
        let s = String::from_utf8(stdout)?.trim().to_string();
        if s.is_empty() {
            return Ok(None);
        }
        // rev-parse emits a 40-char SHA-1. A non-conforming stdout
        // means git itself returned something we don't understand —
        // log + return None so callers see "ref absent" rather than
        // a corruption surface.
        match Oid::try_from(s.as_str()) {
            Ok(o) => Ok(Some(o)),
            Err(e) => {
                tracing::warn!(
                    repo = %repo_id, ref_name = %ref_name, stdout = %s, error = %e,
                    "rev-parse stdout was not a valid Oid"
                );
                Ok(None)
            },
        }
    }

    async fn list(&self, repo_id: &RepoId, prefixes: &[String]) -> Result<Vec<RefEntry>> {
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

    async fn read_head(&self, repo_id: &RepoId) -> Result<HeadState> {
        let git_dir = self.repo_path(repo_id);
        head_state(&git_dir)
    }

    async fn cas_update(
        &self,
        repo_id: &RepoId,
        ref_name: &RefName,
        expected: Option<&Oid>,
        new_sha: &Oid,
    ) -> Result<CasOutcome> {
        let git_dir = self.repo_path(repo_id);
        let expected_arg = expected.map(|o| o.as_str()).unwrap_or(ZERO_SHA);
        let (rc, _, stderr) = crate::git_cmd::run_git(
            &git_dir,
            &[
                "update-ref",
                ref_name.as_str(),
                new_sha.as_str(),
                expected_arg,
            ],
            &[],
            None,
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
        repo_id: &RepoId,
        ref_name: &RefName,
        expected: Option<&Oid>,
    ) -> Result<CasOutcome> {
        let git_dir = self.repo_path(repo_id);
        // `git update-ref -d <ref> [old-sha]` deletes; with
        // expected, requires the ref to currently equal old-sha
        // (CAS). Without expected we pass no extra arg, which makes
        // git delete unconditionally.
        let (rc, _, stderr) = if let Some(exp) = expected {
            crate::git_cmd::run_git(
                &git_dir,
                &["update-ref", "-d", ref_name.as_str(), exp.as_str()],
                &[],
                None,
            )
            .await?
        } else {
            crate::git_cmd::run_git(
                &git_dir,
                &["update-ref", "-d", ref_name.as_str()],
                &[],
                None,
            )
            .await?
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
/// Only compiled into the test binary — production uses `FsRefStore`.
/// Held as M3b foundation: the trait shape gets exercised here so the
/// eventual replicated impl (Raft-shaped) has a contract to satisfy.
///
/// Why this exists: the production `FsRefStore` shells out to
/// `git update-ref` for CAS — a single-node guarantee that breaks the
/// moment two `artifacts serve` processes share a repos dir. Real
/// distributed CAS belongs in a consensus log (e.g. `openraft`), which
/// is multi-week work and not in scope for this session.
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
#[cfg(test)]
pub struct MemRefStore {
    inner: std::sync::Mutex<MemState>,
}

#[cfg(test)]
#[derive(Default)]
struct MemState {
    /// `(repo_id, ref_name) -> oid`. Keys stay String for the
    /// HashMap-borrow ergonomics; the typed `Oid` value is the
    /// contract the trait surface exposes.
    refs: std::collections::HashMap<(String, String), Oid>,
    /// `repo_id -> head_state`. Defaults to the same `Unborn { target:
    /// "refs/heads/main" }` that `git init --bare --initial-branch=main`
    /// produces, so callers can treat MemRefStore as drop-in for a
    /// freshly-initialized FsRefStore.
    heads: std::collections::HashMap<String, HeadState>,
}

#[cfg(test)]
impl Default for MemRefStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
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

#[cfg(test)]
#[async_trait]
impl RefStore for MemRefStore {
    async fn read(&self, repo_id: &RepoId, ref_name: &RefName) -> Result<Option<Oid>> {
        let g = self.lock();
        Ok(g.refs
            .get(&(repo_id.to_string(), ref_name.to_string()))
            .cloned())
    }

    async fn cas_update(
        &self,
        repo_id: &RepoId,
        ref_name: &RefName,
        expected: Option<&Oid>,
        new_sha: &Oid,
    ) -> Result<CasOutcome> {
        let mut g = self.lock();
        let key = (repo_id.to_string(), ref_name.to_string());
        let current = g.refs.get(&key).cloned();
        let matches = match (expected, current.as_ref()) {
            (None, None) => true,
            (Some(e), Some(c)) => e == c,
            _ => false,
        };
        if !matches {
            return Ok(CasOutcome::Conflict { current });
        }
        g.refs.insert(key, new_sha.clone());
        Ok(CasOutcome::Updated)
    }

    async fn list(&self, repo_id: &RepoId, prefixes: &[String]) -> Result<Vec<RefEntry>> {
        let g = self.lock();
        let mut out: Vec<RefEntry> = g
            .refs
            .iter()
            .filter(|((r, _), _)| r.as_str() == repo_id.as_str())
            .filter(|((_, name), _)| {
                prefixes.is_empty() || prefixes.iter().any(|p| name.starts_with(p))
            })
            .filter_map(|((_, name), oid)| {
                // MemRefStore is test-only; inserts go through cas_update
                // which already had a typed `ref_name`. The map's String
                // key was constructed via `ref_name.to_string()`, so
                // try_from is the symmetric reconstruction.
                let n = RefName::try_from(name.as_str()).ok()?;
                Some(RefEntry {
                    name: n,
                    oid: oid.clone(),
                    peeled: None,
                })
            })
            .collect();
        out.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
        Ok(out)
    }

    async fn read_head(&self, repo_id: &RepoId) -> Result<HeadState> {
        let g = self.lock();
        Ok(g.heads
            .get(repo_id.as_str())
            .cloned()
            .unwrap_or_else(|| HeadState::Unborn {
                target: RefName::try_from("refs/heads/main")
                    .expect("'refs/heads/main' satisfies RefName contract"),
            }))
    }

    async fn cas_delete(
        &self,
        repo_id: &RepoId,
        ref_name: &RefName,
        expected: Option<&Oid>,
    ) -> Result<CasOutcome> {
        let mut g = self.lock();
        let key = (repo_id.to_string(), ref_name.to_string());
        let current = g.refs.get(&key).cloned();
        let matches = match (expected, current.as_ref()) {
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
                        // packed-refs is git-emitted, so a non-Oid
                        // here means corruption. Drop the peel
                        // rather than fail enumeration.
                        if let Ok(o) = Oid::try_from(peel.trim()) {
                            e.peeled = Some(o);
                        }
                    }
                }
                continue;
            }
            // `<sha> <name>`
            if let Some((sha, name)) = line.split_once(' ') {
                let (Ok(name_typed), Ok(oid_typed)) = (RefName::try_from(name), Oid::try_from(sha))
                else {
                    // Skip lines whose oid or name don't satisfy our
                    // newtype contracts. packed-refs is small + git-emitted,
                    // so this is corruption, not user input.
                    continue;
                };
                let entry = RefEntry {
                    name: name_typed,
                    oid: oid_typed,
                    peeled: None,
                };
                by_name.insert(name.to_string(), entry);
                last_name = Some(name.to_string());
            }
        }
    }

    // Loose refs override packed. Walk `refs/` recursively.
    let refs_dir = git_dir.join("refs");
    if refs_dir.is_dir() {
        let mut stack = vec![refs_dir];
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
                let oid_hex = s.trim().to_string();
                // 40-hex check via Oid::try_from; symbolic-ref files
                // (`ref: ...`) under refs/ are theoretically possible
                // but not produced by anything we run — skip them
                // defensively.
                let Ok(oid) = Oid::try_from(oid_hex.as_str()) else {
                    continue;
                };
                let rel = match path.strip_prefix(git_dir) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                // Build the full ref name with forward slashes regardless
                // of platform. We control the format on creation, so
                // backslashes shouldn't appear, but be explicit.
                let name_str = rel
                    .components()
                    .filter_map(|c| c.as_os_str().to_str())
                    .collect::<Vec<_>>()
                    .join("/");
                let Ok(name) = RefName::try_from(name_str.as_str()) else {
                    continue;
                };
                by_name.insert(
                    name_str,
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
    if let Some(target_raw) = trimmed.strip_prefix("ref: ") {
        let target_str = target_raw.trim();
        let target = RefName::try_from(target_str)?;
        // Try the loose ref file first.
        let loose = git_dir.join(target_str);
        if let Ok(s) = std::fs::read_to_string(&loose) {
            if let Ok(oid) = Oid::try_from(s.trim()) {
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
                    if name == target_str {
                        if let Ok(oid) = Oid::try_from(sha) {
                            return Ok(HeadState::Symbolic { target, oid });
                        }
                    }
                }
            }
        }
        Ok(HeadState::Unborn { target })
    } else if let Ok(oid) = Oid::try_from(trimmed) {
        Ok(HeadState::Detached { oid })
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

    fn rid(s: &str) -> RepoId {
        RepoId::try_from(s).unwrap()
    }
    fn rn(s: &str) -> RefName {
        RefName::try_from(s).unwrap()
    }
    fn to_oid(s: &str) -> Oid {
        Oid::try_from(s).unwrap()
    }

    fn setup_repo() -> (PathBuf, RepoId, FsRefStore) {
        let tmp = std::env::temp_dir().join(format!("refs-test-{}", new_repo_id()));
        let repos_dir = tmp.join("repos");
        let storage = FsStorage::new(&repos_dir).unwrap();
        let repo_id_str = new_repo_id();
        storage
            .create(&crate::ids::RepoId::try_from(repo_id_str.as_str()).unwrap())
            .unwrap();
        let refs = FsRefStore::new(repos_dir);
        (tmp, rid(&repo_id_str), refs)
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
        let r = refs.read(&repo, &rn("refs/heads/nope")).await.unwrap();
        assert_eq!(r, None);
    }

    #[tokio::test]
    async fn cas_update_creates_ref_when_expected_none() {
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let sha = to_oid(&write_blob(&git_dir, b"hello"));

        let out = refs
            .cas_update(&repo, &rn("refs/test/t"), None, &sha)
            .await
            .unwrap();
        assert_eq!(out, CasOutcome::Updated);
        let r = refs.read(&repo, &rn("refs/test/t")).await.unwrap();
        assert_eq!(r.as_ref(), Some(&sha));
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
            let repo = rid("rtst");
            let rname = rn("refs/heads/x");
            let oid1 = to_oid("0123456789012345678901234567890123456789");
            let oid2 = to_oid("abcabcabcabcabcabcabcabcabcabcabcabcabca");
            let oid3 = to_oid("ffffffffffffffffffffffffffffffffffffffff");
            // create
            assert_eq!(
                s.cas_update(&repo, &rname, None, &oid1).await.unwrap(),
                CasOutcome::Updated,
            );
            // update under matching expected
            assert_eq!(
                s.cas_update(&repo, &rname, Some(&oid1), &oid2)
                    .await
                    .unwrap(),
                CasOutcome::Updated,
            );
            // stale expected → conflict, current returned
            match s
                .cas_update(&repo, &rname, Some(&oid1), &oid3)
                .await
                .unwrap()
            {
                CasOutcome::Conflict { current } => {
                    assert_eq!(current.as_ref(), Some(&oid2),);
                },
                other @ CasOutcome::Updated => {
                    panic!("expected Updated-free conflict, got {other:?}")
                },
            }
        }

        #[tokio::test]
        async fn read_returns_none_for_missing_ref() {
            let s = MemRefStore::new();
            assert!(s
                .read(&rid("rtst"), &rn("refs/heads/nope"))
                .await
                .unwrap()
                .is_none());
        }

        #[tokio::test]
        async fn read_head_defaults_to_unborn_main() {
            let s = MemRefStore::new();
            match s.read_head(&rid("rtst")).await.unwrap() {
                HeadState::Unborn { target } => assert_eq!(target.as_str(), "refs/heads/main"),
                other => panic!("expected Unborn, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn list_filters_by_prefix() {
            let s = MemRefStore::new();
            let repo = rid("rtst");
            let zero = to_oid(&"0".repeat(40));
            s.cas_update(&repo, &rn("refs/heads/main"), None, &zero)
                .await
                .unwrap();
            s.cas_update(&repo, &rn("refs/tags/v1"), None, &zero)
                .await
                .unwrap();
            let heads = s.list(&repo, &["refs/heads/".into()]).await.unwrap();
            assert_eq!(heads.len(), 1);
            assert_eq!(heads[0].name.as_str(), "refs/heads/main");
        }

        #[tokio::test]
        async fn cas_delete_removes_when_expected_matches() {
            let s = MemRefStore::new();
            let repo = rid("rtst");
            let rname = rn("refs/heads/x");
            let oid = to_oid(&"0".repeat(40));
            s.cas_update(&repo, &rname, None, &oid).await.unwrap();
            assert!(s.read(&repo, &rname).await.unwrap().is_some());
            assert_eq!(
                s.cas_delete(&repo, &rname, Some(&oid)).await.unwrap(),
                CasOutcome::Updated,
            );
            assert!(s.read(&repo, &rname).await.unwrap().is_none());
        }

        #[tokio::test]
        async fn cas_delete_conflicts_when_expected_stale() {
            let s = MemRefStore::new();
            let repo = rid("rtst");
            let rname = rn("refs/heads/x");
            let oid_old = to_oid(&"0".repeat(40));
            let oid_new = to_oid(&"1".repeat(40));
            s.cas_update(&repo, &rname, None, &oid_old).await.unwrap();
            s.cas_update(&repo, &rname, Some(&oid_old), &oid_new)
                .await
                .unwrap();
            // Try deleting with the stale oid — should conflict and
            // return current.
            match s.cas_delete(&repo, &rname, Some(&oid_old)).await.unwrap() {
                CasOutcome::Conflict { current } => {
                    assert_eq!(current.as_ref(), Some(&oid_new));
                },
                other @ CasOutcome::Updated => {
                    panic!("expected Updated-free conflict, got {other:?}")
                },
            }
            // Ref is still present — delete didn't happen.
            assert!(s.read(&repo, &rname).await.unwrap().is_some());
        }

        #[tokio::test]
        async fn cas_delete_unconditional_when_expected_none() {
            let s = MemRefStore::new();
            let repo = rid("rtst");
            let rname = rn("refs/heads/x");
            let zero = to_oid(&"0".repeat(40));
            s.cas_update(&repo, &rname, None, &zero).await.unwrap();
            // expected=None bypasses the equality check.
            assert_eq!(
                s.cas_delete(&repo, &rname, None).await.unwrap(),
                CasOutcome::Updated,
            );
            assert!(s.read(&repo, &rname).await.unwrap().is_none());
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
                let oid_a = to_oid(&format!("a{round:039}"));
                let oid_b = to_oid(&format!("b{round:039}"));
                let ref_name = rn(&format!("refs/round/{round}"));

                let h1 = tokio::spawn({
                    let r = ref_name.clone();
                    let oid = oid_a.clone();
                    async move { s1.cas_update(&rid("rtst"), &r, None, &oid).await.unwrap() }
                });
                let h2 = tokio::spawn({
                    let r = ref_name.clone();
                    let oid = oid_b.clone();
                    async move { s2.cas_update(&rid("rtst"), &r, None, &oid).await.unwrap() }
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
        let s = to_oid(&write_blob(&git_dir, b"hello"));
        refs.cas_update(&repo, &rn("refs/test/a"), None, &s)
            .await
            .unwrap();
        refs.cas_update(&repo, &rn("refs/test/sub/b"), None, &s)
            .await
            .unwrap();
        refs.cas_update(&repo, &rn("refs/tags/v1"), None, &s)
            .await
            .unwrap();

        let all = refs.list(&repo, &[]).await.unwrap();
        let names: Vec<&str> = all.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"refs/test/a"));
        assert!(names.contains(&"refs/test/sub/b"));
        assert!(names.contains(&"refs/tags/v1"));
        // Sorted lex.
        for w in all.windows(2) {
            assert!(w[0].name <= w[1].name, "list not sorted: {names:?}");
        }
        // Filter by prefix.
        let only_test = refs.list(&repo, &["refs/test/".to_string()]).await.unwrap();
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
            HeadState::Unborn { target } => assert_eq!(target.as_str(), "refs/heads/main"),
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
        let s = to_oid(&write_blob(&git_dir, b"hello"));
        refs.cas_update(&repo, &rn("refs/test/x"), None, &s)
            .await
            .unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/test/x\n").unwrap();
        let st = refs.read_head(&repo).await.unwrap();
        match st {
            HeadState::Symbolic { target, oid } => {
                assert_eq!(target.as_str(), "refs/test/x");
                assert_eq!(oid.as_str(), s.as_str());
            },
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
        std::fs::write(git_dir.join("refs/test/conflict"), format!("{s_loose}\n")).unwrap();

        let all = refs.list(&repo, &[]).await.unwrap();
        let by_name: std::collections::HashMap<&str, &str> = all
            .iter()
            .map(|e| (e.name.as_str(), e.oid.as_str()))
            .collect();
        assert_eq!(
            by_name.get("refs/test/packed-only"),
            Some(&s_packed.as_str())
        );
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
            .find(|e| e.name.as_str() == "refs/tags/annot")
            .expect("annotated tag missing");
        assert_eq!(entry.oid.as_str(), tag_oid.as_str());
        assert_eq!(
            entry.peeled.as_ref().map(|o| o.as_str()),
            Some(peeled_oid.as_str())
        );
    }

    #[tokio::test]
    async fn cas_update_rejects_stale_expected() {
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let s1 = to_oid(&write_blob(&git_dir, b"one"));
        let s2 = to_oid(&write_blob(&git_dir, b"two"));
        let s3 = to_oid(&write_blob(&git_dir, b"three"));
        let rname = rn("refs/test/x");

        // create
        assert_eq!(
            refs.cas_update(&repo, &rname, None, &s1).await.unwrap(),
            CasOutcome::Updated
        );
        // expected=s1 -> succeeds, now at s2
        assert_eq!(
            refs.cas_update(&repo, &rname, Some(&s1), &s2)
                .await
                .unwrap(),
            CasOutcome::Updated
        );
        // expected=s1 (stale) -> conflict, current should be s2
        match refs
            .cas_update(&repo, &rname, Some(&s1), &s3)
            .await
            .unwrap()
        {
            CasOutcome::Conflict { current } => {
                assert_eq!(current.as_ref(), Some(&s2));
            },
            other @ CasOutcome::Updated => panic!("wanted conflict, got {other:?}"),
        }
    }

    // ── Trait-default method coverage ─────────────────────────────────

    /// A minimal store that implements only the two required methods.
    /// All three default methods (`cas_delete`, `list`, `read_head`)
    /// should return `Err(Error::Other(...))` with a descriptive message.
    struct MinimalStore;

    #[async_trait]
    impl RefStore for MinimalStore {
        async fn read(&self, _repo_id: &RepoId, _ref_name: &RefName) -> Result<Option<Oid>> {
            Ok(None)
        }

        async fn cas_update(
            &self,
            _repo_id: &RepoId,
            _ref_name: &RefName,
            _expected: Option<&Oid>,
            _new_sha: &Oid,
        ) -> Result<CasOutcome> {
            Ok(CasOutcome::Updated)
        }
    }

    #[tokio::test]
    async fn trait_default_cas_delete_returns_err() {
        let s = MinimalStore;
        let err = s
            .cas_delete(&rid("repo-a"), &rn("refs/heads/x"), None)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cas_delete") || msg.contains("not implemented"),
            "unexpected message: {msg}"
        );
    }

    #[tokio::test]
    async fn trait_default_list_returns_err() {
        let s = MinimalStore;
        let err = s.list(&rid("repo-a"), &[]).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("list") || msg.contains("not implemented"),
            "unexpected message: {msg}"
        );
    }

    #[tokio::test]
    async fn trait_default_read_head_returns_err() {
        let s = MinimalStore;
        let err = s.read_head(&rid("repo-a")).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("read_head") || msg.contains("not implemented"),
            "unexpected message: {msg}"
        );
    }

    // ── FsRefStore::cas_delete paths ──────────────────────────────────

    #[tokio::test]
    async fn fs_cas_delete_with_matching_expected_removes_ref() {
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let s = to_oid(&write_blob(&git_dir, b"target-for-delete"));
        let rname = rn("refs/test/del");
        refs.cas_update(&repo, &rname, None, &s).await.unwrap();
        // Expected matches → Updated, ref gone.
        let out = refs.cas_delete(&repo, &rname, Some(&s)).await.unwrap();
        assert_eq!(out, CasOutcome::Updated);
        assert!(refs.read(&repo, &rname).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn fs_cas_delete_with_stale_expected_reports_conflict() {
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let s1 = to_oid(&write_blob(&git_dir, b"v1"));
        let s2 = to_oid(&write_blob(&git_dir, b"v2"));
        let rname = rn("refs/test/del-stale");
        refs.cas_update(&repo, &rname, None, &s1).await.unwrap();
        refs.cas_update(&repo, &rname, Some(&s1), &s2)
            .await
            .unwrap();
        // Try to delete with the old SHA → conflict.
        match refs.cas_delete(&repo, &rname, Some(&s1)).await.unwrap() {
            CasOutcome::Conflict { .. } => {},
            CasOutcome::Updated => panic!("should have conflicted on stale expected"),
        }
        // Ref still present.
        assert!(refs.read(&repo, &rname).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn fs_cas_delete_unconditional_removes_ref() {
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let s = to_oid(&write_blob(&git_dir, b"uc-target"));
        let rname = rn("refs/test/del-uc");
        refs.cas_update(&repo, &rname, None, &s).await.unwrap();
        // expected=None → unconditional delete.
        let out = refs.cas_delete(&repo, &rname, None).await.unwrap();
        assert_eq!(out, CasOutcome::Updated);
        assert!(refs.read(&repo, &rname).await.unwrap().is_none());
    }

    // ── head_state edge cases ─────────────────────────────────────────

    #[tokio::test]
    async fn read_head_detached_when_head_is_raw_oid() {
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let s = to_oid(&write_blob(&git_dir, b"detached-target"));
        // Write the OID directly into HEAD to simulate a detached HEAD state.
        std::fs::write(git_dir.join("HEAD"), format!("{}\n", s.as_str())).unwrap();
        let st = refs.read_head(&repo).await.unwrap();
        match st {
            HeadState::Detached { oid } => assert_eq!(oid.as_str(), s.as_str()),
            other => panic!("expected Detached, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_head_error_on_unrecognized_format() {
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        // Write a HEAD that is neither a symref nor a 40-hex OID.
        std::fs::write(git_dir.join("HEAD"), "not-valid-head\n").unwrap();
        let err = refs.read_head(&repo).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unrecognized") || msg.contains("HEAD"),
            "unexpected error message: {msg}"
        );
    }

    #[tokio::test]
    async fn read_head_symbolic_falls_back_to_packed_refs() {
        // HEAD points at refs/test/packed but there is no loose file —
        // only a packed-refs entry. The fallback should resolve it.
        let (_tmp, repo, refs) = setup_repo();
        let git_dir = refs.repo_path(&repo);
        let sha = write_blob(&git_dir, b"packed-head-target");
        let packed_text = format!("# pack-refs with: peeled\n{sha} refs/test/packed\n");
        std::fs::write(git_dir.join("packed-refs"), packed_text).unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/test/packed\n").unwrap();
        let st = refs.read_head(&repo).await.unwrap();
        match st {
            HeadState::Symbolic { target, oid } => {
                assert_eq!(target.as_str(), "refs/test/packed");
                assert_eq!(oid.as_str(), sha.as_str());
            },
            other => panic!("expected Symbolic from packed fallback, got {other:?}"),
        }
    }
}
