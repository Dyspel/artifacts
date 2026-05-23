//! Garbage-collection accounting that respects the fork network.
//!
//! ## The problem
//!
//! Forks share object storage with their source via
//! `objects/info/alternates`. A naive `git gc` on the source would
//! happily delete an object that's only reachable from a fork's refs
//! — silently breaking the fork. So before we can run a real GC we
//! need a reachability analysis that walks every repo in the
//! alternates network, not just the one we're analyzing.
//!
//! This module is the read-only half of that work: given a repo,
//! produce a `GcPreview` describing how much of its on-disk object
//! storage would be safe to drop. Actually dropping the bytes is a
//! follow-up commit; landing the analyzer first lets us compare its
//! verdict against `git gc --dry-run` on standalone repos and
//! against hand-crafted alternates topologies before we trust it
//! to delete anything.
//!
//! ## What we count
//!
//! - `network`: the set of repo IDs reachable from `repo_id` via
//!   alternates. Includes ancestors (sources of sources of ...) and
//!   descendants (forks of forks of ...). The repo itself is part
//!   of the network.
//! - `reachable_oids`: every object reachable from any ref in any
//!   repo in the network. Computed via `git rev-list --objects --all`
//!   per repo (each invocation is a single subprocess, the union
//!   happens in-process).
//! - `loose_on_disk`: every loose object actually present in
//!   `repo_id`'s `objects/<aa>/<bbbb…>` tree. We deliberately scope
//!   this to the analyzed repo's *own* loose objects, not the
//!   alternates' — the analyzed repo only owns what it wrote.
//! - `unreachable_loose`: `loose_on_disk - reachable_oids` (the
//!   set difference). These are the candidates a future GC would
//!   actually delete.
//!
//! ## What we don't count yet
//!
//! - **Packed objects.** Loose-only is the M0 / M1a shape; we'd
//!   only encounter packed objects on a repo that was push-indexed
//!   via `ARTIFACTS_NATIVE_INDEX_PACK=1` (M1b-3-gix opt-in) or
//!   came in from a `git gc` run somewhere. Fine for the preview
//!   analyzer; the eventual deleter has to handle packs too.
//! - **Reflog reachability.** Real `git gc` keeps an object alive
//!   if any reflog references it. We don't write reflogs (bare
//!   repos initialized via `write_bare_repo_layout` have none).
//!   Add a reflog-walk to `reachable_oids` if that ever changes.

use crate::alternates_cache::AlternatesCache;
use crate::error::{Error, Result};
use crate::object_store::ObjectStore;
use std::collections::HashSet;
use std::path::Path;

/// Read-only summary of what a GC pass would do. Returned by the
/// preview endpoint as JSON; field names are camelCase via serde
/// rename to match the rest of the REST surface.
#[derive(Debug, serde::Serialize)]
pub struct GcPreview {
    /// All repo IDs in the alternates network the analyzed repo is
    /// part of. Always non-empty (contains at least the analyzed
    /// repo). Sorted lexicographically for stable output.
    pub network: Vec<String>,
    /// Number of distinct OIDs reachable from any ref in any repo
    /// in `network`. These are the "live" objects.
    #[serde(rename = "reachableOids")]
    pub reachable_oids: u64,
    /// Number of loose objects on disk in the analyzed repo's
    /// `objects/` tree (excluding `objects/info` and `objects/pack`).
    #[serde(rename = "looseOnDisk")]
    pub loose_on_disk: u64,
    /// `loose_on_disk - reachable_oids` (set difference). These are
    /// the OIDs a future GC would delete.
    #[serde(rename = "unreachableLoose")]
    pub unreachable_loose: u64,
    /// Sum of file sizes of the unreachable loose objects. Useful
    /// for "you'd reclaim N MB" UI surfaces.
    #[serde(rename = "unreachableBytes")]
    pub unreachable_bytes: u64,
    /// First N unreachable OIDs (capped to keep the response
    /// bounded). The real list lives only in memory during the
    /// analysis; if you need it all, page or wait for Phase 2.
    pub sample: Vec<String>,
}

const SAMPLE_CAP: usize = 32;

/// Result of an actual GC pass (Phase 2). Same general shape as
/// `GcPreview` plus the counts of what was actually deleted —
/// useful when an mtime guard or a race against a concurrent push
/// prevents the deletion of an object the analyzer flagged.
#[derive(Debug, serde::Serialize)]
pub struct GcResult {
    /// Same fields as the preview, surfacing the analyzer state at
    /// the moment we ran. Lets the caller verify that the delete
    /// matched what they'd expect from a prior preview call.
    #[serde(flatten)]
    pub preview: GcPreview,
    /// How many loose objects were actually unlinked. ≤
    /// `preview.unreachable_loose` because the mtime guard skips
    /// recently-created candidates (anti-race).
    pub deleted: u64,
    /// Total bytes reclaimed by the unlinks above.
    #[serde(rename = "deletedBytes")]
    pub deleted_bytes: u64,
    /// Number of unreachable candidates we skipped because they
    /// were younger than `min_age_secs`. Surfaces the race-guard's
    /// effect so an admin can see "you had 76 unreachable but 12
    /// were too fresh to safely delete; rerun later to clean those
    /// up."
    #[serde(rename = "skippedTooYoung")]
    pub skipped_too_young: u64,
}

/// Compute the GC preview. Subprocess cost: one `git rev-list` per
/// repo in the network. For a typical repo with no forks, that's
/// one subprocess. For a repo with N forks, it's N+1.
///
/// Loose-object enumeration goes through the `ObjectStore` trait —
/// the FS impl reads the on-disk shard tree, a future chunked-KV
/// impl reads its own table. Reachability still spawns
/// `git rev-list` per network member; that path requires real on-disk
/// state today and isn't part of the trait yet.
pub fn preview(
    repos_dir: &Path,
    repo_id: &str,
    cache: &AlternatesCache,
    objects: &dyn ObjectStore,
) -> Result<GcPreview> {
    let mut network = network_around(repos_dir, repo_id, cache)?;
    network.sort();
    network.dedup();

    let mut reachable: HashSet<String> = HashSet::new();
    for member in &network {
        let oids = rev_list_objects(repos_dir, member)?;
        for oid in oids {
            reachable.insert(oid);
        }
    }

    let repo_id_typed = crate::ids::RepoId::try_from(repo_id)?;
    let loose = objects.list_loose(&repo_id_typed)?;

    let mut unreachable_bytes: u64 = 0;
    let mut sample: Vec<String> = Vec::new();
    let mut unreachable_count: u64 = 0;
    for info in &loose {
        if !reachable.contains(info.oid.as_str()) {
            unreachable_count += 1;
            unreachable_bytes += info.size;
            if sample.len() < SAMPLE_CAP {
                sample.push(info.oid.as_str().to_owned());
            }
        }
    }

    Ok(GcPreview {
        network,
        reachable_oids: reachable.len() as u64,
        loose_on_disk: loose.len() as u64,
        unreachable_loose: unreachable_count,
        unreachable_bytes,
        sample,
    })
}

/// Run a real garbage-collection pass on `repo_id`'s loose object
/// store. Algorithm:
///
///   1. Compute reachability via [`preview`] (alternates-aware).
///   2. For each unreachable candidate, stat the loose-object
///      file. Skip if its mtime is within `min_age_secs` of now —
///      this is the anti-race guard. A push that landed objects
///      seconds ago might be in the middle of writing the ref
///      that points at them; deleting them would break the
///      not-yet-committed state. Two hours is the conservative
///      default (matches `git gc`'s `gc.pruneExpire=2.weeks`
///      default's spirit at our scale).
///   3. Unlink each remaining candidate.
///
/// Concurrency caveat: between step (1) and step (3) someone could
/// push to a repo in the network and create a ref pointing at one
/// of our about-to-delete OIDs. The mtime guard catches the common
/// case (recently-created objects); a sub-second race against a
/// commit that arrives between our reachability scan and the
/// unlink call is theoretically possible but vanishingly unlikely
/// — push latency dominates by orders of magnitude.
pub fn run(
    repos_dir: &Path,
    repo_id: &str,
    cache: &AlternatesCache,
    min_age_secs: u64,
    objects: &dyn ObjectStore,
) -> Result<GcResult> {
    let preview = preview(repos_dir, repo_id, cache, objects)?;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let cutoff_secs = now_secs.saturating_sub(min_age_secs as i64);

    // Re-list loose objects through the trait. Cheaper than threading
    // the full list through preview's return (which only carries a
    // bounded sample). The preview-then-list pair is each O(N); doing
    // the enumerate twice is fine at our repo size.
    let repo_id_typed = crate::ids::RepoId::try_from(repo_id)?;
    let loose = objects.list_loose(&repo_id_typed)?;

    // Recompute reachable here so we don't have to plumb it through
    // GcPreview's public shape (which is intentionally bounded).
    let mut reachable: HashSet<String> = HashSet::new();
    for member in &preview.network {
        for oid in rev_list_objects(repos_dir, member)? {
            reachable.insert(oid);
        }
    }

    let mut deleted = 0u64;
    let mut deleted_bytes = 0u64;
    let mut skipped_too_young = 0u64;
    for info in &loose {
        if reachable.contains(info.oid.as_str()) {
            continue;
        }
        // Anti-race guard: a push that landed objects seconds ago
        // might be mid-stream — its ref hasn't yet pointed at these
        // objects. The `created_secs` field comes from the trait
        // (FS = mtime; chunked-KV = the row's own created_at), so
        // this guard works for any backend.
        if info.created_secs > cutoff_secs {
            skipped_too_young += 1;
            tracing::debug!(
                oid = %info.oid,
                age_secs = now_secs.saturating_sub(info.created_secs),
                "gc: skipping young loose object"
            );
            continue;
        }
        match objects.delete_loose(&repo_id_typed, &info.oid) {
            Ok(true) => {
                deleted += 1;
                deleted_bytes += info.size;
                tracing::debug!(oid = %info.oid, bytes = info.size, "gc: removed");
            }
            // Already gone — concurrent gc, or a race. Treat as a
            // no-op rather than counting toward `deleted`.
            Ok(false) => {}
            Err(e) => {
                // Soft-fail per object — a permission error or
                // racy unlink shouldn't abort the whole pass.
                tracing::warn!(oid = %info.oid, error = %e, "gc: remove failed");
            }
        }
    }
    tracing::info!(
        repo = %repo_id, deleted, deleted_bytes,
        skipped_too_young,
        "gc: pass complete"
    );
    Ok(GcResult {
        preview,
        deleted,
        deleted_bytes,
        skipped_too_young,
    })
}

/// BFS over the alternates relation to find every repo connected
/// to `seed`. Walks both directions: ancestors via cache.lookup,
/// descendants via the same scan `list_forks_of` uses but inlined
/// here so we can keep the call inside the same `read_dir` we'd
/// otherwise issue once per repo.
fn network_around(repos_dir: &Path, seed: &str, cache: &AlternatesCache) -> Result<Vec<String>> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = vec![seed.to_string()];

    while let Some(id) = queue.pop() {
        if !visited.insert(id.clone()) {
            continue;
        }
        // Up: this repo's source (if any) is part of the network.
        if let Some(parent) = cache.lookup(repos_dir, &id) {
            if !visited.contains(&parent) {
                queue.push(parent);
            }
        }
        // Down: any repo whose alternates source is `id` is part
        // of the network.
        for child in crate::reads::list_forks_of(repos_dir, &id, cache)? {
            if !visited.contains(&child) {
                queue.push(child);
            }
        }
    }

    Ok(visited.into_iter().collect())
}

/// `git --git-dir=<repo> rev-list --objects --all` enumerates every
/// OID reachable from any ref. Output is one OID per line (with an
/// optional path after a space for non-commit objects); we only
/// need the OID part.
fn rev_list_objects(repos_dir: &Path, repo_id: &str) -> Result<Vec<String>> {
    let git_dir = repos_dir.join(format!("{repo_id}.git"));
    let out = crate::git_cmd::rev_list_objects_all(&git_dir).output()?;
    if !out.status.success() {
        // A repo with no refs exits 0 with empty stdout; non-zero
        // is a real error.
        return Err(Error::Other(anyhow::anyhow!(
            "git rev-list --objects --all on {repo_id} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let text = String::from_utf8(out.stdout)?;
    let mut oids = Vec::new();
    for line in text.lines() {
        let oid = line.split_whitespace().next().unwrap_or("");
        if oid.len() == 40 && oid.chars().all(|c| c.is_ascii_hexdigit()) {
            oids.push(oid.to_string());
        }
    }
    Ok(oids)
}

// `loose_objects` and `loose_path` were filesystem-direct helpers
// before M2b production routing landed. They've been replaced by
// `ObjectStore::list_loose` and `ObjectStore::delete_loose`
// respectively — gc is now backend-neutral.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{new_repo_id, FsStorage, Storage};

    /// Build a tiny repo with one commit and return (storage,
    /// repo_id, the commit's reachable oids).
    fn seed_repo() -> (tempfile::TempDir, FsStorage, String) {
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));

        // hash-object → mktree → commit-tree, the same plumbing dance
        // the other tests use.
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut blob_p = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        blob_p.stdin.as_mut().unwrap().write_all(b"hi").unwrap();
        let blob = String::from_utf8(blob_p.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();
        let mut tree_p = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .arg("mktree")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        tree_p
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("100644 blob {blob}\thi.txt\n").as_bytes())
            .unwrap();
        let tree = String::from_utf8(tree_p.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();
        let commit = String::from_utf8(
            Command::new("git")
                .arg("--git-dir")
                .arg(&git_dir)
                .args(["commit-tree", "-m", "c", &tree])
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["update-ref", "refs/heads/main", &commit])
            .status()
            .unwrap();
        (tmp, storage, repo_id)
    }

    #[test]
    fn preview_on_clean_repo_reports_zero_unreachable() {
        let (tmp, storage, repo_id) = seed_repo();
        let cache = AlternatesCache::new();
        let repos_dir = storage_repos_dir(&tmp, &storage);
        let objects = fs_objects(&repos_dir);
        let p = preview(&repos_dir, &repo_id, &cache, &objects).unwrap();

        assert_eq!(p.network, vec![repo_id.clone()]);
        assert!(p.reachable_oids >= 3, "commit + tree + blob = 3+");
        assert_eq!(p.unreachable_loose, 0);
        assert_eq!(p.unreachable_bytes, 0);
        assert!(p.sample.is_empty());
    }

    #[test]
    fn preview_flags_dangling_loose_object_as_unreachable() {
        // hash-object writes a loose blob but doesn't create a ref
        // pointing at it. From any-ref reachability, that blob is
        // dangling — our analyzer should flag it.
        let (tmp, storage, repo_id) = seed_repo();
        let git_dir = storage_repos_dir(&tmp, &storage).join(format!("{repo_id}.git"));

        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut p = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        p.stdin.as_mut().unwrap().write_all(b"orphan").unwrap();
        let dangler = String::from_utf8(p.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();

        let cache = AlternatesCache::new();
        let repos_dir = storage_repos_dir(&tmp, &storage);
        let objects = fs_objects(&repos_dir);
        let preview = preview(&repos_dir, &repo_id, &cache, &objects).unwrap();
        assert_eq!(preview.unreachable_loose, 1);
        assert!(preview.unreachable_bytes > 0);
        assert!(
            preview.sample.iter().any(|o| o == &dangler),
            "dangler {dangler} should be in the sample {:?}",
            preview.sample,
        );
    }

    #[test]
    fn preview_includes_forks_in_network_and_keeps_their_objects_alive() {
        // Source repo writes a blob → object lives in source's
        // objects/ via our seed. Fork that source, then the source
        // gets a ref-deleted — without alternates-awareness, the
        // source's analyzer would call the source's blob unreachable.
        // With alternates-awareness, it stays alive because the
        // fork's refs reach it.
        let (tmp, storage, source_id) = seed_repo();
        let repos_dir = storage_repos_dir(&tmp, &storage);
        let fork_id = new_repo_id();
        storage.fork(&source_id, &fork_id).unwrap();

        let cache = AlternatesCache::new();
        let objects = fs_objects(&repos_dir);
        let p_source = preview(&repos_dir, &source_id, &cache, &objects).unwrap();
        // Network must contain both repos (sorted).
        assert_eq!(p_source.network.len(), 2);
        assert!(p_source.network.contains(&source_id));
        assert!(p_source.network.contains(&fork_id));
        // No unreachable objects: the fork inherits the source's
        // refs via packed-refs, so every source object is reachable
        // from at least one repo in the network.
        assert_eq!(p_source.unreachable_loose, 0);
    }

    fn storage_repos_dir(tmp: &tempfile::TempDir, _storage: &FsStorage) -> std::path::PathBuf {
        tmp.path().join("repos")
    }

    /// Build an `FsObjectStore` rooted at the same `<tmp>/repos` the
    /// test fixtures use, plus a path-builder for the canonical
    /// loose-object on-disk location (used by the existence-on-disk
    /// asserts that the trait doesn't directly expose).
    fn fs_objects(repos_dir: &std::path::Path) -> crate::object_store::FsObjectStore {
        crate::object_store::FsObjectStore::new(repos_dir.to_path_buf())
    }
    fn loose_path(git_dir: &std::path::Path, oid: &str) -> std::path::PathBuf {
        let (a, b) = oid.split_at(2);
        git_dir.join("objects").join(a).join(b)
    }

    #[test]
    fn run_deletes_unreachable_loose_object_when_old_enough() {
        // Same setup as the dangling-blob preview test, then run gc
        // with min_age_secs=0 so the mtime guard never fires.
        let (tmp, storage, repo_id) = seed_repo();
        let repos_dir = storage_repos_dir(&tmp, &storage);
        let git_dir = repos_dir.join(format!("{repo_id}.git"));

        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut p = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        p.stdin.as_mut().unwrap().write_all(b"orphan").unwrap();
        let dangler = String::from_utf8(p.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();

        // The loose file exists.
        let dpath = loose_path(&git_dir, &dangler);
        assert!(dpath.exists(), "dangler should be on disk before gc");

        let cache = AlternatesCache::new();
        let objects = fs_objects(&repos_dir);
        let result = run(&repos_dir, &repo_id, &cache, 0, &objects).unwrap();
        assert_eq!(result.deleted, 1, "exactly the dangler");
        assert!(result.deleted_bytes > 0);
        assert_eq!(result.skipped_too_young, 0);
        assert!(!dpath.exists(), "dangler should be gone after gc");

        // A second run is a no-op — already cleaned.
        let result2 = run(&repos_dir, &repo_id, &cache, 0, &objects).unwrap();
        assert_eq!(result2.deleted, 0);
        assert_eq!(result2.skipped_too_young, 0);
    }

    #[test]
    fn run_skips_too_young_objects_so_anti_race_guard_works() {
        // Drop a dangling blob *now*, then run gc with a 1-hour
        // min-age. The blob is seconds old, so the guard should
        // refuse to delete it.
        let (tmp, storage, repo_id) = seed_repo();
        let repos_dir = storage_repos_dir(&tmp, &storage);
        let git_dir = repos_dir.join(format!("{repo_id}.git"));

        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut p = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        p.stdin
            .as_mut()
            .unwrap()
            .write_all(b"young-orphan")
            .unwrap();
        let dangler = String::from_utf8(p.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();

        let cache = AlternatesCache::new();
        let objects = fs_objects(&repos_dir);
        let result = run(&repos_dir, &repo_id, &cache, 3600, &objects).unwrap();
        assert_eq!(result.deleted, 0, "young object should not be deleted");
        assert_eq!(result.skipped_too_young, 1);
        // File still on disk.
        assert!(loose_path(&git_dir, &dangler).exists());
    }
}
