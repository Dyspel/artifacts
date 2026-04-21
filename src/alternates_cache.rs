//! Memoizes the `objects/info/alternates` → `source_id` resolution.
//!
//! Background: `admin_list_repos` needs to report each repo's fork
//! parent, and the parent is stored on-disk as an alternates file
//! pointing at `<repos_dir>/<parent>.git/objects`. Resolving one
//! alternates file costs a `read_to_string` plus two `canonicalize`
//! calls (to defeat symlink escapes). For N repos, that's ~5N syscalls
//! on every poll of `/v1/admin/repos` — the GUI polls every 2s, so
//! this adds up.
//!
//! The strategy here is the cheapest one that's still correct:
//!
//!   1. Stat the alternates file (1 syscall).
//!   2. If its mtime matches what we cached for this repo, return
//!      the cached `Option<String>` without re-reading or re-canonicalizing.
//!   3. Otherwise, do the full resolve and update the cache.
//!
//! "No alternates file" is itself a cachable state (mtime = None,
//! source_id = None) so the common case of non-forks also hits the
//! fast path.
//!
//! Invalidation is mtime-based, not event-based. Alternates files are
//! written exactly once at fork-creation time and never rewritten, so
//! mtime tracking is sufficient: if a fork-create happens between
//! polls, the new file has a new mtime and the cache misses cleanly.
//! If someone hand-edits alternates, same story.

use crate::storage::validate_repo_id;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

#[derive(Clone)]
struct Entry {
    /// `None` means "the file didn't exist when we last looked". We
    /// still cache it — "no alternates" is the dominant case and it'd
    /// be silly to re-check it every poll when the file isn't there.
    mtime: Option<SystemTime>,
    source_id: Option<String>,
}

/// One shared cache per server. `Mutex<HashMap>` is plenty — the
/// hot path is "hash lookup + mtime compare" under the lock, which
/// is on the order of a microsecond. No contention risk at our
/// expected QPS (admin list is a 2-second GUI poll).
#[derive(Default)]
pub struct AlternatesCache {
    inner: Mutex<HashMap<String, Entry>>,
}

impl AlternatesCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve `repo_id`'s source (fork parent) id, using the cache when
    /// the alternates file's mtime is unchanged. Safe to call concurrently;
    /// a poisoned lock is recovered rather than propagated (the cache is
    /// pure memoization — a panic under lock can't violate an invariant).
    pub fn lookup(&self, repos_dir: &Path, repo_id: &str) -> Option<String> {
        let alt_path = repos_dir.join(format!("{repo_id}.git/objects/info/alternates"));
        let mtime = std::fs::metadata(&alt_path)
            .and_then(|m| m.modified())
            .ok();

        // Fast path: cached entry with matching mtime.
        {
            let guard = self
                .inner
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(e) = guard.get(repo_id) {
                if e.mtime == mtime {
                    return e.source_id.clone();
                }
            }
        }

        // Miss: do the full resolve, then update the cache.
        let resolved = resolve(&alt_path, repos_dir);
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.insert(
            repo_id.to_string(),
            Entry {
                mtime,
                source_id: resolved.clone(),
            },
        );
        resolved
    }

    /// Forget a repo_id. Called when a repo is deleted, so the cache
    /// doesn't grow unboundedly across the lifetime of the process.
    pub fn invalidate(&self, repo_id: &str) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.remove(repo_id);
    }
}

/// Actual alternates-file resolver. Pulled out of the cache so the
/// cache stays focused on "memoize by mtime". Same semantics as the
/// previous inline implementation in rest.rs — just not paid on every
/// admin poll.
fn resolve(alt_path: &Path, repos_dir: &Path) -> Option<String> {
    let s = std::fs::read_to_string(alt_path).ok()?;
    let target_str = s.trim();
    if target_str.is_empty() {
        return None;
    }
    let target = PathBuf::from(target_str);
    let canon_root = repos_dir.canonicalize().ok()?;
    let canon_target = target.canonicalize().ok()?;

    let rel = canon_target.strip_prefix(&canon_root).ok()?;
    let mut comps = rel.components();
    let first = comps.next()?;
    let second = comps.next()?;
    if comps.next().is_some() {
        return None;
    }
    let (first, second) = (first.as_os_str().to_str()?, second.as_os_str().to_str()?);
    if second != "objects" {
        return None;
    }
    let source_id = first.strip_suffix(".git")?;
    validate_repo_id(source_id).ok()?;
    Some(source_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_fork(base: &Path, source: &str, fork: &str) {
        let source_objects = base.join(format!("{source}.git/objects"));
        fs::create_dir_all(&source_objects).unwrap();
        let fork_info = base.join(format!("{fork}.git/objects/info"));
        fs::create_dir_all(&fork_info).unwrap();
        fs::write(
            fork_info.join("alternates"),
            source_objects.to_string_lossy().as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn lookup_returns_source_id_for_fork() {
        let tmp = tempfile::tempdir().unwrap();
        setup_fork(tmp.path(), "source-repo-1234", "fork-abc-9999");
        let cache = AlternatesCache::new();
        let got = cache.lookup(tmp.path(), "fork-abc-9999");
        assert_eq!(got.as_deref(), Some("source-repo-1234"));
    }

    #[test]
    fn lookup_returns_none_when_no_alternates_file() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("xyz.git/objects/info")).unwrap();
        let cache = AlternatesCache::new();
        assert_eq!(cache.lookup(tmp.path(), "xyz"), None);
    }

    #[test]
    fn second_lookup_is_served_from_cache() {
        // Observable proof of caching without mtime-manipulation: on a
        // cache hit the entry's `mtime` field won't be re-checked on
        // the happy path. We test indirectly by checking that repeated
        // lookups return the same value and that the entry is present
        // in the internal map. (A miss-all-the-time impl would still
        // produce the same result, but the presence-in-map is the
        // smoking gun that we *stored* an entry to reuse.)
        let tmp = tempfile::tempdir().unwrap();
        setup_fork(tmp.path(), "source-repo-1234", "fork-abc-9999");
        let cache = AlternatesCache::new();
        assert!(cache.inner.lock().unwrap().is_empty());
        let _ = cache.lookup(tmp.path(), "fork-abc-9999");
        assert_eq!(cache.inner.lock().unwrap().len(), 1);
        // Second lookup finds the entry already cached.
        let _ = cache.lookup(tmp.path(), "fork-abc-9999");
        assert_eq!(cache.inner.lock().unwrap().len(), 1);
    }

    #[test]
    fn lookup_reresolves_when_alternates_rewritten() {
        // Rewriting the alternates file bumps its mtime (ext4 has
        // nanosecond resolution; a brief sleep between writes is
        // conservative). The cache should notice and re-resolve.
        let tmp = tempfile::tempdir().unwrap();
        setup_fork(tmp.path(), "source-repo-1234", "fork-abc-9999");
        let cache = AlternatesCache::new();
        assert_eq!(
            cache.lookup(tmp.path(), "fork-abc-9999").as_deref(),
            Some("source-repo-1234"),
        );

        std::thread::sleep(std::time::Duration::from_millis(10));
        let new_source = tmp.path().join("new-source-5678.git/objects");
        fs::create_dir_all(&new_source).unwrap();
        let alt = tmp
            .path()
            .join("fork-abc-9999.git/objects/info/alternates");
        fs::write(&alt, new_source.to_string_lossy().as_bytes()).unwrap();

        assert_eq!(
            cache.lookup(tmp.path(), "fork-abc-9999").as_deref(),
            Some("new-source-5678"),
        );
    }

    #[test]
    fn invalidate_drops_entry() {
        let tmp = tempfile::tempdir().unwrap();
        setup_fork(tmp.path(), "source-repo-1234", "fork-abc-9999");
        let cache = AlternatesCache::new();
        cache.lookup(tmp.path(), "fork-abc-9999");
        assert_eq!(cache.inner.lock().unwrap().len(), 1);
        cache.invalidate("fork-abc-9999");
        assert!(cache.inner.lock().unwrap().is_empty());
    }

    #[test]
    fn resolve_rejects_target_outside_repos_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let fork_info = tmp.path().join("fork-xyz-0000.git/objects/info");
        fs::create_dir_all(&fork_info).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(outside.path().join("evil.git/objects")).unwrap();
        fs::write(
            fork_info.join("alternates"),
            outside
                .path()
                .join("evil.git/objects")
                .to_string_lossy()
                .as_bytes(),
        )
        .unwrap();
        let cache = AlternatesCache::new();
        assert_eq!(cache.lookup(tmp.path(), "fork-xyz-0000"), None);
    }
}
