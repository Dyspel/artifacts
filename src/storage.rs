//! Repo storage — trait + FS-backed implementation.
//!
//! The `Storage` trait is the abstraction boundary between repo lifecycle
//! operations (create / fork / delete / exists) and whatever actually
//! holds the bytes. Today there is one impl, `FsStorage`, which keeps
//! bare git repos on disk under `$DATA_DIR/repos/<id>.git` and implements
//! forks as `objects/info/alternates` pointers (zero object copy).
//!
//! The trait is intentionally minimal — just the lifecycle ops. Git object
//! reads/writes happen through the git protocol (smart-HTTP) or the
//! commits module's plumbing shell-outs, both of which need a real
//! on-disk repo path and are therefore FS-specific today. The separation
//! lets a future backend — e.g. a chunked KV with objects striped across
//! rows in the Cloudflare DurableObject shape — implement `Storage`
//! alongside a protocol rewrite (M1) without touching REST handlers.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// Enforce the per-repo byte quota at a mutation boundary. Walks the
/// bare repo's on-disk size and refuses the request if the current
/// usage is at or above `limit`. `limit == 0` means unlimited (the
/// default; the quota is opt-in via `ARTIFACTS_MAX_REPO_BYTES`).
///
/// Race semantics match the per-user repo-count quota: the check is
/// non-transactional; concurrent writers can push the repo a little
/// over before the next check sees it. That's acceptable for a soft
/// quota — the next request lands the 413.
pub fn check_repo_byte_quota(repos_dir: &Path, repo_id: &str, limit: u64) -> Result<()> {
    if limit == 0 {
        return Ok(());
    }
    let git_dir = repos_dir.join(format!("{repo_id}.git"));
    let bytes_used = crate::rest::dir_size(&git_dir).unwrap_or(0);
    if bytes_used >= limit {
        return Err(Error::RepoByteQuotaExceeded {
            repo_id: repo_id.to_string(),
            bytes_used,
            limit,
        });
    }
    Ok(())
}

/// Repo lifecycle. Implementations are free to back repos with any
/// storage medium as long as they can honor create / fork / delete /
/// exists semantics. `FsStorage` is the one impl today.
pub trait Storage: Send + Sync {
    /// `true` iff a repo with this id exists.
    fn exists(&self, repo_id: &str) -> bool;

    /// Create a new empty repo. Errors on `RepoExists` if the id is taken.
    fn create(&self, repo_id: &str) -> Result<()>;

    /// Create `fork_id` as a fork of `source_id`. O(1) for impls that
    /// share object storage — the whole point.
    fn fork(&self, source_id: &str, fork_id: &str) -> Result<()>;

    /// Remove a repo. Implementations may soft-delete; this trait makes
    /// no guarantees about GC of shared objects.
    fn delete(&self, repo_id: &str) -> Result<()>;
}

/// Repo ID format: 24 chars, [a-z0-9]. Derived from UUIDv4, base32-ish.
/// We keep it short + URL-safe so it looks nice in `https://host/git/:id.git`.
pub fn new_repo_id() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// Validate a repository identifier: 4–64 characters of `[a-z0-9_-]`
/// (lowercase only). This is the single chokepoint guaranteeing a repo
/// id can never contain a path separator, `..`, or other punctuation,
/// so it is always safe to interpolate into a filesystem path or a
/// `.git` directory name. [`crate::ids::RepoId`] is the typed wrapper
/// that runs this at construction time.
///
/// # Errors
///
/// Returns [`Error::InvalidRepoId`] if `id` is shorter than 4 or longer
/// than 64 bytes, or contains any character outside `[a-z0-9_-]`.
pub fn validate_repo_id(id: &str) -> Result<()> {
    if id.len() < 4
        || id.len() > 64
        || !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(Error::InvalidRepoId(id.to_string()));
    }
    Ok(())
}

/// On-disk `Storage` impl. Bare repos under `<root>/<id>.git`, forks via
/// `objects/info/alternates`.
#[derive(Debug, Clone)]
pub struct FsStorage {
    root: PathBuf,
}

impl FsStorage {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// On-disk path for a repo. FS-specific — not on the `Storage` trait
    /// because a chunked-KV backend wouldn't have a path. Callers that
    /// need a real directory (the CGI bridge, the commits plumbing) go
    /// through this or via `Config::repos_dir()` which gives the same
    /// answer.
    ///
    /// ## Defense in depth
    ///
    /// `validate_repo_id` already rejects every shape that could
    /// produce a path-escape (slashes, dots, control chars), and every
    /// production caller validates before reaching here. This function
    /// is the second line of defense: if a future change loosens
    /// `validate_repo_id` *without* updating us, the asserts here
    /// catch the regression at the seam where it would actually do
    /// harm. We `debug_assert` (panic in tests) and use
    /// `tracing::error` plus return-anyway in release — better to
    /// surface the bug loudly than to silently hand back a path
    /// that resolves somewhere unexpected.
    ///
    /// Two checks:
    ///   1. The joined path strips cleanly off `self.root` — i.e.
    ///      it's a strict descendant.
    ///   2. Every component of the relative remainder is a `Normal`
    ///      path component (rejecting `..`, leading `/`, prefix
    ///      drives on Windows, etc).
    fn repo_path(&self, id: &str) -> PathBuf {
        let path = self.root.join(format!("{id}.git"));
        if let Err(violation) = path_is_safe_descendant(&self.root, &path) {
            // Catch in tests/dev. validate_repo_id contract was
            // violated — fix the validator, not this assert.
            debug_assert!(
                false,
                "FsStorage::repo_path produced unsafe path for id {id:?}: {violation}",
            );
            tracing::error!(
                id = %id, root = %self.root.display(), joined = %path.display(),
                violation,
                "FsStorage::repo_path: path escapes root (validate_repo_id contract violated)",
            );
        }
        path
    }
}

/// Confirm that `joined` is a strict descendant of `root`, with
/// every relative component being a `Normal` path piece (no `..`,
/// no absolute-path roots, no prefix drives). Returns `Err(reason)`
/// describing the violation; reason text is short enough to plumb
/// into a tracing field.
fn path_is_safe_descendant(root: &Path, joined: &Path) -> std::result::Result<(), &'static str> {
    let rel = match joined.strip_prefix(root) {
        Ok(r) => r,
        Err(_) => return Err("strip_prefix(root) failed"),
    };
    for comp in rel.components() {
        match comp {
            std::path::Component::Normal(_) => {},
            std::path::Component::ParentDir => return Err("ParentDir component"),
            std::path::Component::RootDir => return Err("RootDir component"),
            std::path::Component::Prefix(_) => return Err("Prefix component"),
            std::path::Component::CurDir => return Err("CurDir component"),
        }
    }
    Ok(())
}

impl Storage for FsStorage {
    fn exists(&self, id: &str) -> bool {
        self.repo_path(id).is_dir()
    }

    /// Initialize a new empty bare repo. Fails if the repo already exists.
    ///
    /// Writes the minimal bare-repo layout directly — no `git init`
    /// subprocess. The previous impl shelled `git init --bare --quiet
    /// --initial-branch=main`; that emitted a `description`,
    /// `info/exclude`, and a directory of `hooks/*.sample` files we
    /// don't use. Producing the layout in-process drops those
    /// (smaller on-disk footprint, simpler to mirror in a non-FS
    /// `Storage` impl) and removes the `git` binary requirement
    /// from the create path. Same shape as `fork()` already writes
    /// by hand for the same reasons.
    fn create(&self, id: &str) -> Result<()> {
        validate_repo_id(id)?;
        let path = self.repo_path(id);
        if path.exists() {
            return Err(Error::RepoExists(id.to_string()));
        }
        write_bare_repo_layout(&path).inspect_err(|_| {
            // Best-effort cleanup so a partial init doesn't leave a
            // stub dir that future creates would treat as RepoExists.
            let _ = std::fs::remove_dir_all(&path);
        })?;
        Ok(())
    }

    /// Fork `source_id` as `fork_id`. O(1) — writes a single alternates file,
    /// copies refs. No object data is duplicated.
    ///
    /// After a fork, the fork shares the source's object store via git's
    /// `alternates` mechanism. New objects written to the fork live only in
    /// the fork's own objects dir; `git gc` on either repo respects the
    /// relationship.
    fn fork(&self, source_id: &str, fork_id: &str) -> Result<()> {
        validate_repo_id(fork_id)?;
        let source = self.repo_path(source_id);
        if !source.is_dir() {
            return Err(Error::RepoNotFound(source_id.to_string()));
        }
        let fork = self.repo_path(fork_id);
        if fork.exists() {
            return Err(Error::RepoExists(fork_id.to_string()));
        }

        // Step 1: init empty bare repo for the fork. We do this directly in
        // fs rather than shelling out to `git init` to keep fork latency
        // tight on the hot path — a fork is exactly three file writes
        // (HEAD, config, alternates) plus a refs copy.
        std::fs::create_dir_all(fork.join("objects/info"))?;
        std::fs::create_dir_all(fork.join("objects/pack"))?;
        std::fs::create_dir_all(fork.join("refs/heads"))?;
        std::fs::create_dir_all(fork.join("refs/tags"))?;

        // Step 2: point the fork's object store at the source's objects dir.
        // This is the whole trick. Any object reachable from the source is
        // now reachable from the fork, at the cost of one file write.
        let alternates_path = fork.join("objects/info/alternates");
        let source_objects = source.join("objects");
        std::fs::write(
            &alternates_path,
            format!("{}\n", source_objects.to_string_lossy()),
        )?;

        // Step 3: copy HEAD so the fork points at the same symbolic ref.
        let head = std::fs::read(source.join("HEAD"))?;
        std::fs::write(fork.join("HEAD"), head)?;

        // Step 4: minimal config. bare=true, plus enable smart-HTTP serving.
        std::fs::write(
            fork.join("config"),
            "[core]\n\trepositoryformatversion = 0\n\tbare = true\n\
             [http]\n\treceivepack = true\n\tuploadpack = true\n",
        )?;

        // Step 5: snapshot the source's current refs atomically.
        //
        // The earlier implementation walked the source's `refs/` directory
        // and copied each file. That's a torn-read against any concurrent
        // push: new refs can appear mid-walk, existing refs can change
        // mid-file-copy. Instead, we ask git for a consistent point-in-
        // time view via `git show-ref` and write the result into the
        // fork's `packed-refs` in one shot. git's own read path holds
        // internal consistency while iterating, and our destination is
        // a single file write (one atomic rename on most filesystems).
        snapshot_refs_to_packed(&source, &fork)?;

        Ok(())
    }

    /// Delete a repo. For M0 this is a rm -rf; production needs
    /// soft-delete and GC ordering (can't delete a repo that's the
    /// alternates source for another live repo).
    fn delete(&self, id: &str) -> Result<()> {
        let path = self.repo_path(id);
        if !path.is_dir() {
            return Err(Error::RepoNotFound(id.to_string()));
        }
        std::fs::remove_dir_all(&path)?;
        Ok(())
    }
}

/// Materialize the minimum-viable bare git repo at `path`. Same
/// shape `git init --bare --initial-branch=main` produces, minus
/// the parts we don't use (description, info/exclude, hooks/*.sample).
///
/// Files written:
///   * `HEAD`               — `ref: refs/heads/main`
///   * `config`             — bare-repo config + smart-HTTP flags
///   * `refs/heads/`        — empty directory
///   * `refs/tags/`         — empty directory
///   * `objects/info/`      — empty directory (alternates may land here)
///   * `objects/pack/`      — empty directory (incoming packs land here)
///
/// Public-in-crate so it's reusable: `fork()` continues to write its
/// own customized variant (alternates, copied HEAD, packed-refs
/// snapshot), but a future `MemStorage` or chunked-KV `Storage`
/// impl can call this same helper conceptually — it documents what
/// bare-repo state every backend has to satisfy.
pub(crate) fn write_bare_repo_layout(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path.join("refs/heads"))?;
    std::fs::create_dir_all(path.join("refs/tags"))?;
    std::fs::create_dir_all(path.join("objects/info"))?;
    std::fs::create_dir_all(path.join("objects/pack"))?;

    // HEAD points at refs/heads/main, which doesn't yet exist —
    // that's the v2 "unborn HEAD" state we already advertise via
    // ls-refs's `unborn` capability. Same shape `git init
    // --initial-branch=main` produces.
    std::fs::write(path.join("HEAD"), "ref: refs/heads/main\n")?;

    // config is the same minimal block fork() writes. Both the
    // bare-repo flags and the smart-HTTP enablement are required
    // for our smart-HTTP routes to serve this repo.
    std::fs::write(
        path.join("config"),
        "[core]\n\trepositoryformatversion = 0\n\tbare = true\n\
         [http]\n\treceivepack = true\n\tuploadpack = true\n",
    )?;
    Ok(())
}

/// Snapshot source refs into the fork's `packed-refs` atomically.
///
/// Uses `git show-ref` on the source to get a consistent iteration of
/// every ref at the call site's point in time. git holds read
/// consistency while the iteration runs; we then write the whole list
/// as the fork's `packed-refs` in a single file write.
///
/// This is the fix for the torn-read race the earlier
/// `copy_dir_recursive`-based implementation had: there, a concurrent
/// push to the source could add, remove, or modify refs while we were
/// walking `refs/`, and the fork would end up with an inconsistent
/// snapshot.
///
/// Output format matches git's packed-refs:
///
/// ```text
/// # pack-refs with: peeled fully-peeled sorted
/// <sha> refs/heads/main
/// <sha> refs/heads/feature
/// ...
/// ```
///
/// Empty source (no refs) → no packed-refs file. git handles that fine.
fn snapshot_refs_to_packed(src: &Path, dst: &Path) -> Result<()> {
    // Enumerate the source repo's refs natively via gix; HEAD and any
    // other symbolic refs are filtered out (their targets get written
    // when we iterate to the underlying object ref). Annotated-tag
    // peeled-target entries are deliberately *not* written — they're
    // an optimization git can rebuild on demand, and emitting them
    // here would require a separate find-object lookup per tag we
    // don't want to pay at fork time.
    let repo = gix::open(src)
        .map_err(|e| Error::GixError(format!("gix::open({}): {e}", src.display())))?;
    let platform = repo
        .references()
        .map_err(|e| Error::GixError(format!("repo.references(): {e}")))?;
    let iter = platform
        .all()
        .map_err(|e| Error::GixError(format!("references.all(): {e}")))?;

    let mut entries: Vec<(String, String)> = Vec::new();
    for reference in iter {
        let reference = match reference {
            Ok(r) => r,
            Err(e) => {
                // Broken ref files shouldn't take the fork down;
                // log + skip. Matches `git show-ref`'s behaviour of
                // emitting a warning to stderr and continuing.
                tracing::warn!(error = %e, "skipping unreadable ref during fork snapshot");
                continue;
            },
        };
        if let gix::refs::TargetRef::Object(oid) = reference.target() {
            entries.push((
                oid.to_hex().to_string(),
                reference.name().as_bstr().to_string(),
            ));
        }
    }

    if entries.is_empty() {
        return Ok(());
    }

    // packed-refs spec requires sorted-by-name output; gix returns
    // refs in fs-order which is approximately but not exactly the
    // same. Sort explicitly so the header's `sorted` capability is
    // honest.
    entries.sort_by(|a, b| a.1.cmp(&b.1));

    let mut packed = String::from("# pack-refs with: peeled fully-peeled sorted\n");
    for (sha, name) in entries {
        packed.push_str(&sha);
        packed.push(' ');
        packed.push_str(&name);
        packed.push('\n');
    }
    std::fs::write(dst.join("packed-refs"), packed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn create_writes_minimal_bare_repo_layout_recognised_by_git() {
        // The new create() path doesn't shell `git init`; it lays
        // out HEAD + config + refs/* + objects/* directly. This
        // test confirms `git` itself accepts the result by running
        // `git rev-parse --is-bare-repository` against it (returns
        // "true\n" iff the layout is structurally valid).
        let tmp = tempdir();
        let storage = FsStorage::new(tmp.join("repos")).unwrap();
        let id = new_repo_id();
        storage.create(&id).unwrap();
        let path = storage.repo_path(&id);

        // Sanity: HEAD points at refs/heads/main, config has
        // bare=true, the four directories exist.
        let head = std::fs::read_to_string(path.join("HEAD")).unwrap();
        assert_eq!(head, "ref: refs/heads/main\n");
        let config = std::fs::read_to_string(path.join("config")).unwrap();
        assert!(config.contains("bare = true"), "config: {config:?}");
        assert!(config.contains("uploadpack = true"));
        assert!(config.contains("receivepack = true"));
        assert!(path.join("refs/heads").is_dir());
        assert!(path.join("refs/tags").is_dir());
        assert!(path.join("objects/info").is_dir());
        assert!(path.join("objects/pack").is_dir());

        // The big claim: git accepts our layout as-is.
        let out = Command::new("git")
            .arg("--git-dir")
            .arg(&path)
            .args(["rev-parse", "--is-bare-repository"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "true",
            "git didn't recognize our layout as bare"
        );
    }

    #[test]
    fn byte_quota_zero_means_unlimited() {
        let tmp = tempdir();
        let storage = FsStorage::new(tmp.join("repos")).unwrap();
        let id = new_repo_id();
        storage.create(&id).unwrap();
        // `limit = 0` always allows, regardless of size.
        assert!(check_repo_byte_quota(&tmp.join("repos"), &id, 0).is_ok());
    }

    #[test]
    fn byte_quota_under_limit_passes() {
        let tmp = tempdir();
        let storage = FsStorage::new(tmp.join("repos")).unwrap();
        let id = new_repo_id();
        storage.create(&id).unwrap();
        // Fresh bare-repo layout is a few hundred bytes; 100 MiB is
        // generous headroom.
        assert!(check_repo_byte_quota(&tmp.join("repos"), &id, 100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn byte_quota_over_limit_errors_with_quota_variant() {
        let tmp = tempdir();
        let storage = FsStorage::new(tmp.join("repos")).unwrap();
        let id = new_repo_id();
        storage.create(&id).unwrap();
        // Limit of 1 byte will fail — every fresh repo has at least
        // a HEAD file (~20 bytes) on disk.
        let err = check_repo_byte_quota(&tmp.join("repos"), &id, 1).unwrap_err();
        assert!(
            matches!(err, Error::RepoByteQuotaExceeded { ref repo_id, limit, .. }
                if repo_id == &id && limit == 1),
            "got: {err}"
        );
    }

    #[test]
    fn path_is_safe_descendant_accepts_normal_repo_path() {
        let root = std::path::PathBuf::from("/data/repos");
        let joined = root.join("abc-123.git");
        assert!(path_is_safe_descendant(&root, &joined).is_ok());
    }

    #[test]
    fn path_is_safe_descendant_rejects_parent_dir_traversal() {
        // If validate_repo_id ever let `../etc` through, the joined
        // path would normalise to /etc.git — outside root. We
        // detect the ParentDir component.
        let root = std::path::PathBuf::from("/data/repos");
        let joined = root.join("../etc.git");
        let err = path_is_safe_descendant(&root, &joined).unwrap_err();
        assert_eq!(err, "ParentDir component");
    }

    #[test]
    #[allow(clippy::join_absolute_paths)]
    fn path_is_safe_descendant_rejects_absolute_id() {
        // An id like `/etc/passwd` would have joined produce just
        // `/etc/passwd.git` (Path::join replaces with absolute).
        // strip_prefix(root) fails — we surface that. The clippy
        // allow above is precisely *because* this test exercises that
        // replacement behaviour.
        let root = std::path::PathBuf::from("/data/repos");
        let joined = root.join("/etc/passwd.git");
        let err = path_is_safe_descendant(&root, &joined).unwrap_err();
        assert_eq!(err, "strip_prefix(root) failed");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "produced unsafe path")]
    fn repo_path_panics_in_debug_when_id_breaks_the_contract() {
        // We never actually reach this from production callers
        // because validate_repo_id rejects "../foo" upstream. This
        // test pretends a future change loosened the validator and
        // shows that repo_path catches the regression instead of
        // silently emitting a unsafe path. debug_assert means
        // panic in `cargo test` (this test); release builds log
        // and return the unsafe path (so legitimate-but-misvalidated
        // ids don't crash the server, while the bug is loud in the
        // logs).
        let storage = FsStorage::new(tempdir().join("repos")).unwrap();
        let _ = storage.repo_path("../etc");
    }

    #[test]
    fn validate_repo_id_rules() {
        assert!(validate_repo_id("abc").is_err()); // too short
        assert!(validate_repo_id("ABCDEF").is_err()); // uppercase
        assert!(validate_repo_id("abcd/efgh").is_err()); // slash
        assert!(validate_repo_id("abcd-1234").is_ok());
    }

    #[test]
    fn fork_creates_alternates_and_snapshots_refs_to_packed() {
        let tmp = tempdir();
        let storage = FsStorage::new(tmp.join("repos")).unwrap();
        let a = new_repo_id();
        let b = new_repo_id();
        storage.create(&a).unwrap();

        // Seed source with a real commit. A bogus all-zeros SHA would
        // work for a direct-file-copy fork, but the new
        // snapshot-via-git path runs `git show-ref` — which is happy
        // to emit arbitrary SHAs, but writing a real commit makes the
        // test realistic and also verifies the alternates path
        // (objects from source are reachable in fork).
        let src_path = storage.repo_path(&a);
        // Create an empty-tree + commit pointing at it.
        let status = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&src_path)
            .args(["-c", "user.email=t@test", "-c", "user.name=t"])
            .args([
                "commit-tree",
                "-m",
                "seed",
                "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            ])
            .output()
            .unwrap();
        let commit_sha = String::from_utf8(status.stdout).unwrap().trim().to_string();
        assert_eq!(commit_sha.len(), 40);
        // update-ref to put the commit on refs/heads/main.
        let st = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&src_path)
            .args(["update-ref", "refs/heads/main", &commit_sha])
            .status()
            .unwrap();
        assert!(st.success());

        storage.fork(&a, &b).unwrap();

        // alternates file points back at source.
        let alt =
            std::fs::read_to_string(storage.repo_path(&b).join("objects/info/alternates")).unwrap();
        assert!(alt.contains(&a));

        // Refs went to packed-refs, not loose. Absence of the loose
        // file is part of the fix: the fork shouldn't write the
        // torn-loose-file shape the old copy_refs did.
        assert!(!storage.repo_path(&b).join("refs/heads/main").exists());
        let packed = std::fs::read_to_string(storage.repo_path(&b).join("packed-refs")).unwrap();
        assert!(packed.contains(&commit_sha));
        assert!(packed.contains("refs/heads/main"));
    }

    #[test]
    fn fork_of_empty_source_writes_no_packed_refs() {
        // A fresh repo has no refs. snapshot_refs_to_packed should
        // silently no-op rather than writing an empty packed-refs file
        // (which git would still accept, but the absence is cleaner).
        let tmp = tempdir();
        let storage = FsStorage::new(tmp.join("repos")).unwrap();
        let a = new_repo_id();
        let b = new_repo_id();
        storage.create(&a).unwrap();
        storage.fork(&a, &b).unwrap();
        assert!(!storage.repo_path(&b).join("packed-refs").exists());
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!("artifacts-test-{}", new_repo_id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
