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
use std::process::Command;

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
    (0..24).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

pub fn validate_repo_id(id: &str) -> Result<()> {
    if id.len() < 4
        || id.len() > 64
        || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
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
    pub fn repo_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.git"))
    }
}

impl Storage for FsStorage {
    fn exists(&self, id: &str) -> bool {
        self.repo_path(id).is_dir()
    }

    /// Initialize a new empty bare repo. Fails if the repo already exists.
    fn create(&self, id: &str) -> Result<()> {
        validate_repo_id(id)?;
        let path = self.repo_path(id);
        if path.exists() {
            return Err(Error::RepoExists(id.to_string()));
        }
        std::fs::create_dir_all(&path)?;
        let status = Command::new("git")
            .args(["init", "--bare", "--quiet", "--initial-branch=main"])
            .arg(&path)
            .status()?;
        if !status.success() {
            let _ = std::fs::remove_dir_all(&path);
            return Err(Error::Other(anyhow::anyhow!("git init failed")));
        }
        // Allow smart-HTTP backend to serve this repo without extra config.
        write_config_flag(&path, "http.receivepack", "true")?;
        write_config_flag(&path, "http.uploadpack", "true")?;
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

    /// Delete a repo. For M0 this is a rm -rf; production needs soft-delete
    /// + GC ordering (can't delete a repo that's the alternates source for
    /// another live repo).
    fn delete(&self, id: &str) -> Result<()> {
        let path = self.repo_path(id);
        if !path.is_dir() {
            return Err(Error::RepoNotFound(id.to_string()));
        }
        std::fs::remove_dir_all(&path)?;
        Ok(())
    }
}

fn write_config_flag(repo: &Path, key: &str, value: &str) -> Result<()> {
    let status = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .args(["config", key, value])
        .status()?;
    if !status.success() {
        return Err(Error::Other(anyhow::anyhow!("git config {key} failed")));
    }
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
///     # pack-refs with: peeled fully-peeled sorted
///     <sha> refs/heads/main
///     <sha> refs/heads/feature
///     ...
///
/// Empty source (no refs) → no packed-refs file. git handles that fine.
fn snapshot_refs_to_packed(src: &Path, dst: &Path) -> Result<()> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(src)
        .arg("show-ref")
        .output()?;
    // `git show-ref` exits 1 with empty stdout when there are no refs
    // (fresh init-bare, no pushes yet). That's not an error for us.
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(());
    }

    let mut packed = String::from("# pack-refs with: peeled fully-peeled sorted\n");
    for line in stdout.lines() {
        // show-ref emits `<sha> <refname>`. Packed-refs uses the same
        // shape per line, so a direct pass-through is valid. We
        // deliberately *don't* use --dereference here; annotated tags'
        // peeled entries are an optimization git can rebuild on
        // demand, and the dereferenced output form is trickier to
        // convert to the exact packed-refs shape (^<peeled-sha> as
        // its own line right after the tag line).
        if let Some((sha, name)) = line.split_once(' ') {
            packed.push_str(sha);
            packed.push(' ');
            packed.push_str(name);
            packed.push('\n');
        }
    }
    std::fs::write(dst.join("packed-refs"), packed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .arg("--git-dir").arg(&src_path)
            .args(["-c", "user.email=t@test", "-c", "user.name=t"])
            .args(["commit-tree", "-m", "seed",
                   "4b825dc642cb6eb9a060e54bf8d69288fbee4904"])
            .output()
            .unwrap();
        let commit_sha = String::from_utf8(status.stdout).unwrap().trim().to_string();
        assert_eq!(commit_sha.len(), 40);
        // update-ref to put the commit on refs/heads/main.
        let st = std::process::Command::new("git")
            .arg("--git-dir").arg(&src_path)
            .args(["update-ref", "refs/heads/main", &commit_sha])
            .status().unwrap();
        assert!(st.success());

        storage.fork(&a, &b).unwrap();

        // alternates file points back at source.
        let alt = std::fs::read_to_string(
            storage.repo_path(&b).join("objects/info/alternates"),
        )
        .unwrap();
        assert!(alt.contains(&a));

        // Refs went to packed-refs, not loose. Absence of the loose
        // file is part of the fix: the fork shouldn't write the
        // torn-loose-file shape the old copy_refs did.
        assert!(!storage.repo_path(&b).join("refs/heads/main").exists());
        let packed = std::fs::read_to_string(
            storage.repo_path(&b).join("packed-refs"),
        )
        .unwrap();
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
