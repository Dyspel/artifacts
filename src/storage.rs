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

        // Step 5: snapshot the source's current refs. This is a shallow
        // copy — the refs themselves are just pointers (40-byte SHAs), and
        // the objects they point at are already reachable via alternates.
        copy_refs(&source, &fork)?;

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

/// Copy `refs/` and `packed-refs` from `src` to `dst`. Walks `refs/`
/// recursively and copies each file. Safe because refs are small: a file
/// per branch containing a 40-byte SHA.
fn copy_refs(src: &Path, dst: &Path) -> Result<()> {
    if let Ok(packed) = std::fs::read(src.join("packed-refs")) {
        std::fs::write(dst.join("packed-refs"), packed)?;
    }
    let refs_src = src.join("refs");
    if !refs_src.is_dir() {
        return Ok(());
    }
    copy_dir_recursive(&refs_src, &dst.join("refs"))?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
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
    fn fork_creates_alternates_and_copies_refs() {
        let tmp = tempdir();
        let storage = FsStorage::new(tmp.join("repos")).unwrap();
        let a = new_repo_id();
        let b = new_repo_id();
        storage.create(&a).unwrap();

        // Write a ref so we can verify it gets copied.
        let ref_path = storage.repo_path(&a).join("refs/heads/main");
        std::fs::write(&ref_path, "0000000000000000000000000000000000000000\n").unwrap();

        storage.fork(&a, &b).unwrap();
        let alt = std::fs::read_to_string(
            storage.repo_path(&b).join("objects/info/alternates"),
        )
        .unwrap();
        assert!(alt.contains(&a));
        let copied_ref = std::fs::read_to_string(
            storage.repo_path(&b).join("refs/heads/main"),
        )
        .unwrap();
        assert_eq!(copied_ref.trim(), "0000000000000000000000000000000000000000");
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!("artifacts-test-{}", new_repo_id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
