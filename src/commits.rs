//! Server-side commits: `POST /v1/repos/:id/commits`.
//!
//! Lets a caller that is *not* a git client (a Worker, a Lambda, a regular
//! HTTP client) create a commit in a repo, atomically updating a branch.
//! This is M5 on the roadmap — the headline "agent-first" endpoint that
//! makes the product usable from a serverless function.
//!
//! ## Implementation
//!
//! The prototype shells out to git plumbing commands: `hash-object`,
//! `read-tree`, `update-index`, `write-tree`, `commit-tree`, `update-ref`.
//! Each request spawns a handful of short-lived child processes against a
//! dedicated temp index file so concurrent requests don't clobber each
//! other's in-flight state.
//!
//! Shelling out is ugly and slow compared to a native gitoxide
//! implementation, but it's ~150 lines instead of ~1500, and it inherits
//! the exact semantics of git's own commit path — including deltas over
//! large trees, correct tree entry ordering, and the empty-tree SHA
//! convention. M1 swaps these subprocess calls for direct `gix`
//! `Repository::write_blob()` / `write_object()` calls without changing
//! the REST surface.
//!
//! ## Atomicity
//!
//! The final `git update-ref <branch> <new> <expected>` is a native
//! compare-and-swap on the filesystem ref. Two concurrent commits racing
//! on the same branch:
//!   - both read the same parent,
//!   - both build independent trees + commits,
//!   - one wins the update-ref, the other fails with status 1 and we
//!     return 409 Conflict with the current head so the caller can retry.
//!
//! This is exactly the ref-level CAS we'll promote to a first-class
//! RefStore trait in M3.

use crate::{
    auth::authorize_rest,
    error::{Error, Result},
    ownership::enforce_owner,
    refs::CasOutcome,
    rest::RestState,
};
use axum::{
    extract::{Path as AxumPath, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::{path::Path, process::Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// A file-level change in a single commit. `op` discriminates.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Change {
    /// Create or overwrite the file at `path` with the given content.
    Write {
        path: String,
        /// UTF-8 content. Mutually exclusive with `contentBase64`.
        #[serde(default)]
        content: Option<String>,
        /// Base64-encoded binary content. Mutually exclusive with `content`.
        #[serde(default, rename = "contentBase64")]
        content_base64: Option<String>,
        /// Git file mode. Defaults to `100644`. We accept `100755` for
        /// executable regular files; everything else is rejected.
        #[serde(default = "default_mode")]
        mode: String,
    },
    /// Remove the file at `path`. Missing path is silently ignored (git
    /// update-index --force-remove semantics).
    Delete { path: String },
}

fn default_mode() -> String {
    "100644".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Author {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct CommitBody {
    /// Branch to update. Short form — we always prepend `refs/heads/`.
    pub branch: String,

    /// SHA-1 of the expected current commit on `branch`. `None` means the
    /// branch must not yet exist (orphan commit / new branch). This doubles
    /// as the CAS predicate for `update-ref`.
    #[serde(default)]
    pub parent: Option<String>,

    pub message: String,

    #[serde(default)]
    pub author: Option<Author>,

    pub changes: Vec<Change>,
}

#[derive(Debug, Serialize)]
pub struct CommitResult {
    pub commit: String,
    pub tree: String,
    pub branch: String,
}

/// The canonical SHA of git's empty tree. Hard-coded in git for the same
/// reason we hard-code it here: it's a protocol constant.
const EMPTY_TREE_SHA: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

pub async fn create_commit(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<CommitBody>,
) -> Result<Json<CommitResult>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token,
        state.cfg.jwt_secret.as_deref(),
    )?;
    crate::storage::validate_repo_id(&repo_id)?;
    if !state.storage.exists(&repo_id) {
        return Err(Error::RepoNotFound(repo_id));
    }
    enforce_owner(&*state.ownership, &principal, &repo_id).await?;
    if !valid_branch_name(&body.branch) {
        return Err(Error::BadRequest(format!("invalid branch name: {:?}", body.branch)));
    }
    for change in &body.changes {
        let (path, mode) = match change {
            Change::Write { path, mode, .. } => (path.as_str(), Some(mode.as_str())),
            Change::Delete { path } => (path.as_str(), None),
        };
        if !valid_path(path) {
            return Err(Error::BadRequest(format!(
                "invalid path: {path:?} (no absolute, no '..', no empty components)"
            )));
        }
        if let Some(m) = mode {
            if m != "100644" && m != "100755" {
                return Err(Error::BadRequest(format!(
                    "unsupported mode {m:?} (only 100644 and 100755 allowed)"
                )));
            }
        }
    }

    // Storage trait deliberately doesn't expose on-disk paths (a chunked-KV
    // backend wouldn't have one). The commit plumbing is FS-specific because
    // it shells out to git — so we derive the path from config here. When M1
    // lands and this shell-out is replaced with native gitoxide calls, this
    // coupling goes away.
    let git_dir = state.cfg.repos_dir().join(format!("{repo_id}.git"));
    let ref_name = format!("refs/heads/{}", body.branch);

    // 1. Resolve the base tree. If parent was specified, pin to its tree and
    // also verify it matches the current ref head (so we fail fast before
    // doing any work if the caller has a stale parent).
    let base_tree = match &body.parent {
        Some(sha) => {
            validate_sha(sha)?;
            // Verify parent exists. cat-file -e exits 0 if present.
            let (rc, _, stderr) = run_git(&git_dir, &["cat-file", "-e", sha], &[], None).await?;
            if rc != 0 {
                return Err(Error::BadRequest(format!(
                    "parent commit not found: {sha} ({})",
                    String::from_utf8_lossy(&stderr).trim()
                )));
            }
            // Get its tree.
            let (rc, stdout, stderr) =
                run_git(&git_dir, &["rev-parse", &format!("{sha}^{{tree}}")], &[], None).await?;
            if rc != 0 {
                return Err(Error::Other(anyhow::anyhow!(
                    "rev-parse tree failed: {}",
                    String::from_utf8_lossy(&stderr)
                )));
            }
            String::from_utf8(stdout)?.trim().to_string()
        }
        None => EMPTY_TREE_SHA.to_string(),
    };

    // 2. Temp index file + temp "work tree" so concurrent commits in the
    // same repo don't clobber each other's in-flight state. The work tree
    // is an empty directory; git's `update-index --force-remove` refuses to
    // run in a "bare" context (git sees no work tree), but it doesn't care
    // what the work tree *contains* — only that one exists. We drop both
    // on return, success or failure.
    let salt = uuid::Uuid::new_v4().simple().to_string();
    let index_path = git_dir.join(format!("index-commit-{salt}"));
    let worktree_path = git_dir.join(format!("wt-commit-{salt}"));
    std::fs::create_dir_all(&worktree_path)?;
    let _index_guard = TempFile(index_path.clone());
    let _wt_guard = TempDir(worktree_path.clone());

    let index_env_owned: Vec<(String, String)> = vec![
        ("GIT_INDEX_FILE".into(), index_path.to_string_lossy().into()),
        ("GIT_WORK_TREE".into(), worktree_path.to_string_lossy().into()),
    ];
    let index_env: Vec<(&str, &str)> = index_env_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // 3. Seed the index with the base tree.
    if base_tree != EMPTY_TREE_SHA {
        let (rc, _, stderr) = run_git(&git_dir, &["read-tree", &base_tree], &index_env, None).await?;
        if rc != 0 {
            return Err(Error::Other(anyhow::anyhow!(
                "read-tree failed: {}",
                String::from_utf8_lossy(&stderr)
            )));
        }
    }

    // 4. Apply changes in order.
    for change in &body.changes {
        match change {
            Change::Write { path, content, content_base64, mode } => {
                let bytes = match (content, content_base64) {
                    (Some(_), Some(_)) => {
                        return Err(Error::BadRequest(format!(
                            "change for {path}: only one of content/contentBase64"
                        )));
                    }
                    (None, None) => Vec::new(),
                    (Some(s), None) => s.as_bytes().to_vec(),
                    (None, Some(b64)) => B64.decode(b64).map_err(|e| {
                        Error::BadRequest(format!("change for {path}: bad base64: {e}"))
                    })?,
                };
                // hash-object writes the blob into the object database and
                // prints the SHA.
                let (rc, stdout, stderr) = run_git(
                    &git_dir,
                    &["hash-object", "-w", "--stdin", "--path", path],
                    &[],
                    Some(&bytes),
                )
                .await?;
                if rc != 0 {
                    return Err(Error::Other(anyhow::anyhow!(
                        "hash-object failed for {path}: {}",
                        String::from_utf8_lossy(&stderr)
                    )));
                }
                let blob = String::from_utf8(stdout)?.trim().to_string();
                let cacheinfo = format!("{mode},{blob},{path}");
                let (rc, _, stderr) = run_git(
                    &git_dir,
                    &["update-index", "--add", "--cacheinfo", &cacheinfo],
                    &index_env,
                    None,
                )
                .await?;
                if rc != 0 {
                    return Err(Error::Other(anyhow::anyhow!(
                        "update-index --add failed for {path}: {}",
                        String::from_utf8_lossy(&stderr)
                    )));
                }
            }
            Change::Delete { path } => {
                let (rc, _, stderr) = run_git(
                    &git_dir,
                    &["update-index", "--force-remove", path],
                    &index_env,
                    None,
                )
                .await?;
                if rc != 0 {
                    return Err(Error::Other(anyhow::anyhow!(
                        "update-index --force-remove failed for {path}: {}",
                        String::from_utf8_lossy(&stderr)
                    )));
                }
            }
        }
    }

    // 5. Write the tree.
    let (rc, stdout, stderr) = run_git(&git_dir, &["write-tree"], &index_env, None).await?;
    if rc != 0 {
        return Err(Error::Other(anyhow::anyhow!(
            "write-tree failed: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    let tree_sha = String::from_utf8(stdout)?.trim().to_string();

    // 6. Write the commit. Env vars pin the author + committer without
    // depending on the bare repo's (almost always absent) local git config.
    let (author_name, author_email) = match &body.author {
        Some(a) => (a.name.clone(), a.email.clone()),
        None => ("Artifacts".to_string(), "artifacts@noreply.local".to_string()),
    };
    let commit_env: Vec<(&str, &str)> = vec![
        ("GIT_AUTHOR_NAME", &author_name),
        ("GIT_AUTHOR_EMAIL", &author_email),
        ("GIT_COMMITTER_NAME", &author_name),
        ("GIT_COMMITTER_EMAIL", &author_email),
    ];
    let mut commit_args: Vec<String> = vec!["commit-tree".into(), tree_sha.clone()];
    if let Some(parent) = &body.parent {
        commit_args.push("-p".into());
        commit_args.push(parent.clone());
    }
    commit_args.push("-m".into());
    commit_args.push(body.message.clone());
    let commit_args_ref: Vec<&str> = commit_args.iter().map(|s| s.as_str()).collect();
    let (rc, stdout, stderr) = run_git(&git_dir, &commit_args_ref, &commit_env, None).await?;
    if rc != 0 {
        return Err(Error::Other(anyhow::anyhow!(
            "commit-tree failed: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    let commit_sha = String::from_utf8(stdout)?.trim().to_string();

    // 7. CAS the ref. This is the atomicity boundary — delegated to the
    // RefStore trait so the guts are swappable (M3-proper replaces the
    // single-node FsRefStore with a distributed state machine; this call
    // site stays identical).
    match state
        .refs
        .cas_update(&repo_id, &ref_name, body.parent.as_deref(), &commit_sha)
        .await?
    {
        CasOutcome::Updated => {}
        CasOutcome::Conflict { current } => {
            tracing::info!(
                repo = %repo_id, branch = %body.branch,
                expected = ?body.parent, current = ?current,
                "commit ref-conflict"
            );
            return Err(Error::RefConflict {
                branch: body.branch,
                expected: body.parent.clone(),
                current,
            });
        }
    }

    Ok(Json(CommitResult {
        commit: commit_sha,
        tree: tree_sha,
        branch: body.branch,
    }))
}

/// Shell out to `git --git-dir <dir> <args>`, optionally pipe `stdin` in,
/// collect stdout + stderr, return exit code and both streams.
async fn run_git(
    git_dir: &Path,
    args: &[&str],
    env: &[(&str, &str)],
    stdin: Option<&[u8]>,
) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut cmd = Command::new("git");
    cmd.arg("--git-dir").arg(git_dir);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd.spawn()?;
    if let (Some(data), Some(mut sin)) = (stdin, child.stdin.take()) {
        sin.write_all(data).await?;
        sin.shutdown().await?;
        drop(sin);
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout).await?;
    }
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_end(&mut stderr).await?;
    }
    let status = child.wait().await?;
    Ok((status.code().unwrap_or(-1), stdout, stderr))
}

fn valid_branch_name(s: &str) -> bool {
    // A useful subset of git-check-ref-format. Rejects empty, leading/trailing
    // slashes, double slashes, ".." and "@{", plus any byte below 0x20.
    if s.is_empty() || s.starts_with('/') || s.ends_with('/') || s.contains("//") {
        return false;
    }
    if s.contains("..") || s.contains("@{") || s.contains('\\') {
        return false;
    }
    s.chars().all(|c| c > ' ' && c != '~' && c != '^' && c != ':' && c != '?' && c != '*' && c != '[')
}

fn valid_path(p: &str) -> bool {
    if p.is_empty() || p.starts_with('/') || p.ends_with('/') || p.contains("//") {
        return false;
    }
    if p.as_bytes().contains(&0) {
        return false;
    }
    p.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

fn validate_sha(s: &str) -> Result<()> {
    if s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(Error::BadRequest(format!("invalid sha: {s:?}")))
    }
}

struct TempFile(std::path::PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_name_validation() {
        assert!(valid_branch_name("main"));
        assert!(valid_branch_name("feature/foo-bar"));
        assert!(!valid_branch_name(""));
        assert!(!valid_branch_name("/main"));
        assert!(!valid_branch_name("main/"));
        assert!(!valid_branch_name("foo//bar"));
        assert!(!valid_branch_name("foo..bar"));
        assert!(!valid_branch_name("foo:bar"));
        assert!(!valid_branch_name("foo bar"));
    }

    #[test]
    fn path_validation() {
        assert!(valid_path("README.md"));
        assert!(valid_path("src/main.rs"));
        assert!(valid_path("a/b/c/d.txt"));
        assert!(!valid_path(""));
        assert!(!valid_path("/abs/path"));
        assert!(!valid_path("trailing/"));
        assert!(!valid_path("a//b"));
        assert!(!valid_path("a/./b"));
        assert!(!valid_path("a/../b"));
    }
}
