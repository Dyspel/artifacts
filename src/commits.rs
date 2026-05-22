//! Server-side commits: `POST /v1/repos/:id/commits`.
//!
//! Lets a caller that is *not* a git client (a Worker, a Lambda, a regular
//! HTTP client) create a commit in a repo, atomically updating a branch.
//! This is M5 on the roadmap — the headline "agent-first" endpoint that
//! makes the product usable from a serverless function.
//!
//! ## Implementation
//!
//! The commit construction is native `gix`: `Repository::write_blob` for
//! each changed file, `Repository::edit_tree(...).upsert/remove/write`
//! for the tree mutation (correct entry ordering + empty-tree convention
//! handled by gix), then `Repository::write_object` for the commit
//! header. No subprocess, no temp index, no per-request work tree —
//! the whole gix flow runs inside one `spawn_blocking` task. Previously
//! this was a five-subprocess dance (`hash-object` / `read-tree` /
//! `update-index` / `write-tree` / `commit-tree` plus a temp
//! `GIT_INDEX_FILE` + `GIT_WORK_TREE`).
//!
//! ## Atomicity
//!
//! The ref update is delegated to `RefStore::cas_update`, which the
//! filesystem impl implements as a `O_EXCL` lock + `rename`. Two
//! concurrent commits racing on the same branch:
//!   - both read the same parent,
//!   - both build independent trees + commits via gix,
//!   - one wins the CAS, the other fails and we return 409
//!     `ref_conflict` with the current head so the caller can retry.

use crate::{
    auth::authorize_rest,
    error::{Error, Result},
    ownership::enforce_owner,
    rate_limit::Class,
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

pub async fn create_commit(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<CommitBody>,
) -> Result<Json<CommitResult>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.authn.rate_limit.check(&principal, Class::Commit)?;
    crate::storage::validate_repo_id(&repo_id)?;
    if !state.data.storage.exists(&repo_id) {
        return Err(Error::RepoNotFound(repo_id));
    }
    enforce_owner(&*state.data.ownership, &principal, &repo_id).await?;
    if !valid_branch_name(&body.branch) {
        return Err(Error::BadRequest(format!(
            "invalid branch name: {:?}",
            body.branch
        )));
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

    let git_dir = state.cfg.repos_dir().join(format!("{repo_id}.git"));
    let ref_name = format!("refs/heads/{}", body.branch);

    // Pre-validate the parent exists before we go anywhere near gix —
    // `ObjectStore::exists` works against loose + packed (FS impl) or
    // a KV lookup (future chunked-KV impl), and is cheaper than gix's
    // find_object error path.
    if let Some(parent_sha) = &body.parent {
        validate_sha(parent_sha)?;
        if !state.data.objects.exists(&repo_id, parent_sha)? {
            return Err(Error::BadRequest(format!(
                "parent commit not found: {parent_sha}"
            )));
        }
    }

    // Decode the inputs (content/base64) and enforce the per-blob size
    // cap on the request thread, before handing off to the blocking
    // task. Failed decode + over-cap errors map cleanly to 400 here.
    let mut prepared_changes: Vec<PreparedChange> = Vec::with_capacity(body.changes.len());
    let max_blob_bytes = state.cfg.max_commit_blob_bytes;
    for change in body.changes {
        match change {
            Change::Write {
                path,
                content,
                content_base64,
                mode,
            } => {
                let bytes = match (content, content_base64) {
                    (Some(_), Some(_)) => {
                        return Err(Error::BadRequest(format!(
                            "change for {path}: only one of content/contentBase64"
                        )));
                    }
                    (None, None) => Vec::new(),
                    (Some(s), None) => s.into_bytes(),
                    (None, Some(b64)) => B64.decode(b64).map_err(|e| {
                        Error::BadRequest(format!("change for {path}: bad base64: {e}"))
                    })?,
                };
                if bytes.len() > max_blob_bytes {
                    return Err(Error::BadRequest(format!(
                        "change for {path}: blob is {} bytes, over limit of {} bytes",
                        bytes.len(),
                        max_blob_bytes
                    )));
                }
                let kind = match mode.as_str() {
                    "100644" => gix::objs::tree::EntryKind::Blob,
                    "100755" => gix::objs::tree::EntryKind::BlobExecutable,
                    _ => unreachable!("mode validated above"),
                };
                prepared_changes.push(PreparedChange::Write { path, bytes, kind });
            }
            Change::Delete { path } => {
                prepared_changes.push(PreparedChange::Delete { path });
            }
        }
    }

    // Author / committer signatures (computed here so the blocking
    // task can move them in without borrowing `body`).
    let (author_name, author_email) = match body.author {
        Some(a) => (a.name, a.email),
        None => (
            "Artifacts".to_string(),
            "artifacts@noreply.local".to_string(),
        ),
    };

    let parent_for_blocking = body.parent.clone();
    let message = body.message.clone();
    let branch_for_blocking = body.branch.clone();
    let git_dir_for_blocking = git_dir.clone();
    let _ = branch_for_blocking;

    // Build tree + write commit via gix. spawn_blocking because every
    // gix op is sync; the surrounding handler is async only for the
    // HTTP boundary + the RefStore CAS below.
    let (commit_sha, tree_sha) = crate::blocking::run_blocking("rest_commit_via_gix", move || {
        build_and_write_commit(BuildCommitInput {
            git_dir: git_dir_for_blocking,
            parent: parent_for_blocking,
            changes: prepared_changes,
            message,
            author_name,
            author_email,
        })
    })
    .await?;

    // 7. CAS the ref. This is the atomicity boundary — delegated to the
    // RefStore trait so the guts are swappable (M3-proper replaces the
    // single-node FsRefStore with a distributed state machine; this call
    // site stays identical).
    match state
        .data
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

    // Post-CAS, pre-response: fan-out to subscribers. Message is truncated
    // to the first line so the event payload stays small regardless of
    // whatever multi-paragraph commit template the caller uses.
    let message_first_line = body.message.split('\n').next().unwrap_or("").to_string();
    state.observ.events.publish(crate::events::Event::commit(
        repo_id,
        &commit_sha,
        &body.branch,
        message_first_line,
    ));

    Ok(Json(CommitResult {
        commit: commit_sha,
        tree: tree_sha,
        branch: body.branch,
    }))
}

/// Internal shape for staging a change after content+size validation.
/// `Write::bytes` is the decoded content (utf-8 or base64-decoded);
/// `Write::kind` is the validated tree-entry mode. `Delete` carries
/// the path verbatim.
enum PreparedChange {
    Write {
        path: String,
        bytes: Vec<u8>,
        kind: gix::objs::tree::EntryKind,
    },
    Delete {
        path: String,
    },
}

/// Inputs to `build_and_write_commit`. One owning struct so the
/// closure signature stays one argument.
struct BuildCommitInput {
    git_dir: std::path::PathBuf,
    parent: Option<String>,
    changes: Vec<PreparedChange>,
    message: String,
    author_name: String,
    author_email: String,
}

/// Synchronous (gix is sync) builder: opens the repo, resolves the
/// base tree, writes each blob, mutates the tree via gix's editor,
/// and writes the commit object. Returns `(commit_sha, tree_sha)`.
///
/// Called from within `spawn_blocking`; do not invoke from an async
/// context directly — every `repo.write_blob` round-trips through the
/// filesystem.
fn build_and_write_commit(input: BuildCommitInput) -> Result<(String, String)> {
    let BuildCommitInput {
        git_dir,
        parent,
        changes,
        message,
        author_name,
        author_email,
    } = input;

    let repo = gix::open(&git_dir)
        .map_err(|e| Error::Other(anyhow::anyhow!("gix::open {}: {e}", git_dir.display())))?;

    // Base tree: parent's tree, or git's canonical empty-tree id.
    let base_tree_id = match &parent {
        Some(sha) => {
            let oid = gix::ObjectId::from_hex(sha.as_bytes()).map_err(|e| {
                Error::Other(anyhow::anyhow!("parent {sha} is not a valid sha-1: {e}"))
            })?;
            let commit = repo
                .find_commit(oid)
                .map_err(|e| Error::Other(anyhow::anyhow!("find parent {sha}: {e}")))?;
            commit
                .tree_id()
                .map_err(|e| Error::Other(anyhow::anyhow!("parent {sha} tree_id: {e}")))?
                .detach()
        }
        None => gix::ObjectId::empty_tree(gix::hash::Kind::Sha1),
    };

    let mut editor = repo
        .edit_tree(base_tree_id)
        .map_err(|e| Error::Other(anyhow::anyhow!("edit_tree on {base_tree_id}: {e}")))?;

    for change in &changes {
        match change {
            PreparedChange::Write { path, bytes, kind } => {
                let blob_id = repo
                    .write_blob(bytes.as_slice())
                    .map_err(|e| Error::Other(anyhow::anyhow!("write_blob {path}: {e}")))?
                    .detach();
                editor
                    .upsert(path.as_str(), *kind, blob_id)
                    .map_err(|e| Error::Other(anyhow::anyhow!("tree upsert {path}: {e}")))?;
            }
            PreparedChange::Delete { path } => {
                editor
                    .remove(path.as_str())
                    .map_err(|e| Error::Other(anyhow::anyhow!("tree remove {path}: {e}")))?;
            }
        }
    }

    let tree_id = editor
        .write()
        .map_err(|e| Error::Other(anyhow::anyhow!("write tree object: {e}")))?
        .detach();

    // Time: `gix-date::Time` is a plain `{ seconds, offset }` struct;
    // we set offset=0 (UTC) and pull seconds from SystemTime. Matches
    // the previous subprocess path's behavior — we never set
    // GIT_*_DATE there, so git defaulted to the same "now/UTC" shape.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let signature = gix::actor::Signature {
        name: author_name.into(),
        email: author_email.into(),
        time: gix::date::Time {
            seconds: now_secs,
            offset: 0,
        },
    };

    let parents = match &parent {
        Some(sha) => {
            let oid = gix::ObjectId::from_hex(sha.as_bytes())
                .map_err(|e| Error::Other(anyhow::anyhow!("parent {sha}: {e}")))?;
            smallvec::smallvec![oid]
        }
        None => smallvec::SmallVec::new(),
    };

    let commit = gix::objs::Commit {
        tree: tree_id,
        parents,
        author: signature.clone(),
        committer: signature,
        message: message.into(),
        encoding: None,
        extra_headers: Vec::new(),
    };
    let commit_id = repo
        .write_object(&commit)
        .map_err(|e| Error::Other(anyhow::anyhow!("write commit object: {e}")))?
        .detach();

    Ok((commit_id.to_string(), tree_id.to_string()))
}

/// Match `git check-ref-format` semantics for a branch-name segment.
///
/// The previous impl was a documented "useful subset" that accepted names
/// git itself later rejected (trailing `.lock`, components beginning with
/// `.`, the literal `"@"`, …). Pre-flight validation should either match
/// git's rules or defer to git; a looser check promises commits that then
/// 500 at `update-ref` time.
///
/// Rules, from git-check-ref-format(1), applied to each `/`-separated
/// component of `s` since we'll prepend `refs/heads/`:
///
///   - no empty component (no `foo//bar`, no leading/trailing `/`)
///   - no component beginning with `.` or ending with `.lock`
///   - no `..`, `@{`, backslash, or ASCII control/space anywhere
///   - no `~ ^ : ? * [` anywhere
///   - may not end with `.` or `/`
///   - may not be the single character `@`
pub(crate) fn valid_branch_name(s: &str) -> bool {
    if s.is_empty()
        || s == "@"
        || s.starts_with('/')
        || s.ends_with('/')
        || s.ends_with('.')
        || s.contains("//")
        || s.contains("..")
        || s.contains("@{")
        || s.contains('\\')
    {
        return false;
    }
    if s.chars().any(|c| {
        // Control chars (<0x20), DEL (0x7f), space, and the reserved
        // set. Everything else is allowed by git's rules.
        let u = c as u32;
        u < 0x20 || u == 0x7f || matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[')
    }) {
        return false;
    }
    // Per-component rules: no component may start with '.' or end with
    // '.lock'. Git applies this to every slash-separated piece.
    for part in s.split('/') {
        if part.is_empty() || part.starts_with('.') || part.ends_with(".lock") {
            return false;
        }
    }
    true
}

/// Validate a path-inside-the-repo as it appears in a commit change-set.
/// Rejects path-traversal, empty/`.`/`..` components, NUL bytes, embedded
/// `.git`, and ASCII control characters. The extra `Path::components()`
/// pass is a belt-and-suspenders check against any future change to the
/// string-level rules that might accidentally let a traversal through.
fn valid_path(p: &str) -> bool {
    if p.is_empty() || p.starts_with('/') || p.ends_with('/') || p.contains("//") {
        return false;
    }
    if p.as_bytes().contains(&0) {
        return false;
    }
    // Lexical per-component checks.
    for part in p.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return false;
        }
        // `.git` as a path component would let a commit write into the
        // bare repo's management directory via the client-side checkout.
        // Git itself rejects this when writing trees; reject early.
        if part.eq_ignore_ascii_case(".git") {
            return false;
        }
        if part.chars().any(|c| {
            let u = c as u32;
            u < 0x20 || u == 0x7f
        }) {
            return false;
        }
    }
    // Defensive: Path::components should never yield anything other than
    // Normal for a well-formed relative path. A RootDir, CurDir, or
    // ParentDir component means our string checks missed something.
    for c in std::path::Path::new(p).components() {
        if !matches!(c, std::path::Component::Normal(_)) {
            return false;
        }
    }
    true
}

pub(crate) fn validate_sha(s: &str) -> Result<()> {
    if s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(Error::BadRequest(format!("invalid sha: {s:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_name_validation_accepts_valid() {
        assert!(valid_branch_name("main"));
        assert!(valid_branch_name("feature/foo-bar"));
        assert!(valid_branch_name("users/alice/wip"));
        assert!(valid_branch_name("v1.0"));
    }

    #[test]
    fn branch_name_validation_rejects_basic_shape() {
        assert!(!valid_branch_name(""));
        assert!(!valid_branch_name("/main"));
        assert!(!valid_branch_name("main/"));
        assert!(!valid_branch_name("foo//bar"));
        assert!(!valid_branch_name("foo..bar"));
        assert!(!valid_branch_name("foo:bar"));
        assert!(!valid_branch_name("foo bar"));
    }

    #[test]
    fn branch_name_validation_rejects_git_specific_cases() {
        // Things our old impl missed but git-check-ref-format rejects.
        assert!(!valid_branch_name("@"), "lone @ is reserved");
        assert!(!valid_branch_name("trailing."), "trailing dot");
        assert!(!valid_branch_name("main.lock"), "trailing .lock");
        assert!(!valid_branch_name(".hidden"), "component starts with dot");
        assert!(!valid_branch_name("feature/.hidden"), "mid-path dot-prefix");
        assert!(!valid_branch_name("feature/wip.lock"), "mid-path .lock");
        assert!(!valid_branch_name("foo@{bar}"), "reserved sequence @{{");
        assert!(!valid_branch_name("with\ttab"), "control chars rejected");
    }

    #[test]
    fn path_validation_accepts_valid() {
        assert!(valid_path("README.md"));
        assert!(valid_path("src/main.rs"));
        assert!(valid_path("a/b/c/d.txt"));
    }

    #[test]
    fn path_validation_rejects_basic_shape() {
        assert!(!valid_path(""));
        assert!(!valid_path("/abs/path"));
        assert!(!valid_path("trailing/"));
        assert!(!valid_path("a//b"));
        assert!(!valid_path("a/./b"));
        assert!(!valid_path("a/../b"));
    }

    #[test]
    fn path_validation_rejects_dot_git_components() {
        // Writing into .git from a commit would be a sandbox escape on
        // the client side when checked out. Git rejects this at tree-
        // write time; we reject earlier for a cleaner error.
        assert!(!valid_path(".git"));
        assert!(!valid_path(".git/config"));
        assert!(!valid_path("subdir/.git/HEAD"));
        assert!(!valid_path(".GIT")); // case-insensitive on git itself
    }

    #[test]
    fn path_validation_rejects_control_bytes() {
        assert!(!valid_path("a\0b"), "NUL");
        assert!(!valid_path("a\tb"), "tab");
        assert!(!valid_path("a\nb"), "newline");
    }
}
