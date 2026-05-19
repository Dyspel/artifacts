//! Read-only REST inspection of a repo's contents.
//!
//! Endpoints this module serves:
//!
//!   GET /v1/repos/:id                — repo metadata + refs + size on disk
//!   GET /v1/repos/:id/commits        — git log, paginated
//!   GET /v1/repos/:id/refs           — flat ref list (heads + tags + notes)
//!   GET /v1/repos/:id/tree           — recursive file tree at a ref
//!   GET /v1/repos/:id/blob           — raw file contents
//!   GET /v1/repos/:id/diff           — parsed commit diff
//!   GET /v1/repos/:id/notes          — git-note contents for a commit
//!
//! All are owner-scoped via `enforce_owner`: admin sees everything, JWT
//! users only their own repos. 404s pass through unchanged from git's
//! exit code so the caller can tell "ref not found" from "file not
//! found in ref" from "repo gone."
//!
//! ## Shape vs DysHub
//!
//! Responses here are deliberately **git-native**, not DysHub-native.
//! The backend BFF (`backend/routes/artifacts-bff/`) shapes these into
//! the exact `{Commit, Ref, FileNode, FileDiff}` forms the Fleet UI
//! expects — including repoId injection, AgentId author mapping, and
//! flattening of CommitNote turns. Keeping the Artifacts API
//! UI-agnostic means a future different UI can consume it without
//! paying the translation tax twice.

use crate::{
    auth::authorize_rest,
    commits::{run_git, validate_sha},
    error::{Error, Result},
    ownership::enforce_owner,
    rate_limit::Class,
    rest::RestState,
};
use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Common authorization prelude ─────────────────────────────────────

/// Common guard for every read endpoint. Returns the resolved git dir
/// once ownership has been enforced. Folds four lines of boilerplate
/// that would otherwise repeat in every handler.
async fn authorize_read(
    state: &RestState,
    headers: &HeaderMap,
    repo_id: &str,
) -> Result<std::path::PathBuf> {
    let principal = authorize_rest(
        headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret.as_deref(),
    )?;
    state.rate_limit.check(&principal, Class::Default)?;
    crate::storage::validate_repo_id(repo_id)?;
    if !state.storage.exists(repo_id) {
        return Err(Error::RepoNotFound(repo_id.to_string()));
    }
    enforce_owner(&*state.ownership, &principal, repo_id).await?;
    Ok(state.cfg.repos_dir().join(format!("{repo_id}.git")))
}

// ── GET /v1/repos/:id ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct RepoDetail {
    pub id: String,
    /// `None` for admin-created repos.
    pub owner: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "sourceId", skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub refs: Vec<RefEntry>,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    /// HEAD SHA if set, for clients that want to know the default commit
    /// without a second ref lookup.
    #[serde(rename = "headSha", skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
    /// Total commits reachable from HEAD. `0` when the repo has no HEAD
    /// yet (freshly created, never pushed). Cheap: `rev-list --count`
    /// walks the graph once and reports an integer.
    #[serde(rename = "commitCount")]
    pub commit_count: u64,
    /// Number of other repos that fork *this* one. Derived by scanning
    /// sibling repos for an `objects/info/alternates` pointing back — so
    /// the cost is O(repos in namespace). Acceptable on a single-repo
    /// detail endpoint; we don't attempt this for the list view.
    #[serde(rename = "forkCount")]
    pub fork_count: u64,
}

/// GET /v1/repos/:id — full repo detail for an owner or admin.
pub async fn get_repo(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Json<RepoDetail>> {
    let git_dir = authorize_read(&state, &headers, &repo_id).await?;
    let Some(row) = state.ownership.get_row(&repo_id).await? else {
        return Err(Error::RepoNotFound(repo_id));
    };
    let refs = list_refs_native(&git_dir).await?;
    let size_bytes = dir_size(&git_dir).unwrap_or(0);
    let head_sha = resolve_ref_sha(&git_dir, "HEAD").await.ok().flatten();
    let source_id = state
        .alternates_cache
        .lookup(&state.cfg.repos_dir(), &repo_id);
    let commit_count = count_commits_from_head(&git_dir).await.unwrap_or(0);
    let fork_count = count_forks_of(
        &state.cfg.repos_dir(),
        &repo_id,
        &state.alternates_cache,
    )
    .unwrap_or(0);
    Ok(Json(RepoDetail {
        id: row.id,
        owner: row.owner,
        created_at: row.created_at,
        source_id,
        refs,
        size_bytes,
        head_sha,
        commit_count,
        fork_count,
    }))
}

// ── GET /v1/repos/:id/commits ────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CommitsQuery {
    /// Ref or SHA to walk from. Defaults to HEAD. Client can pass a
    /// branch name or a commit SHA.
    #[serde(default)]
    pub r#ref: Option<String>,
    /// Max number of commits to return. Default 50, capped at 500 so a
    /// runaway client can't scan a multi-million commit history.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Skip this many commits before starting the walk. Pagination.
    #[serde(default)]
    pub skip: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct CommitSummary {
    pub sha: String,
    pub parents: Vec<String>,
    pub author: Signature,
    pub committer: Signature,
    pub message: String,
    /// Unix epoch seconds from `committer date`, not author — tracks
    /// "when this commit landed here" more accurately for clients
    /// showing a timeline.
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
pub struct Signature {
    pub name: String,
    pub email: String,
}

const COMMITS_LIMIT_DEFAULT: u32 = 50;
const COMMITS_LIMIT_MAX: u32 = 500;
/// Format used by `git log`. `%x00` is a NUL byte (record separator);
/// `%x01` separates fields. We use these two bytes because they never
/// appear in identifiers, refs, or commit messages — safer than any
/// printable delimiter against adversarial input.
const LOG_FORMAT: &str = "%H%x01%P%x01%an%x01%ae%x01%cn%x01%ce%x01%ct%x01%B%x00";

pub async fn list_commits(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    Query(q): Query<CommitsQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<CommitSummary>>> {
    let git_dir = authorize_read(&state, &headers, &repo_id).await?;
    let limit = q.limit.unwrap_or(COMMITS_LIMIT_DEFAULT).min(COMMITS_LIMIT_MAX);
    let skip = q.skip.unwrap_or(0);
    let start = q.r#ref.as_deref().unwrap_or("HEAD");
    validate_ref_or_sha(start)?;

    let args = [
        "log",
        start,
        &format!("--max-count={limit}"),
        &format!("--skip={skip}"),
        &format!("--format={LOG_FORMAT}"),
    ];
    let (rc, stdout, stderr) = run_git(&git_dir, &args, &[], None).await?;
    if rc != 0 {
        let err = String::from_utf8_lossy(&stderr);
        // `unknown revision` → caller asked for a ref/SHA that doesn't
        // exist. 404 is the right status for that.
        if err.contains("unknown revision") || err.contains("bad revision") {
            return Err(Error::BadRequest(format!("unknown ref: {start}")));
        }
        return Err(Error::Other(anyhow::anyhow!("git log failed: {err}")));
    }
    Ok(Json(parse_log_records(&stdout)?))
}

fn parse_log_records(bytes: &[u8]) -> Result<Vec<CommitSummary>> {
    let mut out = Vec::new();
    // Records are NUL-delimited; within a record, fields are \x01-delimited.
    for record in bytes.split(|b| *b == 0) {
        if record.is_empty() {
            continue;
        }
        let fields: Vec<&[u8]> = record.split(|b| *b == 1).collect();
        if fields.len() < 8 {
            // Defensive: if the format string drifts, skip malformed
            // records instead of blowing up the response.
            continue;
        }
        let sha = String::from_utf8(fields[0].to_vec())?.trim().to_string();
        let parents: Vec<String> = std::str::from_utf8(fields[1])
            .unwrap_or("")
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let author_name = String::from_utf8(fields[2].to_vec())?;
        let author_email = String::from_utf8(fields[3].to_vec())?;
        let committer_name = String::from_utf8(fields[4].to_vec())?;
        let committer_email = String::from_utf8(fields[5].to_vec())?;
        let timestamp: i64 = std::str::from_utf8(fields[6])
            .unwrap_or("0")
            .trim()
            .parse()
            .unwrap_or(0);
        // The committer-date field leaves a leading newline before the
        // message because `git log` stamps one after %ct. Strip it.
        let message_raw = &fields[7];
        let message = String::from_utf8(message_raw.to_vec())?
            .trim_start_matches('\n')
            .to_string();
        out.push(CommitSummary {
            sha,
            parents,
            author: Signature { name: author_name, email: author_email },
            committer: Signature { name: committer_name, email: committer_email },
            message,
            timestamp,
        });
    }
    Ok(out)
}

// ── GET /v1/repos/:id/refs ───────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct RefEntry {
    pub name: String,
    pub sha: String,
}

pub async fn list_refs(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<RefEntry>>> {
    let git_dir = authorize_read(&state, &headers, &repo_id).await?;
    let refs = list_refs_native(&git_dir).await?;
    Ok(Json(refs))
}

async fn list_refs_native(git_dir: &Path) -> Result<Vec<RefEntry>> {
    let (rc, stdout, stderr) = run_git(
        git_dir,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
        &[],
        None,
    )
    .await?;
    if rc != 0 {
        return Err(Error::Other(anyhow::anyhow!(
            "for-each-ref failed: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    let text = String::from_utf8(stdout)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let (name, sha) = line.split_once(' ').ok_or_else(|| {
            Error::Other(anyhow::anyhow!("malformed for-each-ref line: {line:?}"))
        })?;
        out.push(RefEntry {
            name: name.to_string(),
            sha: sha.to_string(),
        });
    }
    Ok(out)
}

async fn resolve_ref_sha(git_dir: &Path, r: &str) -> Result<Option<String>> {
    let (rc, stdout, _stderr) = run_git(
        git_dir,
        &["rev-parse", "--verify", &format!("{r}^{{commit}}")],
        &[],
        None,
    )
    .await?;
    if rc != 0 {
        return Ok(None);
    }
    Ok(Some(String::from_utf8(stdout)?.trim().to_string()))
}

// ── GET /v1/repos/:id/tree ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TreeQuery {
    /// Ref or commit SHA to render the tree of. Defaults to HEAD.
    #[serde(default)]
    pub r#ref: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TreeEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: TreeEntryKind,
    /// Size in bytes for blobs; omitted for trees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TreeEntryKind {
    File,
    Dir,
    /// Submodule. Included for completeness; rare in agent repos.
    Submodule,
}

pub async fn get_tree(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    Query(q): Query<TreeQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<TreeEntry>>> {
    let git_dir = authorize_read(&state, &headers, &repo_id).await?;
    let start = q.r#ref.as_deref().unwrap_or("HEAD");
    validate_ref_or_sha(start)?;

    // `ls-tree -r -l -z` recurses, emits sizes for blobs, and NUL-delims
    // the records so paths containing spaces or newlines parse correctly.
    let (rc, stdout, stderr) = run_git(
        &git_dir,
        &["ls-tree", "-r", "-l", "-z", start],
        &[],
        None,
    )
    .await?;
    if rc != 0 {
        let err = String::from_utf8_lossy(&stderr);
        if err.contains("not a valid object name") || err.contains("Not a valid object name") {
            return Err(Error::BadRequest(format!("unknown ref: {start}")));
        }
        return Err(Error::Other(anyhow::anyhow!("ls-tree failed: {err}")));
    }

    let mut entries = Vec::new();
    let mut dirs = std::collections::BTreeSet::<String>::new();
    for record in stdout.split(|b| *b == 0) {
        if record.is_empty() {
            continue;
        }
        // Format: "<mode> <type> <object> <size>\t<path>" where mode/type/
        // object/size are space-separated and <path> is after the single
        // TAB. `-l` makes `<size>` a number for blobs and literal "-" for
        // trees and submodules.
        let line = std::str::from_utf8(record)
            .map_err(|e| Error::Other(anyhow::anyhow!("ls-tree utf8: {e}")))?;
        let (meta, path) = match line.split_once('\t') {
            Some(p) => p,
            None => continue,
        };
        let meta_fields: Vec<&str> = meta.split_whitespace().collect();
        if meta_fields.len() < 4 {
            continue;
        }
        let ty = meta_fields[1];
        let size = meta_fields[3].parse::<u64>().ok();
        // Walk parent directories of every blob so clients get `dir`
        // entries without a second pass.
        if ty == "blob" || ty == "commit" {
            let mut parts = path.split('/').collect::<Vec<_>>();
            parts.pop();
            let mut accum = String::new();
            for part in parts {
                if !accum.is_empty() {
                    accum.push('/');
                }
                accum.push_str(part);
                dirs.insert(accum.clone());
            }
        }
        let kind = match ty {
            "blob" => TreeEntryKind::File,
            "tree" => TreeEntryKind::Dir,
            "commit" => TreeEntryKind::Submodule,
            _ => continue,
        };
        entries.push(TreeEntry {
            path: path.to_string(),
            kind,
            size,
        });
    }
    // Prepend any implied directories that ls-tree -r didn't emit on
    // their own (it only emits leaves for trees).
    for d in dirs {
        if !entries.iter().any(|e| e.path == d) {
            entries.insert(
                0,
                TreeEntry {
                    path: d,
                    kind: TreeEntryKind::Dir,
                    size: None,
                },
            );
        }
    }
    // Sort: dirs before files at every level, alphabetical within.
    entries.sort_by(|a, b| {
        let aa = matches!(a.kind, TreeEntryKind::Dir) as u8;
        let bb = matches!(b.kind, TreeEntryKind::Dir) as u8;
        bb.cmp(&aa).then_with(|| a.path.cmp(&b.path))
    });
    Ok(Json(entries))
}

// ── GET /v1/repos/:id/blob ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BlobQuery {
    /// Commit to read from. Defaults to HEAD.
    #[serde(default)]
    pub commit: Option<String>,
    pub path: String,
}

/// Blob endpoint streams raw bytes with `application/octet-stream`. Text
/// vs binary detection is the caller's concern: the BFF detects null
/// bytes and responds as text or base64 accordingly, same heuristic as
/// gitSyncService uses for REST commits.
///
/// Path resolution (`<commit>:<path>` → blob oid) uses gix in a blocking
/// task; the final byte fetch goes through `ObjectStore::read_object`
/// so the chunked-KV backend can serve blobs without a filesystem walk.
pub async fn get_blob(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    Query(q): Query<BlobQuery>,
    headers: HeaderMap,
) -> Result<Response> {
    let git_dir = authorize_read(&state, &headers, &repo_id).await?;
    let commit = q.commit.as_deref().unwrap_or("HEAD");
    validate_ref_or_sha(commit)?;
    validate_path(&q.path)?;

    // Resolve `<commit>:<path>` → blob oid via gix. Off the tokio
    // pool because gix is sync and the tree walk hits the loose+pack
    // object stores. Returns a clear `blob not found` for any
    // resolution failure (bad rev, missing path, non-blob target).
    let blob_oid = {
        let git_dir = git_dir.clone();
        let commit = commit.to_string();
        let path = q.path.clone();
        crate::blocking::run_blocking("resolve_blob_oid", move || {
            resolve_blob_oid(&git_dir, &commit, &path)
        })
        .await?
    };

    // Final byte fetch through the trait. FsObjectStore.read_object
    // walks loose + pack stores via gix; a future chunked-KV impl
    // serves from its KV. Off the tokio pool for the same reason.
    let objects = state.objects.clone();
    let repo_id_for_read = repo_id.clone();
    let read_result = crate::blocking::run_blocking("read_object", move || {
        objects.read_object(&repo_id_for_read, &blob_oid)
    })
    .await?;

    let (kind, bytes) = read_result.ok_or_else(|| {
        Error::BadRequest(format!("blob not found: {commit}:{}", q.path))
    })?;
    if kind != crate::object_store::ObjectKind::Blob {
        return Err(Error::BadRequest(format!(
            "blob not found: {commit}:{} (resolved to non-blob)",
            q.path
        )));
    }

    tracing::debug!(
        repo = %repo_id,
        commit = %commit,
        path = %q.path,
        bytes = bytes.len(),
        "blob read via ObjectStore",
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    )
        .into_response())
}

/// Resolve `<commit>:<path>` to a blob oid via gix. The function is
/// `sync` so it can run on a `spawn_blocking` worker; gix's object DB
/// reads are not async.
fn resolve_blob_oid(git_dir: &Path, rev: &str, path: &str) -> Result<String> {
    let repo = gix::open(git_dir)
        .map_err(|e| Error::BadRequest(format!("repo open failed: {e}")))?;
    // Resolve the rev (could be HEAD, a ref name, or an OID prefix).
    let commit_obj = repo
        .rev_parse_single(rev)
        .map_err(|e| Error::BadRequest(format!("blob not found: {rev} ({e})")))?
        .object()
        .map_err(|e| Error::BadRequest(format!("blob not found: {rev} ({e})")))?
        .peel_to_kind(gix::object::Kind::Commit)
        .map_err(|e| Error::BadRequest(format!("not a commit-ish: {rev} ({e})")))?
        .into_commit();
    let tree = commit_obj
        .tree()
        .map_err(|e| Error::Other(anyhow::anyhow!("read root tree: {e}")))?;
    let entry = tree
        .lookup_entry_by_path(path)
        .map_err(|e| Error::Other(anyhow::anyhow!("lookup_entry_by_path: {e}")))?
        .ok_or_else(|| Error::BadRequest(format!("blob not found: {rev}:{path}")))?;
    if entry.mode().is_tree() {
        return Err(Error::BadRequest(format!(
            "blob not found: {rev}:{path} (is a directory)"
        )));
    }
    Ok(entry.object_id().to_hex().to_string())
}

// ── GET /v1/repos/:id/diff ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    pub commit: String,
}

#[derive(Debug, Serialize)]
pub struct FileDiff {
    pub path: String,
    pub status: DiffStatus,
    #[serde(rename = "oldPath", skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    pub additions: u32,
    pub deletions: u32,
    pub hunks: Vec<DiffHunk>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Serialize)]
pub struct DiffHunk {
    #[serde(rename = "oldStart")]
    pub old_start: u32,
    #[serde(rename = "oldLines")]
    pub old_lines: u32,
    #[serde(rename = "newStart")]
    pub new_start: u32,
    #[serde(rename = "newLines")]
    pub new_lines: u32,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Serialize)]
pub struct DiffLine {
    pub kind: DiffLineKind,
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffLineKind {
    Ctx,
    Add,
    Del,
}

pub async fn get_diff(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    Query(q): Query<DiffQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<FileDiff>>> {
    let git_dir = authorize_read(&state, &headers, &repo_id).await?;
    validate_sha(&q.commit)?;
    // `git show --format= --numstat -M` gives us add/del counts keyed by
    // path with rename detection. Then a second pass with --unified=3
    // parses hunks. Two shells beats one giant parser chain.
    let (rc, numstat_out, stderr) = run_git(
        &git_dir,
        &["show", "--format=", "--numstat", "-M", &q.commit],
        &[],
        None,
    )
    .await?;
    if rc != 0 {
        return Err(Error::Other(anyhow::anyhow!(
            "git show --numstat failed: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    let (rc, patch_out, stderr) = run_git(
        &git_dir,
        &["show", "--format=", "--unified=3", "-M", &q.commit],
        &[],
        None,
    )
    .await?;
    if rc != 0 {
        return Err(Error::Other(anyhow::anyhow!(
            "git show --unified failed: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    let numstat = std::str::from_utf8(&numstat_out).unwrap_or("");
    let patch = std::str::from_utf8(&patch_out).unwrap_or("");
    Ok(Json(parse_diff(numstat, patch)))
}

fn parse_diff(numstat: &str, patch: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    // First pass: numstat provides add/del counts and path + rename info.
    for line in numstat.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let additions: u32 = parts[0].parse().unwrap_or(0);
        let deletions: u32 = parts[1].parse().unwrap_or(0);
        // Renames in numstat appear as "old => new" or sometimes
        // "prefix{old => new}suffix". Keep the simple case; the patch
        // pass refines status based on `diff --git` header lines.
        let path = parts[2];
        let (old_path, new_path, status) = if let Some((l, r)) = path.split_once(" => ") {
            (Some(l.to_string()), r.to_string(), DiffStatus::Renamed)
        } else {
            (None, path.to_string(), DiffStatus::Modified)
        };
        files.push(FileDiff {
            path: new_path,
            status,
            old_path,
            additions,
            deletions,
            hunks: Vec::new(),
        });
    }
    // Second pass: parse the unified-diff patch and attach hunks to each
    // file. `diff --git a/<path> b/<path>` opens a file section; `@@` lines
    // open hunks. `new file mode` / `deleted file mode` refine the status.
    let mut current_file: Option<usize> = None;
    let mut current_hunk: Option<DiffHunk> = None;
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            // Format: "a/<path> b/<path>". Take the b-side as the canonical
            // path; files[].path was set from numstat which already handles
            // rename-target form.
            if let Some((_, b)) = rest.split_once(" b/") {
                if let Some(ix) = files.iter().position(|f| f.path == b) {
                    // Close any open hunk into the previous file.
                    if let (Some(cur), Some(h)) = (current_file, current_hunk.take()) {
                        files[cur].hunks.push(h);
                    }
                    current_file = Some(ix);
                }
            }
            continue;
        }
        if line.starts_with("new file mode") {
            if let Some(ix) = current_file { files[ix].status = DiffStatus::Added; }
            continue;
        }
        if line.starts_with("deleted file mode") {
            if let Some(ix) = current_file { files[ix].status = DiffStatus::Deleted; }
            continue;
        }
        if let Some(hdr) = line.strip_prefix("@@ ") {
            if let (Some(cur), Some(h)) = (current_file, current_hunk.take()) {
                files[cur].hunks.push(h);
            }
            // "@@ -oldStart,oldLines +newStart,newLines @@ ..." — `,lines`
            // defaults to 1 if absent.
            let parts: Vec<&str> = hdr.split(' ').collect();
            let (old_start, old_lines) = parse_hunk_range(parts.first().copied().unwrap_or(""));
            let (new_start, new_lines) = parse_hunk_range(parts.get(1).copied().unwrap_or(""));
            current_hunk = Some(DiffHunk {
                old_start, old_lines, new_start, new_lines, lines: Vec::new(),
            });
            continue;
        }
        if let Some(h) = current_hunk.as_mut() {
            if let Some(text) = line.strip_prefix('+') {
                if !line.starts_with("+++") {
                    h.lines.push(DiffLine { kind: DiffLineKind::Add, text: text.to_string() });
                }
            } else if let Some(text) = line.strip_prefix('-') {
                if !line.starts_with("---") {
                    h.lines.push(DiffLine { kind: DiffLineKind::Del, text: text.to_string() });
                }
            } else if let Some(text) = line.strip_prefix(' ') {
                h.lines.push(DiffLine { kind: DiffLineKind::Ctx, text: text.to_string() });
            }
        }
    }
    if let (Some(cur), Some(h)) = (current_file, current_hunk) {
        files[cur].hunks.push(h);
    }
    files
}

fn parse_hunk_range(s: &str) -> (u32, u32) {
    // "-123,4" or "+123,4" — with or without sign and lines-count.
    let s = s.trim_start_matches('-').trim_start_matches('+');
    let (start_s, lines_s) = s.split_once(',').unwrap_or((s, "1"));
    (start_s.parse().unwrap_or(0), lines_s.parse().unwrap_or(0))
}

// ── GET /v1/repos/:id/notes ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct NotesQuery {
    /// Full notes ref, e.g. `refs/notes/agent`. Defaults to `refs/notes/commits`
    /// (git's default) so callers without an explicit ref get something sane.
    #[serde(default)]
    pub r#ref: Option<String>,
    pub commit: String,
}

#[derive(Debug, Serialize)]
pub struct NoteResponse {
    pub r#ref: String,
    pub commit: String,
    /// Note contents as-is. Callers that store JSON (e.g. cc-wasm's
    /// `CommitNote`) parse this on their side.
    pub text: String,
}

pub async fn get_note(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    Query(q): Query<NotesQuery>,
    headers: HeaderMap,
) -> Result<Json<NoteResponse>> {
    let git_dir = authorize_read(&state, &headers, &repo_id).await?;
    validate_sha(&q.commit)?;
    let notes_ref = q.r#ref.as_deref().unwrap_or("refs/notes/commits");
    if !is_valid_notes_ref(notes_ref) {
        return Err(Error::BadRequest(format!("invalid notes ref: {notes_ref:?}")));
    }
    let (rc, stdout, stderr) = run_git(
        &git_dir,
        &["notes", &format!("--ref={notes_ref}"), "show", &q.commit],
        &[],
        None,
    )
    .await?;
    if rc != 0 {
        let err = String::from_utf8_lossy(&stderr);
        // git returns non-zero when the note doesn't exist. Surface as a
        // structured 404 so the caller can render "no metadata" without
        // pattern-matching stderr.
        if err.contains("no note found") || err.contains("No note found") {
            return Err(Error::RepoNotFound(format!(
                "no note on {} for commit {}",
                notes_ref, q.commit
            )));
        }
        return Err(Error::Other(anyhow::anyhow!("git notes show: {err}")));
    }
    Ok(Json(NoteResponse {
        r#ref: notes_ref.to_string(),
        commit: q.commit,
        text: String::from_utf8(stdout)?,
    }))
}

mod helpers;
use helpers::{dir_size, is_valid_notes_ref, validate_path, validate_ref_or_sha};

/// `git rev-list --count HEAD` — returns the total number of commits
/// reachable from HEAD. Empty repos (no HEAD) return 0 cleanly instead
/// of an error; a repo with orphan branches but no HEAD is rare enough
/// that we don't count those.
async fn count_commits_from_head(git_dir: &Path) -> Result<u64> {
    let (rc, stdout, _stderr) = run_git(
        git_dir,
        &["rev-list", "--count", "HEAD"],
        &[],
        None,
    )
    .await?;
    if rc != 0 {
        return Ok(0);
    }
    Ok(String::from_utf8(stdout)?
        .trim()
        .parse::<u64>()
        .unwrap_or(0))
}

/// Count how many sibling repos have `this` one as their alternates
/// target. Cheap for small repo counts (O(repos) filesystem reads, each
/// a ~32-byte alternates file); if we grow past thousands of repos per
/// host we'd want this indexed by the OwnershipStore instead.
///
/// Uses the alternates cache so that repeat calls (e.g. the Detail tab
/// polled by the GUI) only pay the full resolve cost on files that
/// actually changed since the last call.
/// IDs of every repo whose alternates source is `repo_id`. Used by
/// the delete-safety check in rest.rs (refuse to delete a repo that
/// other forks depend on, unless `?force=true`) and as the count
/// path's source-of-truth so the two answers can't drift.
pub(crate) fn list_forks_of(
    repos_dir: &Path,
    repo_id: &str,
    cache: &crate::alternates_cache::AlternatesCache,
) -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(repos_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if !name_str.ends_with(".git") {
            continue;
        }
        let sibling_id = &name_str[..name_str.len() - 4]; // strip ".git"
        if sibling_id == repo_id {
            continue;
        }
        if let Some(parent) = cache.lookup(repos_dir, sibling_id) {
            if parent == repo_id {
                out.push(sibling_id.to_string());
            }
        }
    }
    Ok(out)
}

fn count_forks_of(
    repos_dir: &Path,
    repo_id: &str,
    cache: &crate::alternates_cache::AlternatesCache,
) -> std::io::Result<u64> {
    Ok(list_forks_of(repos_dir, repo_id, cache)?.len() as u64)
}

