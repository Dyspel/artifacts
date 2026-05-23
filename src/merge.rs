//! Branch merge: `POST /v1/repos/:id/merge`.
//!
//! Merges `source_branch` into `target_branch` with three strategies:
//!
//!   - `auto` (default): fast-forward when possible, else a three-way merge.
//!   - `ff-only`: fail with `not_fast_forward` if FF isn't possible.
//!   - `merge`: always create a merge commit (two parents), even when FF is
//!     available — useful when the voting/proposal flow wants every merged
//!     proposal to produce a recorded merge commit on the target branch.
//!
//! ## Why server-side merge
//!
//! The REST commits endpoint only accepts a flat list of `ChangeOp`s; it has
//! no notion of "merge these two branches." Callers that want proposal-style
//! workflows (fork → commit on fork → merge fork into main) previously had
//! to clone both sides, run `git merge` locally, and push. This endpoint
//! collapses that dance to one HTTP call and keeps merge logic co-located
//! with ref storage, so the CAS boundary covers the whole operation.
//!
//! ## Implementation
//!
//! Same shell-out model as `commits.rs`. `git merge-tree --write-tree` (git
//! 2.38+) does the three-way merge on the object database alone — no working
//! tree, no index files to sync — and returns either the merged tree SHA or
//! a conflict report. We then build the merge commit via `commit-tree -p
//! target -p source` and CAS-update the target branch ref.

use crate::{
    auth::authorize_rest,
    commits::{valid_branch_name, validate_sha, Author},
    error::{Error, Result},
    git_cmd::run_git,
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
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct MergeBody {
    /// Branch whose tip we want to land into `target_branch`. Must already
    /// exist in the repo (same-repo merge only for M5; cross-repo merge —
    /// e.g. merging a fork's branch back into its parent — is a follow-up
    /// that would pull objects via alternates first).
    #[serde(rename = "sourceBranch")]
    pub source_branch: String,

    /// Branch that receives the merge. Created if missing (the repo's first
    /// commit on a branch name can arrive via merge).
    #[serde(rename = "targetBranch")]
    pub target_branch: String,

    #[serde(default)]
    pub strategy: Strategy,

    /// Commit message for the merge commit. Ignored on a fast-forward since
    /// no commit is created. Required for three-way and forced-merge.
    #[serde(default)]
    pub message: Option<String>,

    #[serde(default)]
    pub author: Option<Author>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    #[default]
    Auto,
    FfOnly,
    Merge,
}

#[derive(Debug, Serialize)]
pub struct MergeResult {
    /// New tip of `target_branch`. On fast-forward, equals `source_commit`.
    /// On three-way, the new merge commit SHA.
    pub commit: String,
    pub tree: String,
    #[serde(rename = "fastForward")]
    pub fast_forward: bool,
    #[serde(rename = "sourceCommit")]
    pub source_commit: String,
    #[serde(rename = "targetBranch")]
    pub target_branch: String,
}

pub async fn merge_branches(
    State(state): State<RestState>,
    AxumPath(repo_id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<MergeBody>,
) -> Result<Json<MergeResult>> {
    let principal = authorize_rest(
        &headers,
        &state.cfg.admin_token(),
        state.cfg.jwt_secret().as_deref(),
    )?;
    state.authn.rate_limit.check(&principal, Class::Commit)?;
    crate::storage::validate_repo_id(&repo_id)?;
    if !state.data.storage.exists(&repo_id) {
        return Err(Error::RepoNotFound(repo_id));
    }
    enforce_owner(&*state.data.ownership, &principal, &repo_id).await?;
    if !valid_branch_name(&body.source_branch) {
        return Err(Error::BadRequest(format!(
            "invalid source branch name: {:?}",
            body.source_branch
        )));
    }
    if !valid_branch_name(&body.target_branch) {
        return Err(Error::BadRequest(format!(
            "invalid target branch name: {:?}",
            body.target_branch
        )));
    }
    if body.source_branch == body.target_branch {
        return Err(Error::BadRequest(
            "source and target branches must differ".into(),
        ));
    }

    let git_dir = state.cfg.repos_dir().join(format!("{repo_id}.git"));
    let source_ref = format!("refs/heads/{}", body.source_branch);
    let target_ref = format!("refs/heads/{}", body.target_branch);

    // 1. Resolve source — must exist.
    let source_sha = match resolve_ref(&git_dir, &source_ref).await? {
        Some(sha) => sha,
        None => {
            return Err(Error::BadRequest(format!(
                "source branch does not exist: {}",
                body.source_branch
            )));
        }
    };
    validate_sha(&source_sha)?;

    // 2. Resolve target — may be absent (new branch).
    let target_sha = resolve_ref(&git_dir, &target_ref).await?;
    if let Some(ref s) = target_sha {
        validate_sha(s)?;
    }

    // 3. No-op case: source already reachable from target (merge-base(source,
    // target) == source). Nothing to do; return target unchanged.
    if let Some(ref t) = target_sha {
        if is_ancestor(&git_dir, &source_sha, t).await? {
            let tree = tree_of(&git_dir, t).await?;
            return Ok(Json(MergeResult {
                commit: t.clone(),
                tree,
                fast_forward: false,
                source_commit: source_sha,
                target_branch: body.target_branch,
            }));
        }
    }

    // 4. Fast-forward case: target reachable from source (merge-base == target).
    // Create no commit; just CAS target ref forward. Skipped when strategy ==
    // "merge" — the caller explicitly wants a merge commit either way.
    let ff_available = match &target_sha {
        None => true, // new branch, anything is a "fast-forward"
        Some(t) => is_ancestor(&git_dir, t, &source_sha).await?,
    };
    if ff_available && body.strategy != Strategy::Merge {
        let repo_id_typed = crate::ids::RepoId::try_from(repo_id.as_str())?;
        let target_ref_typed = crate::ids::RefName::try_from(target_ref.as_str())?;
        let source_sha_typed = crate::ids::Oid::try_from(source_sha.as_str())?;
        let target_sha_typed = match target_sha.as_deref() {
            Some(s) => Some(crate::ids::Oid::try_from(s)?),
            None => None,
        };
        match state
            .data
            .refs
            .cas_update(
                &repo_id_typed,
                &target_ref_typed,
                target_sha_typed.as_ref(),
                &source_sha_typed,
            )
            .await?
        {
            CasOutcome::Updated => {
                let tree = tree_of(&git_dir, &source_sha).await?;
                // FF merge is a ref advance — surface as a commit event so
                // subscribers see the same shape whether we reach main via
                // POST /commits or POST /merge.
                state.observ.events.publish(crate::events::Event::commit(
                    &repo_id,
                    &source_sha,
                    &body.target_branch,
                    format!("merge {} (fast-forward)", body.source_branch),
                ));
                return Ok(Json(MergeResult {
                    commit: source_sha.clone(),
                    tree,
                    fast_forward: true,
                    source_commit: source_sha,
                    target_branch: body.target_branch,
                }));
            }
            CasOutcome::Conflict { current } => {
                return Err(Error::RefConflict {
                    branch: body.target_branch,
                    expected: target_sha,
                    current,
                });
            }
        }
    }

    // 5. Strategy gate: ff-only refuses non-FF merges.
    if body.strategy == Strategy::FfOnly {
        return Err(Error::BadRequest(
            "not a fast-forward: target has diverged from source".to_string(),
        ));
    }

    // 6. Three-way merge. `target_sha` should be `Some` here — if the
    // branch didn't exist, the fast-forward branch at step 4 would have
    // handled it and returned early. But that's a non-trivial invariant
    // across two match arms, and reviewing it is exactly the kind of
    // logic that breaks silently when someone inserts an extra
    // conditional above. Fail loudly with a 500 rather than panic if
    // we ever get here with `None`.
    let target_sha = target_sha.ok_or_else(|| {
        Error::Other(anyhow::anyhow!(
            "merge reached three-way path with no target sha — control flow invariant broken"
        ))
    })?;
    let merge_result = run_merge_tree(&git_dir, &target_sha, &source_sha).await?;
    let merged_tree = match merge_result {
        MergeTreeOutcome::Clean { tree } => tree,
        MergeTreeOutcome::Conflict { paths } => {
            return Err(Error::MergeConflict {
                target_branch: body.target_branch,
                source_branch: body.source_branch,
                conflict_paths: paths,
            });
        }
    };

    // 7. Build the merge commit. Two parents: target first (the branch we're
    // advancing), source second — this matches `git merge` conventions.
    let message = body
        .message
        .clone()
        .unwrap_or_else(|| format!("Merge {} into {}", body.source_branch, body.target_branch));
    let (author_name, author_email) = match &body.author {
        Some(a) => (a.name.clone(), a.email.clone()),
        None => (
            "Artifacts".to_string(),
            "artifacts@noreply.local".to_string(),
        ),
    };
    let commit_env: Vec<(&str, &str)> = vec![
        ("GIT_AUTHOR_NAME", &author_name),
        ("GIT_AUTHOR_EMAIL", &author_email),
        ("GIT_COMMITTER_NAME", &author_name),
        ("GIT_COMMITTER_EMAIL", &author_email),
    ];
    let commit_args = [
        "commit-tree",
        &merged_tree,
        "-p",
        &target_sha,
        "-p",
        &source_sha,
        "-m",
        &message,
    ];
    let (rc, stdout, stderr) = run_git(&git_dir, &commit_args, &commit_env, None).await?;
    if rc != 0 {
        return Err(Error::Other(anyhow::anyhow!(
            "commit-tree failed: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    let commit_sha = String::from_utf8(stdout)?.trim().to_string();

    // 8. CAS the target ref.
    let repo_id_typed = crate::ids::RepoId::try_from(repo_id.as_str())?;
    let target_ref_typed = crate::ids::RefName::try_from(target_ref.as_str())?;
    let target_sha_typed = crate::ids::Oid::try_from(target_sha.as_str())?;
    let commit_sha_typed = crate::ids::Oid::try_from(commit_sha.as_str())?;
    match state
        .data
        .refs
        .cas_update(
            &repo_id_typed,
            &target_ref_typed,
            Some(&target_sha_typed),
            &commit_sha_typed,
        )
        .await?
    {
        CasOutcome::Updated => {}
        CasOutcome::Conflict { current } => {
            tracing::info!(
                repo = %repo_id, branch = %body.target_branch,
                expected = %target_sha, current = ?current,
                "merge ref-conflict"
            );
            return Err(Error::RefConflict {
                branch: body.target_branch,
                expected: Some(target_sha),
                current,
            });
        }
    }

    // Three-way merge commit — emit under the target branch so the event
    // shape is consistent with a direct commit.
    state.observ.events.publish(crate::events::Event::commit(
        &repo_id,
        &commit_sha,
        &body.target_branch,
        format!("merge {} into {}", body.source_branch, body.target_branch),
    ));

    Ok(Json(MergeResult {
        commit: commit_sha,
        tree: merged_tree,
        fast_forward: false,
        source_commit: source_sha,
        target_branch: body.target_branch,
    }))
}

// ── helpers ──────────────────────────────────────────────────────────────

async fn resolve_ref(git_dir: &std::path::Path, ref_name: &str) -> Result<Option<String>> {
    // `show-ref --verify --hash <ref>` prints the SHA if the ref exists,
    // exits 1 if it doesn't. We treat exit 1 as "missing" (normal flow).
    let (rc, stdout, stderr) = run_git(
        git_dir,
        &["show-ref", "--verify", "--hash", ref_name],
        &[],
        None,
    )
    .await?;
    if rc == 0 {
        return Ok(Some(String::from_utf8(stdout)?.trim().to_string()));
    }
    if rc == 1 {
        return Ok(None);
    }
    Err(Error::Other(anyhow::anyhow!(
        "show-ref failed: rc={rc} stderr={}",
        String::from_utf8_lossy(&stderr)
    )))
}

async fn is_ancestor(git_dir: &std::path::Path, ancestor: &str, descendant: &str) -> Result<bool> {
    // `merge-base --is-ancestor A B` exits 0 if A is an ancestor of B, 1 if
    // not. Anything else is an error.
    let (rc, _, stderr) = run_git(
        git_dir,
        &["merge-base", "--is-ancestor", ancestor, descendant],
        &[],
        None,
    )
    .await?;
    match rc {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(Error::Other(anyhow::anyhow!(
            "merge-base --is-ancestor failed: {}",
            String::from_utf8_lossy(&stderr)
        ))),
    }
}

async fn tree_of(git_dir: &std::path::Path, commit: &str) -> Result<String> {
    let (rc, stdout, stderr) = run_git(
        git_dir,
        &["rev-parse", &format!("{commit}^{{tree}}")],
        &[],
        None,
    )
    .await?;
    if rc != 0 {
        return Err(Error::Other(anyhow::anyhow!(
            "rev-parse tree failed: {}",
            String::from_utf8_lossy(&stderr)
        )));
    }
    Ok(String::from_utf8(stdout)?.trim().to_string())
}

enum MergeTreeOutcome {
    Clean { tree: String },
    Conflict { paths: Vec<String> },
}

/// Runs `git merge-tree --write-tree -z <target> <source>` and parses its
/// output. On success (exit 0), stdout starts with the merged tree SHA
/// followed by a NUL byte. On conflict (exit 1), stdout starts with a SHA
/// (the conflicted tree — not used here) followed by a NUL, then
/// NUL-delimited conflict entries: `<mode> <sha> <stage>\t<path>\0` — we
/// extract the `<path>` component to report back.
async fn run_merge_tree(
    git_dir: &std::path::Path,
    target: &str,
    source: &str,
) -> Result<MergeTreeOutcome> {
    let (rc, stdout, stderr) = run_git(
        git_dir,
        &["merge-tree", "--write-tree", "-z", target, source],
        &[],
        None,
    )
    .await?;
    // `merge-tree` uses exit 0 for clean, 1 for conflict, other for errors.
    if rc != 0 && rc != 1 {
        return Err(Error::Other(anyhow::anyhow!(
            "merge-tree failed: rc={rc} stderr={}",
            String::from_utf8_lossy(&stderr)
        )));
    }

    // First record: tree SHA, terminated by NUL.
    let nul = stdout.iter().position(|b| *b == 0).ok_or_else(|| {
        Error::Other(anyhow::anyhow!(
            "merge-tree produced no NUL-terminated tree sha"
        ))
    })?;
    let tree = String::from_utf8(stdout[..nul].to_vec())?
        .trim()
        .to_string();

    if rc == 0 {
        return Ok(MergeTreeOutcome::Clean { tree });
    }

    // Conflict: remaining output is the conflict report. merge-tree with
    // `-z` emits two NUL-delimited sections: "Conflicted file info"
    // (one record per stage-nonzero entry, ending with a double NUL) and
    // then "Informational messages" (ending with a double NUL). We only
    // care about the conflicted paths, which we dedup since each path
    // often appears multiple times (once per non-zero stage).
    let rest = &stdout[nul + 1..];
    let mut paths: Vec<String> = Vec::new();
    for record in rest.split(|b| *b == 0) {
        if record.is_empty() {
            continue;
        }
        // Records in the conflict section have the form "<mode> <sha> <stage>\t<path>".
        // The informational section has free-form text; skip anything without a TAB.
        if let Some(tab_idx) = record.iter().position(|b| *b == b'\t') {
            let path = String::from_utf8(record[tab_idx + 1..].to_vec())?;
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    if paths.is_empty() {
        // Defensive: merge-tree reported a conflict but we couldn't parse
        // any paths. Surface an opaque error rather than silently returning
        // a clean result.
        return Err(Error::Other(anyhow::anyhow!(
            "merge-tree reported conflict but emitted no parseable paths"
        )));
    }
    Ok(MergeTreeOutcome::Conflict { paths })
}
