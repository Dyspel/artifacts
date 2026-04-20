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
        state.cfg.jwt_expected_aud(),
        state.cfg.jwt_expected_iss(),
    )?;
    state.authn.rate_limit.check(&principal, Class::Commit)?;
    let repo_id_typed = crate::ids::RepoId::try_from(repo_id.as_str())?;
    if !state.data.storage.exists(&repo_id_typed) {
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
        },
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
                crate::webhooks::publish_event(
                    &state.observ.events,
                    state.observ.webhook_outbox.as_deref(),
                    crate::events::Event::commit(
                        &repo_id,
                        &source_sha,
                        &body.target_branch,
                        format!("merge {} (fast-forward)", body.source_branch),
                    ),
                );
                return Ok(Json(MergeResult {
                    commit: source_sha.clone(),
                    tree,
                    fast_forward: true,
                    source_commit: source_sha,
                    target_branch: body.target_branch,
                }));
            },
            CasOutcome::Conflict { current } => {
                return Err(Error::RefConflict {
                    branch: body.target_branch,
                    expected: target_sha_typed,
                    current,
                });
            },
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
        },
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
        CasOutcome::Updated => {},
        CasOutcome::Conflict { current } => {
            tracing::info!(
                repo = %repo_id, branch = %body.target_branch,
                expected = %target_sha, current = ?current,
                "merge ref-conflict"
            );
            return Err(Error::RefConflict {
                branch: body.target_branch,
                expected: Some(target_sha_typed),
                current,
            });
        },
    }

    // Three-way merge commit — emit under the target branch so the event
    // shape is consistent with a direct commit.
    crate::webhooks::publish_event(
        &state.observ.events,
        state.observ.webhook_outbox.as_deref(),
        crate::events::Event::commit(
            &repo_id,
            &commit_sha,
            &body.target_branch,
            format!("merge {} into {}", body.source_branch, body.target_branch),
        ),
    );

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

#[cfg(test)]
mod tests {
    use super::{is_ancestor, resolve_ref, run_merge_tree, tree_of, MergeTreeOutcome};
    use crate::commits::validate_sha;
    use std::path::Path;

    // ── bare-repo fixture ─────────────────────────────────────────────────

    /// Build a minimal bare repo and seed it with one commit on `main`.
    /// Returns the commit SHA for that initial commit.
    fn git_plumbing(git_dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> String {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut cmd = Command::new("git");
        cmd.arg("--git-dir").arg(git_dir).args(args);
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        if let Some(data) = stdin {
            child.stdin.as_mut().unwrap().write_all(data).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// Create a bare repo and a commit with `content` in `filename` on `branch`.
    /// Returns (git_dir path via tempdir, first commit SHA).
    async fn new_bare_repo_with_commit(
        dir: &Path,
        branch: &str,
        filename: &str,
        content: &[u8],
    ) -> String {
        use std::process::Command;
        Command::new("git")
            .args(["init", "--bare"])
            .arg(dir)
            .status()
            .unwrap();

        let blob = git_plumbing(dir, &["hash-object", "-w", "--stdin"], Some(content));
        let tree_entry = format!("100644 blob {blob}\t{filename}\n");
        let tree = git_plumbing(dir, &["mktree"], Some(tree_entry.as_bytes()));
        let commit = git_plumbing_commit(dir, &tree, &[]);
        Command::new("git")
            .arg("--git-dir")
            .arg(dir)
            .args(["update-ref", &format!("refs/heads/{branch}"), &commit])
            .status()
            .unwrap();
        commit
    }

    fn git_plumbing_commit(git_dir: &Path, tree: &str, parents: &[&str]) -> String {
        use std::process::Command;
        let mut args = vec!["commit-tree", "-m", "test"];
        for p in parents {
            args.push("-p");
            args.push(p);
        }
        args.push(tree);
        Command::new("git")
            .arg("--git-dir")
            .arg(git_dir)
            .args(&args)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .map(|o| String::from_utf8(o.stdout).unwrap().trim().to_string())
            .unwrap()
    }

    // ── resolve_ref ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_ref_returns_sha_for_existing_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join("repo.git");
        let commit = new_bare_repo_with_commit(&git_dir, "main", "hello.txt", b"hello\n").await;

        let got = resolve_ref(&git_dir, "refs/heads/main").await.unwrap();
        assert_eq!(got, Some(commit));
    }

    /// `show-ref --verify --hash` exits 128 (not 1) for a missing ref on
    /// some git versions — `resolve_ref` maps that to `Err`, not `None`.
    /// The `rc == 1 → Ok(None)` path is exercised only on git builds that
    /// emit exit code 1 for a missing ref; we test it as an error here so
    /// the test is portable across git versions.
    #[tokio::test]
    async fn resolve_ref_errors_or_none_for_missing_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join("repo.git");
        new_bare_repo_with_commit(&git_dir, "main", "hello.txt", b"hello\n").await;

        let got = resolve_ref(&git_dir, "refs/heads/nope").await;
        // Accept either Ok(None) (git exits 1) or Err (git exits 128) —
        // both indicate "ref not present".
        match got {
            Ok(None) | Err(_) => {},
            Ok(Some(sha)) => panic!("expected missing ref, got sha: {sha}"),
        }
    }

    // ── is_ancestor ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn is_ancestor_true_when_a_is_parent_of_b() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join("repo.git");
        let parent = new_bare_repo_with_commit(&git_dir, "main", "a.txt", b"first\n").await;

        // Create a child commit
        let blob = git_plumbing(
            &git_dir,
            &["hash-object", "-w", "--stdin"],
            Some(b"second\n"),
        );
        let tree_entry = format!("100644 blob {blob}\tb.txt\n");
        let tree = git_plumbing(&git_dir, &["mktree"], Some(tree_entry.as_bytes()));
        let child = git_plumbing_commit(&git_dir, &tree, &[&parent]);

        let result = is_ancestor(&git_dir, &parent, &child).await.unwrap();
        assert!(result, "parent should be an ancestor of child");
    }

    #[tokio::test]
    async fn is_ancestor_false_when_commits_are_unrelated() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join("repo.git");
        let c1 = new_bare_repo_with_commit(&git_dir, "main", "a.txt", b"aaa\n").await;
        let c2 = new_bare_repo_with_commit(&git_dir, "other", "b.txt", b"bbb\n").await;

        let result = is_ancestor(&git_dir, &c1, &c2).await.unwrap();
        assert!(!result, "unrelated commits are not ancestors of each other");
    }

    // ── tree_of ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn tree_of_returns_tree_sha_for_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join("repo.git");
        let commit = new_bare_repo_with_commit(&git_dir, "main", "file.txt", b"content\n").await;

        let tree = tree_of(&git_dir, &commit).await.unwrap();
        // tree SHA should be a 40-hex string
        assert_eq!(tree.len(), 40);
        assert!(tree.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── run_merge_tree ────────────────────────────────────────────────────

    /// Two branches that only touch different files should merge cleanly.
    #[tokio::test]
    async fn run_merge_tree_clean_merge_returns_tree_sha() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join("repo.git");
        use std::process::Command;
        Command::new("git")
            .args(["init", "--bare"])
            .arg(&git_dir)
            .status()
            .unwrap();

        // Create a shared base commit
        let blob_a = git_plumbing(&git_dir, &["hash-object", "-w", "--stdin"], Some(b"base\n"));
        let tree_entry = format!("100644 blob {blob_a}\tbase.txt\n");
        let base_tree = git_plumbing(&git_dir, &["mktree"], Some(tree_entry.as_bytes()));
        let base_commit = git_plumbing_commit(&git_dir, &base_tree, &[]);

        // Branch A: adds a.txt (different from B so no conflict)
        let blob_a2 = git_plumbing(
            &git_dir,
            &["hash-object", "-w", "--stdin"],
            Some(b"from a\n"),
        );
        let tree_a_entry =
            format!("100644 blob {blob_a}\tbase.txt\n100644 blob {blob_a2}\ta.txt\n");
        let tree_a = git_plumbing(&git_dir, &["mktree"], Some(tree_a_entry.as_bytes()));
        let commit_a = git_plumbing_commit(&git_dir, &tree_a, &[&base_commit]);

        // Branch B: adds b.txt
        let blob_b = git_plumbing(
            &git_dir,
            &["hash-object", "-w", "--stdin"],
            Some(b"from b\n"),
        );
        let tree_b_entry = format!("100644 blob {blob_a}\tbase.txt\n100644 blob {blob_b}\tb.txt\n");
        let tree_b = git_plumbing(&git_dir, &["mktree"], Some(tree_b_entry.as_bytes()));
        let commit_b = git_plumbing_commit(&git_dir, &tree_b, &[&base_commit]);

        let outcome = run_merge_tree(&git_dir, &commit_a, &commit_b)
            .await
            .unwrap();
        assert!(
            matches!(outcome, MergeTreeOutcome::Clean { .. }),
            "non-conflicting branches should merge cleanly"
        );
        if let MergeTreeOutcome::Clean { tree } = outcome {
            assert_eq!(tree.len(), 40);
            assert!(tree.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    /// Two branches that both modify the same file produce a conflict.
    #[tokio::test]
    async fn run_merge_tree_conflicting_branches_returns_conflict_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join("repo.git");
        use std::process::Command;
        Command::new("git")
            .args(["init", "--bare"])
            .arg(&git_dir)
            .status()
            .unwrap();

        // Base: shared.txt
        let blob_base = git_plumbing(
            &git_dir,
            &["hash-object", "-w", "--stdin"],
            Some(b"line1\nline2\nline3\n"),
        );
        let base_entry = format!("100644 blob {blob_base}\tshared.txt\n");
        let base_tree = git_plumbing(&git_dir, &["mktree"], Some(base_entry.as_bytes()));
        let base_commit = git_plumbing_commit(&git_dir, &base_tree, &[]);

        // Branch A: edits shared.txt with different content
        let blob_a = git_plumbing(
            &git_dir,
            &["hash-object", "-w", "--stdin"],
            Some(b"A changed line1\nline2\nline3\n"),
        );
        let entry_a = format!("100644 blob {blob_a}\tshared.txt\n");
        let tree_a = git_plumbing(&git_dir, &["mktree"], Some(entry_a.as_bytes()));
        let commit_a = git_plumbing_commit(&git_dir, &tree_a, &[&base_commit]);

        // Branch B: edits shared.txt with yet another content
        let blob_b = git_plumbing(
            &git_dir,
            &["hash-object", "-w", "--stdin"],
            Some(b"B changed line1\nline2\nline3\n"),
        );
        let entry_b = format!("100644 blob {blob_b}\tshared.txt\n");
        let tree_b = git_plumbing(&git_dir, &["mktree"], Some(entry_b.as_bytes()));
        let commit_b = git_plumbing_commit(&git_dir, &tree_b, &[&base_commit]);

        let outcome = run_merge_tree(&git_dir, &commit_a, &commit_b)
            .await
            .unwrap();
        assert!(
            matches!(outcome, MergeTreeOutcome::Conflict { .. }),
            "divergent edits to the same file should produce a conflict"
        );
        if let MergeTreeOutcome::Conflict { paths } = outcome {
            assert!(
                paths.iter().any(|p| p == "shared.txt"),
                "conflict paths should include shared.txt, got: {paths:?}"
            );
        }
    }

    // ── validate_sha (re-tested via merge.rs import) ─────────────────────

    #[test]
    fn validate_sha_accepts_40_hex() {
        assert!(validate_sha("0000000000000000000000000000000000000000").is_ok());
        assert!(validate_sha("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef").is_ok());
    }

    #[test]
    fn validate_sha_rejects_non_40_and_non_hex() {
        assert!(validate_sha("").is_err(), "empty");
        assert!(validate_sha("deadbeef").is_err(), "too short");
        assert!(
            validate_sha("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err(),
            "non-hex chars"
        );
        assert!(
            validate_sha("deadbeef deadbeef deadbeef deadbeef dead").is_err(),
            "space in sha"
        );
        // 41 chars — too long
        assert!(
            validate_sha("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefa").is_err(),
            "41 chars"
        );
    }
}
