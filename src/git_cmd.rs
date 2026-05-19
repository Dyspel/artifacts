//! Subprocess facade for the `git` binary.
//!
//! The codebase has ~35 `Command::new("git")` sites scattered across
//! `gc.rs`, `object_store/mod.rs`, `storage.rs`, `smart_http.rs`,
//! `native_pack.rs`, `refs.rs`, `git_wire_v2.rs`, and `commits.rs`.
//! Each one re-derives the same `--git-dir`, stdin / stdout / stderr,
//! exit-code-vs-status pattern. The eventual gix migration (which
//! deletes most of these subprocess calls) needs a single seam to
//! pivot through; this module is the start of that seam.
//!
//! Today the only public surface is [`run_git`], lifted out of
//! `commits.rs` because both `commits` and `refs` were already calling
//! it. Higher-level named helpers (`cat_file_blob_exists`,
//! `pack_objects_with`, `index_pack_into`, `update_ref_cas`, ...) can
//! land in follow-up commits and pull the remaining call sites in one
//! at a time.

use crate::error::Result;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Shell out to `git --git-dir <dir> <args>`, optionally pipe `stdin`
/// in, collect stdout + stderr, return exit code and both streams.
///
/// `env` is a list of `(key, value)` pairs added to the child's
/// environment (in addition to whatever the parent process has set).
/// Used by `commits` for `GIT_INDEX_FILE`, `GIT_AUTHOR_*` etc.
///
/// Returns `(exit_code, stdout, stderr)` rather than an `Err` on
/// non-zero status because most callers want to inspect stderr or
/// the exit code distinctly — "command failed" is a normal control
/// flow in git plumbing (e.g. `rev-parse` returning non-zero for a
/// missing ref).
pub(crate) async fn run_git(
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
