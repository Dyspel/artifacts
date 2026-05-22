//! Subprocess facade for the `git` binary.
//!
//! Every production code path that shells out to `git` goes through a
//! named helper in this module. The Command::new("git") invocations
//! live here and only here — call sites elsewhere take a configured
//! `Command` back and pipe stdin/stdout themselves.
//!
//! The eventual gix migration will replace these helpers with
//! `gix::Repository` calls; until then, this is the single seam that
//! makes the swap one-PR-per-helper instead of one-PR-per-call-site.
//!
//! Test modules (`#[cfg(test)]`) still spawn `git` directly for fixture
//! setup; that's intentional — tests model what a real client would
//! do, and channeling that through a production helper would tie
//! tests to whatever the latest helper API happens to be.

use crate::error::Result;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;

/// The binary we shell out to. Centralized as a constant so a future
/// change (e.g., a build-time-configurable path) only touches one
/// line.
const GIT: &str = "git";

/// Returns a fresh `tokio::process::Command` set up to invoke `git`
/// (no args, no env, no pipe wiring). The async factory — production
/// helpers in this module are mostly async because the surrounding
/// axum handlers are.
fn async_cmd() -> TokioCommand {
    TokioCommand::new(GIT)
}

/// Returns a fresh `std::process::Command` set up to invoke `git`.
/// The sync factory — used by `gc::rev_list_objects` (runs inside a
/// spawn_blocking sweep, doesn't gain from async).
fn sync_cmd() -> std::process::Command {
    std::process::Command::new(GIT)
}

// ---------------------------------------------------------------------
// Generic plumbing — used by `commits.rs`, `refs.rs`, and any code
// path that wants the (exit_code, stdout, stderr) tuple shape.
// ---------------------------------------------------------------------

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
    let mut cmd = async_cmd();
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

// ---------------------------------------------------------------------
// Smart-HTTP pack handlers.
//
// Used by `smart_http::info_refs` and `smart_http::pack_handler` to
// drive the actual `git upload-pack` / `git receive-pack` subprocess
// when the native v2 fast path doesn't apply (or `force_subprocess`
// is set). The caller takes the returned `Command`, sets up the
// stdin pipe with the HTTP request body, spawns, and streams the
// child's stdout back as the HTTP response.
//
// `service` is the bare subcommand — "upload-pack" or "receive-pack".
// Callers strip the `git-` prefix from the smart-HTTP service name
// before calling.
// ---------------------------------------------------------------------

/// `git <service> --stateless-rpc --advertise-refs <git_dir>` — used by
/// the `GET /info/refs` discovery endpoint for v0/v1 clients (v2
/// clients hit the native path).
pub(crate) fn pack_handler_advertise(
    git_dir: &Path,
    service: &str,
    git_protocol: Option<&str>,
) -> TokioCommand {
    let mut cmd = async_cmd();
    cmd.args([service, "--stateless-rpc", "--advertise-refs"])
        .arg(git_dir);
    if let Some(gp) = git_protocol {
        cmd.env("GIT_PROTOCOL", gp);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// `git <service> --stateless-rpc <git_dir>` — used by the
/// `POST /git-{upload,receive}-pack` request bodies. Caller pipes the
/// HTTP body to stdin and streams stdout back to the response.
pub(crate) fn pack_handler_serve(
    git_dir: &Path,
    service: &str,
    git_protocol: Option<&str>,
) -> TokioCommand {
    let mut cmd = async_cmd();
    cmd.args([service, "--stateless-rpc"]).arg(git_dir);
    if let Some(gp) = git_protocol {
        cmd.env("GIT_PROTOCOL", gp);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// `git --git-dir <dir> pack-objects --stdout --revs --thin
/// --delta-base-offset` — used by the native v2 `command=fetch`
/// path when `gix-pack` falls back to subprocess pack generation.
/// Caller writes `want <oid>` / `^<have_oid>` lines to stdin and
/// reads the pack bytes from stdout.
pub(crate) fn pack_objects_revs(git_dir: &Path) -> TokioCommand {
    let mut cmd = async_cmd();
    cmd.arg("--git-dir").arg(git_dir).args([
        "pack-objects",
        "--stdout",
        "--revs",
        "--thin",
        "--delta-base-offset",
    ]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// `git --git-dir <dir> unpack-objects -q` — the default pack-indexing
/// path for the native receive-pack (`ARTIFACTS_NATIVE_INDEX_PACK=1`
/// swaps in `gix-pack::Bundle::write_to_directory` instead). Caller
/// pipes the pack bytes to stdin.
pub(crate) fn unpack_objects(git_dir: &Path) -> TokioCommand {
    let mut cmd = async_cmd();
    cmd.arg("--git-dir")
        .arg(git_dir)
        .args(["unpack-objects", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

// ---------------------------------------------------------------------
// Sync helpers — called from `spawn_blocking` paths where async buys
// nothing.
// ---------------------------------------------------------------------

/// `git --git-dir <dir> rev-list --objects --all` — used by `gc::run`
/// to enumerate every OID reachable from any ref. Caller parses the
/// `<oid> [<path>]` stdout lines.
pub(crate) fn rev_list_objects_all(git_dir: &Path) -> std::process::Command {
    let mut cmd = sync_cmd();
    cmd.arg("--git-dir")
        .arg(git_dir)
        .args(["rev-list", "--objects", "--all"]);
    cmd
}
