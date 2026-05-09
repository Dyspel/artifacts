//! Response builders for the v2 commands `smart_http` serves natively
//! (`ls-refs`, `fetch`).
//!
//! Each builder takes a parsed request from [`crate::git_proto`] and
//! produces the corresponding `axum::Response<Body>`. No routing, no
//! authentication, no subprocess fallback decisions — those live in
//! `smart_http`. This file is purely "given a typed request, build the
//! correctly-framed pkt-line response."
//!
//! The one piece of subprocess I/O that remains in this module is
//! [`generate_pack_via_pack_objects`], the upload-pack fallback used
//! when the native [`crate::native_pack::generate_pack`] path errors.
//! We keep it here so the fallback lives next to its only caller; the
//! M1b-3-gix migration will delete this entirely.

use crate::error::{Error, Result};
use crate::git_cmd;
use crate::git_wire::proto::{LsRefsArgs, V2FetchRequest};
use crate::pkt_line as pkt;
use crate::refs::{HeadState, RefStore};
use axum::{
    body::Body,
    http::{header, Response, StatusCode},
};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Native v2 fetch response. Generates a packfile via the in-process
/// gix-pack path and wraps it in the v2 fetch response framing:
///
/// ```text
/// PKT-LINE("packfile\n")
/// *PKT-LINE([0x01]<chunk>)        -- band-1 sideband (pack data)
/// PKT-LINE flush
/// ```
///
/// If the native generator errors we fall back to a `pack-objects`
/// subprocess. M1b-3-gix will delete the fallback once gix-pack is
/// proven on the production pack shapes.
pub(crate) async fn native_v2_fetch_response(
    repo_path: &Path,
    req: V2FetchRequest,
) -> Result<Response<Body>> {
    // Prefer the native gix-pack path. It uses no subprocess; just a
    // commit walk + pack entry iteration in process. Off the tokio
    // pool because the gix call is sync and we don't want to block a
    // tokio worker on disk I/O.
    let pack = {
        let repo_path_buf = repo_path.to_path_buf();
        let wants = req.wants.clone();
        let haves = req.haves.clone();
        let native = crate::blocking::run_blocking("native_pack", move || {
            crate::native_pack::generate_pack(&repo_path_buf, &wants, &haves)
        })
        .await;
        match native {
            Ok(p) => p,
            Err(e) => {
                // Keep behavior intact while the gix code matures —
                // a working clone via pack-objects is better than a
                // 500.
                tracing::warn!(error = %e, "native_pack failed; falling back to pack-objects");
                generate_pack_via_pack_objects(repo_path, &req.wants, &req.haves).await?
            },
        }
    };

    let mut body = Vec::with_capacity(pack.len() + 256);
    pkt::write_data(&mut body, b"packfile\n");
    // Sideband-1: each pkt-line in the packfile section starts with a
    // 1-byte band marker (0x01 = pack data). Max payload is 65516
    // bytes including the band byte, so chunks of 65515 of pack data.
    const BAND_DATA: u8 = 0x01;
    const CHUNK: usize = pkt::PKT_LINE_MAX_PAYLOAD - 1;
    for chunk in pack.chunks(CHUNK) {
        let mut framed = Vec::with_capacity(chunk.len() + 1);
        framed.push(BAND_DATA);
        framed.extend_from_slice(chunk);
        pkt::write_data(&mut body, &framed);
    }
    pkt::write_flush(&mut body);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-git-upload-pack-result")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .map_err(|e| Error::Other(anyhow::anyhow!("build response: {e}")))
}

/// Subprocess fallback for fetch pack generation. Runs
/// `git pack-objects --stdout --revs --thin --delta-base-offset`,
/// pipes the want/have list to its stdin, and collects the resulting
/// packfile bytes. Stays here next to its only caller; deleted when
/// the gix-pack path no longer needs the safety net.
async fn generate_pack_via_pack_objects(
    repo_path: &Path,
    wants: &[String],
    haves: &[String],
) -> Result<Vec<u8>> {
    let mut child = git_cmd::pack_objects_revs(repo_path).spawn()?;

    // Write `<want>\n` and `^<have>\n` lines.
    let mut input = String::with_capacity(42 * (wants.len() + haves.len()));
    for w in wants {
        input.push_str(w);
        input.push('\n');
    }
    for h in haves {
        input.push('^');
        input.push_str(h);
        input.push('\n');
    }
    if let Some(mut stdin) = child.stdin.take() {
        let bytes = input.into_bytes();
        tokio::spawn(async move {
            let _ = stdin.write_all(&bytes).await;
            let _ = stdin.shutdown().await;
        });
    }

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf).await;
        buf
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        buf
    });

    let status = child.wait().await?;
    let pack = stdout_task.await.map_err(|e| anyhow::anyhow!(e))?;
    let err = stderr_task.await.map_err(|e| anyhow::anyhow!(e))?;
    if !status.success() {
        tracing::error!(
            stderr = %String::from_utf8_lossy(&err),
            "pack-objects failed"
        );
        return Err(Error::Other(anyhow::anyhow!(
            "pack-objects failed: {}",
            String::from_utf8_lossy(&err).trim()
        )));
    }
    Ok(pack)
}

/// One row of the ls-refs response: `<oid> <name>[<extra>]\n`. The
/// `extra` field (when set) is the literal trailer including its
/// leading space — e.g. `" symref-target:refs/heads/main"`.
struct LsRefsRow {
    oid: String,
    name: String,
    extra: Option<String>,
}

/// Build the v2 ls-refs response from `RefStore`. Spec format:
///
///   <oid> <refname>[ symref-target:<target>][ peeled:<oid>]\n
///
/// HEAD goes first when included. For an unborn HEAD (fresh repo, no
/// commits) we use the v2 `unborn` form:
/// `unborn HEAD symref-target:<t>`.
pub(crate) async fn native_ls_refs_response(
    repo_id: &str,
    refs: &dyn RefStore,
    args: LsRefsArgs,
) -> Result<Response<Body>> {
    let mut rows: Vec<LsRefsRow> = Vec::new();

    // ls-refs filtering: an empty prefix list means "no refs". Real
    // clients always include at least `ref-prefix HEAD`, but spec is
    // explicit about this. Distinct from the trait's `list(&[])`
    // which means "all refs".
    if !args.prefixes.is_empty() {
        let want_head = args.prefixes.iter().any(|p| p == "HEAD");
        let other_prefixes: Vec<String> = args
            .prefixes
            .iter()
            .filter(|p| p.as_str() != "HEAD")
            .cloned()
            .collect();

        // HEAD is special: not under any refs/ prefix. Place first
        // so the response order matches what upload-pack produces.
        let repo_id_typed = crate::ids::RepoId::try_from(repo_id)?;

        if want_head {
            match refs.read_head(&repo_id_typed).await? {
                HeadState::Symbolic { target, oid } => {
                    rows.push(LsRefsRow {
                        oid: oid.into_inner(),
                        name: "HEAD".into(),
                        extra: args.symrefs.then(|| format!(" symref-target:{target}")),
                    });
                },
                HeadState::Detached { oid } => {
                    rows.push(LsRefsRow {
                        oid: oid.into_inner(),
                        name: "HEAD".into(),
                        extra: None,
                    });
                },
                HeadState::Unborn { target } => {
                    // Spec: unborn HEAD reports as
                    //   `unborn HEAD symref-target:<target>`.
                    // The OID column is the literal string
                    // `unborn`, not a SHA. Without symrefs, real
                    // upload-pack omits HEAD here too, so match
                    // that.
                    if args.symrefs {
                        rows.push(LsRefsRow {
                            oid: "unborn".into(),
                            name: "HEAD".into(),
                            extra: Some(format!(" symref-target:{target}")),
                        });
                    }
                },
            }
        }

        if !other_prefixes.is_empty() {
            let mut entries = refs.list(&repo_id_typed, &other_prefixes).await?;
            entries.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
            for e in entries {
                let extra = if args.peel {
                    e.peeled.as_ref().map(|p| format!(" peeled:{p}"))
                } else {
                    None
                };
                // LsRefsRow is the wire-protocol shape — strings on the
                // line. Convert here at the trait→wire boundary; the
                // typed values stay inside the trait surface above.
                rows.push(LsRefsRow {
                    oid: e.oid.into_inner(),
                    name: e.name.into_inner(),
                    extra,
                });
            }
        }
    }

    let mut body = Vec::with_capacity(64 * rows.len() + 8);
    for row in &rows {
        let line = match &row.extra {
            Some(extra) => format!("{} {}{}\n", row.oid, row.name, extra),
            None => format!("{} {}\n", row.oid, row.name),
        };
        pkt::write_data(&mut body, line.as_bytes());
    }
    pkt::write_flush(&mut body);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-git-upload-pack-result")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .map_err(|e| Error::Other(anyhow::anyhow!("build response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end native ls-refs against a real FsRefStore. Sets up a
    /// repo with a hand-laid loose ref, simulates HEAD pointing at the
    /// loose ref, and asserts that the v2 response body has the right
    /// pkt-line shape.
    #[tokio::test]
    async fn native_ls_refs_response_emits_v2_listing() {
        let repo = crate::test_support::TestRepo::new();
        let refs = repo.fs_refs();

        // Use refs/test/* (no commit-target requirement) to exercise
        // the path; the response builder is namespace-agnostic.
        let oid = "0123456789abcdef0123456789abcdef01234567";
        std::fs::create_dir_all(repo.git_dir.join("refs/test")).unwrap();
        std::fs::write(repo.git_dir.join("refs/test/x"), format!("{oid}\n")).unwrap();
        // Symbolic HEAD pointing at our test ref.
        std::fs::write(repo.git_dir.join("HEAD"), "ref: refs/test/x\n").unwrap();

        let args = LsRefsArgs {
            peel: false,
            symrefs: true,
            prefixes: vec!["HEAD".into(), "refs/test/".into()],
        };
        let resp = native_ls_refs_response(&repo.repo_id, &refs, args)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-git-upload-pack-result"
        );

        let body = futures::executor::block_on(axum::body::to_bytes(resp.into_body(), 1024 * 1024))
            .unwrap();
        let s = std::str::from_utf8(&body).unwrap();

        // First pkt-line should be HEAD with symref-target annotation.
        // Format: 4-hex-len + "<oid> HEAD symref-target:refs/test/x\n"
        let head_line = format!("{oid} HEAD symref-target:refs/test/x\n");
        let head_pkt = format!("{:04x}{}", head_line.len() + 4, head_line);
        assert!(
            s.starts_with(&head_pkt),
            "expected HEAD pkt-line first, got prefix: {:?}",
            &s[..head_pkt.len().min(s.len())]
        );
        // Then the test ref.
        let ref_line = format!("{oid} refs/test/x\n");
        let ref_pkt = format!("{:04x}{}", ref_line.len() + 4, ref_line);
        assert!(s.contains(&ref_pkt), "missing refs/test/x line in {s:?}");
        // Trailing flush-pkt.
        assert!(s.ends_with("0000"), "missing trailing flush-pkt in {s:?}");
    }

    #[tokio::test]
    async fn native_v2_fetch_response_pack_framing_with_real_repo() {
        let repo = crate::test_support::TestRepo::new();
        let git_dir = &repo.git_dir;

        // Create a minimal commit so we have something to pack.
        // Use git plumbing — same approach as the smoke test, just
        // inline.
        use std::process::Command as StdCmd;
        StdCmd::new("git")
            .args(["--git-dir"])
            .arg(git_dir)
            .args(["config", "user.email", "t@t"])
            .status()
            .unwrap();
        StdCmd::new("git")
            .args(["--git-dir"])
            .arg(git_dir)
            .args(["config", "user.name", "t"])
            .status()
            .unwrap();
        let blob_out = StdCmd::new("git")
            .args(["--git-dir"])
            .arg(git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map(|mut c| {
                use std::io::Write as _;
                c.stdin.as_mut().unwrap().write_all(b"hello\n").unwrap();
                c.wait_with_output().unwrap()
            })
            .unwrap();
        let blob = String::from_utf8(blob_out.stdout)
            .unwrap()
            .trim()
            .to_string();
        let mktree_out = StdCmd::new("git")
            .args(["--git-dir"])
            .arg(git_dir)
            .args(["mktree"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map(|mut c| {
                use std::io::Write as _;
                let line = format!("100644 blob {blob}\thello.txt\n");
                c.stdin
                    .as_mut()
                    .unwrap()
                    .write_all(line.as_bytes())
                    .unwrap();
                c.wait_with_output().unwrap()
            })
            .unwrap();
        let tree = String::from_utf8(mktree_out.stdout)
            .unwrap()
            .trim()
            .to_string();
        let commit_out = StdCmd::new("git")
            .args(["--git-dir"])
            .arg(git_dir)
            .args(["commit-tree", "-m", "initial", &tree])
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap();
        let commit = String::from_utf8(commit_out.stdout)
            .unwrap()
            .trim()
            .to_string();

        let req = V2FetchRequest {
            wants: vec![commit.clone()],
            haves: Vec::new(),
            done: true,
            has_unsupported: false,
            no_progress: true,
        };
        let resp = native_v2_fetch_response(git_dir, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-git-upload-pack-result"
        );

        let body =
            futures::executor::block_on(axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024))
                .unwrap();
        // Header pkt-line is "packfile\n" (9 bytes) → "000Dpackfile\n".
        assert!(body.starts_with(b"000dpackfile\n"));
        // Trailing flush.
        assert!(body.ends_with(b"0000"));
        // Pack must contain the PACK header magic somewhere in the
        // sideband body (after a 5-byte pkt-line + band-byte prefix).
        // We don't know the exact offset because it depends on chunk
        // size; just assert PACK appears as expected.
        let pack_marker = b"PACK\x00\x00\x00\x02";
        assert!(
            body.windows(pack_marker.len()).any(|w| w == pack_marker),
            "no pack header found in response body"
        );
    }

    #[tokio::test]
    async fn native_ls_refs_response_unborn_head() {
        let repo = crate::test_support::TestRepo::new();
        let refs = repo.fs_refs();

        // Fresh repo: HEAD = ref: refs/heads/main, but main doesn't exist.
        let args = LsRefsArgs {
            peel: false,
            symrefs: true,
            prefixes: vec!["HEAD".into(), "refs/heads/".into()],
        };
        let resp = native_ls_refs_response(&repo.repo_id, &refs, args)
            .await
            .unwrap();
        let body = futures::executor::block_on(axum::body::to_bytes(resp.into_body(), 1024 * 1024))
            .unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        // Per spec, unborn HEAD with symref-target arrives as
        //   "unborn HEAD symref-target:refs/heads/main\n"
        let unborn_line = "unborn HEAD symref-target:refs/heads/main\n";
        let unborn_pkt = format!("{:04x}{}", unborn_line.len() + 4, unborn_line);
        assert!(
            s.contains(&unborn_pkt),
            "missing unborn HEAD line in response: {s:?}"
        );
    }
}
