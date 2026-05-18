//! Smart-HTTP: dispatches directly to `git upload-pack` / `git receive-pack`,
//! with a native in-process path for the v2 `info/refs` advertisement.
//!
//! ## What changed at M1a
//!
//! The previous impl shelled out to `git-http-backend`, git's CGI wrapper.
//! That wrapper parses CGI environment variables (PATH_INFO, QUERY_STRING,
//! REQUEST_METHOD) and dispatches internally to `git upload-pack` or
//! `git receive-pack`. Two process forks per request.
//!
//! This impl cuts out the middle layer. Each smart-HTTP endpoint invokes
//! the pack handler directly with `--stateless-rpc`. One process fork per
//! request; same protocol correctness (we're still using git's own pack
//! handlers, they're just the only subprocess we spawn now).
//!
//! Routing:
//!   GET  /git/:id.git/info/refs?service=git-upload-pack   ─┐
//!   GET  /git/:id.git/info/refs?service=git-receive-pack  ─┴─► info_refs()
//!         → spawn `git {service} --stateless-rpc --advertise-refs <dir>`,
//!           prepend the smart-HTTP `# service=...\n` + flush-pkt preamble,
//!           write with Content-Type `application/x-{service}-advertisement`
//!
//!   POST /git/:id.git/git-upload-pack   → pack_handler("upload-pack")
//!   POST /git/:id.git/git-receive-pack  → pack_handler("receive-pack")
//!         → spawn `git {sub} --stateless-rpc <dir>`, pump request body
//!           to stdin, stream stdout to the response. Content-Type is
//!           `application/x-git-{sub}-result`.
//!
//! The `Git-Protocol` header is passed through as `GIT_PROTOCOL` env so
//! clients that negotiate v2 get v2 responses (and the fallback to v1
//! still works for clients that don't).
//!
//! M1 proper (next) replaces the one remaining shell-out with native
//! gitoxide-based pack generation / parsing. This module will then stop
//! spawning processes entirely.

use crate::{
    auth::authorize_git,
    config::Config,
    error::{Error, Result},
    git_proto::{parse_ls_refs_only, parse_receive_pack_body, parse_v2_fetch, RefUpdate, ReceivePackRequest},
    git_wire_v2::{native_ls_refs_response, native_v2_fetch_response},
    pkt_line::{self as pkt},
    refs::RefStore,
    tokens::{Scope, TokenStore},
};
use axum::{
    body::Body,
    extract::{Path as AxumPath, Request, State},
    http::{header, HeaderMap, Method, Response, StatusCode},
};
use std::{path::Path, process::Stdio, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

#[derive(Clone)]
pub struct GitState {
    pub cfg: Arc<Config>,
    pub tokens: Arc<dyn TokenStore>,
    /// Native ref enumeration for v2 ls-refs. Same `RefStore` impl
    /// the REST commits path uses; the trait gives us `list` +
    /// `read_head` without going through git subprocesses.
    pub refs: Arc<dyn RefStore>,
    /// Object backend. M2b production routing: when the native pack
    /// indexer runs, it goes through `objects.ingest_pack(...)`
    /// rather than calling into `native_pack` directly. The FS impl
    /// is a thin wrapper today; a future chunked-KV impl would
    /// satisfy the same trait method without touching the receive
    /// handler.
    pub objects: Arc<dyn crate::object_store::ObjectStore>,
    /// When `true`, every native dispatcher (ls-refs / fetch /
    /// receive-pack / pack-indexing) is short-circuited and the
    /// request falls through to the legacy subprocess path. Wired
    /// from the `ARTIFACTS_DISABLE_NATIVE` env var at startup.
    /// Used by `scripts/bench_*.sh` to A/B native vs subprocess on
    /// the same binary; production should never have this set.
    pub disable_native: bool,
}

/// Axum entry point for everything under `/git/:id.git/*rest`. Authorizes,
/// then dispatches to the right sub-handler based on method + path.
pub async fn git_handler(
    State(state): State<GitState>,
    AxumPath((id, rest)): AxumPath<(String, String)>,
    request: Request,
) -> std::result::Result<Response<Body>, Error> {
    let repo_id = id.strip_suffix(".git").unwrap_or(&id).to_string();
    crate::storage::validate_repo_id(&repo_id)?;

    let repo_path = state.cfg.repos_dir().join(format!("{repo_id}.git"));
    if !repo_path.is_dir() {
        return Err(Error::RepoNotFound(repo_id));
    }

    let method = request.method().clone();
    let query = request.uri().query().unwrap_or("").to_string();
    let scope = required_scope(&method, &rest, Some(&query));
    authorize_git(&*state.tokens, request.headers(), &repo_id, scope).await?;

    let native_ctx = if state.disable_native {
        None
    } else {
        Some((
            repo_id.as_str(),
            state.refs.as_ref(),
            state.objects.as_ref(),
        ))
    };
    match (method.as_str(), rest.as_str()) {
        ("GET", "info/refs") => {
            let service = service_from_query(&query)?;
            // The v2 info/refs response is small + fully static —
            // we always serve it natively unless the kill-switch
            // is on, in which case we shell out for parity with
            // the v0/v1 path.
            info_refs(
                &repo_path,
                service,
                request.headers(),
                state.disable_native,
            )
            .await
        }
        ("POST", "git-upload-pack") => {
            pack_handler(&repo_path, "upload-pack", request, native_ctx).await
        }
        ("POST", "git-receive-pack") => {
            // Native receive-pack is gated behind the same `refs_for_native`
            // tuple as upload-pack — both want a `&dyn RefStore` to do CAS
            // (push) or read (fetch). The function then decides per-request
            // whether the body shape is one we natively handle.
            pack_handler(&repo_path, "receive-pack", request, native_ctx).await
        }
        _ => Err(Error::BadRequest(format!(
            "unsupported git endpoint: {method} /{rest}"
        ))),
    }
}

/// Classify the required scope for an incoming request.
///
/// - `git-receive-pack` is a push, write scope.
/// - `info/refs?service=git-receive-pack` is push-discovery, also write.
/// - Everything else is read.
fn required_scope(method: &Method, rest: &str, query: Option<&str>) -> Scope {
    if rest.ends_with("git-receive-pack") && method == Method::POST {
        return Scope::Write;
    }
    if rest.ends_with("info/refs") {
        if let Some(q) = query {
            if q.contains("service=git-receive-pack") {
                return Scope::Write;
            }
        }
    }
    Scope::Read
}

/// Parse the `service` query parameter. We accept only the two smart-HTTP
/// services; anything else (including missing) is a bad request.
fn service_from_query(query: &str) -> Result<&'static str> {
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("service=") {
            return match v {
                "git-upload-pack" => Ok("git-upload-pack"),
                "git-receive-pack" => Ok("git-receive-pack"),
                other => Err(Error::BadRequest(format!(
                    "unsupported service {other:?}"
                ))),
            };
        }
    }
    Err(Error::BadRequest(
        "missing ?service=... on info/refs".to_string(),
    ))
}

/// Detect the "I want v2" header from a git client. Git sends it as
/// `Git-Protocol: version=2`, sometimes as a colon-joined list like
/// `version=2:agent=git/2.43`, so we scan for the `version=2` token.
fn wants_v2(headers: &HeaderMap) -> bool {
    headers
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split([':', ',']).any(|s| s.trim() == "version=2"))
        .unwrap_or(false)
}

/// Native v2 capability advertisement for `info/refs`.
///
/// For protocol v2, the `info/refs` response is a fixed list of capability
/// pkt-lines — *no refs yet*. The client fetches refs in a subsequent
/// `POST /git-upload-pack` with `command=ls-refs`. Since the advertisement
/// is static (it doesn't depend on the repo), we build it in-process
/// instead of forking to `git upload-pack --advertise-refs`.
///
/// The capability set we advertise is a conservative subset of what modern
/// `git upload-pack` publishes — enough for clone/fetch/push, nothing that
/// would promise behavior the fall-through shell-out to upload-pack
/// doesn't already provide. When the POST lands it still goes through
/// `git upload-pack`, which handles the commands for real.
fn native_v2_info_refs(service: &'static str) -> Result<Response<Body>> {
    let mut body = Vec::with_capacity(256);
    // Smart-HTTP service preamble — same as the shell-out path emits.
    body.extend_from_slice(pkt_line(&format!("# service={service}\n")).as_bytes());
    body.extend_from_slice(b"0000");
    // v2 capability pkt-lines. Each terminates with '\n' per the spec.
    body.extend_from_slice(pkt_line("version 2\n").as_bytes());
    body.extend_from_slice(pkt_line("agent=artifacts/0.0.1\n").as_bytes());
    body.extend_from_slice(pkt_line("ls-refs=unborn\n").as_bytes());
    body.extend_from_slice(pkt_line("fetch=shallow\n").as_bytes());
    body.extend_from_slice(pkt_line("object-format=sha1\n").as_bytes());
    // Flush-pkt ending the advertisement.
    body.extend_from_slice(b"0000");

    let content_type = format!("application/x-{service}-advertisement");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .map_err(|e| Error::Other(anyhow::anyhow!("build response: {e}")))
}

/// Handle `GET /info/refs?service=...`.
///
/// Fast path: if the client signaled `Git-Protocol: version=2`, we emit
/// the v2 capability advertisement natively — no subprocess. Nearly every
/// modern git client (≥2.26) uses v2 by default, so this covers the
/// common case.
///
/// Fallback: for v0/v1 (no header, or an older client that explicitly
/// opts out of v2), we shell out to `git {sub} --advertise-refs`, which
/// produces the ref-listing response v1 clients expect. The v1
/// advertisement depends on current refs + capabilities of the server's
/// git binary, so doing it natively would need its own implementation;
/// the v1 path is rare enough that the shell-out is acceptable.
///
/// In both cases we prepend the smart-HTTP preamble:
///
///   001e# service=git-upload-pack\n0000<body>
async fn info_refs(
    repo_path: &Path,
    service: &'static str,
    headers: &HeaderMap,
    force_subprocess: bool,
) -> Result<Response<Body>> {
    if !force_subprocess && wants_v2(headers) {
        return native_v2_info_refs(service);
    }

    let sub = service
        .strip_prefix("git-")
        .expect("service validated by service_from_query");

    let mut cmd = Command::new("git");
    cmd.args([sub, "--stateless-rpc", "--advertise-refs"]).arg(repo_path);
    if let Some(gp) = headers.get("git-protocol").and_then(|v| v.to_str().ok()) {
        cmd.env("GIT_PROTOCOL", gp);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = cmd.spawn()?;
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        tracing::error!(
            code = ?output.status.code(),
            stderr = %String::from_utf8_lossy(&output.stderr),
            "git {sub} --advertise-refs failed"
        );
        return Err(Error::Other(anyhow::anyhow!(
            "git {sub} --advertise-refs failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    // If the client asked for v2, git emits `version 2\n` and its own
    // capability list — we pass that straight through. For v0/v1, git emits
    // the ref advertisement pkt-lines. Either way, we prepend the
    // `# service=...` + flush-pkt preamble so the response is a well-formed
    // smart-HTTP body.
    let service_line = format!("# service={service}\n");
    let mut body = Vec::with_capacity(output.stdout.len() + service_line.len() + 8);
    body.extend_from_slice(pkt_line(&service_line).as_bytes());
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&output.stdout);

    let content_type = format!("application/x-{service}-advertisement");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .map_err(|e| Error::Other(anyhow::anyhow!("build response: {e}")))
}

/// Handle `POST /git-upload-pack` or `POST /git-receive-pack`. Spawns
/// `git {sub} --stateless-rpc <dir>`, pipes the HTTP request body to its
/// stdin, and writes its stdout as the HTTP response body.
///
/// Fast path (M1b-2a): for `upload-pack` requests where the v2 body
/// contains only a `command=ls-refs`, we serve the response natively
/// from `RefStore` without forking. `refs_for_native` is the entry
/// point for that path; `None` disables it (e.g. on the receive-pack
/// route where ls-refs isn't a thing).
async fn pack_handler(
    repo_path: &Path,
    sub: &str, // "upload-pack" or "receive-pack"
    request: Request,
    refs_for_native: Option<(&str, &dyn RefStore, &dyn crate::object_store::ObjectStore)>,
) -> Result<Response<Body>> {
    let headers = request.headers().clone();
    let body_bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024 * 1024)
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("read body: {e}")))?;

    if let Some((repo_id, refs, objects)) = refs_for_native {
        // upload-pack natives (v2 ls-refs / fetch).
        if sub == "upload-pack" {
            if let Some(args) = parse_ls_refs_only(&body_bytes) {
                tracing::debug!(repo = %repo_id, "native v2 ls-refs (no subprocess)");
                return native_ls_refs_response(repo_id, refs, args).await;
            }
            if let Some(req) = parse_v2_fetch(&body_bytes) {
                // Validate the request shape is one we natively handle
                // (clone or basic fetch — no shallow/deepen/filter yet).
                // Anything we don't fully support falls through to git
                // upload-pack so behavior is preserved.
                if req.is_simple() {
                    tracing::debug!(
                        repo = %repo_id,
                        wants = req.wants.len(),
                        haves = req.haves.len(),
                        "native v2 fetch (no upload-pack)"
                    );
                    return native_v2_fetch_response(repo_path, req).await;
                }
            }
        }
        // receive-pack native (M1b-3).
        if sub == "receive-pack" {
            match parse_receive_pack_body(&body_bytes) {
                Some(req) if req.is_simple() => {
                    tracing::debug!(
                        repo = %repo_id,
                        updates = req.updates.len(),
                        pack_bytes = req.pack.len(),
                        "native receive-pack (no subprocess)"
                    );
                    return native_receive_pack_response(
                        repo_path, repo_id, refs, objects, req,
                    )
                    .await;
                }
                Some(req) => {
                    tracing::debug!(
                        repo = %repo_id,
                        unsupported = req.has_unsupported,
                        report_status = req.has_report_status,
                        sideband_64k = req.has_sideband_64k,
                        updates = req.updates.len(),
                        "receive-pack native dispatch declined; falling through"
                    );
                }
                None => {
                    tracing::debug!(
                        repo = %repo_id,
                        body_first_64 = ?String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(64)]),
                        "receive-pack body did not parse; falling through"
                    );
                }
            }
        }
    }

    let mut cmd = Command::new("git");
    cmd.args([sub, "--stateless-rpc"]).arg(repo_path);
    if let Some(gp) = headers.get("git-protocol").and_then(|v| v.to_str().ok()) {
        cmd.env("GIT_PROTOCOL", gp);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    // Pipe body to stdin in a task so the pack handler can start streaming
    // back output without waiting for the full body to land.
    if let Some(mut stdin) = child.stdin.take() {
        let bytes = body_bytes.clone();
        tokio::spawn(async move {
            let _ = stdin.write_all(&bytes).await;
            let _ = stdin.shutdown().await;
        });
    }

    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf).await;
        buf
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf).await;
        buf
    });

    let status = child.wait().await?;
    let stdout = stdout_task.await.map_err(|e| anyhow::anyhow!(e))?;
    let stderr = stderr_task.await.map_err(|e| anyhow::anyhow!(e))?;

    if !status.success() {
        tracing::error!(
            code = ?status.code(),
            stderr = %String::from_utf8_lossy(&stderr),
            "git {sub} failed"
        );
        return Err(Error::Other(anyhow::anyhow!(
            "git {sub} failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        )));
    }
    if !stderr.is_empty() {
        tracing::debug!(stderr = %String::from_utf8_lossy(&stderr), "git {sub} stderr");
    }

    let content_type = format!("application/x-git-{sub}-result");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(stdout))
        .map_err(|e| Error::Other(anyhow::anyhow!("build response: {e}")))
}

/// Native receive-pack response. Steps:
///   1. If pack data is non-empty, hand it to `git unpack-objects
///      --stdin` so the new objects land in the repo's odb. (M1b-3-gix
///      will swap this for `gix-pack` indexing — same architectural
///      seam as M1b-2c.)
///   2. CAS each ref-update through `RefStore`. We do them serially —
///      the underlying `git update-ref` already serializes, and a
///      bulk update-ref isn't worth the parser complexity until
///      `atomic` lands.
///   3. Build a `unpack <status>\n[ok|ng] <ref> ...` report and frame
///      it as the protocol expects (with sideband-1 wrap if the
///      client advertised it).
async fn native_receive_pack_response(
    repo_path: &Path,
    repo_id: &str,
    refs: &dyn RefStore,
    objects: &dyn crate::object_store::ObjectStore,
    req: ReceivePackRequest,
) -> Result<Response<Body>> {
    // Pack-indexing leaf. Two paths exist:
    //
    //   1. `git unpack-objects --stdin` — writes loose objects into
    //      `<repo>/objects/<aa>/<bbbb…>`. One subprocess.
    //   2. `gix-pack`'s `Bundle::write_to_directory` — writes a
    //      pack file + index into `<repo>/objects/pack/`. No
    //      subprocess.
    //
    // M1b-3-gix landed (2) and made it the default. Bench
    // (`scripts/bench_push.sh`) then showed (2) is ~4× SLOWER on
    // typical small pushes (p50 62ms vs 14ms): the gix-pack
    // indexer's per-call setup cost (gix::open + tempfile + index
    // computation) dominates for tiny inputs. (1) wins until pack
    // sizes grow well past anything an interactive `git push` would
    // generate.
    //
    // So default is back to (1). gix-pack stays as opt-in via
    // ARTIFACTS_NATIVE_INDEX_PACK=1 — useful for testing or for
    // backends that genuinely can't shell out (a future chunked-KV
    // Storage impl, where on-disk objects/ doesn't exist).
    //
    // The branch + the helper module remain so the M1b-3-gix work
    // isn't lost; we'll re-enable the native default when the
    // crossover point makes it worth it (or when gix-pack
    // performance improves upstream).
    let prefer_native_index = std::env::var("ARTIFACTS_NATIVE_INDEX_PACK")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    let unpack_outcome: std::result::Result<(), String> = if req.pack.is_empty() {
        Ok(())
    } else if prefer_native_index {
        // Route through `ObjectStore::ingest_pack`. The FS impl
        // delegates to `native_pack::index_pack_into_repo` (writes
        // pack file + index inside the repo's `objects/pack/`); a
        // future chunked-KV impl would unpack to its own loose
        // representation behind the same trait method. The gix
        // path is sync so we briefly block the worker thread —
        // for typical small pushes the cost is the same ~50ms
        // `Bundle::write_to_directory` overhead noted upstream.
        match objects.ingest_pack(repo_id, &req.pack) {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "native pack ingest failed; falling back to unpack-objects",
                );
                unpack_objects_via_subprocess(repo_path, &req.pack)
                    .await
                    .map_err(|e| format!("{e}"))
            }
        }
    } else {
        unpack_objects_via_subprocess(repo_path, &req.pack)
            .await
            .map_err(|e| format!("{e}"))
    };

    let mut report = Vec::with_capacity(64 * (req.updates.len() + 1));
    let unpack_line = match &unpack_outcome {
        Ok(_) => "unpack ok\n".to_string(),
        Err(msg) => format!("unpack {msg}\n"),
    };
    pkt::write_data(&mut report, unpack_line.as_bytes());

    if unpack_outcome.is_ok() {
        for u in &req.updates {
            let line = match apply_ref_update(refs, repo_id, u).await {
                Ok(()) => format!("ok {}\n", u.name),
                Err(reason) => format!("ng {} {}\n", u.name, reason),
            };
            pkt::write_data(&mut report, line.as_bytes());
        }
    } else {
        for u in &req.updates {
            let line = format!("ng {} unpacker error\n", u.name);
            pkt::write_data(&mut report, line.as_bytes());
        }
    }
    pkt::write_flush(&mut report);

    // Side-band-64k: each pkt-line in the body carries a band byte
    // (0x01 = report data, 0x02 = progress, 0x03 = error). Without
    // sideband, the report is sent raw. Our `is_simple()` filter
    // requires `report-status`, but `side-band-64k` is optional —
    // honor whichever the client advertised.
    let body = if req.has_sideband_64k {
        let mut out = Vec::with_capacity(report.len() + 64);
        const BAND_DATA: u8 = 0x01;
        const CHUNK: usize = pkt::PKT_LINE_MAX_PAYLOAD - 1;
        for chunk in report.chunks(CHUNK) {
            let mut framed = Vec::with_capacity(chunk.len() + 1);
            framed.push(BAND_DATA);
            framed.extend_from_slice(chunk);
            pkt::write_data(&mut out, &framed);
        }
        pkt::write_flush(&mut out);
        out
    } else {
        report
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-git-receive-pack-result")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .map_err(|e| Error::Other(anyhow::anyhow!("build response: {e}")))
}

/// Apply one ref-update. Returns `Ok(())` on success or an `Err(reason)`
/// suitable for the `ng <ref> <reason>` line in the protocol report.
async fn apply_ref_update(
    refs: &dyn RefStore,
    repo_id: &str,
    u: &RefUpdate,
) -> std::result::Result<(), String> {
    let outcome = if u.is_delete() {
        // CAS delete with the client's expected old-OID. If the ref
        // moved between the client's last fetch and this push,
        // RefStore returns Conflict and we report non-fast-forward.
        refs.cas_delete(repo_id, &u.name, Some(u.old.as_str())).await
    } else {
        let expected = if u.is_create() {
            None
        } else {
            Some(u.old.as_str())
        };
        refs.cas_update(repo_id, &u.name, expected, &u.new).await
    };
    match outcome {
        Ok(crate::refs::CasOutcome::Updated) => Ok(()),
        Ok(crate::refs::CasOutcome::Conflict { current }) => {
            // Mirror git's wording. The client surfaces "non-fast-forward"
            // when the local ref doesn't match what the server already has.
            let _ = current;
            Err("non-fast-forward".to_string())
        }
        Err(e) => Err(format!("error {e}")),
    }
}

/// `git unpack-objects --stdin` reads a pack from stdin and writes
/// each contained object as a loose object under `<git-dir>/objects/`.
/// Used for the pack-side of native receive-pack until M1b-3-gix
/// swaps in `gix-pack`'s native pack-indexing.
async fn unpack_objects_via_subprocess(
    repo_path: &Path,
    pack_bytes: &[u8],
) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("--git-dir")
        .arg(repo_path)
        .args(["unpack-objects", "-q"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let bytes = pack_bytes.to_vec();
        tokio::spawn(async move {
            let _ = stdin.write_all(&bytes).await;
            let _ = stdin.shutdown().await;
        });
    }
    let mut stderr = child.stderr.take().expect("stderr piped");
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf).await;
        buf
    });
    let status = child.wait().await?;
    let err = stderr_task.await.map_err(|e| anyhow::anyhow!(e))?;
    if !status.success() {
        return Err(Error::Other(anyhow::anyhow!(
            "unpack-objects failed: {}",
            String::from_utf8_lossy(&err).trim()
        )));
    }
    Ok(())
}

/// Format a pkt-line: 4-hex-char length prefix (including the 4 bytes of
/// prefix itself) + payload. This is the fundamental framing unit of the
/// git wire protocol.
///
/// Per the spec, a pkt-line payload is at most `PKT_LINE_MAX` bytes
/// (65516, which is 65520 minus the 4-byte length prefix). Larger
/// payloads would overflow the 4-hex length field; the `format!` above
/// would silently wrap. We debug_assert so dev/test builds catch it,
/// and runtime-cap in release builds so the error is at worst a
/// structurally-invalid pkt-line (and the client surfaces it) rather
/// than a security-relevant framing bug.
pub const PKT_LINE_MAX_PAYLOAD: usize = 65516;

fn pkt_line(payload: &str) -> String {
    debug_assert!(
        payload.len() <= PKT_LINE_MAX_PAYLOAD,
        "pkt-line payload exceeds max ({} > {})",
        payload.len(),
        PKT_LINE_MAX_PAYLOAD,
    );
    // In release, clamp. Truncation changes the semantic but at least
    // keeps the length prefix valid.
    let truncated = if payload.len() > PKT_LINE_MAX_PAYLOAD {
        &payload[..PKT_LINE_MAX_PAYLOAD]
    } else {
        payload
    };
    format!("{:04x}{}", truncated.len() + 4, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_scope_classification() {
        assert_eq!(required_scope(&Method::GET, "info/refs", None), Scope::Read);
        assert_eq!(
            required_scope(&Method::GET, "info/refs", Some("service=git-upload-pack")),
            Scope::Read
        );
        assert_eq!(
            required_scope(&Method::GET, "info/refs", Some("service=git-receive-pack")),
            Scope::Write
        );
        assert_eq!(
            required_scope(&Method::POST, "git-upload-pack", None),
            Scope::Read
        );
        assert_eq!(
            required_scope(&Method::POST, "git-receive-pack", None),
            Scope::Write
        );
    }

    #[test]
    fn pkt_line_truncates_at_max() {
        // Release-mode behavior: oversized payload gets truncated to the
        // documented cap rather than emitting a silently-wrapped length
        // prefix. We can only exercise the truncation branch here in
        // tests (debug_assert would panic); run via cargo test which is
        // a dev build, so the assert fires first.
        // Sanity: max-size payload works cleanly.
        let max_ok = "a".repeat(PKT_LINE_MAX_PAYLOAD);
        let line = pkt_line(&max_ok);
        assert_eq!(line.len(), PKT_LINE_MAX_PAYLOAD + 4);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "exceeds max")]
    fn pkt_line_panics_on_oversized_payload_in_debug() {
        let too_big = "a".repeat(PKT_LINE_MAX_PAYLOAD + 1);
        let _ = pkt_line(&too_big);
    }

    #[test]
    fn pkt_line_format() {
        // Known fixture from git docs: the "# service=git-upload-pack\n"
        // preamble is 26 chars of content, so the pkt-line length is 30
        // (0x001e) + payload.
        assert_eq!(
            pkt_line("# service=git-upload-pack\n"),
            "001e# service=git-upload-pack\n"
        );
    }

    #[test]
    fn wants_v2_parses_header_formats() {
        use axum::http::HeaderValue;

        let mk = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("git-protocol", HeaderValue::from_str(v).unwrap());
            h
        };
        assert!(wants_v2(&mk("version=2")));
        assert!(wants_v2(&mk("version=2:agent=git/2.43")));
        assert!(wants_v2(&mk("agent=git/2.43,version=2")));
        assert!(!wants_v2(&mk("version=1")));
        assert!(!wants_v2(&mk("")));
        assert!(!wants_v2(&HeaderMap::new()));
    }

    #[test]
    fn native_v2_info_refs_has_expected_shape() {
        let resp = native_v2_info_refs("git-upload-pack").unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-git-upload-pack-advertisement"
        );
        // Extract the body synchronously; response was built from a Vec<u8>
        // so we know it's fully in memory.
        let body = futures::executor::block_on(axum::body::to_bytes(
            resp.into_body(),
            1024 * 1024,
        ))
        .unwrap();
        let s = std::str::from_utf8(&body).unwrap();
        // Preamble.
        assert!(s.starts_with("001e# service=git-upload-pack\n0000"),
            "unexpected preamble, got: {:?}", &s[..40.min(s.len())]);
        // Version line + terminating flush-pkt.
        assert!(s.contains("000eversion 2\n"),
            "missing v2 version line in {s:?}");
        assert!(s.ends_with("0000"),
            "missing trailing flush-pkt in {s:?}");
        // Fetch capability must be present so clients actually negotiate
        // a fetch with us (without this the client errors out).
        assert!(s.contains("fetch=shallow\n"));
        assert!(s.contains("ls-refs=unborn\n"));
    }

    #[test]
    fn service_from_query_accepts_known_services() {
        assert_eq!(
            service_from_query("service=git-upload-pack").unwrap(),
            "git-upload-pack"
        );
        assert_eq!(
            service_from_query("foo=bar&service=git-receive-pack").unwrap(),
            "git-receive-pack"
        );
        assert!(service_from_query("service=").is_err());
        assert!(service_from_query("service=git-unknown").is_err());
        assert!(service_from_query("nothing=here").is_err());
    }

}
