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
    pkt_line::{self as pkt, PktIter, PktLine},
    refs::{HeadState, RefStore},
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
        Some((repo_id.as_str(), state.refs.as_ref()))
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
    refs_for_native: Option<(&str, &dyn RefStore)>,
) -> Result<Response<Body>> {
    let headers = request.headers().clone();
    let body_bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024 * 1024)
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("read body: {e}")))?;

    if let Some((repo_id, refs)) = refs_for_native {
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
                        repo_path, repo_id, refs, req,
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

/// Parsed shape of a v2 ls-refs request. The structure on the wire:
///
///   PKT-LINE("command=ls-refs\n")
///   *PKT-LINE("<capability>\n")    -- e.g. agent=, object-format=
///   PKT-LINE delim (0001)
///   *PKT-LINE("<argument>\n")      -- peel | symrefs | ref-prefix <p>
///   PKT-LINE flush (0000)
///
/// We only handle the case where the body is *exclusively* one ls-refs
/// command — multi-command bodies fall through to `git upload-pack`. In
/// practice `git` always issues one command per HTTP POST in v2, so the
/// fast path covers the real workload.
#[derive(Debug, PartialEq, Eq)]
struct LsRefsArgs {
    pub peel: bool,
    pub symrefs: bool,
    pub prefixes: Vec<String>,
}

/// Returns `Some(args)` iff `body` is a v2 ls-refs request and nothing
/// else. We're conservative: any unfamiliar capability or argument
/// returns `None` so the subprocess path picks it up. That way new
/// protocol extensions don't silently get the wrong response.
fn parse_ls_refs_only(body: &[u8]) -> Option<LsRefsArgs> {
    let mut iter = PktIter::new(body);

    // 1. command line.
    let first = match iter.next()? {
        Ok(PktLine::Data(d)) => d,
        _ => return None,
    };
    let first = std::str::from_utf8(first).ok()?.trim_end_matches('\n');
    if first != "command=ls-refs" {
        return None;
    }

    // 2. capability lines until delim. Accept the small fixed set of
    //    capabilities `git` actually sends; reject anything unknown.
    let mut saw_delim = false;
    for item in iter.by_ref() {
        match item.ok()? {
            PktLine::Delim => {
                saw_delim = true;
                break;
            }
            PktLine::Flush => {
                // No args section at all — still a valid ls-refs.
                return Some(LsRefsArgs {
                    peel: false,
                    symrefs: false,
                    prefixes: Vec::new(),
                });
            }
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                if !is_known_capability(s) {
                    return None;
                }
            }
            PktLine::RespEnd => return None,
        }
    }
    if !saw_delim {
        return None;
    }

    // 3. argument lines until flush.
    let mut peel = false;
    let mut symrefs = false;
    let mut prefixes: Vec<String> = Vec::new();
    for item in iter.by_ref() {
        match item.ok()? {
            PktLine::Flush => {
                return Some(LsRefsArgs {
                    peel,
                    symrefs,
                    prefixes,
                });
            }
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                if s == "peel" {
                    peel = true;
                } else if s == "symrefs" {
                    symrefs = true;
                } else if let Some(p) = s.strip_prefix("ref-prefix ") {
                    prefixes.push(p.to_string());
                } else if s == "unborn" {
                    // Tolerate: `unborn` is a flag that says "include
                    // unborn HEAD in the response if applicable", which
                    // we already do unconditionally when symrefs is set.
                } else {
                    // Unknown argument — fall through to subprocess.
                    return None;
                }
            }
            PktLine::Delim | PktLine::RespEnd => return None,
        }
    }
    None
}

/// Capability lines we'll silently accept on a v2 ls-refs request.
/// Anything else we don't understand → fall back to upload-pack so we
/// can't serve a wrong response for a feature we haven't audited.
fn is_known_capability(line: &str) -> bool {
    line.starts_with("agent=")
        || line.starts_with("object-format=")
        || line.starts_with("session-id=")
}

/// Parsed shape of a v2 fetch request body. Mirrors the subset of args
/// `git` actually emits during clone + non-shallow fetch. Anything
/// unfamiliar trips `simple = false` and we fall back to upload-pack
/// rather than guess the right protocol response.
#[derive(Debug, Default, PartialEq, Eq)]
struct V2FetchRequest {
    wants: Vec<String>,
    haves: Vec<String>,
    done: bool,
    /// Set when the client sent any arg we don't fully implement yet
    /// (shallow, deepen, filter, sideband-all, ...). Used to gate the
    /// native dispatch — we'd rather defer to `git upload-pack` than
    /// produce a subtly-wrong response.
    has_unsupported: bool,
    /// True if we saw `no-progress`; we suppress sideband band-2 in that
    /// case. Currently we never emit progress, so this is informational.
    no_progress: bool,
}

impl V2FetchRequest {
    fn is_simple(&self) -> bool {
        // Native path only handles fetches the client has explicitly
        // closed with `done` (single-round negotiation, no acks needed)
        // and without any feature flag we haven't audited.
        self.done && !self.has_unsupported
    }
}

/// Returns `Some(req)` iff `body` is a v2 fetch command. Conservative:
/// we accept the well-known capabilities and arguments and tag any
/// unfamiliar one via `has_unsupported`. Multi-command bodies, malformed
/// pkt-lines, or non-fetch commands return `None`.
fn parse_v2_fetch(body: &[u8]) -> Option<V2FetchRequest> {
    let mut iter = PktIter::new(body);

    let first = match iter.next()? {
        Ok(PktLine::Data(d)) => d,
        _ => return None,
    };
    let first = std::str::from_utf8(first).ok()?.trim_end_matches('\n');
    if first != "command=fetch" {
        return None;
    }

    let mut saw_delim = false;
    for item in iter.by_ref() {
        match item.ok()? {
            PktLine::Delim => {
                saw_delim = true;
                break;
            }
            PktLine::Flush => {
                // No args at all is malformed for fetch — reject.
                return None;
            }
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                if !is_known_capability(s) {
                    return None;
                }
            }
            PktLine::RespEnd => return None,
        }
    }
    if !saw_delim {
        return None;
    }

    let mut req = V2FetchRequest::default();
    for item in iter.by_ref() {
        match item.ok()? {
            PktLine::Flush => return Some(req),
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                if let Some(oid) = s.strip_prefix("want ") {
                    if !is_hex40(oid) {
                        return None;
                    }
                    req.wants.push(oid.to_string());
                } else if let Some(oid) = s.strip_prefix("have ") {
                    if !is_hex40(oid) {
                        return None;
                    }
                    req.haves.push(oid.to_string());
                } else if s == "done" {
                    req.done = true;
                } else if s == "no-progress" {
                    req.no_progress = true;
                } else if matches!(s, "thin-pack" | "ofs-delta" | "include-tag") {
                    // Standard caps `git pack-objects --thin
                    // --delta-base-offset` already produces; nothing
                    // for us to do beyond knowing the client wants
                    // them.
                } else {
                    // Anything else (shallow, deepen, deepen-since,
                    // filter, sideband-all, packfile-uris, ...) needs
                    // protocol work we haven't done. Mark as
                    // unsupported and let the simple-check fall
                    // through to upload-pack.
                    req.has_unsupported = true;
                }
            }
            PktLine::Delim | PktLine::RespEnd => return None,
        }
    }
    None
}

fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Native v2 fetch response. Generates a packfile via
/// `git pack-objects --stdout --revs --thin --delta-base-offset` and
/// wraps it in the v2 fetch response framing:
///
///     PKT-LINE("packfile\n")
///     *PKT-LINE([0x01]<chunk>)        -- band-1 sideband (pack data)
///     PKT-LINE flush
///
/// Why pack-objects (subprocess) here, when M1b-2b's headline is
/// "native fetch via gitoxide"? Pragmatic split: this commit lands the
/// native v2 protocol layer (parsing, sideband framing, pkt-line
/// response) — that's the structurally important part. Pack generation
/// is a leaf operation we can swap to gix-pack in M1b-2c without
/// touching anything else. Replacing `git upload-pack` (which spawns
/// pack-objects internally anyway) with a direct pack-objects call
/// already cuts a process layer and gives us a much smaller surface
/// to migrate.
async fn native_v2_fetch_response(
    repo_path: &Path,
    req: V2FetchRequest,
) -> Result<Response<Body>> {
    // M1b-2c: prefer the native gix-pack path. It uses no
    // subprocess; just a commit walk + pack entry iteration in
    // process. Wrap in spawn_blocking because the gix call is sync
    // and we don't want to block a tokio worker on disk I/O.
    let pack = {
        let repo_path_buf = repo_path.to_path_buf();
        let wants = req.wants.clone();
        let haves = req.haves.clone();
        match tokio::task::spawn_blocking(move || {
            crate::native_pack::generate_pack(&repo_path_buf, &wants, &haves)
        })
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("native_pack join: {e}")))?
        {
            Ok(p) => p,
            Err(e) => {
                // Fall back to the pack-objects subprocess if the
                // native path errors. This keeps behavior intact while
                // the gix code matures — we'd rather a working clone
                // via pack-objects than a 500.
                tracing::warn!(error = %e, "native_pack failed; falling back to pack-objects");
                generate_pack_via_pack_objects(repo_path, &req.wants, &req.haves).await?
            }
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

/// One ref-update command from a `git push`. Format on the wire:
///   `<old-oid> <new-oid> <refname>[\0<capabilities>]\n`
#[derive(Debug, Clone, PartialEq, Eq)]
struct RefUpdate {
    old: String,
    new: String,
    name: String,
}

impl RefUpdate {
    /// `0000…000` is the canonical "ref doesn't exist" marker. A push
    /// where `old` is zero is a create; where `new` is zero is a delete.
    const ZERO: &'static str = "0000000000000000000000000000000000000000";

    fn is_create(&self) -> bool {
        self.old == Self::ZERO
    }
    fn is_delete(&self) -> bool {
        self.new == Self::ZERO
    }
}

/// Parsed shape of a smart-HTTP push body.
#[derive(Debug)]
struct ReceivePackRequest {
    updates: Vec<RefUpdate>,
    /// Capabilities advertised by the client on the first ref-update
    /// line (after a `\0`). We only need a few for the dispatch
    /// decision: whether to wrap the report in sideband-1, and whether
    /// the client expects a report at all.
    has_report_status: bool,
    has_sideband_64k: bool,
    /// True when the request shape includes anything we don't handle
    /// natively yet — e.g. an `atomic` push (all-or-nothing semantics
    /// across multiple refs requires its own implementation), or a
    /// `push-options` block we'd need to carry through to a hook.
    has_unsupported: bool,
    /// The pack bytes (everything after the ref-updates flush). May be
    /// empty: a push that only deletes refs sends no pack.
    pack: Vec<u8>,
}

impl ReceivePackRequest {
    fn is_simple(&self) -> bool {
        // A native receive-pack has to negotiate the report response
        // back to the client. Without `report-status` the client
        // doesn't expect any report. We only handle the "with-report"
        // case for now — without-report would mean returning empty,
        // which is a different code path and rarely seen.
        if !self.has_report_status {
            return false;
        }
        if self.has_unsupported {
            return false;
        }
        if self.updates.is_empty() {
            return false;
        }
        true
    }
}

/// Parse the receive-pack body up to and including the flush-pkt that
/// terminates the ref-updates section. Everything past that flush is
/// treated as the pack payload (or no pack, if the push is delete-only).
///
/// Returns `None` for malformed or unfamiliar bodies — caller falls
/// through to `git receive-pack` which has every quirk covered.
fn parse_receive_pack_body(body: &[u8]) -> Option<ReceivePackRequest> {
    let mut req = ReceivePackRequest {
        updates: Vec::new(),
        has_report_status: false,
        has_sideband_64k: false,
        has_unsupported: false,
        pack: Vec::new(),
    };

    let mut buf = body;
    let mut first = true;
    loop {
        let (line, rest) = match crate::pkt_line::read(buf) {
            Ok((l, r)) => (l, r),
            Err(_) => return None,
        };
        match line {
            PktLine::Flush => {
                buf = rest;
                break;
            }
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                // First line carries capabilities after a NUL byte.
                let (head, caps) = match s.split_once('\0') {
                    Some((h, c)) => (h, Some(c)),
                    None => (s, None),
                };
                let parts: Vec<&str> = head.splitn(3, ' ').collect();
                if parts.len() != 3 {
                    return None;
                }
                let old = parts[0];
                let new = parts[1];
                let name = parts[2];
                if !is_hex40(old) || !is_hex40(new) {
                    return None;
                }
                req.updates.push(RefUpdate {
                    old: old.to_string(),
                    new: new.to_string(),
                    name: name.to_string(),
                });
                if first {
                    if let Some(caps) = caps {
                        for c in caps.split(' ') {
                            match c {
                                "" => {}
                                "report-status" | "report-status-v2" => {
                                    // We emit the v1 report shape
                                    // (`ok <ref>` / `ng <ref> <reason>`).
                                    // v2 adds optional `option ...` lines
                                    // which we never produce, so the v1
                                    // shape is also a valid v2 report.
                                    req.has_report_status = true;
                                }
                                "side-band-64k" => req.has_sideband_64k = true,
                                "ofs-delta" | "delete-refs" | "no-thin"
                                | "quiet" => {}
                                "atomic" | "push-options" | "push-cert" => {
                                    req.has_unsupported = true;
                                }
                                other if other.starts_with("agent=")
                                    || other.starts_with("session-id=")
                                    || other.starts_with("object-format=") =>
                                {
                                    // Informational, ignore.
                                }
                                _ => {
                                    // Unknown caps trip the safety
                                    // net: better to fall through to
                                    // receive-pack than serve a
                                    // wrong response.
                                    req.has_unsupported = true;
                                }
                            }
                        }
                    } else {
                        // First update without caps — the client never
                        // advertised report-status, so we can't tell
                        // it the result. Defer to subprocess.
                        req.has_unsupported = true;
                    }
                    first = false;
                }
                buf = rest;
            }
            PktLine::Delim | PktLine::RespEnd => return None,
        }
    }

    req.pack = buf.to_vec();
    Some(req)
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
        let repo_path_buf = repo_path.to_path_buf();
        let pack = req.pack.clone();
        match tokio::task::spawn_blocking(move || {
            crate::native_pack::index_pack_into_repo(&repo_path_buf, &pack)
        })
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "native pack index failed; falling back to unpack-objects");
                unpack_objects_via_subprocess(repo_path, &req.pack)
                    .await
                    .map_err(|e| format!("{e}"))
            }
            Err(e) => Err(format!("native index join: {e}")),
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

/// Drive `git pack-objects --stdout --revs --thin --delta-base-offset`
/// with the given wants (one OID per line) and haves (each prefixed
/// with `^` to exclude its closure). Returns the raw pack bytes.
///
/// Empty wants → empty pack (still a valid 32-byte pack with zero
/// entries); pack-objects handles that case for free.
async fn generate_pack_via_pack_objects(
    repo_path: &Path,
    wants: &[String],
    haves: &[String],
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.arg("--git-dir").arg(repo_path).args([
        "pack-objects",
        "--stdout",
        "--revs",
        "--thin",
        "--delta-base-offset",
    ]);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

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
/// `extra` field (when set) is the literal trailer including its leading
/// space — e.g. `" symref-target:refs/heads/main"`.
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
/// commits) we use the v2 `unborn` form: `unborn HEAD symref-target:<t>`.
async fn native_ls_refs_response(
    repo_id: &str,
    refs: &dyn RefStore,
    args: LsRefsArgs,
) -> Result<Response<Body>> {
    let mut rows: Vec<LsRefsRow> = Vec::new();

    // ls-refs filtering: an empty prefix list means "no refs". Real
    // clients always include at least `ref-prefix HEAD`, but spec is
    // explicit about this. Distinct from the trait's `list(&[])` which
    // means "all refs".
    if !args.prefixes.is_empty() {
        let want_head = args.prefixes.iter().any(|p| p == "HEAD");
        let other_prefixes: Vec<String> = args
            .prefixes
            .iter()
            .filter(|p| p.as_str() != "HEAD")
            .cloned()
            .collect();

        // HEAD is special: not under any refs/ prefix. Place first so
        // the response order matches what upload-pack produces.
        if want_head {
            match refs.read_head(repo_id).await? {
                HeadState::Symbolic { target, oid } => {
                    rows.push(LsRefsRow {
                        oid,
                        name: "HEAD".into(),
                        extra: args.symrefs.then(|| format!(" symref-target:{target}")),
                    });
                }
                HeadState::Detached { oid } => {
                    rows.push(LsRefsRow {
                        oid,
                        name: "HEAD".into(),
                        extra: None,
                    });
                }
                HeadState::Unborn { target } => {
                    // Spec: unborn HEAD reports as
                    //   `unborn HEAD symref-target:<target>`.
                    // The OID column is the literal string `unborn`,
                    // not a SHA. Without symrefs, real upload-pack
                    // omits HEAD here too, so match that.
                    if args.symrefs {
                        rows.push(LsRefsRow {
                            oid: "unborn".into(),
                            name: "HEAD".into(),
                            extra: Some(format!(" symref-target:{target}")),
                        });
                    }
                }
            }
        }

        if !other_prefixes.is_empty() {
            let mut entries = refs.list(repo_id, &other_prefixes).await?;
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            for e in entries {
                let extra = if args.peel {
                    e.peeled.as_ref().map(|p| format!(" peeled:{p}"))
                } else {
                    None
                };
                rows.push(LsRefsRow {
                    oid: e.oid,
                    name: e.name,
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

    fn build_ls_refs_body(
        capabilities: &[&str],
        arguments: &[&str],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        crate::pkt_line::write_data(&mut buf, b"command=ls-refs\n");
        for cap in capabilities {
            let mut line = (*cap).to_string();
            line.push('\n');
            crate::pkt_line::write_data(&mut buf, line.as_bytes());
        }
        crate::pkt_line::write_delim(&mut buf);
        for arg in arguments {
            let mut line = (*arg).to_string();
            line.push('\n');
            crate::pkt_line::write_data(&mut buf, line.as_bytes());
        }
        crate::pkt_line::write_flush(&mut buf);
        buf
    }

    #[test]
    fn parse_ls_refs_only_accepts_typical_clone_request() {
        // Default `git clone` with v2 sends:
        //   command=ls-refs / agent=... / object-format=sha1 / 0001
        //   peel / symrefs / ref-prefix HEAD / ref-prefix refs/heads/
        //   ref-prefix refs/tags/ / 0000
        let body = build_ls_refs_body(
            &["agent=git/2.43.0", "object-format=sha1"],
            &[
                "peel",
                "symrefs",
                "ref-prefix HEAD",
                "ref-prefix refs/heads/",
                "ref-prefix refs/tags/",
            ],
        );
        let args = parse_ls_refs_only(&body).expect("should parse");
        assert!(args.peel);
        assert!(args.symrefs);
        assert_eq!(
            args.prefixes,
            vec![
                "HEAD".to_string(),
                "refs/heads/".to_string(),
                "refs/tags/".to_string(),
            ]
        );
    }

    #[test]
    fn parse_ls_refs_only_rejects_fetch_command() {
        // A `command=fetch` body must not be parsed as ls-refs — would
        // cause a wrong response. Returning None falls through to
        // upload-pack subprocess which handles fetch correctly.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=fetch\n");
        crate::pkt_line::write_delim(&mut body);
        crate::pkt_line::write_data(&mut body, b"thin-pack\n");
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_only_rejects_unknown_argument() {
        // Unfamiliar args force fallthrough to subprocess so we never
        // serve a stale-spec response for a feature we haven't audited.
        let body = build_ls_refs_body(
            &["agent=git/2.43.0"],
            &["peel", "future-flag-we-dont-know"],
        );
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_only_accepts_zero_args() {
        // A bare `command=ls-refs\n0000` (no delim, no args) is a valid
        // v2 request meaning "list all refs, no extras". We accept it.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=ls-refs\n");
        crate::pkt_line::write_flush(&mut body);
        let args = parse_ls_refs_only(&body).expect("should parse");
        assert!(!args.peel);
        assert!(!args.symrefs);
        assert!(args.prefixes.is_empty());
    }

    /// End-to-end native ls-refs against a real FsRefStore. Sets up a
    /// repo with a hand-laid loose ref + a packed-refs file, simulates
    /// HEAD pointing at the loose ref, and asserts that the v2
    /// response body has the right pkt-line shape.
    #[tokio::test]
    async fn native_ls_refs_response_emits_v2_listing() {
        use crate::refs::{FsRefStore, RefStore};
        use crate::storage::{new_repo_id, FsStorage, Storage};

        let tmp = std::env::temp_dir().join(format!("nat-ls-{}", new_repo_id()));
        let repos_dir = tmp.join("repos");
        let storage = FsStorage::new(&repos_dir).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let refs = FsRefStore::new(repos_dir.clone());
        let git_dir = repos_dir.join(format!("{repo_id}.git"));

        // Use refs/test/* (no commit-target requirement) to exercise the
        // path; the response builder is namespace-agnostic.
        let oid = "0123456789abcdef0123456789abcdef01234567";
        std::fs::create_dir_all(git_dir.join("refs/test")).unwrap();
        std::fs::write(git_dir.join("refs/test/x"), format!("{oid}\n")).unwrap();
        // Symbolic HEAD pointing at our test ref.
        std::fs::write(git_dir.join("HEAD"), "ref: refs/test/x\n").unwrap();

        let args = LsRefsArgs {
            peel: false,
            symrefs: true,
            prefixes: vec!["HEAD".into(), "refs/test/".into()],
        };
        let resp = native_ls_refs_response(&repo_id, &refs, args).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-git-upload-pack-result"
        );

        let body = futures::executor::block_on(axum::body::to_bytes(
            resp.into_body(),
            1024 * 1024,
        ))
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

    fn build_receive_pack_body(updates: &[(&str, &str, &str)], caps: &str, pack: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (i, (old, new, name)) in updates.iter().enumerate() {
            let mut line = format!("{old} {new} {name}");
            if i == 0 {
                line.push('\0');
                line.push_str(caps);
            }
            line.push('\n');
            crate::pkt_line::write_data(&mut buf, line.as_bytes());
        }
        crate::pkt_line::write_flush(&mut buf);
        buf.extend_from_slice(pack);
        buf
    }

    #[test]
    fn parse_receive_pack_typical_single_update_create() {
        let pack = b"PACK_FAKE_BYTES";
        let body = build_receive_pack_body(
            &[(
                "0000000000000000000000000000000000000000",
                "0123456789abcdef0123456789abcdef01234567",
                "refs/heads/main",
            )],
            "report-status side-band-64k ofs-delta agent=git/2.43",
            pack,
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.is_simple());
        assert_eq!(req.updates.len(), 1);
        assert!(req.updates[0].is_create());
        assert!(req.has_report_status);
        assert!(req.has_sideband_64k);
        assert_eq!(req.pack, pack);
    }

    #[test]
    fn parse_receive_pack_marks_atomic_unsupported() {
        let body = build_receive_pack_body(
            &[(
                "0000000000000000000000000000000000000000",
                "0123456789abcdef0123456789abcdef01234567",
                "refs/heads/main",
            )],
            "report-status side-band-64k atomic agent=git/2.43",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.has_unsupported);
        assert!(!req.is_simple());
    }

    #[test]
    fn parse_receive_pack_marks_delete_only_simple_but_apply_rejects_native() {
        // A push that only deletes a ref sends no pack. The parser
        // accepts it, but apply_ref_update returns "native delete not
        // implemented" so the report says ng. We test the parser
        // here; the apply behavior is exercised by smoke.
        let body = build_receive_pack_body(
            &[(
                "0123456789abcdef0123456789abcdef01234567",
                "0000000000000000000000000000000000000000",
                "refs/heads/old",
            )],
            "report-status side-band-64k delete-refs agent=git/2.43",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.is_simple());
        assert!(req.updates[0].is_delete());
    }

    #[test]
    fn parse_receive_pack_rejects_no_caps() {
        // No capabilities means the client doesn't expect a report —
        // we don't natively handle that flow.
        let mut buf = Vec::new();
        crate::pkt_line::write_data(
            &mut buf,
            b"0000000000000000000000000000000000000000 0123456789abcdef0123456789abcdef01234567 refs/heads/main\n",
        );
        crate::pkt_line::write_flush(&mut buf);
        let req = parse_receive_pack_body(&buf).expect("should parse");
        assert!(!req.is_simple());
    }

    fn build_fetch_body(args: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        crate::pkt_line::write_data(&mut buf, b"command=fetch\n");
        crate::pkt_line::write_data(&mut buf, b"agent=git/test\n");
        crate::pkt_line::write_data(&mut buf, b"object-format=sha1\n");
        crate::pkt_line::write_delim(&mut buf);
        for a in args {
            let mut line = (*a).to_string();
            line.push('\n');
            crate::pkt_line::write_data(&mut buf, line.as_bytes());
        }
        crate::pkt_line::write_flush(&mut buf);
        buf
    }

    #[test]
    fn parse_v2_fetch_typical_clone() {
        // Clone of one ref: thin-pack + ofs-delta + one want + done.
        let body = build_fetch_body(&[
            "thin-pack",
            "ofs-delta",
            "no-progress",
            "want 0123456789abcdef0123456789abcdef01234567",
            "done",
        ]);
        let req = parse_v2_fetch(&body).expect("should parse");
        assert!(req.is_simple());
        assert_eq!(req.wants.len(), 1);
        assert!(req.haves.is_empty());
        assert!(req.done);
        assert!(req.no_progress);
        assert!(!req.has_unsupported);
    }

    #[test]
    fn parse_v2_fetch_with_haves_for_incremental_fetch() {
        let body = build_fetch_body(&[
            "thin-pack",
            "want 0123456789abcdef0123456789abcdef01234567",
            "have 89abcdef0123456789abcdef0123456789abcdef",
            "done",
        ]);
        let req = parse_v2_fetch(&body).expect("should parse");
        assert!(req.is_simple());
        assert_eq!(req.wants.len(), 1);
        assert_eq!(req.haves.len(), 1);
    }

    #[test]
    fn parse_v2_fetch_marks_shallow_unsupported() {
        // We don't natively handle shallow yet; the request must
        // fall through to upload-pack so the response is correct.
        let body = build_fetch_body(&[
            "thin-pack",
            "want 0123456789abcdef0123456789abcdef01234567",
            "shallow 89abcdef0123456789abcdef0123456789abcdef",
            "done",
        ]);
        let req = parse_v2_fetch(&body).expect("should parse");
        assert!(req.has_unsupported);
        assert!(!req.is_simple());
    }

    #[test]
    fn parse_v2_fetch_rejects_non_hex_want() {
        let body = build_fetch_body(&["want not-a-sha", "done"]);
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[test]
    fn parse_v2_fetch_rejects_ls_refs_command() {
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=ls-refs\n");
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[tokio::test]
    async fn native_v2_fetch_response_pack_framing_with_real_repo() {
        use crate::storage::{new_repo_id, FsStorage, Storage};

        let tmp = std::env::temp_dir().join(format!("nat-fetch-{}", new_repo_id()));
        let repos_dir = tmp.join("repos");
        let storage = FsStorage::new(&repos_dir).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = repos_dir.join(format!("{repo_id}.git"));

        // Create a minimal commit so we have something to pack.
        // Use git plumbing — same approach as the smoke test, just
        // inline.
        use std::process::Command as StdCmd;
        StdCmd::new("git")
            .args(["--git-dir"])
            .arg(&git_dir)
            .args(["config", "user.email", "t@t"])
            .status()
            .unwrap();
        StdCmd::new("git")
            .args(["--git-dir"])
            .arg(&git_dir)
            .args(["config", "user.name", "t"])
            .status()
            .unwrap();
        let blob_out = StdCmd::new("git")
            .args(["--git-dir"])
            .arg(&git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map(|mut c| {
                use std::io::Write as _;
                c.stdin
                    .as_mut()
                    .unwrap()
                    .write_all(b"hello\n")
                    .unwrap();
                c.wait_with_output().unwrap()
            })
            .unwrap();
        let blob = String::from_utf8(blob_out.stdout).unwrap().trim().to_string();
        let mktree_out = StdCmd::new("git")
            .args(["--git-dir"])
            .arg(&git_dir)
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
        let tree = String::from_utf8(mktree_out.stdout).unwrap().trim().to_string();
        let commit_out = StdCmd::new("git")
            .args(["--git-dir"])
            .arg(&git_dir)
            .args(["commit-tree", "-m", "initial", &tree])
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap();
        let commit = String::from_utf8(commit_out.stdout).unwrap().trim().to_string();

        let req = V2FetchRequest {
            wants: vec![commit.clone()],
            haves: Vec::new(),
            done: true,
            has_unsupported: false,
            no_progress: true,
        };
        let resp = native_v2_fetch_response(&git_dir, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-git-upload-pack-result"
        );

        let body = futures::executor::block_on(axum::body::to_bytes(
            resp.into_body(),
            16 * 1024 * 1024,
        ))
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
        use crate::refs::{FsRefStore, RefStore};
        use crate::storage::{new_repo_id, FsStorage, Storage};

        let tmp = std::env::temp_dir().join(format!("nat-unborn-{}", new_repo_id()));
        let repos_dir = tmp.join("repos");
        let storage = FsStorage::new(&repos_dir).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let refs = FsRefStore::new(repos_dir);

        // Fresh repo: HEAD = ref: refs/heads/main, but main doesn't exist.
        let args = LsRefsArgs {
            peel: false,
            symrefs: true,
            prefixes: vec!["HEAD".into(), "refs/heads/".into()],
        };
        let resp = native_ls_refs_response(&repo_id, &refs, args).await.unwrap();
        let body = futures::executor::block_on(axum::body::to_bytes(
            resp.into_body(),
            1024 * 1024,
        ))
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
