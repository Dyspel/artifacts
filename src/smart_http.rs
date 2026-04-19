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
    authorize_git(&*state.tokens, request.headers(), &repo_id, scope)?;

    match (method.as_str(), rest.as_str()) {
        ("GET", "info/refs") => {
            let service = service_from_query(&query)?;
            info_refs(&repo_path, service, request.headers()).await
        }
        ("POST", "git-upload-pack") => {
            pack_handler(&repo_path, "upload-pack", request).await
        }
        ("POST", "git-receive-pack") => {
            pack_handler(&repo_path, "receive-pack", request).await
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
        .map(|v| {
            v.split(|c: char| c == ':' || c == ',')
                .any(|s| s.trim() == "version=2")
        })
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
) -> Result<Response<Body>> {
    if wants_v2(headers) {
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
async fn pack_handler(
    repo_path: &Path,
    sub: &str, // "upload-pack" or "receive-pack"
    request: Request,
) -> Result<Response<Body>> {
    let headers = request.headers().clone();
    let body_bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024 * 1024)
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("read body: {e}")))?;

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

/// Format a pkt-line: 4-hex-char length prefix (including the 4 bytes of
/// prefix itself) + payload. This is the fundamental framing unit of the
/// git wire protocol.
fn pkt_line(payload: &str) -> String {
    format!("{:04x}{}", payload.len() + 4, payload)
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
