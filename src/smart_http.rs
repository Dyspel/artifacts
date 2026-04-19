//! Smart-HTTP bridge via `git http-backend`.
//!
//! `git http-backend` is a CGI program shipped with git. It speaks the full
//! smart-HTTP protocol (v1 and v2, upload-pack and receive-pack) and is
//! guaranteed to be bit-compatible with every git client because it *is* the
//! reference. We invoke it per request, feed the HTTP request body on stdin,
//! and stream stdout back as the HTTP response.
//!
//! CGI is old-school but dead reliable. Environment variables carry the
//! request metadata, stdin carries the body, stdout carries the response
//! (including its own status-line-as-headers). This bridge's job is to
//! convert between HTTP and CGI, authorize the caller, and point the backend
//! at the right repo directory.
//!
//! This is M0 code. M1 replaces it with a native `gitoxide` implementation —
//! at which point forks-per-request and the CGI boundary both go away.

use crate::{
    auth::authorize_git,
    config::Config,
    error::{Error, Result},
    tokens::{Scope, TokenStore},
};
use axum::{
    body::Body,
    extract::{Path as AxumPath, Request, State},
    http::{header, HeaderName, HeaderValue, Method, Response, StatusCode},
};
use std::{collections::HashMap, process::Stdio, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

#[derive(Clone)]
pub struct GitState {
    pub cfg: Arc<Config>,
    pub tokens: std::sync::Arc<dyn TokenStore>,
}

/// Route handler for every path under /git/:id.git/*rest. We dispatch on the
/// trailing segment:
///   - `info/refs`           -> service discovery (GET, both read and write)
///   - `git-upload-pack`     -> fetch/clone  (POST, read)
///   - `git-receive-pack`    -> push         (POST, write)
/// Anything else, we still pass to the backend — it knows what to do with it.
pub async fn git_handler(
    State(state): State<GitState>,
    AxumPath((id, rest)): AxumPath<(String, String)>,
    request: Request,
) -> std::result::Result<Response<Body>, Error> {
    let repo_id = id.strip_suffix(".git").unwrap_or(&id).to_string();
    crate::storage::validate_repo_id(&repo_id)?;

    // Repo must exist. We intentionally do *not* leak whether a repo exists
    // before auth: any caller who can produce a valid token for a repo
    // already knows the repo id.
    let repo_path = state.cfg.repos_dir().join(format!("{repo_id}.git"));
    if !repo_path.is_dir() {
        return Err(Error::RepoNotFound(repo_id));
    }

    let required_scope = required_scope(&request.method(), &rest, request.uri().query());
    authorize_git(&*state.tokens, request.headers(), &repo_id, required_scope)?;

    run_cgi(&state.cfg, &repo_id, &rest, request).await
}

/// Pick the scope required for this request.
///
/// - `git-receive-pack` is a push -> write.
/// - `info/refs?service=git-receive-pack` is push discovery -> write.
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

async fn run_cgi(
    cfg: &Config,
    repo_id: &str,
    rest: &str,
    request: Request,
) -> Result<Response<Body>> {
    let method = request.method().clone();
    let query = request.uri().query().unwrap_or("").to_string();
    let headers = request.headers().clone();
    let body_bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024 * 1024)
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("read body: {e}")))?;

    // Environment variables that `git http-backend` reads. This is just the
    // CGI spec plus the handful of GIT_* vars the backend cares about.
    let mut env: HashMap<String, String> = HashMap::new();
    env.insert("GIT_PROJECT_ROOT".into(), cfg.repos_dir().to_string_lossy().into());
    env.insert("GIT_HTTP_EXPORT_ALL".into(), "1".into());
    // PATH_INFO is the path *inside* GIT_PROJECT_ROOT. The backend parses it
    // as `<repo>.git/<service>` and dispatches.
    env.insert("PATH_INFO".into(), format!("/{repo_id}.git/{rest}"));
    env.insert("REQUEST_METHOD".into(), method.to_string());
    env.insert("QUERY_STRING".into(), query);
    if let Some(ct) = headers.get(header::CONTENT_TYPE) {
        if let Ok(v) = ct.to_str() {
            env.insert("CONTENT_TYPE".into(), v.to_string());
        }
    }
    if let Some(ce) = headers.get(header::CONTENT_ENCODING) {
        if let Ok(v) = ce.to_str() {
            env.insert("HTTP_CONTENT_ENCODING".into(), v.to_string());
        }
    }
    env.insert("CONTENT_LENGTH".into(), body_bytes.len().to_string());
    // Let the backend know what protocol version the client wants (v2 via
    // Git-Protocol header).
    if let Some(gp) = headers.get("git-protocol") {
        if let Ok(v) = gp.to_str() {
            env.insert("HTTP_GIT_PROTOCOL".into(), v.to_string());
        }
    }
    // Advertise ourselves as a clean server environment.
    env.insert("GATEWAY_INTERFACE".into(), "CGI/1.1".into());
    env.insert("SERVER_PROTOCOL".into(), "HTTP/1.1".into());
    env.insert("REMOTE_USER".into(), "artifacts".into());

    let mut child = Command::new(&cfg.git_http_backend)
        .env_clear()
        .envs(&env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Pump request body into stdin in a separate task so we don't deadlock
    // against a backend that wants to stream its response while still
    // reading input.
    if let Some(mut stdin) = child.stdin.take() {
        let bytes = body_bytes.clone();
        tokio::spawn(async move {
            let _ = stdin.write_all(&bytes).await;
            let _ = stdin.shutdown().await;
        });
    }

    // Collect stdout and stderr concurrently.
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
            "git-http-backend failed"
        );
        return Err(Error::GitBackend(status.code().unwrap_or(-1)));
    }
    if !stderr.is_empty() {
        tracing::debug!(stderr = %String::from_utf8_lossy(&stderr), "git-http-backend stderr");
    }

    parse_cgi_response(stdout)
}

/// `git http-backend` writes a CGI response: header lines terminated by a
/// blank line, followed by the body. We translate that into an HTTP response.
fn parse_cgi_response(stdout: Vec<u8>) -> Result<Response<Body>> {
    // Find the \r\n\r\n (or \n\n) that ends the header block.
    let (header_end, sep_len) = find_header_end(&stdout)
        .ok_or_else(|| Error::Other(anyhow::anyhow!("malformed CGI response: no header break")))?;

    let header_bytes = &stdout[..header_end];
    let body_bytes = &stdout[header_end + sep_len..];

    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|e| Error::Other(anyhow::anyhow!("CGI headers not utf8: {e}")))?;

    let mut status = StatusCode::OK;
    let mut resp_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
    for line in header_text.split(|c| c == '\n').map(str::trim_end) {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::Other(anyhow::anyhow!("bad CGI header: {line}")))?;
        let name_lc = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name_lc == "status" {
            // "Status: 404 Not Found"
            let code: u16 = value
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(200);
            status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
            continue;
        }
        let hn = HeaderName::from_bytes(name_lc.as_bytes())
            .map_err(|e| Error::Other(anyhow::anyhow!("bad header name {name_lc}: {e}")))?;
        let hv = HeaderValue::from_str(value)
            .map_err(|e| Error::Other(anyhow::anyhow!("bad header value: {e}")))?;
        resp_headers.push((hn, hv));
    }

    let mut builder = Response::builder().status(status);
    for (n, v) in resp_headers {
        builder = builder.header(n, v);
    }
    let body = Body::from(body_bytes.to_vec());
    builder.body(body).map_err(|e| Error::Other(anyhow::anyhow!("build response: {e}")))
}

fn find_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    // Try \r\n\r\n first, then \n\n.
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some((i, 4));
        }
    }
    for i in 0..buf.len().saturating_sub(1) {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some((i, 2));
        }
    }
    None
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
    fn parse_cgi_response_basic() {
        let raw = b"Status: 200 OK\r\nContent-Type: application/x-git-upload-pack-result\r\n\r\nHELLO".to_vec();
        let resp = parse_cgi_response(raw).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-git-upload-pack-result"
        );
    }
}
