//! Per-request correlation IDs + a structured one-line info log for every
//! REST request served.
//!
//! ## Shape
//!
//! Every request carries a `X-Request-Id` header. If the incoming
//! request already has one (set by a reverse proxy, or a Dyspel
//! service-to-service call), we keep it — that's the value of request
//! IDs, so they cross service boundaries. If absent, we generate a
//! UUIDv4 simple-form (32 hex chars).
//!
//! The ID lives in the tracing span for the rest of request handling,
//! so any `tracing::info!` / `tracing::error!` emitted by a handler
//! inherits it as a structured field. That's what makes production
//! debugging tractable — grep one id, see the whole request's logs.
//!
//! The response carries `X-Request-Id: <id>` so the client can correlate
//! its own logs with ours without a round trip through the server log
//! file.
//!
//! ## Why a single log line per request
//!
//! At info level we emit exactly one structured line per request — at
//! the end, once the status and duration are known. That keeps log
//! volume bounded, avoids pre-request noise, and matches what ops
//! tooling expects from an HTTP server. Handlers are free to add
//! tracing events inside; they inherit the request span and keep the
//! id.

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use std::time::Instant;
use tracing::Instrument;
use uuid::Uuid;

pub async fn instrument(req: Request, next: Next) -> Response {
    let id = extract_or_generate_id(&req);
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let start = Instant::now();

    // Span is the scope inside which the handler runs. Any tracing
    // event it emits inherits request_id/method/path as fields.
    let span = tracing::info_span!(
        "req",
        request_id = %id,
        method = %method,
        path = %path,
    );

    // Move `id` into the async block so the response header can carry
    // it. We've already embedded it in the span above.
    async move {
        let mut resp = next.run(req).await;
        let status = resp.status().as_u16();
        let duration_ms = start.elapsed().as_millis() as u64;

        if let Ok(v) = HeaderValue::from_str(&id) {
            resp.headers_mut()
                .insert(axum::http::HeaderName::from_static("x-request-id"), v);
        }

        // One-line structured summary. info! at ERROR for 5xx so ops
        // tooling that alerts on ERROR-level server logs catches them.
        if status >= 500 {
            tracing::error!(status, duration_ms, "req");
        } else if status >= 400 {
            tracing::warn!(status, duration_ms, "req");
        } else {
            tracing::info!(status, duration_ms, "req");
        }
        resp
    }
    .instrument(span)
    .await
}

/// Accept a well-formed client-provided X-Request-Id; fall back to a
/// fresh UUIDv4 simple hex (32 chars). We reject empty values and
/// values that aren't ASCII-printable to prevent header-smuggling
/// shenanigans — a request ID is a short opaque correlation token,
/// not a place for arbitrary bytes.
fn extract_or_generate_id(req: &Request) -> String {
    let provided = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .filter(|s| {
            s.chars()
                .all(|c| c.is_ascii_graphic() || c == '-' || c == '_')
        })
        .map(str::to_string);
    provided.unwrap_or_else(|| Uuid::new_v4().simple().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue as HV, Method, Uri};

    fn req_with(header: Option<&str>) -> Request {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(Uri::from_static("/v1/health"))
            .body(Body::empty())
            .unwrap();
        if let Some(v) = header {
            req.headers_mut()
                .insert("x-request-id", HV::from_str(v).unwrap());
        }
        req
    }

    #[test]
    fn extracts_client_provided_id_when_valid() {
        let id = extract_or_generate_id(&req_with(Some("client-id-42_abc")));
        assert_eq!(id, "client-id-42_abc");
    }

    #[test]
    fn generates_uuid_when_missing() {
        let id = extract_or_generate_id(&req_with(None));
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn rejects_empty_client_id() {
        let id = extract_or_generate_id(&req_with(Some("")));
        assert_eq!(id.len(), 32); // fell through to generated UUID
    }

    #[test]
    fn rejects_whitespace_only_client_id() {
        let id = extract_or_generate_id(&req_with(Some("   ")));
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn rejects_overlong_client_id() {
        let long = "a".repeat(200);
        let id = extract_or_generate_id(&req_with(Some(&long)));
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn rejects_non_printable_client_id() {
        // Spaces / control chars should bounce back to the generated UUID.
        let id = extract_or_generate_id(&req_with(Some("a b")));
        assert_eq!(id.len(), 32);
    }

    // Verify HeaderMap access works as we expect for header extraction.
    #[test]
    fn header_extraction_sanity() {
        let mut h = HeaderMap::new();
        h.insert("x-request-id", HV::from_static("abc"));
        assert_eq!(h.get("x-request-id").unwrap().to_str().unwrap(), "abc");
    }
}
