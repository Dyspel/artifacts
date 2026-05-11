//! Prometheus-format metrics.
//!
//! One install of the `metrics` facade at startup; instrumentation
//! sprinkled at the handlers and at the error-path. `GET /metrics`
//! emits the standard Prometheus text exposition that any scraper
//! understands (Prometheus itself, VictoriaMetrics, OpenTelemetry
//! collector in prometheus-receiver mode, etc.).
//!
//! We deliberately don't pull in a full OTel export pipeline here.
//! `/metrics` is the widest-compat smallest-footprint option for a
//! single-node prototype; an OTel exporter is a drop-in swap when we
//! have somewhere to send the spans to.
//!
//! ## Metrics exported
//!
//! - `artifacts_requests_total{method, path, status}` — counter
//! - `artifacts_request_duration_seconds{method, path}` — histogram
//! - `artifacts_rate_limited_total{class}` — counter (incremented by
//!   `Error::RateLimited` mapping)
//! - `artifacts_quota_exceeded_total` — counter
//! - `artifacts_audit_events_total{event}` — counter (one increment per
//!   audit-event record, labeled by event kind so dashboards can chart
//!   `repo.create` rate vs `token.revoke` rate independently)
//! - `artifacts_tokens_active_total` — gauge (rows in the token store
//!   that would currently authorize a request — not revoked, not
//!   expired). Refreshed at startup, every 60 seconds via a dedicated
//!   tokio task, and at the tail of each hourly token-prune sweep.
//!   Useful for capacity planning + spotting anomalous-mass token
//!   issuance within a minute of it happening.
//! - `artifacts_webhooks_active_total` — gauge (non-revoked webhook
//!   subscription count, across all repos). Same 60-second refresh
//!   cadence as the token gauge. Useful for catching subscription
//!   leaks (handlers adding faster than they remove).
//! - `artifacts_repos_total` — gauge (rows in the `repos` table:
//!   every repo the server knows about, both user- and admin-owned).
//!   Refreshed at startup and every 60 seconds via a dedicated tokio
//!   task. Tracks create/delete activity within a minute — useful for
//!   capacity planning and detecting runaway creation loops.
//! - `artifacts_audit_events_stored_total` — gauge (rows currently in
//!   the audit log; distinct from `artifacts_audit_events_total{event}`
//!   which is monotonic lifetime emissions). Goes *down* when the
//!   retention sweep prunes, so this is the metric to watch to
//!   confirm prune is actually working and to catch unbounded growth
//!   before disk fills. Refreshed at startup, every 60 seconds, and
//!   at the tail of each hourly prune sweep.
//! - `artifacts_webhook_deliveries_total{kind, outcome}` — counter
//!   (already-shipped; incremented by the webhook dispatcher with
//!   outcome ∈ {ok, http_error, transport_error})
//! - `artifacts_build_info{version}` — gauge=1, static for version info
//!
//! The `path` label is the *matched route template* (`/v1/repos/:id`),
//! not the raw URI (`/v1/repos/abc123`). Otherwise the cardinality
//! explodes as repos are created.

use axum::{
    body::Body,
    extract::{MatchedPath, Request},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Instant;

/// Install the prometheus exporter as the global `metrics` recorder and
/// return a handle for rendering the text exposition at `/metrics`.
///
/// Defines histogram buckets tuned for HTTP request latencies — a
/// handful of buckets from 1ms to 10s covers everything we care about.
/// Bucket granularity costs memory per metric series; too few and
/// p99-ish percentiles become unreliable. Seven buckets is a reasonable
/// middle ground.
pub fn init() -> anyhow::Result<PrometheusHandle> {
    const BUCKETS: &[f64] = &[
        0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
    ];
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(
                "artifacts_request_duration_seconds".to_string(),
            ),
            BUCKETS,
        )
        .map_err(|e| anyhow::anyhow!("register histogram buckets: {e}"))?
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("install prometheus recorder: {e}"))?;
    // Emit a static build_info metric so scrapers can see what's running.
    metrics::gauge!("artifacts_build_info", "version" => env!("CARGO_PKG_VERSION"))
        .set(1.0);
    Ok(handle)
}

/// Axum middleware: per-request timing + status counter.
///
/// Runs around every request to /v1/* (the REST surface). Not wrapped
/// around /git/* because those responses often stream large bodies and
/// the timing there is dominated by client work; we'd want per-operation
/// metrics (clone-size, clone-duration) instead of per-request, which
/// is a separate instrumentation effort.
pub async fn track_metrics(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().as_str().to_string();
    let matched = req.extensions().get::<MatchedPath>().map(|m| m.as_str());
    let raw_uri = req.uri().path();
    let path = path_label_for(matched, raw_uri);

    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    let elapsed = start.elapsed().as_secs_f64();

    metrics::counter!(
        "artifacts_requests_total",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status.clone(),
    )
    .increment(1);
    metrics::histogram!(
        "artifacts_request_duration_seconds",
        "method" => method,
        "path" => path,
    )
    .record(elapsed);

    response
}

/// Compute the `path` label for the request metrics. Returns the
/// matched route template (`/v1/repos/:id`) when one exists; otherwise
/// returns the constant `"<unmatched>"` rather than the raw URI.
///
/// Why constant-on-unmatched: an unauthenticated scanner hitting
/// `/scan/<unique-id>` once per probe would otherwise produce one
/// Prometheus series per random path and blow up the scrape size. The
/// raw URI is still useful for debugging — `track_metrics` emits it as
/// a structured log field when the fallback fires, so 404 patterns
/// remain visible in logs without polluting the metric label space.
pub(crate) fn path_label_for(matched: Option<&str>, raw_uri: &str) -> String {
    match matched {
        Some(m) => m.to_string(),
        None => {
            tracing::debug!(uri = raw_uri, "request hit an unmatched route");
            "<unmatched>".to_string()
        }
    }
}

/// Render the Prometheus exposition. Returns `text/plain; version=0.0.4`
/// which every scraper accepts.
pub fn render(handle: &PrometheusHandle) -> Response<Body> {
    let body = handle.render();
    let mut resp = Response::new(Body::from(body));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_label_uses_matched_route_template() {
        // Matched routes pass through verbatim — this is the case for
        // every legit endpoint, including parameterized ones where the
        // template (`/v1/repos/:id`) is what we want as the label.
        let label = path_label_for(Some("/v1/repos/:id"), "/v1/repos/abc123");
        assert_eq!(label, "/v1/repos/:id");
    }

    #[test]
    fn path_label_collapses_unmatched_to_constant() {
        // Unmatched paths must collapse to a single label so a 404
        // scanner hitting random suffixes can't explode the metric
        // label space.
        let a = path_label_for(None, "/scan/random-1");
        let b = path_label_for(None, "/scan/random-2");
        assert_eq!(a, "<unmatched>");
        assert_eq!(b, "<unmatched>");
        assert_eq!(a, b, "every unmatched path must share one label");
    }
}
