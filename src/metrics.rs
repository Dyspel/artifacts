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
//!   incremented by the webhook dispatcher.
//!   `kind` is the event type (`commit`, `fork`, `status`).
//!   `outcome` ∈ {`success` (2xx-3xx), `client_error` (4xx, not
//!   retried), `exhausted` (gave up after MAX_ATTEMPTS retries on
//!   5xx / transport error)}.
//! - `artifacts_sqlite_lock_wait_seconds{store}` — histogram
//!   recording how long each handler waits to acquire the per-store
//!   `tokio::sync::Mutex<Connection>` before issuing its SQL. Each
//!   store has one connection and one mutex, so this is the
//!   contention signal: if p99 climbs the SQLite-serialization is
//!   becoming a bottleneck and a connection pool (`deadpool-sqlite`)
//!   would help. `store` ∈ {`tokens`, `ownership`, `audit`}.
//! - `artifacts_object_reads_total{backend, outcome}` — counter,
//!   incremented once per `ObjectStore::read_object` call. `backend`
//!   names the impl (`fs` today; a future chunked-KV impl would
//!   add its own label). `outcome` ∈ {`hit` (object found),
//!   `miss` (object absent — includes malformed oid + missing repo),
//!   `error` (gix surfaced a non-NotFound error)}. Driven by every
//!   blob-read endpoint hit and any other production caller of the
//!   trait method.
//! - `artifacts_object_read_duration_seconds{backend}` — histogram
//!   over the same call site. Loose-object reads are sub-millisecond;
//!   pack-resolved reads pay a `gix::open` + index binary-search and
//!   land in the low-millisecond range. p99 climbing means either a
//!   cold disk cache or pack indexes too large for the binary-search
//!   to stay snappy.
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
    // SQLite-lock waits are typically microseconds; sub-millisecond
    // buckets give a useful low-end. The shared top-end (10s) matches
    // the request-duration histogram so dashboards can render both on
    // the same axis. A wait this long means the process is wedged on
    // a single store anyway.
    const SQLITE_LOCK_BUCKETS: &[f64] = &[
        0.000_010, 0.000_050, 0.000_100, 0.000_500, 0.001, 0.005, 0.010, 0.050, 0.100, 1.0, 10.0,
    ];
    // ObjectStore reads: loose-object hits sit in the 10s-of-µs range,
    // pack-resolved hits cross 1ms because gix::open + index walk.
    // Sub-millisecond buckets keep the loose vs pack split visible;
    // the 1s top-end catches "something fell off a cliff" without
    // wasting buckets on the request-level 10s timeout.
    const OBJECT_READ_BUCKETS: &[f64] = &[
        0.000_050, 0.000_100, 0.000_250, 0.000_500, 0.001, 0.002, 0.005, 0.010, 0.025, 0.100, 1.0,
    ];
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(
                "artifacts_request_duration_seconds".to_string(),
            ),
            BUCKETS,
        )
        .map_err(|e| anyhow::anyhow!("register histogram buckets: {e}"))?
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(
                "artifacts_sqlite_lock_wait_seconds".to_string(),
            ),
            SQLITE_LOCK_BUCKETS,
        )
        .map_err(|e| anyhow::anyhow!("register sqlite-lock histogram buckets: {e}"))?
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full(
                "artifacts_object_read_duration_seconds".to_string(),
            ),
            OBJECT_READ_BUCKETS,
        )
        .map_err(|e| anyhow::anyhow!("register object-read histogram buckets: {e}"))?
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("install prometheus recorder: {e}"))?;
    // Emit a static build_info metric so scrapers can see what's running.
    metrics::gauge!("artifacts_build_info", "version" => env!("CARGO_PKG_VERSION")).set(1.0);
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

/// Claim a connection from a SQLite pool and record how long the
/// claim took.
///
/// Wraps `r2d2::Pool::get()` with a histogram measurement keyed by
/// store name (`tokens` / `ownership` / `audit` / `webhooks`). Every
/// store-side handler funnels through here, so the histogram is the
/// canonical "is SQLite pool contention real yet?" signal.
///
/// Returns the `PooledConnection` the caller would have got from
/// `pool.get()` — no behavior change beyond the metric emission.
/// On pool-exhaustion / r2d2 error, the error is mapped into
/// `crate::error::Error::Other` so the trait-level `Result` types
/// don't have to carry an `r2d2` import.
// F4 (Rust type-system discipline) considered making this generic
// over a marker-type-based store label (`fn get_pooled<L: StoreLabel>(...)`)
// to resolve the histogram label-key at compile time. Bench result on
// 2026-05-23 host: the bench_concurrent.sh noise floor for p99 across
// 3 runs was ±40 ms — far larger than the ~10 ns per-call indirection
// the marker-type rewrite would save. Reverted before commit per the
// goal's "revert any change that doesn't show measurable p99
// improvement" clause. Keeping the `&'static str` shape.
pub(crate) fn get_pooled(
    pool: &crate::db_migrate::DbPool,
    store: &'static str,
) -> crate::error::Result<r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>> {
    let start = Instant::now();
    let conn = pool
        .get()
        .map_err(|e| crate::error::Error::Other(anyhow::anyhow!("sqlite pool ({store}): {e}")))?;
    metrics::histogram!(
        "artifacts_sqlite_lock_wait_seconds",
        "store" => store,
    )
    .record(start.elapsed().as_secs_f64());
    let _ = pool;
    Ok(conn)
}

/// Update the pool-state gauges for `store`. Cheap — `Pool::state()`
/// is a `Mutex::lock + read counters` round-trip. Call from periodic
/// refresh tasks (the same ones that refresh `_tokens_active_total`
/// etc.).
///
/// Emits two gauges:
///   - `artifacts_sqlite_pool_size{store}` — configured max
///   - `artifacts_sqlite_pool_in_use{store}` — claimed connections
pub(crate) fn refresh_pool_gauges(pool: &crate::db_migrate::DbPool, store: &'static str) {
    let state = pool.state();
    let size = pool.max_size();
    let in_use = state.connections.saturating_sub(state.idle_connections);
    metrics::gauge!("artifacts_sqlite_pool_size", "store" => store).set(size as f64);
    metrics::gauge!("artifacts_sqlite_pool_in_use", "store" => store).set(in_use as f64);
}

/// Spawn a periodic refresher for the pool gauges of every SQLite
/// store. One task instead of four — the work is just two gauge sets
/// per pool per tick, far cheaper than the 60-second `tick` makes it
/// look. Cloned pools share the underlying r2d2 `Arc<Inner>` so
/// memory cost is trivial.
pub fn spawn_pool_gauge_refresher(
    pools: Vec<(&'static str, crate::db_migrate::DbPool)>,
    tick: std::time::Duration,
) {
    // Publish once immediately so the first scrape doesn't see 0.
    for (name, p) in &pools {
        refresh_pool_gauges(p, name);
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        ticker.tick().await; // skip the immediate one
        loop {
            ticker.tick().await;
            for (name, p) in &pools {
                refresh_pool_gauges(p, name);
            }
        }
    });
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
