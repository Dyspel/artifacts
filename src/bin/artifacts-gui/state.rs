//! Shared state between the polling thread and the render loop.
//!
//! `AppState` is the mutable, lock-protected bag the poller writes into.
//! `StateSnapshot` is the cheap Clone the render loop reads — taken once
//! at the top of each frame so the render pass doesn't hold the lock
//! while it walks 1500-line view code.
//!
//! `Sample` / `MetricsSnapshot` are the server-sourced shapes we pull
//! out of `/v1/admin/repos` and `/metrics`. Kept serde-deserializable
//! so the polling module can `into_json` directly into them.

use serde::Deserialize;
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

/// Window of recent (Instant, metrics) observations we keep for time-series
/// charts on the Overview tab. 5 minutes at 2-sec polls = ~150 samples,
/// which is light. The sample is `Clone` because the render path pulls
/// snapshots; we don't want rendering to hold the poller's mutex.
#[derive(Clone)]
pub(crate) struct Sample {
    pub(crate) at: Instant,
    pub(crate) metrics: MetricsSnapshot,
}

pub(crate) const HISTORY_WINDOW_SECS: u64 = 300;

#[derive(Default)]
pub(crate) struct AppState {
    pub(crate) repos: Vec<RepoSummary>,
    pub(crate) metrics: MetricsSnapshot,
    pub(crate) history: VecDeque<Sample>,
    pub(crate) last_poll: Option<Instant>,
    pub(crate) last_error: Option<String>,
    pub(crate) poll_count: u64,
    /// Populated by the poller whenever `selected_for_detail` is set and
    /// the `/v1/admin/repos/:id` endpoint is reachable. Lives here (not
    /// on `App`) because the poller writes it and the UI thread reads it;
    /// keeping all "server-sourced data" in one struct makes the
    /// lock-ownership story obvious.
    pub(crate) detail: Option<RepoDetail>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct RepoSummary {
    pub(crate) id: String,
    pub(crate) owner: Option<String>,
    #[serde(rename = "createdAt")]
    pub(crate) created_at: i64,
    #[serde(rename = "sourceId", default)]
    pub(crate) source_id: Option<String>,
}

/// Full detail for one repo. Server emits it with `summary` flattened so
/// the client sees one flat shape; we match.
#[derive(Clone, Deserialize)]
pub(crate) struct RepoDetail {
    pub(crate) id: String,
    pub(crate) owner: Option<String>,
    #[serde(rename = "createdAt")]
    pub(crate) created_at: i64,
    #[serde(rename = "sourceId", default)]
    pub(crate) source_id: Option<String>,
    #[serde(rename = "sizeBytes")]
    pub(crate) size_bytes: u64,
    pub(crate) refs: Vec<RefEntry>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct RefEntry {
    pub(crate) name: String,
    pub(crate) sha: String,
}

#[derive(Default, Clone)]
pub(crate) struct MetricsSnapshot {
    pub(crate) requests_total: u64,
    pub(crate) rate_limited_total: u64,
    pub(crate) quota_exceeded_total: u64,
    /// Aggregated histogram: buckets summed across every label series
    /// into one BTreeMap keyed by upper-bound `le`. Values are cumulative
    /// counts since server start, which is what Prometheus emits; we
    /// compute percentiles over *deltas* between snapshots at render
    /// time, not from the cumulative itself. Cumulative-percentile is
    /// a flatline at the max-ever-observed latency and doesn't reflect
    /// current conditions.
    pub(crate) latency_buckets: BTreeMap<OrdF64, u64>,
    pub(crate) build_version: Option<String>,
}

/// Lightweight snapshot so we don't hold the mutex across rendering.
/// History is cloned too — it's ~150 small structs, cheap — so plot
/// rendering can run without blocking the poller.
#[derive(Default, Clone)]
pub(crate) struct StateSnapshot {
    pub(crate) repos: Vec<RepoSummary>,
    pub(crate) metrics: MetricsSnapshot,
    pub(crate) history: VecDeque<Sample>,
    pub(crate) detail: Option<RepoDetail>,
}

impl AppState {
    pub(crate) fn clone_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            repos: self.repos.clone(),
            metrics: self.metrics.clone(),
            history: self.history.clone(),
            detail: self.detail.clone(),
        }
    }
}

/// `f64` doesn't implement `Ord`; wrap for `BTreeMap`. Only safe for the
/// values we actually bucketize (finite non-NaN + +Inf from parse).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct OrdF64(pub(crate) f64);
impl Eq for OrdF64 {}
impl PartialOrd for OrdF64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OrdF64 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}
