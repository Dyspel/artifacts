//! artifacts-gui — live structural view of an Artifacts server.
//!
//! Connects to an Artifacts instance over HTTP (admin-token auth), polls
//! `/v1/admin/repos` + `/metrics` every few seconds, and renders three
//! views with eframe/egui:
//!
//!   Overview — request rate, aggregate latency percentiles, and the
//!              rate-limit / quota counters.
//!   Repos    — sortable table of every known repo with id, owner,
//!              created-at, and source (for forks).
//!   Forks    — tree view of the fork network: roots expand to their
//!              forks, recursively.
//!
//! Build:  cargo build --bin artifacts-gui --features gui
//! Run:    artifacts-gui --url http://127.0.0.1:8787 --admin-token $TOK
//!
//! Wayland / X11 is picked automatically via winit (eframe's default
//! features include both). On a Wayland session you get Wayland; on an
//! XWayland or pure-X11 session you get X11. Nothing to configure.
//!
//! This binary is deliberately read-only. It never POSTs, never
//! mutates, never holds more than a cached snapshot of server state.
//! If you need to do something to the server, use curl.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser, Clone)]
#[command(name = "artifacts-gui", about = "Live view of an Artifacts server")]
struct Cli {
    /// Base URL of the Artifacts server (not including /v1).
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    url: String,

    /// Admin token (matches ARTIFACTS_ADMIN_TOKEN on the server). Env
    /// override keeps the token out of shell history.
    #[arg(long, env = "ARTIFACTS_ADMIN_TOKEN")]
    admin_token: String,

    /// Seconds between successive polls. Lower = fresher UI, higher load
    /// on the server. Default 2s is fine up to a few hundred repos.
    #[arg(long, default_value_t = 2.0)]
    poll_interval_secs: f64,
}

// ─────────────────────────────────────────────────────────────────────
// Shared state — polled by the background thread, read by egui's
// update loop.
// ─────────────────────────────────────────────────────────────────────

/// Window of recent (Instant, metrics) observations we keep for time-series
/// charts on the Overview tab. 5 minutes at 2-sec polls = ~150 samples,
/// which is light. The sample is `Clone` because eframe's render thread
/// pulls snapshots; we don't want rendering to hold the poller's mutex.
#[derive(Clone)]
struct Sample {
    at: Instant,
    metrics: MetricsSnapshot,
}

const HISTORY_WINDOW_SECS: u64 = 300;

#[derive(Default)]
struct AppState {
    repos: Vec<RepoSummary>,
    metrics: MetricsSnapshot,
    history: VecDeque<Sample>,
    last_poll: Option<Instant>,
    last_error: Option<String>,
    poll_count: u64,
    /// Populated by the poller whenever `selected_for_detail` is set and
    /// the `/v1/admin/repos/:id` endpoint is reachable. Lives here (not
    /// on `App`) because the poller writes it and the UI thread reads it;
    /// keeping all "server-sourced data" in one struct makes the
    /// lock-ownership story obvious.
    detail: Option<RepoDetail>,
}

#[derive(Clone, serde::Deserialize)]
struct RepoSummary {
    id: String,
    owner: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: i64,
    #[serde(rename = "sourceId", default)]
    source_id: Option<String>,
}

/// Full detail for one repo. Server emits it with `summary` flattened so
/// the client sees one flat shape; we match.
#[derive(Clone, serde::Deserialize)]
struct RepoDetail {
    id: String,
    owner: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: i64,
    #[serde(rename = "sourceId", default)]
    source_id: Option<String>,
    #[serde(rename = "sizeBytes")]
    size_bytes: u64,
    refs: Vec<RefEntry>,
}

#[derive(Clone, serde::Deserialize)]
struct RefEntry {
    name: String,
    sha: String,
}

#[derive(Default, Clone)]
struct MetricsSnapshot {
    requests_total: u64,
    rate_limited_total: u64,
    quota_exceeded_total: u64,
    /// Aggregated histogram: buckets summed across every label series
    /// into one BTreeMap keyed by upper-bound `le`. Values are cumulative
    /// counts since server start, which is what Prometheus emits; we
    /// compute percentiles over *deltas* between snapshots at render
    /// time, not from the cumulative itself. Cumulative-percentile is
    /// a flatline at the max-ever-observed latency and doesn't reflect
    /// current conditions.
    latency_buckets: BTreeMap<OrdF64, u64>,
    build_version: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────
// Polling — runs on a worker thread, updates shared state.
// ─────────────────────────────────────────────────────────────────────

fn poll_once(url: &str, token: &str) -> Result<(Vec<RepoSummary>, MetricsSnapshot)> {
    let base = url.trim_end_matches('/');

    let repos: Vec<RepoSummary> = ureq::get(&format!("{base}/v1/admin/repos"))
        .set("Authorization", &format!("Bearer {token}"))
        .timeout(Duration::from_secs(10))
        .call()
        .context("GET /v1/admin/repos")?
        .into_json()
        .context("parse admin/repos response")?;

    let metrics_text = ureq::get(&format!("{base}/metrics"))
        .timeout(Duration::from_secs(10))
        .call()
        .context("GET /metrics")?
        .into_string()
        .context("read /metrics body")?;

    Ok((repos, parse_metrics(&metrics_text)))
}

/// Fetch full detail for a single repo. Called by the poller when the
/// user has selected one. Slightly more expensive than the list (walks
/// the repo dir on the server to compute size + refs), so we do it at
/// most once per poll cycle — not per click.
fn poll_detail(url: &str, token: &str, repo_id: &str) -> Result<RepoDetail> {
    let base = url.trim_end_matches('/');
    ureq::get(&format!("{base}/v1/admin/repos/{repo_id}"))
        .set("Authorization", &format!("Bearer {token}"))
        .timeout(Duration::from_secs(10))
        .call()
        .with_context(|| format!("GET /v1/admin/repos/{repo_id}"))?
        .into_json()
        .context("parse admin/repos/:id response")
}

fn spawn_poller(
    cli: Cli,
    state: Arc<Mutex<AppState>>,
    selected: Arc<Mutex<Option<String>>>,
) {
    let interval = Duration::from_secs_f64(cli.poll_interval_secs.max(0.1));
    std::thread::spawn(move || loop {
        match poll_once(&cli.url, &cli.admin_token) {
            Ok((repos, metrics)) => {
                let now = Instant::now();
                let mut s = state.lock().expect("state mutex poisoned");
                s.repos = repos;
                s.metrics = metrics.clone();
                s.last_poll = Some(now);
                s.last_error = None;
                s.poll_count += 1;
                // Push + prune history. We keep samples within the last
                // HISTORY_WINDOW_SECS so the chart stays bounded and
                // relative-time math doesn't need to worry about ancient
                // observations dragging in a scale that dwarfs current
                // activity.
                s.history.push_back(Sample { at: now, metrics });
                while let Some(front) = s.history.front() {
                    if now.duration_since(front.at).as_secs() > HISTORY_WINDOW_SECS {
                        s.history.pop_front();
                    } else {
                        break;
                    }
                }
                drop(s);
            }
            Err(e) => {
                let mut s = state.lock().expect("state mutex poisoned");
                s.last_error = Some(format!("{e:#}"));
                // Keep going to the detail fetch anyway — list and
                // detail have independent failure modes.
                drop(s);
            }
        }

        // Second leg: if a repo is selected, keep its detail fresh.
        // If the user hasn't selected anything, this is skipped.
        let requested = selected.lock().ok().and_then(|g| g.clone());
        if let Some(id) = requested {
            match poll_detail(&cli.url, &cli.admin_token, &id) {
                Ok(detail) => {
                    if let Ok(mut s) = state.lock() {
                        // Stash the detail only if the selection hasn't
                        // changed underfoot. Otherwise we'd briefly
                        // show stale data for the previous selection.
                        if detail.id == id {
                            s.detail = Some(detail);
                        }
                    }
                }
                Err(e) => {
                    if let Ok(mut s) = state.lock() {
                        s.last_error = Some(format!("detail {id}: {e:#}"));
                    }
                }
            }
        } else if let Ok(mut s) = state.lock() {
            // No selection → drop any stale detail so the Detail tab
            // shows "pick a repo" instead of an old one.
            s.detail = None;
        }

        std::thread::sleep(interval);
    });
}

// ─────────────────────────────────────────────────────────────────────
// Prometheus text parser
//
// We only care about a handful of metrics. Full prom parsing is
// overkill; the linewise shape is easy to read by hand.
// ─────────────────────────────────────────────────────────────────────

fn parse_metrics(text: &str) -> MetricsSnapshot {
    let mut out = MetricsSnapshot::default();
    // Aggregate histogram buckets across all label series. Prometheus
    // cumulative histograms can be summed across series at the same
    // `le` to produce an overall cumulative histogram with the right
    // semantics.
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("artifacts_rate_limited_total") {
            out.rate_limited_total = last_number(rest).unwrap_or(0.0) as u64;
        } else if let Some(rest) = line.strip_prefix("artifacts_quota_exceeded_total") {
            out.quota_exceeded_total = last_number(rest).unwrap_or(0.0) as u64;
        } else if line.starts_with("artifacts_requests_total{") {
            out.requests_total += last_number(line).unwrap_or(0.0) as u64;
        } else if line.starts_with("artifacts_request_duration_seconds_bucket{") {
            if let (Some(le), Some(count)) = (extract_le(line), last_number(line)) {
                *out.latency_buckets.entry(OrdF64(le)).or_insert(0) += count as u64;
            }
        } else if line.starts_with("artifacts_build_info{") {
            out.build_version = extract_label(line, "version");
        }
    }
    out
}

/// Compute the p-th percentile (0.0..=1.0) of the observations *between*
/// two histogram snapshots. Returns `None` if there were no observations
/// in that interval — so the chart draws a gap instead of a flatline
/// when traffic stops, and so the overview table shows "—".
///
/// Algorithm:
///   1. delta[le] = newer[le] - older[le]   (observations in this bucket's
///      cumulative range during the interval)
///   2. total = delta[+Inf]                  (all observations in interval)
///   3. find smallest le where delta[le] ≥ total × p
///   4. return that le (seconds); caller converts to ms for display
///
/// This matches Prometheus's `histogram_quantile(p, rate(...[T]))` —
/// the interval replaces the rate window.
fn percentile_between(
    older: &BTreeMap<OrdF64, u64>,
    newer: &BTreeMap<OrdF64, u64>,
    p: f64,
) -> Option<f64> {
    let new_total = newer.get(&OrdF64(f64::INFINITY)).copied().unwrap_or(0);
    let old_total = older.get(&OrdF64(f64::INFINITY)).copied().unwrap_or(0);
    let total = new_total.saturating_sub(old_total);
    if total == 0 {
        return None;
    }
    let target = ((total as f64) * p).ceil() as u64;
    // BTreeMap iterates in key order (ascending `le`), which is what we
    // want for "smallest le whose delta cumulative is ≥ target".
    for (le, new_cum) in newer {
        let old_cum = older.get(le).copied().unwrap_or(0);
        let delta = new_cum.saturating_sub(old_cum);
        if delta >= target {
            return Some(le.0);
        }
    }
    None
}

/// Last whitespace-separated token, parsed as f64.
fn last_number(s: &str) -> Option<f64> {
    s.split_whitespace().last()?.parse().ok()
}

fn extract_le(line: &str) -> Option<f64> {
    let v = extract_label(line, "le")?;
    if v == "+Inf" { Some(f64::INFINITY) } else { v.parse().ok() }
}

fn extract_label(line: &str, name: &str) -> Option<String> {
    // Crude: find `name="..."` inside the {..} block.
    let lhs = line.find('{')?;
    let rhs = line.find('}')?;
    let labels = &line[lhs + 1..rhs];
    for kv in labels.split(',') {
        let kv = kv.trim();
        let (k, v) = kv.split_once('=')?;
        if k == name {
            return Some(v.trim_matches('"').to_string());
        }
    }
    None
}

/// `f64` doesn't implement `Ord`; wrap for `BTreeMap`. Only safe for the
/// values we actually bucketize (finite non-NaN + +Inf from parse).
#[derive(Debug, Clone, Copy, PartialEq)]
struct OrdF64(f64);
impl Eq for OrdF64 {}
impl PartialOrd for OrdF64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OrdF64 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.partial_cmp(&other.0).unwrap_or(std::cmp::Ordering::Equal)
    }
}

// ─────────────────────────────────────────────────────────────────────
// eframe App
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Overview,
    Repos,
    Forks,
    Detail,
}

struct App {
    cli: Cli,
    state: Arc<Mutex<AppState>>,
    view: View,
    /// Which repo's detail to show in the Detail tab. The poller reads
    /// `selected_for_detail` each loop and fetches that repo's detail
    /// into `state.detail` — so selecting a repo costs one extra HTTP
    /// call per poll cycle (not per click) and the UI thread never
    /// blocks on the network.
    selected_repo: Option<String>,
    selected_for_detail: Arc<Mutex<Option<String>>>,
}

impl App {
    /// Setter used by click handlers on the Repos and Forks tabs. Writes
    /// to both the local field and the shared slot the poller watches.
    fn select_repo(&mut self, id: String) {
        self.selected_repo = Some(id.clone());
        if let Ok(mut slot) = self.selected_for_detail.lock() {
            *slot = Some(id);
        }
        self.view = View::Detail;
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Keep the UI updating as the polling thread writes fresh state.
        // 500ms cadence is cheap; actual repaint scheduling is cheap in
        // egui because it diffs.
        ctx.request_repaint_after(Duration::from_millis(500));

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("artifacts-gui");
                ui.separator();
                ui.label(&self.cli.url);
                ui.separator();
                let s = self.state.lock().unwrap();
                if let Some(t) = s.last_poll {
                    ui.label(format!(
                        "polled {}s ago · n={}",
                        t.elapsed().as_secs(),
                        s.poll_count
                    ));
                } else {
                    ui.label("connecting…");
                }
                if let Some(err) = &s.last_error {
                    ui.separator();
                    ui.colored_label(egui::Color32::from_rgb(220, 50, 50), err);
                }
            });
        });

        egui::SidePanel::left("nav")
            .resizable(false)
            .min_width(120.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.selectable_value(&mut self.view, View::Overview, "Overview");
                ui.selectable_value(&mut self.view, View::Repos, "Repos");
                ui.selectable_value(&mut self.view, View::Forks, "Forks");
                ui.selectable_value(&mut self.view, View::Detail, "Detail");
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            let snapshot = self.state.lock().unwrap().clone_snapshot();
            match self.view {
                View::Overview => render_overview(ui, &snapshot),
                View::Repos => {
                    if let Some(clicked) = render_repos(ui, &snapshot, self.selected_repo.as_deref()) {
                        self.select_repo(clicked);
                    }
                }
                View::Forks => render_forks(ui, &snapshot),
                View::Detail => render_detail(ui, &snapshot, self.selected_repo.as_deref()),
            }
        });
    }
}

/// Lightweight snapshot so we don't hold the mutex across rendering.
/// History is cloned too — it's ~150 small structs, cheap — so plot
/// rendering can run without blocking the poller.
#[derive(Default, Clone)]
struct StateSnapshot {
    repos: Vec<RepoSummary>,
    metrics: MetricsSnapshot,
    history: VecDeque<Sample>,
    detail: Option<RepoDetail>,
}
impl AppState {
    fn clone_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            repos: self.repos.clone(),
            metrics: self.metrics.clone(),
            history: self.history.clone(),
            detail: self.detail.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Views
// ─────────────────────────────────────────────────────────────────────

fn render_overview(ui: &mut egui::Ui, s: &StateSnapshot) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading("Overview");
        ui.add_space(8.0);

        // Current values table (unchanged).
        egui::Grid::new("overview_grid")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .show(ui, |ui| {
                ui.strong("Server version");
                ui.label(s.metrics.build_version.as_deref().unwrap_or("—"));
                ui.end_row();

                ui.strong("Total repos");
                ui.label(s.repos.len().to_string());
                ui.end_row();

                ui.strong("Requests served");
                ui.label(s.metrics.requests_total.to_string());
                ui.end_row();

                ui.strong("Rate-limited");
                ui.label(s.metrics.rate_limited_total.to_string());
                ui.end_row();

                ui.strong("Quota exceeded");
                ui.label(s.metrics.quota_exceeded_total.to_string());
                ui.end_row();
            });

        ui.add_space(16.0);
        ui.heading("Latency — last interval");
        ui.add_space(4.0);
        // Compute over the last two samples in the history. If fewer
        // than 2 samples yet, or the last interval had no requests,
        // we render "—" instead of stale cumulative values.
        let latest_pct = last_interval_percentiles(&s.history);
        egui::Grid::new("latency_grid")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .show(ui, |ui| {
                ui.strong("p50");
                ui.monospace(fmt_ms(latest_pct.0));
                ui.end_row();
                ui.strong("p95");
                ui.monospace(fmt_ms(latest_pct.1));
                ui.end_row();
                ui.strong("p99");
                ui.monospace(fmt_ms(latest_pct.2));
                ui.end_row();
            });

        ui.add_space(16.0);
        ui.label(
            egui::RichText::new(
                "Percentiles are over the last poll interval, not cumulative \
             since startup. If no requests happened in the last interval, \
             the value shows — (not the prior reading). Bucket granularity \
             is set by the 12 buckets in src/metrics.rs; tighten those if \
             you need sub-ms resolution.",
            )
            .color(egui::Color32::GRAY)
            .italics(),
        );

        ui.add_space(20.0);
        ui.separator();
        ui.add_space(10.0);
        ui.heading("Time series");
        ui.label(
            egui::RichText::new(format!(
                "Last {}s of polls, x-axis = seconds ago.",
                HISTORY_WINDOW_SECS
            ))
            .color(egui::Color32::GRAY)
            .italics(),
        );
        ui.add_space(6.0);

        render_request_rate_plot(ui, &s.history);
        ui.add_space(12.0);
        render_latency_plot(ui, &s.history);
        ui.add_space(12.0);
        render_errors_plot(ui, &s.history);
    });
}

/// Time-series: requests/sec derived from consecutive counter deltas.
/// We plot rate-between-samples rather than the raw counter, because
/// the counter grows unboundedly and the interesting signal is "is the
/// server active right now".
fn render_request_rate_plot(ui: &mut egui::Ui, history: &VecDeque<Sample>) {
    ui.label(egui::RichText::new("Requests / sec").strong());
    let points = rate_points(history, |m| m.requests_total);
    draw_plot(ui, "req_rate_plot", &[("req/s", &points)], /*y_log*/ false);
}

/// Time-series: p50, p95, p99 of the observations between each pair of
/// consecutive samples. The cumulative histogram only ever grows, so
/// "cumulative p99" is a flatline at max-ever-observed latency — what
/// the user observed in v1 of this chart. Interval-percentile matches
/// the Prometheus idiom `histogram_quantile(p, rate(..._bucket[1m]))`.
fn render_latency_plot(ui: &mut egui::Ui, history: &VecDeque<Sample>) {
    ui.label(egui::RichText::new("Latency percentiles (ms, per-interval)").strong());
    let p50 = interval_percentile_points(history, 0.50);
    let p95 = interval_percentile_points(history, 0.95);
    let p99 = interval_percentile_points(history, 0.99);
    draw_plot(
        ui,
        "latency_plot",
        &[("p50", &p50), ("p95", &p95), ("p99", &p99)],
        false,
    );
}

/// Build a time-series of interval percentiles across the history. For
/// each consecutive (prev, curr) pair, compute `percentile_between` —
/// plot point is `[-curr_age, percentile_ms]`. Intervals with zero
/// observations are skipped (no point emitted), so the line breaks
/// rather than misleading the reader with a flat value.
fn interval_percentile_points(
    history: &VecDeque<Sample>,
    p: f64,
) -> Vec<[f64; 2]> {
    if history.len() < 2 {
        return Vec::new();
    }
    let now = Instant::now();
    let mut out = Vec::with_capacity(history.len() - 1);
    let mut prev = &history[0];
    for s in history.iter().skip(1) {
        if let Some(v_secs) =
            percentile_between(&prev.metrics.latency_buckets, &s.metrics.latency_buckets, p)
        {
            let age = now.duration_since(s.at).as_secs_f64();
            // Convert s → ms for the chart.
            out.push([-age, v_secs * 1000.0]);
        }
        prev = s;
    }
    out
}

/// Rate-limit + quota-exceeded counters as rates over time. These are
/// usually zero; a non-zero line is something an operator cares about.
fn render_errors_plot(ui: &mut egui::Ui, history: &VecDeque<Sample>) {
    ui.label(egui::RichText::new("Rate-limited / quota-exceeded (per sec)").strong());
    let rl = rate_points(history, |m| m.rate_limited_total);
    let qe = rate_points(history, |m| m.quota_exceeded_total);
    draw_plot(
        ui,
        "errors_plot",
        &[("rate_limited", &rl), ("quota_exceeded", &qe)],
        false,
    );
}

/// Convert history into `[-age_secs, value]` points. x is negative so the
/// most-recent sample sits at x=0 and the oldest is on the left.
#[cfg(test)]
fn abs_points(
    history: &VecDeque<Sample>,
    f: impl Fn(&MetricsSnapshot) -> f64,
) -> Vec<[f64; 2]> {
    let now = Instant::now();
    history
        .iter()
        .map(|s| {
            let age = now.duration_since(s.at).as_secs_f64();
            [-age, f(&s.metrics)]
        })
        .collect()
}

/// p50/p95/p99 (ms) over the last poll interval. Returns `(None,...)`
/// if fewer than 2 samples, or if the interval had no observations.
fn last_interval_percentiles(history: &VecDeque<Sample>) -> (Option<f64>, Option<f64>, Option<f64>) {
    if history.len() < 2 {
        return (None, None, None);
    }
    let older = &history[history.len() - 2].metrics.latency_buckets;
    let newer = &history[history.len() - 1].metrics.latency_buckets;
    let ms = |p| percentile_between(older, newer, p).map(|s| s * 1000.0);
    (ms(0.50), ms(0.95), ms(0.99))
}

fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{:.2} ms", x),
        None => "—".to_string(),
    }
}

/// Convert history into per-second rate points by diffing consecutive
/// counters. First sample yields no rate, so the series starts one
/// sample later than the raw history.
fn rate_points(
    history: &VecDeque<Sample>,
    f: impl Fn(&MetricsSnapshot) -> u64,
) -> Vec<[f64; 2]> {
    if history.len() < 2 {
        return Vec::new();
    }
    let now = Instant::now();
    let mut out = Vec::with_capacity(history.len() - 1);
    let mut prev = &history[0];
    for s in history.iter().skip(1) {
        let dt = s.at.duration_since(prev.at).as_secs_f64();
        if dt > 0.0 {
            // i64 diff handles the rare case of a counter reset between polls
            // (server restart) without producing a wildly negative spike — we
            // clamp to 0 on the way down.
            let delta = f(&s.metrics) as i64 - f(&prev.metrics) as i64;
            let rate = (delta.max(0) as f64) / dt;
            let age = now.duration_since(s.at).as_secs_f64();
            out.push([-age, rate]);
        }
        prev = s;
    }
    out
}

fn draw_plot(
    ui: &mut egui::Ui,
    id: &str,
    series: &[(&str, &Vec<[f64; 2]>)],
    _y_log: bool,
) {
    let any_data = series.iter().any(|(_, v)| !v.is_empty());
    if !any_data {
        ui.label(
            egui::RichText::new("(collecting samples…)")
                .color(egui::Color32::GRAY)
                .italics(),
        );
        return;
    }
    Plot::new(id)
        .height(120.0)
        .allow_zoom(false)
        .allow_drag(false)
        .allow_scroll(false)
        .show_axes([true, true])
        .include_x(-(HISTORY_WINDOW_SECS as f64))
        .include_x(0.0)
        .include_y(0.0)
        .show(ui, |plot_ui| {
            for (name, pts) in series {
                let line = Line::new(PlotPoints::from((*pts).clone())).name(*name);
                plot_ui.line(line);
            }
        });
}

/// Return `Some(repo_id)` if the user clicked a row, else `None`.
fn render_repos(ui: &mut egui::Ui, s: &StateSnapshot, selected: Option<&str>) -> Option<String> {
    ui.heading(format!("Repos ({})", s.repos.len()));
    ui.label(
        egui::RichText::new("Click a row to see refs, size on disk, and fork source.")
            .color(egui::Color32::GRAY)
            .italics(),
    );
    ui.add_space(4.0);

    let mut clicked: Option<String> = None;
    egui::ScrollArea::both().show(ui, |ui| {
        egui::Grid::new("repos_grid")
            .striped(true)
            .num_columns(4)
            .spacing([16.0, 2.0])
            .show(ui, |ui| {
                ui.strong("id");
                ui.strong("owner");
                ui.strong("created");
                ui.strong("source");
                ui.end_row();
                for r in &s.repos {
                    let is_selected = selected.map(|x| x == r.id).unwrap_or(false);
                    // Make the id cell act as a selectable label. Cheap
                    // click target — the whole row is visually highlighted
                    // via selection state on the first cell.
                    if ui.selectable_label(is_selected, egui::RichText::new(&r.id).monospace()).clicked() {
                        clicked = Some(r.id.clone());
                    }
                    ui.label(r.owner.as_deref().unwrap_or("<admin>"));
                    ui.label(format_age(r.created_at));
                    ui.monospace(r.source_id.as_deref().unwrap_or("—"));
                    ui.end_row();
                }
            });
    });
    clicked
}

fn render_detail(ui: &mut egui::Ui, s: &StateSnapshot, selected: Option<&str>) {
    match (selected, s.detail.as_ref()) {
        (None, _) => {
            ui.heading("Detail");
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("No repo selected. Click one on the Repos tab, or a node in the Forks graph.")
                    .color(egui::Color32::GRAY)
                    .italics(),
            );
        }
        (Some(id), None) => {
            ui.heading("Detail");
            ui.add_space(8.0);
            ui.label(format!("Loading detail for {id}…"));
        }
        (Some(_id), Some(d)) => render_detail_body(ui, d),
    }
}

fn render_detail_body(ui: &mut egui::Ui, d: &RepoDetail) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.heading("Detail");
        ui.add_space(8.0);
        egui::Grid::new("detail_grid")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .show(ui, |ui| {
                ui.strong("id");
                ui.monospace(&d.id);
                ui.end_row();

                ui.strong("owner");
                ui.label(d.owner.as_deref().unwrap_or("<admin>"));
                ui.end_row();

                ui.strong("created");
                ui.label(format!(
                    "{} ({} unix)",
                    format_age(d.created_at),
                    d.created_at
                ));
                ui.end_row();

                ui.strong("fork of");
                match &d.source_id {
                    Some(src) => {
                        ui.monospace(src);
                    }
                    None => {
                        ui.label("— (root)");
                    }
                }
                ui.end_row();

                ui.strong("size on disk");
                ui.label(format_bytes(d.size_bytes));
                ui.end_row();

                ui.strong("refs");
                ui.label(format!("{} total", d.refs.len()));
                ui.end_row();
            });

        ui.add_space(16.0);
        ui.separator();
        ui.heading("Refs");
        if d.refs.is_empty() {
            ui.label(
                egui::RichText::new("(no refs — empty repo)")
                    .color(egui::Color32::GRAY)
                    .italics(),
            );
        } else {
            egui::Grid::new("refs_grid")
                .striped(true)
                .num_columns(2)
                .spacing([24.0, 2.0])
                .show(ui, |ui| {
                    ui.strong("name");
                    ui.strong("sha");
                    ui.end_row();
                    for r in &d.refs {
                        ui.label(&r.name);
                        // Show a short prefix of the SHA for scannability;
                        // full sha on hover via tooltip.
                        let short: String = r.sha.chars().take(10).collect();
                        ui.monospace(short).on_hover_text(&r.sha);
                        ui.end_row();
                    }
                });
        }
    });
}

/// Humanize byte counts: 123 → "123 B", 1500 → "1.5 KB", etc.
fn format_bytes(n: u64) -> String {
    const UNITS: &[(&str, u64)] = &[
        ("GB", 1024 * 1024 * 1024),
        ("MB", 1024 * 1024),
        ("KB", 1024),
    ];
    for (unit, size) in UNITS {
        if n >= *size {
            return format!("{:.2} {}", n as f64 / *size as f64, unit);
        }
    }
    format!("{} B", n)
}

fn render_forks(ui: &mut egui::Ui, s: &StateSnapshot) {
    ui.heading("Fork network");
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new(
            "Roots (repos created from scratch) at the top; their forks \
             nested underneath via the alternates file.",
        )
        .color(egui::Color32::GRAY)
        .italics(),
    );
    ui.add_space(8.0);

    // Build parent → children map.
    let mut children: HashMap<String, Vec<&RepoSummary>> = HashMap::new();
    let mut roots: Vec<&RepoSummary> = Vec::new();
    for r in &s.repos {
        match &r.source_id {
            Some(parent) => children.entry(parent.clone()).or_default().push(r),
            None => roots.push(r),
        }
    }
    // Repos whose declared source isn't in the list either (partial data,
    // parent was deleted, etc.) get promoted to pseudo-roots so they stay
    // visible.
    let ids: std::collections::HashSet<&str> =
        s.repos.iter().map(|r| r.id.as_str()).collect();
    let mut orphans: Vec<&RepoSummary> = Vec::new();
    for r in &s.repos {
        if let Some(p) = &r.source_id {
            if !ids.contains(p.as_str()) {
                orphans.push(r);
            }
        }
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        for root in &roots {
            render_tree_node(ui, root, &children, 0);
        }
        if !orphans.is_empty() {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("Orphan forks (parent unknown):")
                    .color(egui::Color32::from_rgb(200, 160, 40)),
            );
            for o in orphans {
                render_tree_node(ui, o, &children, 0);
            }
        }
    });
}

fn render_tree_node(
    ui: &mut egui::Ui,
    r: &RepoSummary,
    children: &HashMap<String, Vec<&RepoSummary>>,
    depth: usize,
) {
    ui.horizontal(|ui| {
        ui.add_space(depth as f32 * 20.0);
        ui.monospace(&r.id);
        ui.label(format!("· {}", r.owner.as_deref().unwrap_or("<admin>")));
        ui.label(
            egui::RichText::new(format_age(r.created_at)).color(egui::Color32::GRAY),
        );
    });
    if let Some(kids) = children.get(&r.id) {
        for k in kids {
            render_tree_node(ui, k, children, depth + 1);
        }
    }
}

fn format_age(epoch: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let age = now.saturating_sub(epoch);
    match age {
        s if s < 60 => format!("{}s ago", s),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    let state = Arc::new(Mutex::new(AppState::default()));
    let selected_for_detail: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    spawn_poller(
        cli.clone(),
        Arc::clone(&state),
        Arc::clone(&selected_for_detail),
    );

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 680.0])
            .with_title("artifacts-gui"),
        ..Default::default()
    };

    let app = App {
        cli,
        state,
        view: View::Overview,
        selected_repo: None,
        selected_for_detail,
    };
    eframe::run_native(
        "artifacts-gui",
        options,
        Box::new(|_cc| Box::new(app)),
    )
    .map_err(|e| anyhow!("eframe: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_metrics_extracts_counters_and_buckets() {
        let text = "\
# TYPE artifacts_rate_limited_total counter
artifacts_rate_limited_total 7
# TYPE artifacts_quota_exceeded_total counter
artifacts_quota_exceeded_total 2
# TYPE artifacts_requests_total counter
artifacts_requests_total{method=\"GET\",path=\"/v1/health\",status=\"200\"} 10
artifacts_requests_total{method=\"POST\",path=\"/v1/repos\",status=\"401\"} 5
# TYPE artifacts_request_duration_seconds histogram
artifacts_request_duration_seconds_bucket{method=\"GET\",path=\"/v1/health\",le=\"0.001\"} 10
artifacts_request_duration_seconds_bucket{method=\"GET\",path=\"/v1/health\",le=\"0.01\"} 10
artifacts_request_duration_seconds_bucket{method=\"GET\",path=\"/v1/health\",le=\"+Inf\"} 10
# TYPE artifacts_build_info gauge
artifacts_build_info{version=\"0.0.1\"} 1
";
        let m = parse_metrics(text);
        assert_eq!(m.rate_limited_total, 7);
        assert_eq!(m.quota_exceeded_total, 2);
        assert_eq!(m.requests_total, 15);
        assert_eq!(m.build_version.as_deref(), Some("0.0.1"));
        // Buckets are stored raw now. 10 at 0.001, 10 at 0.01, 10 at +Inf.
        assert_eq!(m.latency_buckets.get(&OrdF64(0.001)).copied(), Some(10));
        assert_eq!(m.latency_buckets.get(&OrdF64(0.01)).copied(), Some(10));
        assert_eq!(m.latency_buckets.get(&OrdF64(f64::INFINITY)).copied(), Some(10));
    }

    fn buckets(pairs: &[(f64, u64)]) -> BTreeMap<OrdF64, u64> {
        pairs.iter().map(|(k, v)| (OrdF64(*k), *v)).collect()
    }

    #[test]
    fn percentile_between_returns_none_when_interval_empty() {
        // Same cumulative count on both sides → no new observations.
        let a = buckets(&[(0.001, 10), (0.01, 10), (f64::INFINITY, 10)]);
        let b = buckets(&[(0.001, 10), (0.01, 10), (f64::INFINITY, 10)]);
        assert_eq!(percentile_between(&a, &b, 0.50), None);
        assert_eq!(percentile_between(&a, &b, 0.99), None);
    }

    #[test]
    fn percentile_between_finds_bucket_from_delta() {
        // older: 10 observations all at ≤1ms.
        // newer: 10 more observations, but at ≤10ms. Interval delta =
        // 10 observations at the 0.01 bucket → any percentile should
        // land at 0.01.
        let older = buckets(&[(0.001, 10), (0.01, 10), (f64::INFINITY, 10)]);
        let newer = buckets(&[(0.001, 10), (0.01, 20), (f64::INFINITY, 20)]);
        assert_eq!(percentile_between(&older, &newer, 0.50), Some(0.01));
        assert_eq!(percentile_between(&older, &newer, 0.99), Some(0.01));
    }

    #[test]
    fn percentile_between_gives_different_answers_for_different_p() {
        // Interval adds: 90 fast (≤1ms) + 10 slow (>1ms, ≤10ms).
        // p50 should land at the fast bucket (0.001s).
        // p95 should land at the slow bucket (0.01s).
        let older = buckets(&[(0.001, 0), (0.01, 0), (f64::INFINITY, 0)]);
        let newer = buckets(&[(0.001, 90), (0.01, 100), (f64::INFINITY, 100)]);
        assert_eq!(percentile_between(&older, &newer, 0.50), Some(0.001));
        assert_eq!(percentile_between(&older, &newer, 0.95), Some(0.01));
    }

    #[test]
    fn last_interval_percentiles_returns_none_with_too_few_samples() {
        let mut h: VecDeque<Sample> = VecDeque::new();
        assert_eq!(last_interval_percentiles(&h), (None, None, None));
        h.push_back(make_sample(0.0, mk_metrics(0)));
        assert_eq!(last_interval_percentiles(&h), (None, None, None));
    }

    #[test]
    fn last_interval_percentiles_uses_only_the_last_pair() {
        let mut h: VecDeque<Sample> = VecDeque::new();
        // Three samples; the last interval only saw slow observations.
        // An older interval had fast observations, but those must NOT
        // influence the "last interval" values.
        h.push_back(Sample {
            at: Instant::now().checked_sub(Duration::from_secs(4)).unwrap_or_else(Instant::now),
            metrics: MetricsSnapshot {
                latency_buckets: buckets(&[(0.001, 0), (0.01, 0), (f64::INFINITY, 0)]),
                ..Default::default()
            },
        });
        h.push_back(Sample {
            at: Instant::now().checked_sub(Duration::from_secs(2)).unwrap_or_else(Instant::now),
            metrics: MetricsSnapshot {
                latency_buckets: buckets(&[(0.001, 50), (0.01, 50), (f64::INFINITY, 50)]),
                ..Default::default()
            },
        });
        h.push_back(Sample {
            at: Instant::now(),
            metrics: MetricsSnapshot {
                latency_buckets: buckets(&[(0.001, 50), (0.01, 60), (f64::INFINITY, 60)]),
                ..Default::default()
            },
        });
        let (p50, _p95, _p99) = last_interval_percentiles(&h);
        // The last interval added 10 observations, all in the 0.01 bucket.
        assert_eq!(p50, Some(10.0)); // 10 ms
    }

    #[test]
    fn extract_le_handles_plus_inf() {
        let s = "foo_bucket{le=\"+Inf\"} 42";
        assert!(extract_le(s).unwrap().is_infinite());
    }

    fn make_sample(ago_secs: f64, metrics: MetricsSnapshot) -> Sample {
        // Slight trick: we build the Sample with a backdated Instant so the
        // test is time-deterministic. Using checked_sub so tests don't
        // panic on boxes where `Instant` is clamped (shouldn't happen on
        // Linux, but cheap safety).
        let at = Instant::now()
            .checked_sub(Duration::from_secs_f64(ago_secs))
            .unwrap_or_else(Instant::now);
        Sample { at, metrics }
    }

    fn mk_metrics(requests_total: u64) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total,
            ..Default::default()
        }
    }

    #[test]
    fn rate_points_empty_or_single_yields_nothing() {
        let mut h: VecDeque<Sample> = VecDeque::new();
        assert!(rate_points(&h, |m| m.requests_total).is_empty());
        h.push_back(make_sample(0.0, mk_metrics(0)));
        assert!(rate_points(&h, |m| m.requests_total).is_empty());
    }

    #[test]
    fn rate_points_computes_delta_per_second() {
        // Two samples 2s apart, counter delta = 20 → expect 10 req/s.
        let mut h: VecDeque<Sample> = VecDeque::new();
        h.push_back(make_sample(2.0, mk_metrics(100)));
        h.push_back(make_sample(0.0, mk_metrics(120)));
        let pts = rate_points(&h, |m| m.requests_total);
        assert_eq!(pts.len(), 1);
        // y is rate; allow small float wobble from Instant::now() drift.
        assert!((pts[0][1] - 10.0).abs() < 0.1, "got rate {:?}", pts[0][1]);
    }

    #[test]
    fn rate_points_clamps_to_zero_on_counter_reset() {
        // Second sample's counter is *smaller* than first — would happen
        // across a server restart. The naive `a - b` would go wildly
        // negative; we clamp to 0.
        let mut h: VecDeque<Sample> = VecDeque::new();
        h.push_back(make_sample(2.0, mk_metrics(100)));
        h.push_back(make_sample(0.0, mk_metrics(5)));
        let pts = rate_points(&h, |m| m.requests_total);
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0][1], 0.0);
    }

    #[test]
    fn abs_points_keeps_raw_values_in_x_negative_order() {
        // abs_points emits [-age, value] — older samples get more-negative x.
        let mut h: VecDeque<Sample> = VecDeque::new();
        h.push_back(make_sample(10.0, mk_metrics(1)));
        h.push_back(make_sample(5.0, mk_metrics(2)));
        h.push_back(make_sample(0.0, mk_metrics(3)));
        let pts = abs_points(&h, |m| m.requests_total as f64);
        assert_eq!(pts.len(), 3);
        assert!(pts[0][0] < pts[1][0]);
        assert!(pts[1][0] < pts[2][0]);
        assert!(pts[0][0] < 0.0);
        // y values untouched
        assert_eq!(pts[0][1], 1.0);
        assert_eq!(pts[2][1], 3.0);
    }

    #[test]
    fn format_bytes_rolls_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        // Just below the MB threshold.
        assert_eq!(format_bytes(1024 * 1024 - 1), "1024.00 KB");
    }

    #[test]
    fn format_age_rolls_units() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        assert!(format_age(now - 5).ends_with("s ago"));
        assert!(format_age(now - 120).ends_with("m ago"));
        assert!(format_age(now - 7200).ends_with("h ago"));
        assert!(format_age(now - 172800).ends_with("d ago"));
    }
}
