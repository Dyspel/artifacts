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

#[derive(Default, Clone)]
struct MetricsSnapshot {
    requests_total: u64,
    rate_limited_total: u64,
    quota_exceeded_total: u64,
    latency_p50_ms: f64,
    latency_p95_ms: f64,
    latency_p99_ms: f64,
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

fn spawn_poller(cli: Cli, state: Arc<Mutex<AppState>>) {
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
            }
            Err(e) => {
                let mut s = state.lock().expect("state mutex poisoned");
                s.last_error = Some(format!("{e:#}"));
            }
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
    // Accumulate histogram buckets across all label series. For a
    // prometheus cumulative histogram, sum-of-cumulative-counts at
    // each `le` across series gives the overall cumulative count — so
    // computing percentiles from the aggregate is mathematically
    // correct (not a "sum of percentiles" fallacy).
    let mut bucket_agg: BTreeMap<OrdF64, u64> = BTreeMap::new();

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
            // Sum over all label series → total served.
            out.requests_total += last_number(line).unwrap_or(0.0) as u64;
        } else if line.starts_with("artifacts_request_duration_seconds_bucket{") {
            if let (Some(le), Some(count)) = (extract_le(line), last_number(line)) {
                *bucket_agg.entry(OrdF64(le)).or_insert(0) += count as u64;
            }
        } else if line.starts_with("artifacts_build_info{") {
            out.build_version = extract_label(line, "version");
        }
    }

    // Compute percentiles from the aggregate histogram.
    if let Some(&total) = bucket_agg.get(&OrdF64(f64::INFINITY)) {
        if total > 0 {
            let targets = [(0.50, &mut out.latency_p50_ms),
                           (0.95, &mut out.latency_p95_ms),
                           (0.99, &mut out.latency_p99_ms)];
            for (p, slot) in targets {
                let need = (total as f64 * p).ceil() as u64;
                for (le, cum) in &bucket_agg {
                    if *cum >= need {
                        *slot = le.0 * 1000.0; // seconds → ms
                        break;
                    }
                }
            }
        }
    }
    out
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
}

struct App {
    cli: Cli,
    state: Arc<Mutex<AppState>>,
    view: View,
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
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            let snapshot = self.state.lock().unwrap().clone_snapshot();
            match self.view {
                View::Overview => render_overview(ui, &snapshot),
                View::Repos => render_repos(ui, &snapshot),
                View::Forks => render_forks(ui, &snapshot),
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
}
impl AppState {
    fn clone_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            repos: self.repos.clone(),
            metrics: self.metrics.clone(),
            history: self.history.clone(),
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
        ui.heading("Latency (aggregate across endpoints)");
        ui.add_space(4.0);
        egui::Grid::new("latency_grid")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .show(ui, |ui| {
                ui.strong("p50");
                ui.monospace(format!("{:.2} ms", s.metrics.latency_p50_ms));
                ui.end_row();
                ui.strong("p95");
                ui.monospace(format!("{:.2} ms", s.metrics.latency_p95_ms));
                ui.end_row();
                ui.strong("p99");
                ui.monospace(format!("{:.2} ms", s.metrics.latency_p99_ms));
                ui.end_row();
            });

        ui.add_space(16.0);
        ui.label(
            egui::RichText::new(
                "Percentiles are bucket-approximations — upper-edge of the first \
             bucket at or above the target fraction. For sub-ms accuracy, \
             tighten the bucket set in src/metrics.rs.",
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

/// Time-series: p50, p95, p99 over time. Raw values from each sample —
/// already a per-poll snapshot, no rate math needed.
fn render_latency_plot(ui: &mut egui::Ui, history: &VecDeque<Sample>) {
    ui.label(egui::RichText::new("Latency percentiles (ms)").strong());
    let p50: Vec<[f64; 2]> = abs_points(history, |m| m.latency_p50_ms);
    let p95: Vec<[f64; 2]> = abs_points(history, |m| m.latency_p95_ms);
    let p99: Vec<[f64; 2]> = abs_points(history, |m| m.latency_p99_ms);
    draw_plot(
        ui,
        "latency_plot",
        &[("p50", &p50), ("p95", &p95), ("p99", &p99)],
        false,
    );
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

fn render_repos(ui: &mut egui::Ui, s: &StateSnapshot) {
    ui.heading(format!("Repos ({})", s.repos.len()));
    ui.add_space(4.0);

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
                    ui.monospace(&r.id);
                    ui.label(r.owner.as_deref().unwrap_or("<admin>"));
                    ui.label(format_age(r.created_at));
                    ui.monospace(r.source_id.as_deref().unwrap_or("—"));
                    ui.end_row();
                }
            });
    });
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
    spawn_poller(cli.clone(), Arc::clone(&state));

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
    fn parse_metrics_extracts_counters_and_percentiles() {
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
        // All 10 observations fall at or below the 0.001 bucket, so p50,
        // p95, p99 should all land at 1 ms.
        assert!((m.latency_p50_ms - 1.0).abs() < 1e-6);
        assert!((m.latency_p95_ms - 1.0).abs() < 1e-6);
        assert!((m.latency_p99_ms - 1.0).abs() < 1e-6);
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
    fn format_age_rolls_units() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        assert!(format_age(now - 5).ends_with("s ago"));
        assert!(format_age(now - 120).ends_with("m ago"));
        assert!(format_age(now - 7200).ends_with("h ago"));
        assert!(format_age(now - 172800).ends_with("d ago"));
    }
}
