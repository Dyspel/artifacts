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
use std::collections::{BTreeMap, HashMap};
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

#[derive(Default)]
struct AppState {
    repos: Vec<RepoSummary>,
    metrics: MetricsSnapshot,
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
                let mut s = state.lock().expect("state mutex poisoned");
                s.repos = repos;
                s.metrics = metrics;
                s.last_poll = Some(Instant::now());
                s.last_error = None;
                s.poll_count += 1;
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
#[derive(Default, Clone)]
struct StateSnapshot {
    repos: Vec<RepoSummary>,
    metrics: MetricsSnapshot,
}
impl AppState {
    fn clone_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            repos: self.repos.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Views
// ─────────────────────────────────────────────────────────────────────

fn render_overview(ui: &mut egui::Ui, s: &StateSnapshot) {
    ui.heading("Overview");
    ui.add_space(8.0);

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
    ui.label(egui::RichText::new(
        "Percentiles are bucket-approximations — upper-edge of the first \
         bucket at or above the target fraction. For sub-ms accuracy, \
         tighten the bucket set in src/metrics.rs."
    ).color(egui::Color32::GRAY).italics());
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

    #[test]
    fn format_age_rolls_units() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        assert!(format_age(now - 5).ends_with("s ago"));
        assert!(format_age(now - 120).ends_with("m ago"));
        assert!(format_age(now - 7200).ends_with("h ago"));
        assert!(format_age(now - 172800).ends_with("d ago"));
    }
}
