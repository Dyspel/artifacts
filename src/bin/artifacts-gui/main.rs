//! artifacts-gui — live structural view of an Artifacts server.
//!
//! Connects to an Artifacts instance over HTTP (admin-token auth), polls
//! `/v1/admin/repos` + `/metrics` every few seconds, and renders four
//! views with eframe/egui:
//!
//!   Overview — request rate, aggregate latency percentiles, and the
//!              rate-limit / quota counters.
//!   Repos    — sortable table of every known repo with id, owner,
//!              created-at, and source (for forks).
//!   Forks    — graphical node/edge view of the fork network.
//!   Detail   — full server-sourced detail for the selected repo.
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
//!
//! Code is split by concern across sibling modules — `state` owns the
//! shared types, `polling` the background thread, `metrics` the
//! Prometheus-text parser, and one module per tab under the same name.
//! This file wires them together: the `App` struct, the eframe loop,
//! and the process entry point.

mod detail;
mod forks;
mod metrics;
mod overview;
mod polling;
mod repos;
mod state;
mod util;

use anyhow::{anyhow, Result};
use clap::Parser;
use eframe::egui;
use polling::{lock_state, spawn_poller};
use state::AppState;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Parser, Clone)]
#[command(name = "artifacts-gui", about = "Live view of an Artifacts server")]
pub(crate) struct Cli {
    /// Base URL of the Artifacts server (not including /v1).
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    pub(crate) url: String,

    /// Admin token (matches ARTIFACTS_ADMIN_TOKEN on the server). Env
    /// override keeps the token out of shell history.
    #[arg(long, env = "ARTIFACTS_ADMIN_TOKEN")]
    pub(crate) admin_token: String,

    /// Seconds between successive polls. Lower = fresher UI, higher load
    /// on the server. Default 2s is fine up to a few hundred repos.
    #[arg(long, default_value_t = 2.0)]
    pub(crate) poll_interval_secs: f64,
}

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
    /// Pan+zoom for the Forks graph view. Stored on App so they
    /// persist across frames and between tab switches.
    graph_pan: egui::Vec2,
    graph_zoom: f32,
}

impl App {
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
                let s = lock_state(&self.state);
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
            // Snapshot once per frame so render code doesn't hold the
            // poller's mutex while walking view code.
            let snapshot = lock_state(&self.state).clone_snapshot();
            match self.view {
                View::Overview => overview::render_overview(ui, &snapshot),
                View::Repos => {
                    if let Some(clicked) =
                        repos::render_repos(ui, &snapshot, self.selected_repo.as_deref())
                    {
                        self.select_repo(clicked);
                    }
                }
                View::Forks => {
                    if let Some(clicked) = forks::render_forks(
                        ui,
                        &snapshot,
                        self.selected_repo.as_deref(),
                        &mut self.graph_pan,
                        &mut self.graph_zoom,
                    ) {
                        self.select_repo(clicked);
                    }
                }
                View::Detail => {
                    detail::render_detail(ui, &snapshot, self.selected_repo.as_deref())
                }
            }
        });
    }
}

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
        graph_pan: egui::Vec2::ZERO,
        graph_zoom: 1.0,
    };
    eframe::run_native("artifacts-gui", options, Box::new(|_cc| Box::new(app)))
        .map_err(|e| anyhow!("eframe: {e}"))?;

    Ok(())
}
