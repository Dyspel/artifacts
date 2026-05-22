//! Overview tab: single-value tables + time-series charts.
//!
//! All three charts share `draw_plot`, which gates on "(collecting
//! samples…)" when nothing is plottable yet. X axis is seconds-ago;
//! y starts at 0 so quiet idle stays visible at the baseline rather
//! than auto-ranging and rescaling every frame.

use crate::metrics::{fmt_ms, interval_percentile_points, last_interval_percentiles, rate_points};
use crate::state::{Sample, StateSnapshot, HISTORY_WINDOW_SECS};
use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use std::collections::VecDeque;

pub(crate) fn render_overview(ui: &mut egui::Ui, s: &StateSnapshot) {
    egui::ScrollArea::vertical().show(ui, |ui| {
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
        ui.heading("Latency — last interval");
        ui.add_space(4.0);
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
                "Last {HISTORY_WINDOW_SECS}s of polls, x-axis = seconds ago."
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
    draw_plot(ui, "req_rate_plot", &[("req/s", &points)]);
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
    );
}

fn draw_plot(ui: &mut egui::Ui, id: &str, series: &[(&str, &Vec<[f64; 2]>)]) {
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
