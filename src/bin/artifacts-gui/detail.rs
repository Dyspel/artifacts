//! Detail tab: everything we know about one repo, from the server's
//! `GET /v1/admin/repos/:id` response. Also owns `format_bytes` since
//! it's the only view that needs it.

use crate::state::{RepoDetail, StateSnapshot};
use crate::util::format_age;
use eframe::egui;

pub(crate) fn render_detail(ui: &mut egui::Ui, s: &StateSnapshot, selected: Option<&str>) {
    match (selected, s.detail.as_ref()) {
        (None, _) => {
            ui.heading("Detail");
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(
                    "No repo selected. Click one on the Repos tab, or a node in the Forks graph.",
                )
                .color(egui::Color32::GRAY)
                .italics(),
            );
        },
        (Some(id), None) => {
            ui.heading("Detail");
            ui.add_space(8.0);
            ui.label(format!("Loading detail for {id}…"));
        },
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
                    },
                    None => {
                        ui.label("— (root)");
                    },
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
pub(crate) fn format_bytes(n: u64) -> String {
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
    format!("{n} B")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_rolls_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(1024 * 1024 - 1), "1024.00 KB");
    }
}
