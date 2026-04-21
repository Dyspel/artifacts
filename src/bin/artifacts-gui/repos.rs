//! Repos tab: scrollable four-column table. Clicking a row returns
//! that repo's id to the caller so the Detail tab can populate.

use crate::state::StateSnapshot;
use crate::util::format_age;
use eframe::egui;

/// Return `Some(repo_id)` if the user clicked a row, else `None`.
pub(crate) fn render_repos(
    ui: &mut egui::Ui,
    s: &StateSnapshot,
    selected: Option<&str>,
) -> Option<String> {
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
                    if ui
                        .selectable_label(is_selected, egui::RichText::new(&r.id).monospace())
                        .clicked()
                    {
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
