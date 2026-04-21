//! Forks tab: graphical fork-network. Nodes + edges rendered on a
//! panner/zoomer canvas; click selects a repo.
//!
//! Layout is a classic tree layout (post-order, leaves get consecutive
//! x, parents center over children). Pure functions here; the caller
//! (`main::App`) owns the persistent pan/zoom state and a layout cache.
//!
//! The layout depends only on `(id, source_id)` pairs, which change at
//! most once per poll (every ~2s). Recomputing every frame means ~60
//! Hz of tree-walking + HashMap inserts during drag/zoom, which at
//! 1000+ repos shows up as dropped frames. `ForkLayoutCache` keeps the
//! last `positions` + ids-set behind an order-invariant fingerprint so
//! we only rebuild when the repo list actually changes.

use crate::state::{RepoSummary, StateSnapshot};
use eframe::egui;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

/// Cached, layout-frozen view of the repo list. Owned by `App`,
/// updated in place at the top of `render_forks`.
#[derive(Default)]
pub(crate) struct ForkLayoutCache {
    /// Order-invariant hash of (id, source_id) pairs. When this matches
    /// the current snapshot we skip the rebuild.
    fingerprint: u64,
    positions: HashMap<String, (f64, f64)>,
    ids: HashSet<String>,
    max_x: f64,
    max_depth: f64,
}

impl ForkLayoutCache {
    /// Rebuild the cache from `repos` if the fingerprint changed.
    /// No-op otherwise — which is the 99% case between polls.
    fn refresh(&mut self, repos: &[RepoSummary]) {
        let fp = fingerprint(repos);
        // The first-frame-with-data case: the default cache has
        // `fingerprint=0` and an empty `positions`. A real repo list's
        // fingerprint could collide with zero, so additionally require
        // that we've populated at least once (or that the input is
        // itself empty — then no rebuild is needed regardless).
        let populated = !self.positions.is_empty() || repos.is_empty();
        if fp == self.fingerprint && populated {
            return;
        }

        self.positions.clear();
        self.ids.clear();
        self.max_x = 0.0;
        self.max_depth = 0.0;
        self.fingerprint = fp;

        if repos.is_empty() {
            return;
        }

        for r in repos {
            self.ids.insert(r.id.clone());
        }

        let mut children: HashMap<String, Vec<&RepoSummary>> = HashMap::new();
        let mut roots: Vec<&RepoSummary> = Vec::new();
        for r in repos {
            match &r.source_id {
                Some(parent) if self.ids.contains(parent.as_str()) => {
                    children.entry(parent.clone()).or_default().push(r);
                }
                Some(_) | None => roots.push(r),
            }
        }
        // Stable sort so layout doesn't jitter when the server returns
        // rows in a different order between polls.
        for kids in children.values_mut() {
            kids.sort_by(|a, b| a.id.cmp(&b.id));
        }
        roots.sort_by(|a, b| a.id.cmp(&b.id));

        let mut next_x: f64 = 0.0;
        for root in &roots {
            layout_subtree(root, &children, 0, &mut next_x, &mut self.positions);
            next_x += 1.5;
        }
        self.max_depth = self
            .positions
            .values()
            .map(|(_, y)| *y)
            .fold(0.0_f64, f64::max);
        self.max_x = self
            .positions
            .values()
            .map(|(x, _)| *x)
            .fold(0.0_f64, f64::max);
    }
}

/// Order-invariant hash over `(id, source_id)` pairs. XOR folding so
/// the same hash comes out no matter which order the server returns
/// rows. O(n), no allocation.
fn fingerprint(repos: &[RepoSummary]) -> u64 {
    let mut fp = repos.len() as u64;
    for r in repos {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        r.id.hash(&mut h);
        r.source_id.hash(&mut h);
        fp ^= h.finish();
    }
    fp
}

/// Graphical fork-network. Returns `Some(id)` if the user clicked a node.
pub(crate) fn render_forks(
    ui: &mut egui::Ui,
    s: &StateSnapshot,
    selected: Option<&str>,
    pan: &mut egui::Vec2,
    zoom: &mut f32,
    cache: &mut ForkLayoutCache,
) -> Option<String> {
    ui.heading("Fork network");
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("Drag to pan · scroll to zoom · click a node.")
                .color(egui::Color32::GRAY)
                .italics(),
        );
        if ui.small_button("fit").clicked() {
            *pan = egui::Vec2::ZERO;
            *zoom = 1.0;
        }
    });
    ui.add_space(8.0);

    if s.repos.is_empty() {
        ui.label(
            egui::RichText::new("(no repos yet)")
                .color(egui::Color32::GRAY)
                .italics(),
        );
        return None;
    }

    // Rebuild only if the repo list actually changed. The cache carries
    // `positions`, the ids-set (for orphan detection), and max extents.
    cache.refresh(&s.repos);
    let positions = &cache.positions;
    let ids = &cache.ids;
    let max_x = cache.max_x;
    let max_depth = cache.max_depth;

    // Reserve the rest of the central panel for the graph canvas.
    let (response, painter) =
        ui.allocate_painter(ui.available_size(), egui::Sense::click_and_drag());
    let rect = response.rect;

    // Pan via drag.
    if response.dragged() {
        *pan += response.drag_delta();
    }
    // Zoom via scroll when the cursor is over the canvas. Centered on the
    // cursor so the node you're aiming at stays put as you zoom.
    if response.hovered() {
        let scroll = ui.input(|i| i.raw_scroll_delta.y);
        if scroll != 0.0 {
            let factor = (scroll * 0.005).exp();
            let new_zoom = (*zoom * factor).clamp(0.25, 4.0);
            if let Some(pointer) = response.hover_pos() {
                let rel = pointer - rect.center() - *pan;
                *pan = (rel - rel * (new_zoom / *zoom)) + *pan;
            }
            *zoom = new_zoom;
        }
    }

    // Grid → pixel transform. Scale grid coordinates to fit roughly the
    // available space at zoom=1.0, centered. Everything below is f32; the
    // layout returns f64 but we cast once here.
    let x_span = (max_x as f32).max(1.0);
    let y_span = (max_depth as f32).max(1.0);
    let cell_w = (rect.width() / (x_span + 2.0)).clamp(60.0, 220.0);
    let cell_h = (rect.height() / (y_span + 2.0)).clamp(50.0, 120.0);
    let base_origin = egui::pos2(rect.left() + cell_w * 0.5, rect.top() + cell_h * 0.5);
    let to_px = |(x, y): (f64, f64)| -> egui::Pos2 {
        base_origin + egui::vec2(x as f32 * cell_w, y as f32 * cell_h) * *zoom + *pan
    };

    // Edges — draw first so nodes render on top.
    let edge_color = egui::Color32::from_gray(120);
    for r in &s.repos {
        let Some(parent) = &r.source_id else { continue };
        let (Some(child_pos), Some(parent_pos)) = (positions.get(&r.id), positions.get(parent))
        else {
            continue;
        };
        let from = to_px(*parent_pos);
        let to = to_px(*child_pos);
        painter.line_segment([from, to], egui::Stroke::new(1.5, edge_color));
    }

    // Nodes. Store pixel rects so we can hit-test on click.
    let node_w = 150.0_f32 * *zoom;
    let node_h = 36.0_f32 * *zoom;
    let mut node_rects: Vec<(String, egui::Rect)> = Vec::with_capacity(s.repos.len());
    for r in &s.repos {
        let Some(pos) = positions.get(&r.id) else {
            continue;
        };
        let center = to_px(*pos);
        let rect = egui::Rect::from_center_size(center, egui::vec2(node_w, node_h));
        node_rects.push((r.id.clone(), rect));

        let is_selected = selected.map(|x| x == r.id).unwrap_or(false);
        let is_orphan = r
            .source_id
            .as_ref()
            .map(|p| !ids.contains(p.as_str()))
            .unwrap_or(false);
        let is_root = r.source_id.is_none();
        let (fill, stroke_color) = match (is_selected, is_root, is_orphan) {
            (true, _, _) => (
                egui::Color32::from_rgb(60, 120, 200),
                egui::Color32::from_rgb(150, 200, 255),
            ),
            (false, _, true) => (
                egui::Color32::from_rgb(120, 80, 30),
                egui::Color32::from_rgb(220, 160, 60),
            ),
            (false, true, false) => (
                egui::Color32::from_rgb(50, 80, 50),
                egui::Color32::from_rgb(120, 200, 120),
            ),
            (false, false, false) => (
                egui::Color32::from_rgb(55, 55, 65),
                egui::Color32::from_rgb(160, 160, 170),
            ),
        };
        painter.rect(rect, 4.0 * *zoom, fill, egui::Stroke::new(1.0, stroke_color));

        // Node text: short-id first line, owner second.
        let short: String = r.id.chars().take(12).collect();
        painter.text(
            rect.center() - egui::vec2(0.0, 8.0 * *zoom),
            egui::Align2::CENTER_CENTER,
            short,
            egui::FontId::monospace(12.0 * *zoom),
            egui::Color32::from_gray(240),
        );
        painter.text(
            rect.center() + egui::vec2(0.0, 9.0 * *zoom),
            egui::Align2::CENTER_CENTER,
            r.owner.as_deref().unwrap_or("<admin>"),
            egui::FontId::proportional(10.0 * *zoom),
            egui::Color32::from_gray(180),
        );
    }

    // Hit-test on click.
    let clicked_id = if response.clicked() {
        response.interact_pointer_pos().and_then(|pos| {
            node_rects
                .into_iter()
                .rev() // prefer topmost on overlap
                .find(|(_, r)| r.contains(pos))
                .map(|(id, _)| id)
        })
    } else {
        None
    };

    // Legend in a little corner box, independent of pan/zoom.
    let legend_rect = egui::Rect::from_min_size(
        rect.left_top() + egui::vec2(8.0, 8.0),
        egui::vec2(140.0, 66.0),
    );
    painter.rect_filled(legend_rect, 4.0, egui::Color32::from_black_alpha(120));
    let mut y = legend_rect.top() + 8.0;
    for (color, label) in &[
        (egui::Color32::from_rgb(120, 200, 120), "root"),
        (egui::Color32::from_rgb(160, 160, 170), "fork"),
        (egui::Color32::from_rgb(220, 160, 60), "orphan"),
    ] {
        painter.circle_filled(
            egui::pos2(legend_rect.left() + 16.0, y + 6.0),
            5.0,
            *color,
        );
        painter.text(
            egui::pos2(legend_rect.left() + 28.0, y),
            egui::Align2::LEFT_TOP,
            *label,
            egui::FontId::proportional(12.0),
            egui::Color32::from_gray(220),
        );
        y += 18.0;
    }

    clicked_id
}

/// Post-order layout: assign `positions[&id] = (x, y)` for every repo
/// reachable from `root`. Leaves get consecutive integer x values;
/// internal nodes sit at the midpoint of their first and last child.
/// Returns the x coordinate assigned to `root`.
pub(crate) fn layout_subtree(
    root: &RepoSummary,
    children: &HashMap<String, Vec<&RepoSummary>>,
    depth: usize,
    next_x: &mut f64,
    positions: &mut HashMap<String, (f64, f64)>,
) -> f64 {
    let kids = children.get(&root.id);
    let x = match kids {
        None => {
            let x = *next_x;
            *next_x += 1.0;
            x
        }
        Some(kids) if kids.is_empty() => {
            let x = *next_x;
            *next_x += 1.0;
            x
        }
        Some(kids) => {
            let first = layout_subtree(kids[0], children, depth + 1, next_x, positions);
            let mut last = first;
            for kid in kids.iter().skip(1) {
                last = layout_subtree(kid, children, depth + 1, next_x, positions);
            }
            (first + last) / 2.0
        }
    };
    positions.insert(root.id.clone(), (x, depth as f64));
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sm(id: &str, source: Option<&str>) -> RepoSummary {
        RepoSummary {
            id: id.to_string(),
            owner: None,
            created_at: 0,
            source_id: source.map(str::to_string),
        }
    }

    #[test]
    fn layout_subtree_leaf_gets_consecutive_x() {
        let children: HashMap<String, Vec<&RepoSummary>> = HashMap::new();
        let a = sm("a", None);
        let b = sm("b", None);
        let mut positions = HashMap::new();
        let mut next_x = 0.0;
        layout_subtree(&a, &children, 0, &mut next_x, &mut positions);
        layout_subtree(&b, &children, 0, &mut next_x, &mut positions);
        assert_eq!(positions["a"], (0.0, 0.0));
        assert_eq!(positions["b"], (1.0, 0.0));
    }

    #[test]
    fn layout_subtree_parent_centers_over_children() {
        let root = sm("r", None);
        let c1 = sm("c1", Some("r"));
        let c2 = sm("c2", Some("r"));
        let c3 = sm("c3", Some("r"));
        let mut children: HashMap<String, Vec<&RepoSummary>> = HashMap::new();
        children.insert("r".to_string(), vec![&c1, &c2, &c3]);
        let mut positions = HashMap::new();
        let mut next_x = 0.0;
        layout_subtree(&root, &children, 0, &mut next_x, &mut positions);
        assert_eq!(positions["c1"], (0.0, 1.0));
        assert_eq!(positions["c2"], (1.0, 1.0));
        assert_eq!(positions["c3"], (2.0, 1.0));
        assert_eq!(positions["r"], (1.0, 0.0));
    }

    #[test]
    fn fingerprint_is_order_invariant() {
        let a = sm("a", None);
        let b = sm("b", Some("a"));
        let c = sm("c", Some("a"));
        assert_eq!(
            fingerprint(&[a.clone(), b.clone(), c.clone()]),
            fingerprint(&[c, b, a]),
        );
    }

    #[test]
    fn fingerprint_changes_when_new_repo_arrives() {
        let a = sm("a", None);
        let b = sm("b", Some("a"));
        let c = sm("c", Some("a"));
        assert_ne!(
            fingerprint(&[a.clone(), b.clone()]),
            fingerprint(&[a, b, c]),
        );
    }

    #[test]
    fn cache_skips_rebuild_when_fingerprint_matches() {
        let a = sm("a", None);
        let b = sm("b", Some("a"));
        let mut cache = ForkLayoutCache::default();
        let repos = vec![a, b];
        cache.refresh(&repos);
        let positions_ptr = cache.positions.values().next().copied();
        let fp1 = cache.fingerprint;

        // Mutate positions to "stale" values; if refresh no-ops on an
        // unchanged fingerprint, our mutation survives. If it rebuilds,
        // it'll be overwritten.
        for v in cache.positions.values_mut() {
            *v = (99.0, 99.0);
        }
        cache.refresh(&repos);
        assert_eq!(cache.fingerprint, fp1);
        assert!(cache.positions.values().all(|v| *v == (99.0, 99.0)));
        assert!(positions_ptr.is_some());
    }

    #[test]
    fn cache_rebuilds_when_repo_added() {
        let a = sm("a", None);
        let b = sm("b", Some("a"));
        let mut cache = ForkLayoutCache::default();
        cache.refresh(&[a.clone(), b.clone()]);
        assert_eq!(cache.positions.len(), 2);

        let c = sm("c", Some("a"));
        cache.refresh(&[a, b, c]);
        assert_eq!(cache.positions.len(), 3);
        assert!(cache.ids.contains("c"));
    }

    #[test]
    fn cache_populates_ids_and_handles_empty() {
        let mut cache = ForkLayoutCache::default();
        cache.refresh(&[]);
        assert!(cache.positions.is_empty());
        assert!(cache.ids.is_empty());

        let a = sm("a", None);
        cache.refresh(&[a]);
        assert_eq!(cache.positions.len(), 1);
        assert!(cache.ids.contains("a"));
    }

    #[test]
    fn layout_subtree_nested() {
        let r = sm("r", None);
        let a = sm("a", Some("r"));
        let a1 = sm("a1", Some("a"));
        let a2 = sm("a2", Some("a"));
        let b = sm("b", Some("r"));
        let mut children: HashMap<String, Vec<&RepoSummary>> = HashMap::new();
        children.insert("r".to_string(), vec![&a, &b]);
        children.insert("a".to_string(), vec![&a1, &a2]);
        let mut positions = HashMap::new();
        let mut next_x = 0.0;
        layout_subtree(&r, &children, 0, &mut next_x, &mut positions);
        assert_eq!(positions["a1"], (0.0, 2.0));
        assert_eq!(positions["a2"], (1.0, 2.0));
        assert_eq!(positions["a"], (0.5, 1.0));
        assert_eq!(positions["b"], (2.0, 1.0));
        assert_eq!(positions["r"], (1.25, 0.0));
    }
}
