//! Background polling and lock-recovery helpers.
//!
//! The poller thread fetches `/v1/admin/repos` + `/metrics` every
//! `poll_interval_secs` and, if a repo is selected, also
//! `/v1/admin/repos/:id`. Writes to shared state via a std::sync::Mutex
//! (the state itself is just plain data — no invariants a panic under
//! lock could observably violate, which is why we recover from poison
//! instead of propagating).

use crate::metrics::parse_metrics;
use crate::state::{AppState, MetricsSnapshot, RepoDetail, RepoSummary, Sample, HISTORY_WINDOW_SECS};
use crate::Cli;
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub(crate) fn poll_once(url: &str, token: &str) -> Result<(Vec<RepoSummary>, MetricsSnapshot)> {
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
pub(crate) fn poll_detail(url: &str, token: &str, repo_id: &str) -> Result<RepoDetail> {
    let base = url.trim_end_matches('/');
    ureq::get(&format!("{base}/v1/admin/repos/{repo_id}"))
        .set("Authorization", &format!("Bearer {token}"))
        .timeout(Duration::from_secs(10))
        .call()
        .with_context(|| format!("GET /v1/admin/repos/{repo_id}"))?
        .into_json()
        .context("parse admin/repos/:id response")
}

/// Lock the shared state, recovering from poisoning.
///
/// A poisoned mutex means *a previous thread panicked while holding it*.
/// The canonical Rust move is to propagate — `.expect()` — which in
/// this process means the poller thread crashes, the UI silently stops
/// getting updates, and the user sees an ever-increasing "polled Ns
/// ago" forever. That's worse than continuing with potentially torn
/// state: the state is just `Vec<RepoSummary>` + scalars, no invariant
/// we can observably violate. So we take the inner and keep going.
///
/// If a poisoning ever occurs, log once at ERROR so ops sees it.
pub(crate) fn lock_state(state: &Mutex<AppState>) -> MutexGuard<'_, AppState> {
    match state.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            tracing::error!(
                "state mutex was poisoned by an earlier panic; \
                 continuing with recovered state"
            );
            poisoned.into_inner()
        }
    }
}

pub(crate) fn lock_selection(m: &Mutex<Option<String>>) -> MutexGuard<'_, Option<String>> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            tracing::error!("selection mutex was poisoned; recovering");
            poisoned.into_inner()
        }
    }
}

pub(crate) fn spawn_poller(
    cli: Cli,
    state: Arc<Mutex<AppState>>,
    selected: Arc<Mutex<Option<String>>>,
) {
    let interval = Duration::from_secs_f64(cli.poll_interval_secs.max(0.1));
    std::thread::spawn(move || loop {
        match poll_once(&cli.url, &cli.admin_token) {
            Ok((repos, metrics)) => {
                let now = Instant::now();
                let mut s = lock_state(&state);
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
                let mut s = lock_state(&state);
                s.last_error = Some(format!("{e:#}"));
                // Keep going to the detail fetch anyway — list and
                // detail have independent failure modes.
                drop(s);
            }
        }

        // Second leg: if a repo is selected, keep its detail fresh.
        // If the user hasn't selected anything, this is skipped.
        let requested = lock_selection(&selected).clone();
        if let Some(id) = requested {
            match poll_detail(&cli.url, &cli.admin_token, &id) {
                Ok(detail) => {
                    let mut s = lock_state(&state);
                    // Stash the detail only if the selection hasn't
                    // changed underfoot. Otherwise we'd briefly
                    // show stale data for the previous selection.
                    if detail.id == id {
                        s.detail = Some(detail);
                    }
                }
                Err(e) => {
                    lock_state(&state).last_error = Some(format!("detail {id}: {e:#}"));
                }
            }
        } else {
            // No selection → drop any stale detail so the Detail tab
            // shows "pick a repo" instead of an old one.
            lock_state(&state).detail = None;
        }

        std::thread::sleep(interval);
    });
}
