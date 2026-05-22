//! Background polling and lock-recovery helpers.
//!
//! The poller thread fetches `/v1/admin/repos` + `/metrics` every
//! `poll_interval_secs` and, if a repo is selected, also
//! `/v1/admin/repos/:id`. Writes to shared state via a std::sync::Mutex
//! (the state itself is just plain data — no invariants a panic under
//! lock could observably violate, which is why we recover from poison
//! instead of propagating).

use crate::metrics::parse_metrics;
use crate::state::{
    AppState, MetricsSnapshot, RepoDetail, RepoSummary, Sample, HISTORY_WINDOW_SECS,
};
use crate::Cli;
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub(crate) fn poll_once(url: &str, token: &str) -> Result<(Vec<RepoSummary>, MetricsSnapshot)> {
    let base = url.trim_end_matches('/');
    let repos = fetch_all_repos(base, token)?;

    let metrics_text = ureq::get(&format!("{base}/metrics"))
        .timeout(Duration::from_secs(10))
        .call()
        .context("GET /metrics")?
        .into_string()
        .context("read /metrics body")?;

    Ok((repos, parse_metrics(&metrics_text)))
}

/// Page size for the repo-list walk. Matches the server's
/// MAX_LIMIT on `/v1/admin/repos`; smaller wastes round-trips,
/// larger gets clamped server-side.
const PAGE_LIMIT: u32 = 5000;

/// Cap on the number of paging round-trips. With PAGE_LIMIT=5000
/// this is 500_000 repos before we bail — orders of magnitude
/// past anything a real fleet would hold, but enough to make a
/// runaway loop loud instead of silent if the server ever returns
/// non-empty pages indefinitely.
const MAX_PAGES: u32 = 100;

/// Walk `/v1/admin/repos` to the end. The endpoint is paginated and
/// silently truncates without query params past PAGE_LIMIT; calling
/// without offset once meant the GUI lost visibility of any repo past
/// row 1000 (the server default). We loop until we've covered
/// X-Total-Count, or the page comes back short, whichever fires first.
fn fetch_all_repos(base: &str, token: &str) -> Result<Vec<RepoSummary>> {
    fetch_all_repos_with(|offset| {
        let resp = ureq::get(&format!(
            "{base}/v1/admin/repos?limit={PAGE_LIMIT}&offset={offset}"
        ))
        .set("Authorization", &format!("Bearer {token}"))
        .timeout(Duration::from_secs(10))
        .call()
        .context("GET /v1/admin/repos")?;
        let total = resp
            .header("x-total-count")
            .and_then(|h| h.parse::<u64>().ok());
        let page: Vec<RepoSummary> = resp.into_json().context("parse admin/repos response")?;
        Ok((page, total))
    })
}

/// Pure-Rust iteration logic, factored out so the loop is unit-testable
/// without standing up a real HTTP server. `fetch_page(offset)` must
/// return `(page, optional X-Total-Count)`; the loop returns once any
/// terminating condition fires.
fn fetch_all_repos_with(
    mut fetch_page: impl FnMut(u32) -> Result<(Vec<RepoSummary>, Option<u64>)>,
) -> Result<Vec<RepoSummary>> {
    let mut out: Vec<RepoSummary> = Vec::new();
    let mut offset: u32 = 0;
    let mut total: Option<u64> = None;
    for _ in 0..MAX_PAGES {
        let (page, page_total) = fetch_page(offset)?;
        if total.is_none() {
            total = page_total;
        }
        let page_len = page.len() as u32;
        out.extend(page);
        // Terminate when we've reached the advertised total, when
        // the page came back short of PAGE_LIMIT, or when the page
        // was empty.
        let reached_total = total.map(|t| out.len() as u64 >= t).unwrap_or(false);
        if reached_total || page_len < PAGE_LIMIT || page_len == 0 {
            return Ok(out);
        }
        offset = offset.saturating_add(page_len);
    }
    // MAX_PAGES exhausted without termination — return what we have
    // rather than spin forever; surface it so ops can investigate.
    tracing::warn!(
        pages = MAX_PAGES,
        collected = out.len(),
        "fetch_all_repos hit page cap; some repos may be missing"
    );
    Ok(out)
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

#[cfg(test)]
mod tests {
    //! Pin the pagination-walk contract on `fetch_all_repos_with`. The
    //! real HTTP wrapper is a thin shell around this loop, so testing
    //! the loop is enough to catch every termination / truncation bug
    //! we'd care about in production.
    use super::*;

    fn mk(id: &str) -> RepoSummary {
        RepoSummary {
            id: id.to_string(),
            owner: None,
            created_at: 0,
            source_id: None,
        }
    }

    #[test]
    fn single_short_page_terminates() {
        // Server has fewer rows than PAGE_LIMIT — one call, done.
        let mut calls = 0;
        let got = fetch_all_repos_with(|_| {
            calls += 1;
            Ok((vec![mk("a"), mk("b")], Some(2)))
        })
        .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(calls, 1, "short page should not request a second");
    }

    #[test]
    fn walks_multiple_full_pages_until_total_reached() {
        // 3 full pages of PAGE_LIMIT + total advertised as 3*PAGE_LIMIT.
        // We should make exactly 3 calls and not over-request.
        let total = (PAGE_LIMIT as u64) * 3;
        let mut calls = 0;
        let got = fetch_all_repos_with(|offset| {
            calls += 1;
            let page: Vec<RepoSummary> = (0..PAGE_LIMIT)
                .map(|i| mk(&format!("p{}-{i}", offset / PAGE_LIMIT)))
                .collect();
            Ok((page, Some(total)))
        })
        .unwrap();
        assert_eq!(got.len() as u64, total);
        assert_eq!(calls, 3);
    }

    #[test]
    fn empty_first_page_terminates_cleanly() {
        let mut calls = 0;
        let got = fetch_all_repos_with(|_| {
            calls += 1;
            Ok((Vec::new(), Some(0)))
        })
        .unwrap();
        assert!(got.is_empty());
        assert_eq!(calls, 1);
    }

    #[test]
    fn falls_back_to_short_page_when_total_header_missing() {
        // If X-Total-Count is absent (older server), the loop has to
        // rely on the short-page rule. A page returning < PAGE_LIMIT
        // means done.
        let mut calls = 0;
        let got = fetch_all_repos_with(|_| {
            calls += 1;
            Ok((vec![mk("only")], None))
        })
        .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(calls, 1);
    }

    #[test]
    fn caps_at_max_pages_when_pages_never_shrink() {
        // Pathological server: always returns full pages without ever
        // exposing a total. The cap stops us from looping forever.
        let mut calls = 0;
        let got = fetch_all_repos_with(|_| {
            calls += 1;
            let page: Vec<RepoSummary> = (0..PAGE_LIMIT).map(|i| mk(&format!("x{i}"))).collect();
            Ok((page, None))
        })
        .unwrap();
        assert_eq!(calls, MAX_PAGES as usize);
        assert_eq!(got.len(), (PAGE_LIMIT * MAX_PAGES) as usize);
    }
}
