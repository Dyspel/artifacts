//! Prometheus-text parsing + percentile / rate math.
//!
//! Kept server-agnostic: consumes a `String` of prom text and produces
//! a `MetricsSnapshot` (see `state::MetricsSnapshot`). No I/O.

use crate::state::{MetricsSnapshot, OrdF64, Sample};
use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

pub(crate) fn parse_metrics(text: &str) -> MetricsSnapshot {
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
pub(crate) fn percentile_between(
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
pub(crate) fn last_number(s: &str) -> Option<f64> {
    s.split_whitespace().last()?.parse().ok()
}

pub(crate) fn extract_le(line: &str) -> Option<f64> {
    let v = extract_label(line, "le")?;
    if v == "+Inf" {
        Some(f64::INFINITY)
    } else {
        v.parse().ok()
    }
}

pub(crate) fn extract_label(line: &str, name: &str) -> Option<String> {
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

/// Build a time-series of interval percentiles across the history. For
/// each consecutive (prev, curr) pair, compute `percentile_between` —
/// plot point is `[-curr_age, percentile_ms]`. Intervals with zero
/// observations are skipped (no point emitted), so the line breaks
/// rather than misleading the reader with a flat value.
pub(crate) fn interval_percentile_points(history: &VecDeque<Sample>, p: f64) -> Vec<[f64; 2]> {
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

/// p50/p95/p99 (ms) over the last poll interval. Returns `(None,...)`
/// if fewer than 2 samples, or if the interval had no observations.
pub(crate) fn last_interval_percentiles(
    history: &VecDeque<Sample>,
) -> (Option<f64>, Option<f64>, Option<f64>) {
    if history.len() < 2 {
        return (None, None, None);
    }
    let older = &history[history.len() - 2].metrics.latency_buckets;
    let newer = &history[history.len() - 1].metrics.latency_buckets;
    let ms = |p| percentile_between(older, newer, p).map(|s| s * 1000.0);
    (ms(0.50), ms(0.95), ms(0.99))
}

pub(crate) fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.2} ms"),
        None => "—".to_string(),
    }
}

/// Convert history into per-second rate points by diffing consecutive
/// counters. First sample yields no rate, so the series starts one
/// sample later than the raw history.
pub(crate) fn rate_points(
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

/// Convert history into `[-age_secs, value]` points. x is negative so the
/// most-recent sample sits at x=0 and the oldest is on the left.
#[cfg(test)]
pub(crate) fn abs_points(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
        assert_eq!(m.latency_buckets.get(&OrdF64(0.001)).copied(), Some(10));
        assert_eq!(m.latency_buckets.get(&OrdF64(0.01)).copied(), Some(10));
        assert_eq!(
            m.latency_buckets.get(&OrdF64(f64::INFINITY)).copied(),
            Some(10)
        );
    }

    fn buckets(pairs: &[(f64, u64)]) -> BTreeMap<OrdF64, u64> {
        pairs.iter().map(|(k, v)| (OrdF64(*k), *v)).collect()
    }

    #[test]
    fn percentile_between_returns_none_when_interval_empty() {
        let a = buckets(&[(0.001, 10), (0.01, 10), (f64::INFINITY, 10)]);
        let b = buckets(&[(0.001, 10), (0.01, 10), (f64::INFINITY, 10)]);
        assert_eq!(percentile_between(&a, &b, 0.50), None);
        assert_eq!(percentile_between(&a, &b, 0.99), None);
    }

    #[test]
    fn percentile_between_finds_bucket_from_delta() {
        let older = buckets(&[(0.001, 10), (0.01, 10), (f64::INFINITY, 10)]);
        let newer = buckets(&[(0.001, 10), (0.01, 20), (f64::INFINITY, 20)]);
        assert_eq!(percentile_between(&older, &newer, 0.50), Some(0.01));
        assert_eq!(percentile_between(&older, &newer, 0.99), Some(0.01));
    }

    #[test]
    fn percentile_between_gives_different_answers_for_different_p() {
        let older = buckets(&[(0.001, 0), (0.01, 0), (f64::INFINITY, 0)]);
        let newer = buckets(&[(0.001, 90), (0.01, 100), (f64::INFINITY, 100)]);
        assert_eq!(percentile_between(&older, &newer, 0.50), Some(0.001));
        assert_eq!(percentile_between(&older, &newer, 0.95), Some(0.01));
    }

    #[test]
    fn extract_le_handles_plus_inf() {
        let s = "foo_bucket{le=\"+Inf\"} 42";
        assert!(extract_le(s).unwrap().is_infinite());
    }

    fn make_sample(ago_secs: f64, metrics: MetricsSnapshot) -> Sample {
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
        let mut h: VecDeque<Sample> = VecDeque::new();
        h.push_back(make_sample(2.0, mk_metrics(100)));
        h.push_back(make_sample(0.0, mk_metrics(120)));
        let pts = rate_points(&h, |m| m.requests_total);
        assert_eq!(pts.len(), 1);
        assert!((pts[0][1] - 10.0).abs() < 0.1, "got rate {:?}", pts[0][1]);
    }

    #[test]
    fn rate_points_clamps_to_zero_on_counter_reset() {
        let mut h: VecDeque<Sample> = VecDeque::new();
        h.push_back(make_sample(2.0, mk_metrics(100)));
        h.push_back(make_sample(0.0, mk_metrics(5)));
        let pts = rate_points(&h, |m| m.requests_total);
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0][1], 0.0);
    }

    #[test]
    fn abs_points_keeps_raw_values_in_x_negative_order() {
        let mut h: VecDeque<Sample> = VecDeque::new();
        h.push_back(make_sample(10.0, mk_metrics(1)));
        h.push_back(make_sample(5.0, mk_metrics(2)));
        h.push_back(make_sample(0.0, mk_metrics(3)));
        let pts = abs_points(&h, |m| m.requests_total as f64);
        assert_eq!(pts.len(), 3);
        assert!(pts[0][0] < pts[1][0]);
        assert!(pts[1][0] < pts[2][0]);
        assert!(pts[0][0] < 0.0);
        assert_eq!(pts[0][1], 1.0);
        assert_eq!(pts[2][1], 3.0);
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
        h.push_back(Sample {
            at: Instant::now()
                .checked_sub(Duration::from_secs(4))
                .unwrap_or_else(Instant::now),
            metrics: MetricsSnapshot {
                latency_buckets: buckets(&[(0.001, 0), (0.01, 0), (f64::INFINITY, 0)]),
                ..Default::default()
            },
        });
        h.push_back(Sample {
            at: Instant::now()
                .checked_sub(Duration::from_secs(2))
                .unwrap_or_else(Instant::now),
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
        assert_eq!(p50, Some(10.0)); // 10 ms
    }
}
