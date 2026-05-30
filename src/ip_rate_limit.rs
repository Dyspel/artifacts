//! Per-IP rate limiter for the unauthenticated boundary.
//!
//! The principal-keyed [`crate::rate_limit::RateLimiter`] only fires
//! after auth resolves — by design it can't see callers that fail (or
//! skip) authentication. The two unauthenticated routes
//! (`/v1/health`, `/v1/health/ready`) need a separate cap so an
//! unauthenticated scanner can't pound them.
//!
//! Token-bucket shape, same as `rate_limit.rs`. Keyed on the peer
//! socket's IP address (sans port). One global budget — generous
//! enough that a real load balancer's health probe never trips it,
//! tight enough that a scanner's loop does.
//!
//! Buckets live in RAM, never persisted. The cleanup task evicts
//! buckets untouched for an hour so the map can't grow unbounded if
//! a CIDR sprays one-shot probes.

use crate::error::{Error, Result};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Burst / sustain budget. Mirrors `rate_limit::Budget` so the math
/// is identical; the constants live here because the per-IP threshold
/// is policy-distinct from the per-subject thresholds.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub capacity: u32,
    pub refill_per_sec: f64,
}

/// Default unauth budget: burst 60, sustain 2/sec. A k8s liveness
/// probe at the standard 10s cadence + a readiness probe at 5s
/// stays under 0.3/sec from the orchestrator; sixty in burst is
/// generous for "ten clients each polling once a second on a deploy
/// rollout" while still cutting off a 1000-rps scanner in a fraction
/// of a second.
const DEFAULT_UNAUTH: Budget = Budget {
    capacity: 60,
    refill_per_sec: 2.0,
};

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct IpRateLimiter {
    budget: Budget,
    buckets: DashMap<IpAddr, Bucket>,
}

impl IpRateLimiter {
    pub fn with_defaults() -> Self {
        Self {
            budget: DEFAULT_UNAUTH,
            buckets: DashMap::new(),
        }
    }

    /// Consume one token for `ip`. Returns `Error::RateLimited` if the
    /// bucket is empty.
    pub fn check(&self, ip: IpAddr) -> Result<()> {
        let now = Instant::now();
        let mut entry = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.budget.capacity as f64,
            last_refill: now,
        });

        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens =
            (entry.tokens + elapsed * self.budget.refill_per_sec).min(self.budget.capacity as f64);
        entry.last_refill = now;

        if entry.tokens < 1.0 {
            let wait = ((1.0 - entry.tokens) / self.budget.refill_per_sec).ceil() as u64;
            return Err(Error::RateLimited {
                retry_after_secs: wait.max(1),
            });
        }
        entry.tokens -= 1.0;
        Ok(())
    }

    /// Drop buckets untouched for `stale_after`. Cleanup-task target.
    ///
    /// Uses `Instant::elapsed()` rather than `Instant::now() -
    /// stale_after`: the latter panics if `stale_after` exceeds the
    /// process uptime (the subtraction underflows the monotonic clock),
    /// which is reachable with a long eviction window on a
    /// freshly-started server. `elapsed()` only ever subtracts a past
    /// instant from now, so it cannot underflow.
    pub fn evict_stale(&self, stale_after: Duration) {
        self.buckets
            .retain(|_, b| b.last_refill.elapsed() < stale_after);
    }

    #[cfg(test)]
    fn peek(&self, ip: IpAddr) -> Option<f64> {
        self.buckets.get(&ip).map(|b| b.tokens)
    }
}

/// Cleanup task — evicts stale IP buckets on `tick`.
pub fn spawn_cleanup(
    limiter: Arc<IpRateLimiter>,
    tick: Duration,
    stale_after: Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        loop {
            tokio::select! {
                _ = ticker.tick() => limiter.evict_stale(stale_after),
                _ = cancel.cancelled() => return,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_then_429() {
        let rl = IpRateLimiter::with_defaults();
        let ip = ip4("203.0.113.7");
        // DEFAULT_UNAUTH capacity is 60. Drain it.
        for _ in 0..60 {
            rl.check(ip).unwrap();
        }
        assert!(matches!(
            rl.check(ip),
            Err(Error::RateLimited { retry_after_secs }) if retry_after_secs >= 1,
        ));
    }

    #[test]
    fn evict_stale_with_window_exceeding_uptime_does_not_panic() {
        // Regression: the old `Instant::now() - stale_after` form panics
        // (monotonic-clock underflow) when the window exceeds process
        // uptime. A ~100-year window must be safe, and since no bucket
        // is that old, a freshly-touched bucket must survive.
        let rl = IpRateLimiter::with_defaults();
        let ip = ip4("203.0.113.42");
        rl.check(ip).unwrap();
        rl.evict_stale(Duration::from_secs(100 * 365 * 24 * 3600));
        assert!(
            rl.peek(ip).is_some(),
            "a fresh bucket must survive an oversized eviction window"
        );
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let rl = IpRateLimiter::with_defaults();
        let a = ip4("198.51.100.10");
        let b = ip4("198.51.100.20");
        for _ in 0..60 {
            rl.check(a).unwrap();
        }
        // a is drained; b is fresh.
        assert!(matches!(rl.check(a), Err(Error::RateLimited { .. })));
        rl.check(b).unwrap();
    }

    #[tokio::test]
    async fn refill_returns_tokens() {
        // Test-local limiter with fast refill for determinism.
        let rl = IpRateLimiter {
            budget: Budget {
                capacity: 2,
                refill_per_sec: 50.0,
            },
            buckets: DashMap::new(),
        };
        let ip = ip4("192.0.2.1");
        rl.check(ip).unwrap();
        rl.check(ip).unwrap();
        assert!(rl.check(ip).is_err());
        // 50/sec → one token in 20ms. Wait 50ms for safety.
        tokio::time::sleep(Duration::from_millis(50)).await;
        rl.check(ip).unwrap();
    }

    #[test]
    fn evict_drops_stale_buckets() {
        let rl = IpRateLimiter::with_defaults();
        let ip = ip4("203.0.113.42");
        rl.check(ip).unwrap();
        assert!(rl.peek(ip).is_some());
        std::thread::sleep(Duration::from_millis(2));
        rl.evict_stale(Duration::from_millis(1));
        assert!(rl.peek(ip).is_none());
    }
}
