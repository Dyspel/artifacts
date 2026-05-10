//! Per-subject token-bucket rate limiter.
//!
//! Every authenticated REST call consumes one token from the caller's
//! per-class bucket. A bucket holds at most `capacity` tokens and
//! refills at `refill_per_sec`. When the bucket hits zero, the request
//! is rejected with 429 and a `Retry-After` header.
//!
//! ## Why per-subject, not per-IP
//!
//! Subjects (JWT `userId` or admin) are the identity the server already
//! trusts — we know we're rate-limiting *the user* rather than *a
//! particular TCP connection*. Per-IP limiting belongs at the ingress
//! (nginx, caddy, cloudflared) where there's no principal yet. Running
//! both is complementary: ingress bounds brute-force from unauth
//! sources, this module bounds "authenticated but misbehaving."
//!
//! ## What this module deliberately doesn't do
//!
//! - **No limit on unauthenticated requests.** Failed-auth calls cost
//!   nothing here because we can't key on a subject. Brute force
//!   against `/v1/*` is the ingress's problem.
//! - **No persistence.** Buckets live in RAM; a restart grants a fresh
//!   bucket to every caller. Acceptable because the limits are tight
//!   per-call-rate, not per-day-quota — a restart isn't a way to burst
//!   up to some large total.
//! - **Admin is fully exempt.** The admin token is a platform
//!   credential; if someone's abusing it you've already lost.

use crate::{
    auth::Principal,
    error::{Error, Result},
};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Which bucket to charge a call against. Tiered by how expensive the
/// operation is on the server side.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    /// `POST /v1/repos`, `POST /v1/repos/:id/forks` — creates filesystem
    /// state. Tightest limit.
    Create = 0,
    /// `POST /v1/repos/:id/tokens`, etc — touches SQLite but no disk.
    Token = 1,
    /// `POST /v1/repos/:id/commits` — agents commit often, so the limit
    /// is generous; but it's still bounded so a runaway loop can't pin
    /// the CPU.
    Commit = 2,
    /// Anything else (catch-all).
    Default = 3,
}

/// A bucket's capacity and fill rate. `capacity` is the burst allowance;
/// `refill_per_sec` is the sustained throughput.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub capacity: u32,
    pub refill_per_sec: f64,
}

impl Budget {
    /// Convenience: specify a per-minute sustained rate.
    pub const fn per_min(capacity: u32, per_min: u32) -> Self {
        Self {
            capacity,
            refill_per_sec: (per_min as f64) / 60.0,
        }
    }
}

/// Default budgets tuned for Dyspel's expected shape:
/// a legitimate heavy user doesn't hit these; a misbehaving loop does
/// within seconds.
const DEFAULT_CREATE: Budget = Budget::per_min(20, 10); // burst 20, sustain 10/min
const DEFAULT_TOKEN: Budget = Budget::per_min(120, 120); // burst 120, sustain 2/sec
const DEFAULT_COMMIT: Budget = Budget {
    // burst 600, sustain 10/sec
    capacity: 600,
    refill_per_sec: 10.0,
};
const DEFAULT_DEFAULT: Budget = Budget::per_min(300, 300); // burst 300, sustain 5/sec

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    budgets: [Budget; 4],
    buckets: DashMap<(String, Class), Bucket>,
}

impl RateLimiter {
    pub fn with_defaults() -> Self {
        Self {
            budgets: [
                DEFAULT_CREATE,
                DEFAULT_TOKEN,
                DEFAULT_COMMIT,
                DEFAULT_DEFAULT,
            ],
            buckets: DashMap::new(),
        }
    }

    /// Consume one token from the caller's bucket for `class`. Returns
    /// `Error::RateLimited` if the bucket is empty. Admin principals
    /// are exempt.
    pub fn check(&self, principal: &Principal, class: Class) -> Result<()> {
        if matches!(principal, Principal::Admin) {
            return Ok(());
        }
        let Some(subject) = principal.subject() else {
            // Non-admin without a subject shouldn't occur today, but be
            // conservative and treat it as unauthenticated (skip).
            return Ok(());
        };
        let budget = self.budgets[class as usize];
        let now = Instant::now();
        let mut entry = self
            .buckets
            .entry((subject.to_string(), class))
            .or_insert_with(|| Bucket {
                tokens: budget.capacity as f64,
                last_refill: now,
            });

        // Refill from the last-touched-at based on elapsed real time.
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * budget.refill_per_sec).min(budget.capacity as f64);
        entry.last_refill = now;

        if entry.tokens < 1.0 {
            // Time until we've accumulated one full token, rounded up to
            // whole seconds for the Retry-After header.
            let wait = ((1.0 - entry.tokens) / budget.refill_per_sec).ceil() as u64;
            return Err(Error::RateLimited {
                retry_after_secs: wait.max(1),
            });
        }
        entry.tokens -= 1.0;
        Ok(())
    }

    /// Drop buckets that haven't been touched in `stale_after`. Keeps
    /// the map from growing unboundedly if subjects come and go.
    ///
    /// Uses `Instant::elapsed()` rather than `Instant::now() -
    /// stale_after`: the subtraction form panics when `stale_after`
    /// exceeds the process uptime (monotonic-clock underflow), which is
    /// reachable with a long eviction window early in a server's life.
    /// `elapsed()` subtracts a past instant from now and cannot
    /// underflow.
    pub fn evict_stale(&self, stale_after: Duration) {
        self.buckets
            .retain(|_, bucket| bucket.last_refill.elapsed() < stale_after);
    }

    /// For tests: peek at the current token count of a bucket. Returns
    /// `None` if the bucket hasn't been created yet.
    #[cfg(test)]
    pub fn peek(&self, subject: &str, class: Class) -> Option<f64> {
        self.buckets
            .get(&(subject.to_string(), class))
            .map(|b| b.tokens)
    }
}

/// Spawn a tokio task that evicts stale buckets every `tick` with
/// staleness threshold `stale_after`. The task ends when the `Arc`
/// reaches refcount 1 (not load-bearing here — the limiter lives for
/// the whole server lifetime).
pub fn spawn_cleanup(
    limiter: Arc<RateLimiter>,
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

    fn alice() -> Principal {
        Principal::User {
            subject: "alice".into(),
        }
    }

    #[test]
    fn admin_is_exempt() {
        let rl = RateLimiter::with_defaults();
        // Hammer it; should never 429.
        for _ in 0..10_000 {
            rl.check(&Principal::Admin, Class::Create).unwrap();
        }
    }

    #[test]
    fn evict_stale_with_window_exceeding_uptime_does_not_panic() {
        // Regression: the old `Instant::now() - stale_after` form panics
        // (monotonic-clock underflow) when the window exceeds process
        // uptime. A ~100-year window must be safe, and a freshly-touched
        // bucket must survive it.
        let rl = RateLimiter::with_defaults();
        rl.check(&alice(), Class::Create).unwrap();
        rl.evict_stale(Duration::from_secs(100 * 365 * 24 * 3600));
        assert!(
            rl.peek("alice", Class::Create).is_some(),
            "a fresh bucket must survive an oversized eviction window"
        );
    }

    #[test]
    fn user_burst_up_to_capacity_then_429() {
        let rl = RateLimiter::with_defaults();
        // Default Create capacity is 20.
        for _ in 0..20 {
            rl.check(&alice(), Class::Create).unwrap();
        }
        let r = rl.check(&alice(), Class::Create);
        assert!(matches!(r, Err(Error::RateLimited { retry_after_secs }) if retry_after_secs >= 1));
    }

    #[test]
    fn separate_classes_have_separate_budgets() {
        let rl = RateLimiter::with_defaults();
        // Drain Create.
        for _ in 0..20 {
            rl.check(&alice(), Class::Create).unwrap();
        }
        assert!(matches!(
            rl.check(&alice(), Class::Create),
            Err(Error::RateLimited { .. })
        ));
        // Token bucket is independent — this should succeed.
        rl.check(&alice(), Class::Token).unwrap();
    }

    #[test]
    fn separate_subjects_have_separate_buckets() {
        let rl = RateLimiter::with_defaults();
        let bob = Principal::User {
            subject: "bob".into(),
        };
        for _ in 0..20 {
            rl.check(&alice(), Class::Create).unwrap();
        }
        // Alice is drained; Bob should still succeed.
        assert!(matches!(
            rl.check(&alice(), Class::Create),
            Err(Error::RateLimited { .. })
        ));
        rl.check(&bob, Class::Create).unwrap();
    }

    #[tokio::test]
    async fn refill_restores_capacity_over_time() {
        let rl = RateLimiter {
            // Slow refill (4/sec → one token per 250ms) so the three
            // rapid drain checks can't refill a token between calls even
            // under heavy load (coverage instrumentation inflates
            // per-call latency). The bucket clock is a real `Instant`,
            // so a large token-period vs. inter-call-gap ratio is the
            // robust knob, not virtual time.
            budgets: [
                Budget {
                    capacity: 2,
                    refill_per_sec: 4.0,
                }, // Create
                DEFAULT_TOKEN,
                DEFAULT_COMMIT,
                DEFAULT_DEFAULT,
            ],
            buckets: DashMap::new(),
        };
        rl.check(&alice(), Class::Create).unwrap();
        rl.check(&alice(), Class::Create).unwrap();
        assert!(rl.check(&alice(), Class::Create).is_err());
        // One token refills in 250ms; wait 400ms for margin.
        tokio::time::sleep(Duration::from_millis(400)).await;
        rl.check(&alice(), Class::Create).unwrap();
    }

    #[test]
    fn evict_drops_stale_buckets() {
        let rl = RateLimiter::with_defaults();
        rl.check(&alice(), Class::Create).unwrap();
        assert!(rl.peek("alice", Class::Create).is_some());
        // Evict everything older than 0s (i.e., everything touched
        // before "now"). The insertion was strictly before this call,
        // so it should get dropped.
        std::thread::sleep(Duration::from_millis(2));
        rl.evict_stale(Duration::from_millis(1));
        assert!(rl.peek("alice", Class::Create).is_none());
    }
}
