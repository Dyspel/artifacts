//! Outbound webhook delivery.
//!
//! What this is: subscribers register a URL + secret with a repo,
//! and we POST a JSON event body to that URL whenever an event fires
//! for that repo on the in-process bus. Each delivery is signed with
//! HMAC-SHA256 over the body, with the digest in
//! `X-Artifacts-Signature: sha256=<hex>` so subscribers can verify
//! authenticity without trusting the network path.
//!
//! ## What this is *not*
//!
//! - Durable. Subscriptions live in memory; restarting the process
//!   loses them. The store is behind the `WebhookRegistry` trait so a
//!   future SQLite impl drops in without touching the rest of the
//!   plumbing — same shape as `TokenStore` / `OwnershipStore`.
//! - Reliable. Each delivery is best-effort: one HTTP attempt, no
//!   retries, no dead-letter queue. Subscribers that need
//!   exactly-once should poll `/v1/events` SSE instead. M6-deliver
//!   adds retries with exponential backoff.
//! - Observable beyond stderr. Per-delivery status lives in the
//!   `tracing` log only; a future commit can plumb counts through
//!   the Prometheus exporter.
//!
//! ## Threading
//!
//! Delivery runs on a dedicated `tokio::spawn_blocking` per-event so
//! that a slow webhook target can't tie up axum's request workers.
//! `ureq` is sync, which suits this use case — the spawn_blocking
//! call sleeps the blocking-pool thread, never the tokio reactor.

use crate::events::Event;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// One subscription. Stored alongside other subscriptions for the
/// same repo in `WebhookRegistry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    /// Repo this subscription fires for. We filter by repo at
    /// dispatch time rather than baking it into the event body —
    /// keeps the trait small.
    pub repo_id: String,
    pub url: String,
    /// HMAC-SHA256 secret. Stored in plaintext today (no DB to hash
    /// against); when the SQLite-backed registry lands it should be
    /// stored hashed the same way TokenStore does.
    #[serde(skip_serializing)]
    pub secret: Option<String>,
    /// Subset of event kinds to fire on. Empty = all kinds.
    pub events: Vec<String>,
}

/// The registry contract. In-memory `MemRegistry` is the only impl
/// today; SQLite-backed comes when subscriptions need to survive a
/// restart.
pub trait WebhookRegistry: Send + Sync {
    fn add(&self, sub: Subscription) -> String;
    fn list(&self, repo_id: &str) -> Vec<Subscription>;
    fn remove(&self, repo_id: &str, hook_id: &str) -> bool;
    fn matching(&self, repo_id: &str, kind: &str) -> Vec<Subscription>;
}

/// In-memory `WebhookRegistry`. `Mutex<Vec>` is plenty for the
/// subscription cardinality we'd see on a single machine (dozens, not
/// thousands).
#[derive(Default, Clone)]
pub struct MemRegistry {
    inner: Arc<std::sync::Mutex<Vec<Subscription>>>,
}

impl MemRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Subscription>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl WebhookRegistry for MemRegistry {
    fn add(&self, mut sub: Subscription) -> String {
        if sub.id.is_empty() {
            sub.id = Uuid::new_v4().to_string();
        }
        let id = sub.id.clone();
        self.lock().push(sub);
        id
    }

    fn list(&self, repo_id: &str) -> Vec<Subscription> {
        self.lock()
            .iter()
            .filter(|s| s.repo_id == repo_id)
            .cloned()
            .collect()
    }

    fn remove(&self, repo_id: &str, hook_id: &str) -> bool {
        let mut g = self.lock();
        let before = g.len();
        g.retain(|s| !(s.repo_id == repo_id && s.id == hook_id));
        before != g.len()
    }

    fn matching(&self, repo_id: &str, kind: &str) -> Vec<Subscription> {
        self.lock()
            .iter()
            .filter(|s| s.repo_id == repo_id)
            .filter(|s| s.events.is_empty() || s.events.iter().any(|e| e == kind))
            .cloned()
            .collect()
    }
}

/// Long-lived task that subscribes to the event bus and dispatches
/// each event to every matching subscription. Owns its own broadcast
/// receiver; the registry handle is shared with the REST endpoints
/// so add/list/remove see the same set the dispatcher walks.
pub fn spawn_dispatcher(
    registry: Arc<dyn WebhookRegistry>,
    bus: crate::events::EventBus,
) {
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => dispatch_event(&*registry, &ev).await,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(dropped = n, "webhook dispatcher lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

async fn dispatch_event(registry: &dyn WebhookRegistry, ev: &Event) {
    let (repo_id, kind) = repo_and_kind(ev);
    let subs = registry.matching(repo_id, kind);
    if subs.is_empty() {
        return;
    }
    let body = match serde_json::to_vec(ev) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "webhook serialize failed");
            return;
        }
    };
    for sub in subs {
        let body = body.clone();
        // ureq is sync — push it onto the blocking pool so a slow
        // webhook target can't stall the tokio runtime. The handle
        // is dropped immediately; no retries, no result inspection.
        // M6-deliver layers backoff + at-least-once on top.
        tokio::task::spawn_blocking(move || {
            let signature = sign_body(sub.secret.as_deref(), &body);
            let agent = ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(5))
                .build();
            let mut req = agent.post(&sub.url)
                .set("Content-Type", "application/json")
                .set("X-Artifacts-Hook-Id", &sub.id)
                .set("X-Artifacts-Event", &kind_str(&body));
            if let Some(sig) = signature.as_deref() {
                req = req.set("X-Artifacts-Signature", sig);
            }
            match req.send_bytes(&body) {
                Ok(resp) => {
                    let status = resp.status();
                    if !(200..400).contains(&status) {
                        tracing::warn!(
                            hook = %sub.id, url = %sub.url, status,
                            "webhook delivery non-2xx",
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        hook = %sub.id, url = %sub.url, error = %e,
                        "webhook delivery failed",
                    );
                }
            }
        });
    }
}

/// Compute `sha256=<hex>` over `body` keyed by `secret`. Returns
/// `None` when there's no secret — subscribers that don't care
/// about authenticity (private network, mTLS upstream, etc.) can
/// skip the verification.
fn sign_body(secret: Option<&str>, body: &[u8]) -> Option<String> {
    let secret = secret?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2 + 7);
    hex.push_str("sha256=");
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    Some(hex)
}

/// Pull `(repo_id, kind)` out of an `Event` without recomputing the
/// JSON. Cheap enough that we don't bother caching.
fn repo_and_kind(ev: &Event) -> (&str, &str) {
    match ev {
        Event::Commit { repo_id, .. } => (repo_id, "commit"),
        Event::Fork { parent_repo_id, .. } => (parent_repo_id, "fork"),
        Event::Status { repo_id, .. } => (repo_id, "status"),
    }
}

/// Read the `kind` value out of the already-serialized event body.
/// Used to set the `X-Artifacts-Event` header without re-borrowing
/// the typed Event after we've moved the body into a blocking task.
fn kind_str(body: &[u8]) -> String {
    let s = std::str::from_utf8(body).unwrap_or("");
    if let Some(start) = s.find("\"kind\":\"") {
        let after = &s[start + 8..];
        if let Some(end) = after.find('"') {
            return after[..end].to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_list_round_trip() {
        let r = MemRegistry::new();
        let id = r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "http://example".into(),
            secret: None,
            events: vec![],
        });
        assert!(!id.is_empty());
        let listed = r.list("r1");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
    }

    #[test]
    fn list_filters_by_repo() {
        let r = MemRegistry::new();
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u1".into(),
            secret: None,
            events: vec![],
        });
        r.add(Subscription {
            id: String::new(),
            repo_id: "r2".into(),
            url: "u2".into(),
            secret: None,
            events: vec![],
        });
        assert_eq!(r.list("r1").len(), 1);
        assert_eq!(r.list("r2").len(), 1);
        assert_eq!(r.list("r3").len(), 0);
    }

    #[test]
    fn remove_targets_specific_hook_only() {
        let r = MemRegistry::new();
        let id1 = r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u1".into(),
            secret: None,
            events: vec![],
        });
        let id2 = r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u2".into(),
            secret: None,
            events: vec![],
        });
        assert!(r.remove("r1", &id1));
        let rem = r.list("r1");
        assert_eq!(rem.len(), 1);
        assert_eq!(rem[0].id, id2);
        // removing again is a no-op.
        assert!(!r.remove("r1", &id1));
    }

    #[test]
    fn matching_filters_by_kind_when_events_set() {
        let r = MemRegistry::new();
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u-all".into(),
            secret: None,
            events: vec![],
        });
        r.add(Subscription {
            id: String::new(),
            repo_id: "r1".into(),
            url: "u-commit".into(),
            secret: None,
            events: vec!["commit".into()],
        });
        let m_commit = r.matching("r1", "commit");
        assert_eq!(m_commit.len(), 2);
        let m_fork = r.matching("r1", "fork");
        // only the all-kinds subscription matches.
        assert_eq!(m_fork.len(), 1);
        assert_eq!(m_fork[0].url, "u-all");
    }

    #[test]
    fn sign_body_produces_stable_hex() {
        let s = sign_body(Some("supersecret"), b"hello").unwrap();
        // Known good (verified with openssl):
        //   $ printf hello | openssl dgst -sha256 -hmac supersecret
        //   c6d323717f52016e8e0b606500d0b11721618a8d75df8acead4d9395544f4787
        assert_eq!(
            s,
            "sha256=c6d323717f52016e8e0b606500d0b11721618a8d75df8acead4d9395544f4787"
        );
    }

    #[test]
    fn sign_body_returns_none_without_secret() {
        assert!(sign_body(None, b"x").is_none());
    }

    #[test]
    fn kind_str_extracts_the_kind_key() {
        let body = br#"{"kind":"commit","repoId":"r1"}"#;
        assert_eq!(kind_str(body), "commit");
    }

    #[test]
    fn kind_str_returns_unknown_on_garbage() {
        assert_eq!(kind_str(b"not json"), "unknown");
    }
}
