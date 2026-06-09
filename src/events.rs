//! In-process event bus.
//!
//! A single broadcast channel lives in `RestState`; every mutating
//! handler that updates a ref (`commits::create_commit`,
//! `merge::merge_branches`), creates a repo, or forks one, `.send()`s
//! a typed `Event` onto it. Subscribers — the SSE handler here today,
//! future Durable-Object or Redis-pubsub fanouts — see the same stream.
//!
//! ## Why `tokio::sync::broadcast`
//!
//! Multi-consumer, lag-tolerant, lossy by design. If a slow subscriber
//! can't keep up with the channel, the oldest events are dropped for
//! that subscriber (but not others) and the next read returns
//! `RecvError::Lagged(n)`. That's the right tradeoff for a live-update
//! UI — the user would rather see a gap and catch up than block the
//! whole process waiting for one browser tab. Capacity is sized for
//! bursts during a typical agent commit (~tens of commits in a second
//! across a repo cluster); backpressure past that is absorbed as lag.
//!
//! Kept namespace-agnostic at this layer: every subscriber sees every
//! event. Filtering (by repo owner, by repo id) happens at the SSE
//! endpoint handler and in the BFF layer above — centralizing the
//! filter downstream means new filters don't require a schema change.

use crate::{error::Result, rest::RestState};
use axum::{
    extract::State,
    http::HeaderMap,
    response::sse::{Event as SseEvent, KeepAlive, Sse},
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

/// Max number of events buffered for a lagging subscriber. Past this,
/// the oldest events are dropped and the subscriber gets
/// `RecvError::Lagged(n)`. 512 is generous — a sustained fire-hose
/// past this probably indicates a bug, not legitimate traffic.
pub const EVENT_CHANNEL_CAPACITY: usize = 512;

/// Fan-out channel owned by `RestState`. Cheap clone, multiple
/// producers (every mutating handler), multiple consumers (every open
/// SSE subscriber).
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self { tx }
    }

    /// Publish an event. Errors are swallowed — if nobody is listening,
    /// that's fine; the channel stays up for the next subscriber.
    pub fn publish(&self, ev: Event) {
        // send returns Err when there are no subscribers; that's normal.
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// All the event types the bus carries. Flat, self-describing, designed
/// to map 1:1 onto DysHub's StreamEvent after user-filtering in the
/// BFF. `t` is unix epoch milliseconds — same resolution the UI expects.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Event {
    /// A branch ref on a repo advanced to a new commit. Fired by both
    /// the REST commit endpoint and the merge endpoint.
    Commit {
        #[serde(rename = "repoId")]
        repo_id: String,
        #[serde(rename = "commitId")]
        commit_id: String,
        branch: String,
        message: String,
        t: i64,
    },
    /// A repo gained a fork. Fired by the fork endpoint.
    Fork {
        #[serde(rename = "parentRepoId")]
        parent_repo_id: String,
        #[serde(rename = "childRepoId")]
        child_repo_id: String,
        t: i64,
    },
    /// Repo lifecycle status change (for future use — e.g., "repo went
    /// idle after 5 min with no events"). Emitted for the create event
    /// today so the UI picks up brand-new repos without a polling refresh.
    Status {
        #[serde(rename = "repoId")]
        repo_id: String,
        from: String,
        to: String,
        t: i64,
    },
}

/// The kind of an [`Event`], reified so a webhook subscription that
/// filters on a misspelled kind is rejected at creation time (the
/// `events` array fails to deserialize) rather than silently never
/// matching any event. The wire form is the lowercase variant name,
/// matching the `kind` tag the `Event` enum serializes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Commit,
    Fork,
    Status,
}

impl EventKind {
    /// The wire string: `"commit"`, `"fork"`, or `"status"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Commit => "commit",
            EventKind::Fork => "fork",
            EventKind::Status => "status",
        }
    }
}

impl Event {
    pub fn commit(
        repo_id: impl Into<String>,
        commit_id: impl Into<String>,
        branch: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Commit {
            repo_id: repo_id.into(),
            commit_id: commit_id.into(),
            branch: branch.into(),
            message: message.into(),
            t: now_ms(),
        }
    }
    pub fn fork(parent: impl Into<String>, child: impl Into<String>) -> Self {
        Self::Fork {
            parent_repo_id: parent.into(),
            child_repo_id: child.into(),
            t: now_ms(),
        }
    }
    pub fn status(
        repo_id: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> Self {
        Self::Status {
            repo_id: repo_id.into(),
            from: from.into(),
            to: to.into(),
            t: now_ms(),
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `GET /v1/events` — Server-Sent Events stream of every bus event.
///
/// Admin-only, and enforced as such. The bus carries *every* repo's
/// events (commit messages, repo ids, fork topology), so a non-admin
/// subscriber would see across tenant boundaries — exactly the leak
/// `enforce_owner` prevents on every other read endpoint. The BFF
/// subscribes with the admin token and filters per-user in Node. A
/// future enhancement may add a per-repo filter here (e.g.
/// `?repoId=abc`) so owner principals can tail their own repo; until
/// that exists, the stream is admin-only.
pub async fn sse_stream(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = std::result::Result<SseEvent, Infallible>>>> {
    crate::rest::require_admin(&state, &headers)?;
    state.authn.rate_limit.check(
        &crate::auth::Principal::Admin,
        crate::rate_limit::Class::Default,
    )?;
    let rx = state.observ.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|r| match r {
        Ok(ev) => {
            // serde_json::to_string is infallible on our types; unwrap is fine.
            let payload = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_string());
            Some(Ok(SseEvent::default().data(payload)))
        },
        // Lag: serialize how many we dropped so the subscriber can log
        // or force-reload. Dropping the error entirely would silently
        // corrupt the UI's view of the stream.
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
            let payload = serde_json::json!({ "kind": "lag", "dropped": n });
            Some(Ok(SseEvent::default().data(payload.to_string())))
        },
    });
    // KeepAlive sends a `:keepalive` comment every 15s so intermediaries
    // (nginx default idle timeout is 60s) don't close long-lived idle
    // connections. Browsers reconnect automatically on EOF either way,
    // but an accidental disconnect loses events between close and next
    // connect.
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15))))
}

#[cfg(test)]
mod tests {
    use super::{Event, EventBus, EventKind};

    #[test]
    fn event_kind_as_str_and_serde_round_trip() {
        for (k, s) in [
            (EventKind::Commit, "commit"),
            (EventKind::Fork, "fork"),
            (EventKind::Status, "status"),
        ] {
            assert_eq!(k.as_str(), s);
            // Wire form is the bare lowercase variant name.
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{s}\""));
            let back: EventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, k);
        }
        // A misspelled kind fails to deserialize (the whole point of N3).
        assert!(serde_json::from_str::<EventKind>("\"comit\"").is_err());
    }

    #[test]
    fn event_constructors_build_the_right_variants() {
        let c = Event::commit("r1", "abc", "refs/heads/main", "msg");
        assert!(matches!(c, Event::Commit { .. }));
        let f = Event::fork("parent", "child");
        match f {
            Event::Fork {
                parent_repo_id,
                child_repo_id,
                ..
            } => {
                assert_eq!(parent_repo_id, "parent");
                assert_eq!(child_repo_id, "child");
            },
            _ => panic!("expected Fork"),
        }
        let s = Event::status("r1", "active", "idle");
        assert!(matches!(s, Event::Status { .. }));
    }

    #[tokio::test]
    async fn bus_default_publish_reaches_a_subscriber() {
        // Default delegates to new(); a subscriber taken before publish
        // sees the event, and the serialized form carries the `kind` tag.
        let bus = EventBus::default();
        let mut rx = bus.subscribe();
        bus.publish(Event::fork("p", "c"));
        let ev = rx.recv().await.unwrap();
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"kind\":\"fork\""), "got {json}");

        // Publishing with no live subscriber is a no-op, not an error.
        drop(rx);
        bus.publish(Event::status("r", "a", "b"));
    }
}
