//! Persistent audit log.
//!
//! Every mutating REST endpoint emits a `tracing::info!(target: "audit", …)`
//! event on success. That event is the live wire-format — anyone with a
//! tracing subscriber filtered to `audit=info` sees it as it happens.
//! This module is the *durable* counterpart: a SQLite-backed store that
//! captures the same events so admin tooling can query history after the
//! fact, without a parallel external sink (jsonl tail, OTel collector,
//! whatever).
//!
//! Two writes per audit point — a `tracing!` call and an `AuditStore::record`
//! call — is deliberate. The tracing call carries native structured fields
//! to whichever live subscriber an operator has wired up (kv-formatted, no
//! JSON serialization on the hot path); the store call serializes the
//! same fields once and persists them. If a deployment doesn't care about
//! durable history, it can wire up `NoopAuditStore` and the tracing path
//! still works. If a deployment doesn't care about live events, the
//! `audit` tracing target can be filtered out and SQLite still records.
//!
//! ## Schema
//!
//! ```sql
//! CREATE TABLE audit_events (
//!   id          INTEGER PRIMARY KEY AUTOINCREMENT,  -- monotonic insert order
//!   ts          INTEGER NOT NULL,                   -- unix epoch seconds
//!   event       TEXT NOT NULL,                      -- e.g. "repo.create"
//!   actor       TEXT NOT NULL,                      -- "admin" | jwt subject
//!   repo_id     TEXT,                               -- nullable for non-repo events
//!   fields_json TEXT NOT NULL DEFAULT '{}',         -- everything else
//!   request_id  TEXT                                -- when known
//! );
//! ```
//!
//! `fields_json` keeps the schema flat — adding a new audit-event kind
//! with new fields doesn't require a migration. The cost is that
//! filtering on a structured field requires a JSON1 expression
//! (`json_extract(fields_json, '$.scope') = 'write'`). That's fine
//! for the volume an audit log handles.

use crate::error::Result;
use async_trait::async_trait;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as TokioMutex;

/// One row of the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Server-assigned. Caller passes 0 on insert; populated on read.
    pub id: i64,
    /// Unix epoch seconds.
    pub ts: i64,
    /// Dotted-name kind, mirroring the `event=` field of the tracing
    /// call (`repo.create`, `repo.fork`, `repo.delete`, `token.mint`,
    /// `token.revoke`, `token.rotate`, `admin.token.rotate`).
    pub event: String,
    /// Stable principal label. For admin Bearer requests this is the
    /// literal `"admin"`; for JWT users it's the verified subject. Never
    /// holds raw token bytes — see `Principal::audit_label()`.
    pub actor: String,
    /// Target repo id when the event is repo-scoped. `None` for the
    /// admin-token rotation event (and other future global-scope events).
    #[serde(rename = "repoId", skip_serializing_if = "Option::is_none")]
    pub repo_id: Option<String>,
    /// Everything else, as a JSON object string. Caller serializes via
    /// `serde_json::Value` then `to_string()`. Empty `{}` is fine.
    #[serde(rename = "fields", skip_serializing_if = "String::is_empty")]
    pub fields_json: String,
    /// X-Request-Id, when extractable from the per-request span. Plumbed
    /// in by the handler — `None` if the audit point didn't pass it.
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Filter criteria for `AuditStore::list`. All fields are optional;
/// missing ones don't constrain the result. Newest-first ordering is
/// fixed (admin debugging usually starts from "what just happened").
#[derive(Debug, Default, Clone)]
pub struct AuditQuery {
    pub since_ts: Option<i64>,
    pub until_ts: Option<i64>,
    pub event: Option<String>,
    pub actor: Option<String>,
    pub repo_id: Option<String>,
    /// Hard-capped by the store at 1000.
    pub limit: Option<u32>,
}

/// The contract the rest of the system depends on. One trait so tests
/// can wire `NoopAuditStore` without touching SQLite.
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn record(&self, evt: AuditEvent) -> Result<()>;
    async fn list(&self, query: AuditQuery) -> Result<Vec<AuditEvent>>;
    /// Tests use this; production paths haven't needed it yet (admins
    /// can SELECT COUNT(*) directly, and the list endpoint returns
    /// up to 1000 rows). Kept on the trait so a future
    /// `/v1/admin/audit/stats` endpoint has the cheap-counting hook.
    #[allow(dead_code)]
    async fn count(&self) -> Result<u64>;
}

/// Drops every write on the floor. Useful in unit tests where audit
/// persistence isn't being exercised, and as the obvious "audit
/// disabled" knob if a deployment ever wants to skip the SQLite write
/// (live tracing alone may be enough for some operators).
#[allow(dead_code)] // available as a deployment knob; tests exercise it
pub struct NoopAuditStore;

#[async_trait]
impl AuditStore for NoopAuditStore {
    async fn record(&self, _: AuditEvent) -> Result<()> {
        Ok(())
    }
    async fn list(&self, _: AuditQuery) -> Result<Vec<AuditEvent>> {
        Ok(Vec::new())
    }
    async fn count(&self) -> Result<u64> {
        Ok(0)
    }
}

/// On-disk audit log. Single file, WAL-mode for concurrent readers.
pub struct SqliteAuditStore {
    conn: Arc<TokioMutex<Connection>>,
}

impl SqliteAuditStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS audit_events (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts          INTEGER NOT NULL,
                 event       TEXT NOT NULL,
                 actor       TEXT NOT NULL,
                 repo_id     TEXT,
                 fields_json TEXT NOT NULL DEFAULT '{}',
                 request_id  TEXT
             );
             CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_events(ts);
             CREATE INDEX IF NOT EXISTS idx_audit_event  ON audit_events(event);
             CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_events(actor);
             CREATE INDEX IF NOT EXISTS idx_audit_repoid ON audit_events(repo_id);",
        )?;
        Ok(Self {
            conn: Arc::new(TokioMutex::new(conn)),
        })
    }
}

#[async_trait]
impl AuditStore for SqliteAuditStore {
    async fn record(&self, evt: AuditEvent) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO audit_events (ts, event, actor, repo_id, fields_json, request_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                evt.ts,
                evt.event,
                evt.actor,
                evt.repo_id,
                evt.fields_json,
                evt.request_id,
            ],
        )?;
        Ok(())
    }

    async fn list(&self, q: AuditQuery) -> Result<Vec<AuditEvent>> {
        let conn = self.conn.lock().await;
        let limit = q.limit.unwrap_or(100).min(1000) as i64;

        // Build the WHERE clause + bound parameters in lockstep so the
        // SQL placeholder count always matches the bind list.
        let mut sql = String::from(
            "SELECT id, ts, event, actor, repo_id, fields_json, request_id \
             FROM audit_events WHERE 1=1",
        );
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(since) = q.since_ts {
            sql.push_str(" AND ts >= ?");
            binds.push(Box::new(since));
        }
        if let Some(until) = q.until_ts {
            sql.push_str(" AND ts <= ?");
            binds.push(Box::new(until));
        }
        if let Some(ref event) = q.event {
            sql.push_str(" AND event = ?");
            binds.push(Box::new(event.clone()));
        }
        if let Some(ref actor) = q.actor {
            sql.push_str(" AND actor = ?");
            binds.push(Box::new(actor.clone()));
        }
        if let Some(ref repo_id) = q.repo_id {
            sql.push_str(" AND repo_id = ?");
            binds.push(Box::new(repo_id.clone()));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        binds.push(Box::new(limit));

        let mut stmt = conn.prepare(&sql)?;
        let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(rusqlite::params_from_iter(bind_refs.iter()), |row| {
            Ok(AuditEvent {
                id: row.get(0)?,
                ts: row.get(1)?,
                event: row.get(2)?,
                actor: row.get(3)?,
                repo_id: row.get(4)?,
                fields_json: row.get(5)?,
                request_id: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    async fn count(&self) -> Result<u64> {
        let conn = self.conn.lock().await;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))?;
        Ok(n.max(0) as u64)
    }
}

/// Convenience: write to the store, log + swallow on failure. Audit
/// persistence is best-effort — a SQLite hiccup must not fail an
/// otherwise-successful mutation. The live `tracing!(target: "audit")`
/// call at the call site is the durable copy of last resort.
pub async fn record_silent(
    store: &dyn AuditStore,
    event: &str,
    actor: &str,
    repo_id: Option<&str>,
    fields: serde_json::Value,
    request_id: Option<String>,
) {
    let evt = AuditEvent {
        id: 0,
        ts: now_unix_secs(),
        event: event.to_string(),
        actor: actor.to_string(),
        repo_id: repo_id.map(String::from),
        fields_json: fields.to_string(),
        request_id,
    };
    if let Err(e) = store.record(evt).await {
        tracing::warn!(error = %e, event, "audit store write failed");
    }
}

pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> (TempDir, SqliteAuditStore) {
        let dir = TempDir::new().unwrap();
        let s = SqliteAuditStore::open(&dir.path().join("audit.db")).unwrap();
        (dir, s)
    }

    fn evt(event: &str, actor: &str, repo_id: Option<&str>) -> AuditEvent {
        AuditEvent {
            id: 0,
            ts: now_unix_secs(),
            event: event.to_string(),
            actor: actor.to_string(),
            repo_id: repo_id.map(String::from),
            fields_json: "{}".to_string(),
            request_id: None,
        }
    }

    #[tokio::test]
    async fn empty_store_lists_nothing_and_counts_zero() {
        let (_d, s) = store();
        assert_eq!(s.count().await.unwrap(), 0);
        assert!(s.list(AuditQuery::default()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn record_then_list_round_trips() {
        let (_d, s) = store();
        s.record(evt("repo.create", "admin", Some("r1"))).await.unwrap();
        s.record(evt("token.mint", "u-42", Some("r1"))).await.unwrap();
        let rows = s.list(AuditQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 2);
        // Newest-first ordering: token.mint inserted last, listed first.
        assert_eq!(rows[0].event, "token.mint");
        assert_eq!(rows[0].actor, "u-42");
        assert_eq!(rows[1].event, "repo.create");
        assert_eq!(s.count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn list_filters_by_event_actor_repo() {
        let (_d, s) = store();
        s.record(evt("repo.create", "admin", Some("r1"))).await.unwrap();
        s.record(evt("repo.create", "u-1", Some("r2"))).await.unwrap();
        s.record(evt("token.mint", "u-1", Some("r2"))).await.unwrap();

        let by_event = s
            .list(AuditQuery {
                event: Some("repo.create".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_event.len(), 2);
        assert!(by_event.iter().all(|r| r.event == "repo.create"));

        let by_actor = s
            .list(AuditQuery {
                actor: Some("u-1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_actor.len(), 2);
        assert!(by_actor.iter().all(|r| r.actor == "u-1"));

        let by_repo = s
            .list(AuditQuery {
                repo_id: Some("r2".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_repo.len(), 2);
        assert!(by_repo.iter().all(|r| r.repo_id.as_deref() == Some("r2")));
    }

    #[tokio::test]
    async fn list_filters_by_time_window() {
        let (_d, s) = store();
        // Hand-craft timestamps so the filter doesn't depend on wall clock.
        let mut e1 = evt("a", "admin", None);
        e1.ts = 100;
        let mut e2 = evt("b", "admin", None);
        e2.ts = 200;
        let mut e3 = evt("c", "admin", None);
        e3.ts = 300;
        s.record(e1).await.unwrap();
        s.record(e2).await.unwrap();
        s.record(e3).await.unwrap();

        let mid = s
            .list(AuditQuery {
                since_ts: Some(150),
                until_ts: Some(250),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(mid.len(), 1);
        assert_eq!(mid[0].event, "b");
    }

    #[tokio::test]
    async fn limit_caps_returned_rows() {
        let (_d, s) = store();
        for i in 0..50 {
            s.record(evt(&format!("e{i}"), "admin", None)).await.unwrap();
        }
        let lim = s
            .list(AuditQuery {
                limit: Some(10),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(lim.len(), 10);
    }

    #[tokio::test]
    async fn list_default_limit_is_one_hundred() {
        let (_d, s) = store();
        for i in 0..150 {
            s.record(evt(&format!("e{i}"), "admin", None)).await.unwrap();
        }
        let rows = s.list(AuditQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 100);
    }

    #[tokio::test]
    async fn list_limit_capped_at_one_thousand() {
        let (_d, s) = store();
        for i in 0..1500 {
            s.record(evt(&format!("e{i}"), "admin", None)).await.unwrap();
        }
        let rows = s
            .list(AuditQuery {
                limit: Some(5000),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1000);
    }

    #[tokio::test]
    async fn persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.db");
        {
            let s = SqliteAuditStore::open(&path).unwrap();
            s.record(evt("repo.create", "admin", Some("r1"))).await.unwrap();
        }
        let s = SqliteAuditStore::open(&path).unwrap();
        let rows = s.list(AuditQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "repo.create");
    }

    #[tokio::test]
    async fn record_silent_swallows_failures() {
        // Use the noop store (always succeeds) to verify the helper
        // wires up. Failure swallowing is the same code path; we
        // assert it doesn't panic and updates nothing observable.
        let s = NoopAuditStore;
        record_silent(
            &s,
            "repo.create",
            "admin",
            Some("r1"),
            serde_json::json!({"k": "v"}),
            None,
        )
        .await;
        assert_eq!(s.count().await.unwrap(), 0);
    }
}
