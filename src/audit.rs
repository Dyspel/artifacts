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

use crate::db_migrate::DbPool;
use crate::error::Result;
use async_trait::async_trait;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seed for the audit hash chain — 32 zero bytes. The first row's
/// `prev_hash` is GENESIS when the table is empty or has no chained
/// rows yet (migration v2 just ran against a populated table).
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// SHA-256 of `prev_hash || ts || event || \0 || actor || \0 ||
/// repo_id || \0 || fields_json || \0 || request_id`. The `\0`
/// separators stop concatenation ambiguity (without them, distinct
/// field combinations could produce the same byte string).
///
/// Inputs come from `AuditEvent` after the caller has already
/// serialized `fields_json`; the hash is therefore deterministic
/// given the same logical event content. Stable across releases —
/// changing this function silently breaks chain verification on
/// existing rows, so it's intentionally simple.
pub fn hash_row(prev_hash: &[u8], evt: &AuditEvent) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev_hash);
    h.update(evt.ts.to_le_bytes());
    h.update(evt.event.as_bytes());
    h.update([0]);
    h.update(evt.actor.as_bytes());
    h.update([0]);
    h.update(
        evt.repo_id
            .as_ref()
            .map(crate::ids::RepoId::as_str)
            .unwrap_or("")
            .as_bytes(),
    );
    h.update([0]);
    h.update(evt.fields_json.as_bytes());
    h.update([0]);
    h.update(evt.request_id.as_deref().unwrap_or("").as_bytes());
    h.finalize().to_vec()
}

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
    pub repo_id: Option<crate::ids::RepoId>,
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
    /// Number of newest-first rows to skip before returning. Used
    /// for paginating audit history for compliance walks.
    /// Symmetric with `/v1/admin/repos?offset=`. `None` is treated
    /// as 0 by the store.
    pub offset: Option<u32>,
}

/// The contract the rest of the system depends on. One trait so tests
/// can wire `NoopAuditStore` without touching SQLite.
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn record(&self, evt: AuditEvent) -> Result<()>;
    async fn list(&self, query: AuditQuery) -> Result<Vec<AuditEvent>>;
    /// Total row count. Powers `GET /v1/admin/audit/stats` so admin
    /// tooling can surface "rows logged" without paginating through
    /// the whole table. SQLite makes this an indexed-row count —
    /// constant-time on a covering index.
    async fn count(&self) -> Result<u64>;
    /// Delete rows with `ts < cutoff_ts`. Returns the row count
    /// removed. The retention task in `spawn_prune_task` calls this
    /// on a timer; admins can also invoke directly for one-shot
    /// cleanups. A `cutoff_ts == 0` is a no-op (the table can't
    /// have negative-timestamp rows).
    async fn prune_older_than(&self, cutoff_ts: i64) -> Result<u64>;
    /// Walk the chained portion of the log and recompute each
    /// `row_hash`. Returns the number of rows whose stored hash
    /// matched, or `Err` on the first mismatch. Default impl
    /// returns `Ok(0)` so non-chain-aware stores (`NoopAuditStore`)
    /// compose without overriding.
    async fn verify_chain(&self) -> Result<ChainVerifyOk> {
        Ok(ChainVerifyOk { verified: 0 })
    }
    /// Exercise the store's write path with a transient row that's
    /// immediately deleted. Mirrors `TokenStore::probe_write` — the
    /// readiness probe calls this so an unwritable backing store
    /// surfaces at probe time rather than at the next real mutation.
    async fn probe_write(&self) -> Result<()> {
        Ok(())
    }
}

/// Drops every write on the floor. Used by tests where audit
/// persistence isn't being exercised — gated `#[cfg(test)]` because
/// no production wiring instantiates it (deployments that don't want
/// durable history can point the SQLite path at a tmpfs).
#[cfg(test)]
pub struct NoopAuditStore;

#[cfg(test)]
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
    async fn prune_older_than(&self, _: i64) -> Result<u64> {
        Ok(0)
    }
}

/// On-disk audit log. Single file, WAL-mode for concurrent readers
/// via an `r2d2` connection pool.
pub struct SqliteAuditStore {
    conn: DbPool,
}

const MIGRATIONS: [crate::db_migrate::Migration; 2] = [
    crate::db_migrate::Migration {
        version: 1,
        name: "init",
        up: |c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS audit_events (
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
            )
        },
    },
    crate::db_migrate::Migration {
        // Tamper-evidence: each row's `row_hash` chains to the
        // previous row's `row_hash` via `prev_hash`. Rows inserted
        // before this migration ran keep both columns NULL and stand
        // outside the chain — the chain still detects edits to any
        // row written after the upgrade, which is the practical
        // threat model (live audit data).
        version: 2,
        name: "add_hash_chain",
        up: |c| {
            crate::db_migrate::add_column_if_missing(c, "audit_events", "prev_hash", "BLOB")?;
            crate::db_migrate::add_column_if_missing(c, "audit_events", "row_hash", "BLOB")
        },
    },
];

crate::db_migrate::sqlite_store_boilerplate!(SqliteAuditStore, "audit", MIGRATIONS);

/// Result of a successful `verify_chain` run.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct ChainVerifyOk {
    /// Number of rows whose stored `row_hash` matched the recomputed
    /// hash. Rows that predate v2 (NULL `row_hash`) are not counted.
    pub verified: u64,
}

#[async_trait]
impl AuditStore for SqliteAuditStore {
    async fn record(&self, evt: AuditEvent) -> Result<()> {
        let mut conn = self.pooled()?;
        // The SELECT-tail-then-INSERT pair MUST be atomic against
        // other recorders, or two concurrent writers read the same
        // tail and insert two rows sharing one `prev_hash` — a forked
        // chain that `verify_chain` reports as tampering. A plain
        // pooled connection gives each writer its own connection, so
        // the old "same lock" assumption (true under the single
        // `Mutex<Connection>`) no longer holds. `BEGIN IMMEDIATE`
        // takes SQLite's write lock up front, serializing the pair
        // (other writers block on busy_timeout, then retry as a 503).
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // The first row of a fresh chain uses GENESIS_HASH (all-zero
        // 32 bytes); rows that predate the v2 migration have NULL
        // row_hash and are not part of the chain — we still chain
        // forward from there using GENESIS_HASH so the new tail is
        // self-consistent. Only an empty result falls back to
        // GENESIS; a real DB error propagates (the old `unwrap_or`
        // silently restarted the chain mid-table on any failure,
        // which itself breaks verification).
        let prev_hash: Vec<u8> = match tx.query_row(
            "SELECT row_hash FROM audit_events
                 WHERE row_hash IS NOT NULL
                 ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(h) => h,
            Err(rusqlite::Error::QueryReturnedNoRows) => GENESIS_HASH.to_vec(),
            Err(e) => return Err(e.into()),
        };
        let row_hash = hash_row(&prev_hash, &evt);
        tx.execute(
            "INSERT INTO audit_events
               (ts, event, actor, repo_id, fields_json, request_id, prev_hash, row_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                evt.ts,
                evt.event,
                evt.actor,
                evt.repo_id.as_ref().map(crate::ids::RepoId::as_str),
                evt.fields_json,
                evt.request_id,
                prev_hash,
                row_hash,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    async fn list(&self, q: AuditQuery) -> Result<Vec<AuditEvent>> {
        let conn = self.pooled()?;
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
        sql.push_str(" ORDER BY id DESC LIMIT ? OFFSET ?");
        binds.push(Box::new(limit));
        binds.push(Box::new(q.offset.unwrap_or(0) as i64));

        let mut stmt = conn.prepare(&sql)?;
        let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        let rows = stmt.query_map(rusqlite::params_from_iter(bind_refs.iter()), |row| {
            Ok(AuditEvent {
                id: row.get(0)?,
                ts: row.get(1)?,
                event: row.get(2)?,
                actor: row.get(3)?,
                repo_id: row
                    .get::<_, Option<String>>(4)?
                    .and_then(|s| crate::ids::RepoId::try_from(s).ok()),
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
        let conn = self.pooled()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))?;
        Ok(n.max(0) as u64)
    }

    async fn prune_older_than(&self, cutoff_ts: i64) -> Result<u64> {
        let conn = self.pooled()?;
        let affected =
            conn.execute("DELETE FROM audit_events WHERE ts < ?1", params![cutoff_ts])?;
        Ok(affected as u64)
    }

    async fn probe_write(&self) -> Result<()> {
        let conn = self.pooled()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _probe (k INTEGER PRIMARY KEY);
             INSERT OR REPLACE INTO _probe (k) VALUES (1);
             DELETE FROM _probe WHERE k = 1;",
        )?;
        Ok(())
    }

    async fn verify_chain(&self) -> Result<ChainVerifyOk> {
        let conn = self.pooled()?;
        let mut stmt = conn.prepare(
            "SELECT id, ts, event, actor, repo_id, fields_json, request_id,
                    prev_hash, row_hash
             FROM audit_events
             WHERE row_hash IS NOT NULL
             ORDER BY id ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut expected_prev: Option<Vec<u8>> = None;
        let mut verified: u64 = 0;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let evt = AuditEvent {
                id,
                ts: row.get(1)?,
                event: row.get(2)?,
                actor: row.get(3)?,
                repo_id: row
                    .get::<_, Option<String>>(4)?
                    .and_then(|s| crate::ids::RepoId::try_from(s).ok()),
                fields_json: row.get(5)?,
                request_id: row.get(6)?,
            };
            let stored_prev: Vec<u8> = row.get(7)?;
            let stored_hash: Vec<u8> = row.get(8)?;
            // First chained row's `prev_hash` must equal GENESIS;
            // subsequent rows chain to the previously-verified hash.
            let expected = expected_prev.as_deref().unwrap_or(&GENESIS_HASH);
            if stored_prev != expected {
                return Err(crate::error::Error::Other(anyhow::anyhow!(
                    "audit chain broken at row id={id}: prev_hash mismatch"
                )));
            }
            let recomputed = hash_row(&stored_prev, &evt);
            if recomputed != stored_hash {
                return Err(crate::error::Error::Other(anyhow::anyhow!(
                    "audit chain broken at row id={id}: row_hash mismatch"
                )));
            }
            expected_prev = Some(stored_hash);
            verified += 1;
        }
        Ok(ChainVerifyOk { verified })
    }
}

/// Spawn a background task that calls `prune_older_than` on a timer.
/// Mirror of `tokens::spawn_prune_task` for the audit store.
///
/// `retention` is how long an event must survive before becoming
/// eligible for pruning; `tick` is how often the task wakes up. A
/// `retention == Duration::ZERO` (or `0` days from the CLI flag)
/// disables pruning entirely — useful for compliance scenarios that
/// require indefinite retention until an external archiver moves
/// rows out.
///
/// First prune fires after the first `tick` (not at startup) so it
/// doesn't contend with boot-time work.
///
/// Also refreshes the `artifacts_audit_events_stored_total` gauge at
/// the tail of each prune sweep — the dedicated 60s refresher keeps
/// the gauge fresh between sweeps, but a sweep that deletes a large
/// retention-eligible batch should be reflected immediately rather
/// than waiting up to a minute for the next ticker fire.
pub fn spawn_prune_task(
    store: Arc<dyn AuditStore>,
    tick: std::time::Duration,
    retention: std::time::Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if retention.is_zero() {
        tracing::info!("audit retention disabled — prune task not spawned");
        return None;
    }
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        // Skip the immediate fire so prune doesn't run during boot.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let cutoff = now_unix_secs().saturating_sub(retention.as_secs() as i64);
                    match store.prune_older_than(cutoff).await {
                        Ok(0) => {}
                        Ok(n) => tracing::info!(pruned = n, "audit prune"),
                        Err(e) => tracing::error!(error = %e, "audit prune failed"),
                    }
                    refresh_events_stored_gauge(&*store).await;
                }
                _ = cancel.cancelled() => return,
            }
        }
    }))
}

/// One-shot — read the audit event count and publish to the
/// `artifacts_audit_events_stored_total` gauge. Distinct from the
/// monotonic `artifacts_audit_events_total{event}` counter (which
/// tracks lifetime emissions): this gauge is "rows currently in the
/// table," which goes *down* when retention prunes. Operators watch
/// it to confirm the prune sweep is actually deleting things, and to
/// catch unbounded growth before disk fills.
///
/// Failure is best-effort logged; the gauge keeps its previous
/// value rather than going to zero on a transient SQLite error.
pub async fn refresh_events_stored_gauge(store: &dyn AuditStore) {
    match store.count().await {
        Ok(n) => metrics::gauge!("artifacts_audit_events_stored_total").set(n as f64),
        Err(e) => tracing::warn!(error = %e, "audit-events-stored gauge refresh failed"),
    }
}

/// Spawn a dedicated refresher for the audit-events-stored gauge.
/// Same shape as the token / webhook / repo gauges — 60s tick keeps
/// the value fresh enough for capacity dashboards while a SQLite
/// `SELECT COUNT(*)` against an indexed table stays cheap.
pub fn spawn_events_stored_gauge_refresher(
    store: Arc<dyn AuditStore>,
    tick: std::time::Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        // The caller populates the gauge synchronously at startup, so
        // skip the immediate fire and let the loop own all subsequent
        // refreshes.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => refresh_events_stored_gauge(&*store).await,
                _ = cancel.cancelled() => return,
            }
        }
    })
}

/// Emit an audit event: both as a live `tracing::info!(target: "audit",
/// …)` line *and* into the durable `AuditStore`. Single helper so call
/// sites can't drop one half of the pair.
///
/// The `fields` value is serialized as one JSON blob in the tracing
/// line (downstream log processors can re-parse it) — we trade
/// per-key structured tracing fields for call-site brevity and the
/// guarantee that the live and durable copies agree by construction.
pub async fn record(
    store: &dyn AuditStore,
    event: &str,
    actor: &str,
    repo_id: Option<&crate::ids::RepoId>,
    fields: serde_json::Value,
    request_id: Option<String>,
) {
    tracing::info!(
        target: "audit",
        event,
        actor,
        repo_id = repo_id.map(crate::ids::RepoId::as_str),
        fields = %fields,
    );
    record_silent(store, event, actor, repo_id, fields, request_id).await;
}

/// Lower-level: write to the store only, log + swallow on failure.
/// Audit persistence is best-effort — a SQLite hiccup must not fail
/// an otherwise-successful mutation. Called only from [`record`]; not
/// public because every production call site wants both halves (live
/// tracing + durable write).
async fn record_silent(
    store: &dyn AuditStore,
    event: &str,
    actor: &str,
    repo_id: Option<&crate::ids::RepoId>,
    fields: serde_json::Value,
    request_id: Option<String>,
) {
    // Prometheus counter — labeled by event kind so dashboards can
    // chart `repo.create` rate vs `token.revoke` rate independently.
    // Always-on (cardinality is bounded by the audit-event vocabulary
    // — currently 11 kinds: server.{start,shutdown}, repo.{create,
    // fork,delete}, token.{mint,revoke,rotate}, admin.{token,jwt_key,
    // webhook_key}.rotate) and incremented up front so a SQLite hiccup
    // doesn't drop the count. The `event` parameter is `&str` rather
    // than an enum to keep callers ergonomic; the vocabulary is
    // enforced by convention. J2 audit confirmed every audit::record
    // call site passes a string literal from the list above — no
    // user-controllable value reaches this label.
    metrics::counter!("artifacts_audit_events_total", "event" => event.to_string()).increment(1);
    let evt = AuditEvent {
        id: 0,
        ts: now_unix_secs(),
        event: event.to_string(),
        actor: actor.to_string(),
        repo_id: repo_id.cloned(),
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
            repo_id: repo_id.map(|s| crate::ids::RepoId::try_from(s).unwrap()),
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
    async fn noop_store_uses_trait_default_verify_and_probe() {
        // NoopAuditStore overrides record/list/count/prune but not
        // verify_chain / probe_write — so this exercises the defaults.
        let s = NoopAuditStore;
        assert_eq!(s.verify_chain().await.unwrap().verified, 0);
        s.probe_write().await.unwrap();
    }

    #[tokio::test]
    async fn spawn_prune_task_disabled_for_zero_retention() {
        let store: Arc<dyn AuditStore> = Arc::new(NoopAuditStore);
        let handle = spawn_prune_task(
            store,
            std::time::Duration::from_secs(3600),
            std::time::Duration::ZERO,
            tokio_util::sync::CancellationToken::new(),
        );
        assert!(handle.is_none(), "zero retention must not spawn a task");
    }

    #[tokio::test]
    async fn refresh_events_stored_gauge_runs_without_panic() {
        let (_d, s) = store();
        refresh_events_stored_gauge(&s).await;
    }

    #[tokio::test]
    async fn list_reconstructs_repo_id_from_row() {
        let (_d, s) = store();
        s.record(evt("repo.create", "admin", Some("repo-a")))
            .await
            .unwrap();
        let rows = s.list(AuditQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].repo_id.as_ref().map(crate::ids::RepoId::as_str),
            Some("repo-a")
        );
    }

    #[tokio::test]
    async fn record_then_list_round_trips() {
        let (_d, s) = store();
        s.record(evt("repo.create", "admin", Some("repo-1")))
            .await
            .unwrap();
        s.record(evt("token.mint", "u-42", Some("repo-1")))
            .await
            .unwrap();
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
        s.record(evt("repo.create", "admin", Some("repo-1")))
            .await
            .unwrap();
        s.record(evt("repo.create", "u-1", Some("repo-2")))
            .await
            .unwrap();
        s.record(evt("token.mint", "u-1", Some("repo-2")))
            .await
            .unwrap();

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
                repo_id: Some("repo-2".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_repo.len(), 2);
        assert!(by_repo
            .iter()
            .all(|r| r.repo_id.as_ref().map(crate::ids::RepoId::as_str) == Some("repo-2")));
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
            s.record(evt(&format!("e{i}"), "admin", None))
                .await
                .unwrap();
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
    async fn offset_skips_newest_rows() {
        // Insert 5 events; query limit=2 offset=1 must return rows
        // 4 and 3 (in newest-first order), skipping the very newest.
        // This is the contract callers paginating compliance-walks
        // depend on: page N+1 starts where page N ended.
        let (_d, s) = store();
        for i in 0..5 {
            s.record(evt(&format!("e{i}"), "admin", None))
                .await
                .unwrap();
        }
        let page = s
            .list(AuditQuery {
                limit: Some(2),
                offset: Some(1),
                ..Default::default()
            })
            .await
            .unwrap();
        let names: Vec<&str> = page.iter().map(|r| r.event.as_str()).collect();
        assert_eq!(names, vec!["e3", "e2"]);
    }

    #[tokio::test]
    async fn offset_past_end_returns_empty() {
        let (_d, s) = store();
        s.record(evt("only", "admin", None)).await.unwrap();
        let page = s
            .list(AuditQuery {
                limit: Some(10),
                offset: Some(50),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_default_limit_is_one_hundred() {
        let (_d, s) = store();
        for i in 0..150 {
            s.record(evt(&format!("e{i}"), "admin", None))
                .await
                .unwrap();
        }
        let rows = s.list(AuditQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 100);
    }

    #[tokio::test]
    async fn list_limit_capped_at_one_thousand() {
        let (_d, s) = store();
        for i in 0..1500 {
            s.record(evt(&format!("e{i}"), "admin", None))
                .await
                .unwrap();
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
            s.record(evt("repo.create", "admin", Some("repo-1")))
                .await
                .unwrap();
        }
        let s = SqliteAuditStore::open(&path).unwrap();
        let rows = s.list(AuditQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "repo.create");
    }

    #[tokio::test]
    async fn prune_older_than_removes_only_old_rows() {
        let (_d, s) = store();
        let mut e_old = evt("a", "admin", None);
        e_old.ts = 100;
        let mut e_mid = evt("b", "admin", None);
        e_mid.ts = 200;
        let mut e_new = evt("c", "admin", None);
        e_new.ts = 300;
        s.record(e_old).await.unwrap();
        s.record(e_mid).await.unwrap();
        s.record(e_new).await.unwrap();

        // Cutoff = 200: rows with ts < 200 are removed (the `a` row).
        let removed = s.prune_older_than(200).await.unwrap();
        assert_eq!(removed, 1);
        let rows = s.list(AuditQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.ts >= 200));
    }

    #[tokio::test]
    async fn prune_with_zero_cutoff_is_noop() {
        let (_d, s) = store();
        s.record(evt("a", "admin", None)).await.unwrap();
        let removed = s.prune_older_than(0).await.unwrap();
        assert_eq!(removed, 0);
        assert_eq!(s.count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn prune_idempotent_on_empty_store() {
        let (_d, s) = store();
        let removed = s.prune_older_than(now_unix_secs()).await.unwrap();
        assert_eq!(removed, 0);
    }

    #[tokio::test]
    async fn record_silent_swallows_failures() {
        // Use the noop store (always succeeds) to verify the helper
        // wires up. Failure swallowing is the same code path; we
        // assert it doesn't panic and updates nothing observable.
        let s = NoopAuditStore;
        let rid = crate::ids::RepoId::try_from("repo-1").unwrap();
        record_silent(
            &s,
            "repo.create",
            "admin",
            Some(&rid),
            serde_json::json!({"k": "v"}),
            None,
        )
        .await;
        assert_eq!(s.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn empty_chain_verifies_zero_rows() {
        let (_d, s) = store();
        let ok = s.verify_chain().await.unwrap();
        assert_eq!(ok.verified, 0);
    }

    #[tokio::test]
    async fn fresh_inserts_chain_correctly() {
        let (_d, s) = store();
        for i in 0..3 {
            s.record(evt(&format!("e{i}"), "admin", None))
                .await
                .unwrap();
        }
        let ok = s.verify_chain().await.unwrap();
        assert_eq!(ok.verified, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_records_keep_the_chain_intact() {
        // Regression for the pooled-connection chain fork: before
        // `record` wrapped SELECT-tail + INSERT in a BEGIN IMMEDIATE
        // transaction, two recorders on separate pool connections
        // could read the same tail and insert rows sharing one
        // `prev_hash`, which `verify_chain` reports as tampering.
        // Fire many records concurrently across worker threads and
        // assert every one chained (no fork, no lost row).
        let (_d, s) = store();
        let s = std::sync::Arc::new(s);
        const N: u64 = 64;
        let mut handles = Vec::new();
        for i in 0..N {
            let s = s.clone();
            handles.push(tokio::spawn(async move {
                s.record(evt(&format!("e{i}"), "admin", None))
                    .await
                    .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let ok = s.verify_chain().await.unwrap();
        assert_eq!(
            ok.verified, N,
            "all {N} concurrent inserts must chain without a fork"
        );
    }

    #[tokio::test]
    async fn tampered_field_breaks_chain() {
        // Insert two events, then directly rewrite the first row's
        // event name in SQLite without recomputing the hash. The
        // verifier must catch the mismatch at row id=1.
        let (dir, s) = store();
        s.record(evt("e1", "admin", None)).await.unwrap();
        s.record(evt("e2", "admin", None)).await.unwrap();
        // Sneak around the AuditStore trait — direct SQLite write.
        let conn = rusqlite::Connection::open(dir.path().join("audit.db")).unwrap();
        conn.execute(
            "UPDATE audit_events SET event = 'TAMPERED' WHERE id = 1",
            [],
        )
        .unwrap();
        drop(conn);
        let err = s.verify_chain().await.expect_err("expected ChainBreak");
        assert!(
            err.to_string().contains("audit chain broken"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn tampered_prev_hash_breaks_chain() {
        let (dir, s) = store();
        s.record(evt("a", "admin", None)).await.unwrap();
        s.record(evt("b", "admin", None)).await.unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("audit.db")).unwrap();
        // Overwrite row id=2's prev_hash with bogus bytes — row_hash
        // is no longer derivable from prev_hash, so verification
        // must fail on the prev_hash branch (the recompute would
        // also fail, but prev_hash mismatch is the first check).
        conn.execute(
            "UPDATE audit_events SET prev_hash = X'DEADBEEF' WHERE id = 2",
            [],
        )
        .unwrap();
        drop(conn);
        assert!(s.verify_chain().await.is_err());
    }

    /// Tampering a mid-chain row must (a) be detected and (b) report the
    /// offending row id — not the last row, not a generic "chain broken"
    /// without the specific id. This is the property that makes admin
    /// tooling useful for forensics: "row K is corrupt" tells a
    /// responder which entry to investigate.
    #[tokio::test]
    async fn tampered_mid_chain_row_names_offending_id() {
        let (dir, s) = store();
        for i in 0..5 {
            s.record(evt(&format!("e{i}"), "admin", None))
                .await
                .unwrap();
        }
        // Tamper row 3's fields_json. The verifier walks ASC and must
        // halt on row 3 — not row 4 or row 5 — because the chain is
        // self-recomputing and the first mismatch wins.
        let conn = rusqlite::Connection::open(dir.path().join("audit.db")).unwrap();
        conn.execute(
            "UPDATE audit_events SET fields_json = '{\"x\":1}' WHERE id = 3",
            [],
        )
        .unwrap();
        drop(conn);
        let err = s.verify_chain().await.expect_err("expected ChainBreak");
        let msg = err.to_string();
        assert!(msg.contains("audit chain broken"), "msg was: {msg}");
        assert!(
            msg.contains("id=3"),
            "error must identify the offending row (id=3); was: {msg}"
        );
        // And NOT mention the later rows — those aren't where the
        // first break occurred. If the verifier kept walking and
        // reported the last mismatch, a responder would chase the
        // wrong row.
        assert!(
            !msg.contains("id=4") && !msg.contains("id=5"),
            "first-mismatch-wins violated; msg: {msg}"
        );
    }

    /// Tampering by ROW DELETION must also be detected — an attacker
    /// who removes a damaging audit row can't slip past verification.
    /// When row K is deleted, row K+1's stored `prev_hash` still
    /// references the (now-missing) row K's hash, but the verifier's
    /// running `expected_prev` was set from row K-1. The mismatch
    /// catches the gap. The offending row reported is K+1, the first
    /// row that fails the walk.
    #[tokio::test]
    async fn deleted_row_breaks_chain_at_successor() {
        let (dir, s) = store();
        for i in 0..5 {
            s.record(evt(&format!("e{i}"), "admin", None))
                .await
                .unwrap();
        }
        let conn = rusqlite::Connection::open(dir.path().join("audit.db")).unwrap();
        // Delete row 3.
        conn.execute("DELETE FROM audit_events WHERE id = 3", [])
            .unwrap();
        drop(conn);
        let err = s
            .verify_chain()
            .await
            .expect_err("expected ChainBreak after deletion");
        let msg = err.to_string();
        assert!(msg.contains("audit chain broken"), "msg was: {msg}");
        // The successor row (id=4) is where the chain first
        // detects the gap.
        assert!(
            msg.contains("id=4"),
            "deletion must surface at the successor row (id=4); was: {msg}"
        );
    }

    /// Direct row_hash overwrite (not prev_hash, not the row fields):
    /// the stored hash diverges from `hash_row(prev_hash, evt)` so
    /// the row_hash branch of the verifier fires. Pins that the
    /// verifier's recompute step actually runs.
    #[tokio::test]
    async fn tampered_row_hash_breaks_chain() {
        let (dir, s) = store();
        s.record(evt("a", "admin", None)).await.unwrap();
        s.record(evt("b", "admin", None)).await.unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("audit.db")).unwrap();
        // Stomp row 1's stored row_hash with bogus 32 bytes. prev_hash
        // is fine, fields are fine — only the stored hash is wrong.
        conn.execute(
            "UPDATE audit_events SET row_hash = randomblob(32) WHERE id = 1",
            [],
        )
        .unwrap();
        drop(conn);
        let err = s
            .verify_chain()
            .await
            .expect_err("expected ChainBreak on row_hash mismatch");
        let msg = err.to_string();
        assert!(
            msg.contains("audit chain broken") && msg.contains("id=1"),
            "row_hash tamper must surface at id=1; was: {msg}"
        );
    }

    #[test]
    fn hash_row_is_deterministic_and_distinguishes_inputs() {
        let evt_a = AuditEvent {
            id: 0,
            ts: 1000,
            event: "x".into(),
            actor: "admin".into(),
            repo_id: None,
            fields_json: "{}".into(),
            request_id: None,
        };
        let mut evt_b = evt_a.clone();
        evt_b.actor = "user".into();
        let h_a1 = hash_row(&GENESIS_HASH, &evt_a);
        let h_a2 = hash_row(&GENESIS_HASH, &evt_a);
        let h_b = hash_row(&GENESIS_HASH, &evt_b);
        assert_eq!(h_a1, h_a2, "same input must hash the same");
        assert_ne!(h_a1, h_b, "different actors must hash differently");
        assert_eq!(h_a1.len(), 32, "SHA-256 output is 32 bytes");
    }

    // -----------------------------------------------------------------------
    // AuditQuery filter-branch coverage
    // -----------------------------------------------------------------------

    /// Insert rows with distinct timestamps and verify that `since_ts` and
    /// `until_ts` filters work individually (covering the two SQL branches
    /// that are only exercised when the fields are `Some`).
    #[tokio::test]
    async fn list_since_ts_filter_only() {
        let (_d, s) = store();
        let mut e1 = evt("a", "u1", None);
        e1.ts = 50;
        let mut e2 = evt("b", "u1", None);
        e2.ts = 150;
        s.record(e1).await.unwrap();
        s.record(e2).await.unwrap();
        let rows = s
            .list(AuditQuery {
                since_ts: Some(100),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "b");
    }

    #[tokio::test]
    async fn list_until_ts_filter_only() {
        let (_d, s) = store();
        let mut e1 = evt("a", "u1", None);
        e1.ts = 50;
        let mut e2 = evt("b", "u1", None);
        e2.ts = 150;
        s.record(e1).await.unwrap();
        s.record(e2).await.unwrap();
        let rows = s
            .list(AuditQuery {
                until_ts: Some(100),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "a");
    }

    /// `event` filter: only rows whose event field matches exactly.
    #[tokio::test]
    async fn list_event_filter() {
        let (_d, s) = store();
        s.record(evt("repo.create", "admin", None)).await.unwrap();
        s.record(evt("token.mint", "admin", None)).await.unwrap();
        let rows = s
            .list(AuditQuery {
                event: Some("repo.create".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "repo.create");
    }

    /// `actor` filter: only rows whose actor matches.
    #[tokio::test]
    async fn list_actor_filter() {
        let (_d, s) = store();
        s.record(evt("e1", "alice", None)).await.unwrap();
        s.record(evt("e2", "bob", None)).await.unwrap();
        let rows = s
            .list(AuditQuery {
                actor: Some("alice".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actor, "alice");
    }

    /// `repo_id` filter: only rows whose repo_id matches.
    #[tokio::test]
    async fn list_repo_id_filter() {
        let (_d, s) = store();
        s.record(evt("e1", "admin", Some("repo-one")))
            .await
            .unwrap();
        s.record(evt("e2", "admin", Some("repo-two")))
            .await
            .unwrap();
        s.record(evt("e3", "admin", None)).await.unwrap();
        let rows = s
            .list(AuditQuery {
                repo_id: Some("repo-one".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].repo_id.as_ref().map(crate::ids::RepoId::as_str),
            Some("repo-one")
        );
    }

    /// All five filter fields combined.
    #[tokio::test]
    async fn list_all_filters_combined() {
        let (_d, s) = store();
        // Row that matches all filters.
        let mut match_row = evt("repo.create", "admin", Some("repo-a"));
        match_row.ts = 200;
        // Row that doesn't match on ts.
        let mut ts_miss = evt("repo.create", "admin", Some("repo-a"));
        ts_miss.ts = 50;
        // Row that doesn't match on event.
        let mut ev_miss = evt("token.mint", "admin", Some("repo-a"));
        ev_miss.ts = 200;
        s.record(match_row).await.unwrap();
        s.record(ts_miss).await.unwrap();
        s.record(ev_miss).await.unwrap();
        let rows = s
            .list(AuditQuery {
                since_ts: Some(100),
                until_ts: Some(300),
                event: Some("repo.create".into()),
                actor: Some("admin".into()),
                repo_id: Some("repo-a".into()),
                limit: Some(10),
                offset: None,
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event, "repo.create");
    }

    /// `verify_chain` on a non-empty store must report the correct count.
    #[tokio::test]
    async fn verify_chain_returns_correct_count_for_populated_chain() {
        let (_d, s) = store();
        for i in 0..7 {
            s.record(evt(&format!("e{i}"), "admin", None))
                .await
                .unwrap();
        }
        let ok = s.verify_chain().await.unwrap();
        assert_eq!(ok.verified, 7, "verify_chain must count all chained rows");
    }

    /// `count` after inserts and after pruning reflects actual row count.
    #[tokio::test]
    async fn count_reflects_inserts_and_prune() {
        let (_d, s) = store();
        assert_eq!(s.count().await.unwrap(), 0);
        for i in 0..5 {
            let mut e = evt(&format!("e{i}"), "admin", None);
            e.ts = i as i64 * 100 + 100;
            s.record(e).await.unwrap();
        }
        assert_eq!(s.count().await.unwrap(), 5);
        // Prune rows older than ts=300 (rows with ts < 300 → e0@100, e1@200).
        let pruned = s.prune_older_than(300).await.unwrap();
        assert_eq!(pruned, 2);
        assert_eq!(s.count().await.unwrap(), 3);
    }

    /// `probe_write` on a real store must succeed.
    #[tokio::test]
    async fn probe_write_succeeds_on_real_store() {
        let (_d, s) = store();
        s.probe_write().await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Uncovered branch coverage
    // -----------------------------------------------------------------------

    /// `record_silent` calls `store.record(evt)` and logs-swallows on failure.
    /// We exercise the Err branch by using a store implementation that always
    /// returns an error from `record`.
    #[tokio::test]
    async fn record_silent_swallows_store_error() {
        struct AlwaysErrStore;
        #[async_trait::async_trait]
        impl AuditStore for AlwaysErrStore {
            async fn record(&self, _: AuditEvent) -> Result<()> {
                Err(crate::error::Error::Other(anyhow::anyhow!(
                    "injected error"
                )))
            }
            async fn list(&self, _: AuditQuery) -> Result<Vec<AuditEvent>> {
                Ok(Vec::new())
            }
            async fn count(&self) -> Result<u64> {
                Ok(0)
            }
            async fn prune_older_than(&self, _: i64) -> Result<u64> {
                Ok(0)
            }
        }
        let s = AlwaysErrStore;
        // Must not panic; the error is swallowed.
        record_silent(
            &s,
            "repo.create",
            "admin",
            None,
            serde_json::json!({}),
            None,
        )
        .await;
        // Verify count is still 0 (no write happened).
        assert_eq!(s.count().await.unwrap(), 0);
    }

    /// `refresh_events_stored_gauge` with a store whose `count` always fails —
    /// the Err branch is logged but must not panic.
    #[tokio::test]
    async fn refresh_events_stored_gauge_err_branch_does_not_panic() {
        struct CountErrStore;
        #[async_trait::async_trait]
        impl AuditStore for CountErrStore {
            async fn record(&self, _: AuditEvent) -> Result<()> {
                Ok(())
            }
            async fn list(&self, _: AuditQuery) -> Result<Vec<AuditEvent>> {
                Ok(Vec::new())
            }
            async fn count(&self) -> Result<u64> {
                Err(crate::error::Error::Other(anyhow::anyhow!("count broken")))
            }
            async fn prune_older_than(&self, _: i64) -> Result<u64> {
                Ok(0)
            }
        }
        // Must not panic even though count() returns Err.
        refresh_events_stored_gauge(&CountErrStore).await;
    }

    /// `spawn_prune_task` fires the tick/prune/gauge loop. We verify that the
    /// Ok(n > 0) and Err branches inside the task loop are reachable by using
    /// a real store where we seed a row old enough to prune, then cancel.
    ///
    /// Because the loop only fires after the first tick, we use a very short
    /// tick so the test doesn't take long.
    #[tokio::test]
    async fn spawn_prune_task_prunes_old_rows_and_cancels() {
        let (_d, s) = store();
        // Seed an event with ts=1 (ancient).
        let mut e = evt("old", "admin", None);
        e.ts = 1;
        s.record(e).await.unwrap();
        assert_eq!(s.count().await.unwrap(), 1);

        let store_arc: std::sync::Arc<dyn AuditStore> = std::sync::Arc::new(s);
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = spawn_prune_task(
            store_arc.clone(),
            std::time::Duration::from_millis(10),
            // retention = 1 second: anything older than 1 second from now
            // is prunable — the ts=1 row qualifies.
            std::time::Duration::from_secs(1),
            cancel.clone(),
        )
        .expect("task must be spawned with non-zero retention");

        // Give the prune loop time to fire once.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();
        let _ = handle.await;

        // The ancient row should have been pruned.
        assert_eq!(
            store_arc.count().await.unwrap(),
            0,
            "prune loop must have deleted the ancient row"
        );
    }

    /// list() with non-empty result set covers the `for r in rows { out.push(r?) }` branch.
    #[tokio::test]
    async fn list_non_empty_result_iterates_rows() {
        let (_d, s) = store();
        s.record(evt("x", "admin", None)).await.unwrap();
        s.record(evt("y", "admin", None)).await.unwrap();
        let rows = s.list(AuditQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 2);
        // Newest-first: y was inserted after x.
        assert_eq!(rows[0].event, "y");
        assert_eq!(rows[1].event, "x");
    }
}
