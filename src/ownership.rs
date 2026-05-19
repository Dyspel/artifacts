//! Repo ownership — who is allowed to REST-poke a given repo.
//!
//! Auth gave us a `Principal` from the JWT (`Admin` or `User { subject }`).
//! Ownership is the other half: every repo has a recorded owner
//! `subject` (or `NULL` for repos created under the admin token before
//! ownership tracking existed). A REST call succeeds iff the caller is
//! `Admin`, or the caller's `subject` matches the repo's owner.
//!
//! This module is deliberately minimal — trait + SQLite impl + one
//! enforcement helper. No generic ACL model, no groups, no sharing.
//! If Dyspel later wants "user X grants user Y read access to repo Z,"
//! that's a grants table on top of this.
//!
//! ## Why a separate store?
//!
//! It could have been a column on `tokens` or folded into `Storage`. It
//! isn't, because ownership has a different lifecycle than either:
//!
//! - Tokens come and go (mint, expire, revoke) but the owner of a repo
//!   doesn't change when a token is revoked.
//! - The `Storage` trait is about bytes on disk; ownership is a
//!   permission fact about a logical resource. Coupling them would
//!   force any future `ChunkedStorage` to reimplement ownership too.
//!
//! The SQLite impl shares the same DB file as `SqliteTokenStore` —
//! separate connection, separate table, WAL-mode concurrency.

use crate::{
    auth::Principal,
    error::{Error, Result},
};
use async_trait::async_trait;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as TokioMutex;

/// Records which user "owns" each repo.
#[async_trait]
pub trait OwnershipStore: Send + Sync {
    /// Record that `repo_id` is owned by `owner` (a JWT subject). Pass
    /// `None` when the creator is admin — we still record the row so
    /// `get_owner` can distinguish "no such repo" from "admin-created".
    async fn record_owner(&self, repo_id: &str, owner: Option<&str>) -> Result<()>;

    /// Read the owner for a repo. Returns:
    /// - `Ok(Some(Some(subject)))` — user-owned
    /// - `Ok(Some(None))` — admin-created; no user owner
    /// - `Ok(None)` — no ownership record at all (legacy / pre-ownership)
    async fn get_owner(&self, repo_id: &str) -> Result<Option<Option<String>>>;

    /// Remove the ownership record (called after a repo is deleted).
    /// Idempotent; returning Ok when the row didn't exist is fine.
    async fn delete(&self, repo_id: &str) -> Result<()>;

    /// Count the repos currently owned by `subject`. Used for the
    /// per-user repo-count quota check on create / fork.
    ///
    /// We enforce the quota in the handler after recording the new
    /// owner, because the race between check-then-insert is ~milliseconds
    /// on a single node and the quota is a soft limit (200 requested →
    /// 200 created) rather than a hard invariant. Under pathological
    /// concurrent-create load you can overshoot by a few; if that ever
    /// matters, wrap this in a `SELECT count(*) ... FOR UPDATE` or move
    /// the check into the same transaction as the INSERT.
    async fn count_by_owner(&self, subject: &str) -> Result<u64>;

    /// List every repo the store knows about. Admin-only surface —
    /// intended for the inspection endpoint and the GUI visualizer.
    /// Order is `created_at DESC` so the newest repos show first.
    async fn list_all(&self) -> Result<Vec<RepoRow>>;

    /// Page-shaped variant of `list_all` for the admin REST surface.
    /// Same ordering (`created_at DESC`); the implementation pushes
    /// `LIMIT`/`OFFSET` into SQL so a paginated request doesn't load
    /// the entire table into Rust memory just to slice it.
    ///
    /// Default impl falls back to `list_all` + slice so non-SQL
    /// stores (the in-memory test store) don't need to special-case
    /// this. Production stores override.
    async fn list_paginated(&self, limit: u32, offset: u32) -> Result<Vec<RepoRow>> {
        let all = self.list_all().await?;
        let off = offset as usize;
        if off >= all.len() {
            return Ok(Vec::new());
        }
        let end = (off + limit as usize).min(all.len());
        Ok(all[off..end].to_vec())
    }

    /// Total row count for the admin list. Used to populate the
    /// `X-Total-Count` header alongside a paginated response so callers
    /// can tell whether they need another page. Constant-time on SQLite
    /// (`SELECT COUNT(*)`); default falls back to `list_all().len()`.
    async fn count_all(&self) -> Result<u64> {
        Ok(self.list_all().await?.len() as u64)
    }

    /// List repos owned by a specific user subject. Admin-owned repos
    /// (owner_subject = NULL) are excluded; they belong to no user's
    /// fleet. Order is `created_at DESC`. Uses the `idx_repos_owner`
    /// index so this stays cheap as the table grows.
    async fn list_by_owner(&self, subject: &str) -> Result<Vec<RepoRow>>;

    /// Page-shaped variant of `list_by_owner`. Symmetric with
    /// `list_paginated` but scoped to one owner — backs the paginated
    /// `GET /v1/repos` so a user's fleet view isn't unbounded.
    ///
    /// Default impl falls back to `list_by_owner` + slice; SQLite
    /// pushes `LIMIT`/`OFFSET` into the indexed query.
    async fn list_paginated_by_owner(
        &self,
        subject: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<RepoRow>> {
        let all = self.list_by_owner(subject).await?;
        let off = offset as usize;
        if off >= all.len() {
            return Ok(Vec::new());
        }
        let end = (off + limit as usize).min(all.len());
        Ok(all[off..end].to_vec())
    }

    /// Fetch one row by id. Used by the admin-detail endpoint, which
    /// needs `created_at` alongside the ownership check. A dedicated
    /// PK-lookup is O(1); previously this was a `list_all().find(...)`
    /// scan over the whole table.
    async fn get_row(&self, repo_id: &str) -> Result<Option<RepoRow>>;
}

/// One row of the `repos` table. `owner` is `None` for admin-created
/// repos (the owner_subject column is NULL).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RepoRow {
    pub id: String,
    pub owner: Option<String>,
    pub created_at: i64,
}

/// SQLite-backed `OwnershipStore`. Shares the DB file with
/// `SqliteTokenStore`; its own connection, its own table.
pub struct SqliteOwnershipStore {
    conn: Arc<TokioMutex<Connection>>,
}

const MIGRATIONS: [crate::db_migrate::Migration; 1] =
    [crate::db_migrate::Migration {
        version: 1,
        name: "init",
        up: |c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS repos (
                     id             TEXT PRIMARY KEY,
                     owner_subject  TEXT,
                     created_at     INTEGER NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS idx_repos_owner ON repos(owner_subject);",
            )
        },
    }];

impl SqliteOwnershipStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = crate::db_migrate::open_with_migrations(path, "ownership", &MIGRATIONS)?;
        Ok(Self {
            conn: Arc::new(TokioMutex::new(conn)),
        })
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[async_trait]
impl OwnershipStore for SqliteOwnershipStore {
    async fn record_owner(&self, repo_id: &str, owner: Option<&str>) -> Result<()> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        conn.execute(
            "INSERT OR REPLACE INTO repos (id, owner_subject, created_at)
             VALUES (?1, ?2, ?3)",
            params![repo_id, owner, now_secs()],
        )?;
        Ok(())
    }

    async fn get_owner(&self, repo_id: &str) -> Result<Option<Option<String>>> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        let mut stmt =
            conn.prepare_cached("SELECT owner_subject FROM repos WHERE id = ?1")?;
        let mut rows = stmt.query(params![repo_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        // SQLite nullable — returns Option<String> for an i64-nullable column.
        let owner: Option<String> = row.get(0)?;
        Ok(Some(owner))
    }

    async fn delete(&self, repo_id: &str) -> Result<()> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        conn.execute("DELETE FROM repos WHERE id = ?1", params![repo_id])?;
        Ok(())
    }

    async fn count_by_owner(&self, subject: &str) -> Result<u64> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        let mut stmt = conn
            .prepare_cached("SELECT COUNT(*) FROM repos WHERE owner_subject = ?1")?;
        let mut rows = stmt.query(params![subject])?;
        let row = rows.next()?.expect("COUNT(*) always returns one row");
        let n: i64 = row.get(0)?;
        Ok(n as u64)
    }

    async fn list_all(&self) -> Result<Vec<RepoRow>> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        let mut stmt = conn.prepare_cached(
            "SELECT id, owner_subject, created_at
             FROM repos
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RepoRow {
                id: row.get(0)?,
                owner: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    async fn list_paginated(&self, limit: u32, offset: u32) -> Result<Vec<RepoRow>> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        let mut stmt = conn.prepare_cached(
            "SELECT id, owner_subject, created_at
             FROM repos
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            Ok(RepoRow {
                id: row.get(0)?,
                owner: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    async fn count_all(&self) -> Result<u64> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        let mut stmt = conn.prepare_cached("SELECT COUNT(*) FROM repos")?;
        let mut rows = stmt.query([])?;
        let row = rows.next()?.expect("COUNT(*) always returns one row");
        let n: i64 = row.get(0)?;
        Ok(n as u64)
    }

    async fn list_by_owner(&self, subject: &str) -> Result<Vec<RepoRow>> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        let mut stmt = conn.prepare_cached(
            "SELECT id, owner_subject, created_at
             FROM repos
             WHERE owner_subject = ?1
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![subject], |row| {
            Ok(RepoRow {
                id: row.get(0)?,
                owner: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    async fn list_paginated_by_owner(
        &self,
        subject: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<RepoRow>> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        let mut stmt = conn.prepare_cached(
            "SELECT id, owner_subject, created_at
             FROM repos
             WHERE owner_subject = ?1
             ORDER BY created_at DESC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(
            params![subject, limit as i64, offset as i64],
            |row| {
                Ok(RepoRow {
                    id: row.get(0)?,
                    owner: row.get(1)?,
                    created_at: row.get(2)?,
                })
            },
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    async fn get_row(&self, repo_id: &str) -> Result<Option<RepoRow>> {
        let conn = crate::metrics::lock_sqlite(&self.conn, "ownership").await;
        let mut stmt = conn.prepare_cached(
            "SELECT id, owner_subject, created_at FROM repos WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![repo_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(RepoRow {
            id: row.get(0)?,
            owner: row.get(1)?,
            created_at: row.get(2)?,
        }))
    }
}

/// Quota helper: enforce that `principal` hasn't exceeded the per-user
/// repo-count quota. Admin bypasses. Non-admin callers without a
/// subject (shouldn't happen today — all non-admin principals carry a
/// subject) are treated as over-quota to fail closed.
///
/// Call this *before* creating a new repo so the creation and the
/// quota check agree about the count. Race with concurrent creates is
/// bounded by request concurrency per user, which is tiny in practice.
pub async fn check_repo_quota(
    ownership: &dyn OwnershipStore,
    principal: &Principal,
    limit: u64,
) -> Result<()> {
    if matches!(principal, Principal::Admin) {
        return Ok(());
    }
    let subject = principal.subject().ok_or(Error::QuotaExceeded {
        subject: "<no-subject>".to_string(),
        limit,
    })?;
    let current = ownership.count_by_owner(subject).await?;
    if current >= limit {
        return Err(Error::QuotaExceeded {
            subject: subject.to_string(),
            limit,
        });
    }
    Ok(())
}

/// One-shot — read the total repo count and publish to the
/// `artifacts_repos_total` gauge. Called at startup and on a 60s
/// ticker so capacity-planning + anomaly-detection dashboards see
/// repo growth within a minute. Failure is best-effort logged; the
/// gauge keeps its previous value rather than going to zero on a
/// transient SQLite error.
pub async fn refresh_repos_gauge(store: &dyn OwnershipStore) {
    match store.count_all().await {
        Ok(n) => metrics::gauge!("artifacts_repos_total").set(n as f64),
        Err(e) => tracing::warn!(error = %e, "repos-total gauge refresh failed"),
    }
}

/// Spawn a dedicated refresher for the repos-total gauge. Runs at
/// `tick` cadence — same shape as `tokens::spawn_active_gauge_refresher`
/// and `webhooks::spawn_active_gauge_refresher`, all three running in
/// parallel so each metric stays fresh independently.
pub fn spawn_repos_gauge_refresher(store: Arc<dyn OwnershipStore>, tick: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        // Skip the immediate-fire tick — the caller already populates
        // the gauge synchronously at startup; this loop owns refreshes
        // only.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            refresh_repos_gauge(&*store).await;
        }
    });
}

/// Enforcement helper: caller's `principal` must be permitted to act on
/// `repo_id`. Returns `Ok(())` on success, `Error::Forbidden` otherwise.
///
/// Rules:
/// - `Admin` is always allowed.
/// - `User { subject }` is allowed iff the stored owner matches
///   `subject` exactly.
/// - If the repo has no ownership record at all (legacy / pre-ownership
///   repos from before this feature), only `Admin` can act. Fail closed.
pub async fn enforce_owner(
    ownership: &dyn OwnershipStore,
    principal: &Principal,
    repo_id: &str,
) -> Result<()> {
    if matches!(principal, Principal::Admin) {
        return Ok(());
    }
    let caller = principal
        .subject()
        .ok_or(Error::Forbidden("non-admin principal has no subject"))?;
    match ownership.get_owner(repo_id).await? {
        Some(Some(owner)) if owner == caller => Ok(()),
        Some(Some(_)) => Err(Error::Forbidden("not the repo owner")),
        // Admin-created repo, or no record at all: non-admin can't touch.
        Some(None) | None => Err(Error::Forbidden("repo is admin-owned or unregistered")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Principal;
    use tempfile::tempdir;

    fn fresh_store() -> (tempfile::TempDir, SqliteOwnershipStore) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("artifacts.db");
        let store = SqliteOwnershipStore::open(&path).unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn record_and_read_owner_roundtrip() {
        let (_d, store) = fresh_store();
        store.record_owner("r1", Some("user-a")).await.unwrap();
        let o = store.get_owner("r1").await.unwrap();
        assert_eq!(o, Some(Some("user-a".to_string())));
    }

    #[tokio::test]
    async fn record_admin_owned_as_none() {
        let (_d, store) = fresh_store();
        store.record_owner("r2", None).await.unwrap();
        let o = store.get_owner("r2").await.unwrap();
        assert_eq!(o, Some(None));
    }

    #[tokio::test]
    async fn unknown_repo_returns_none() {
        let (_d, store) = fresh_store();
        assert_eq!(store.get_owner("ghost").await.unwrap(), None);
    }

    #[tokio::test]
    async fn delete_removes_row() {
        let (_d, store) = fresh_store();
        store.record_owner("r3", Some("u")).await.unwrap();
        store.delete("r3").await.unwrap();
        assert_eq!(store.get_owner("r3").await.unwrap(), None);
        // Idempotent: second delete doesn't error.
        store.delete("r3").await.unwrap();
    }

    #[tokio::test]
    async fn enforce_admin_bypasses_all() {
        let (_d, store) = fresh_store();
        // No record at all.
        enforce_owner(&store, &Principal::Admin, "no-such-repo")
            .await
            .unwrap();
        // Admin-created.
        store.record_owner("r", None).await.unwrap();
        enforce_owner(&store, &Principal::Admin, "r").await.unwrap();
    }

    #[tokio::test]
    async fn enforce_user_matches_owner() {
        let (_d, store) = fresh_store();
        store.record_owner("r", Some("alice")).await.unwrap();
        let p = Principal::User {
            subject: "alice".into(),
        };
        enforce_owner(&store, &p, "r").await.unwrap();
    }

    #[tokio::test]
    async fn enforce_user_rejects_different_owner() {
        let (_d, store) = fresh_store();
        store.record_owner("r", Some("alice")).await.unwrap();
        let bob = Principal::User {
            subject: "bob".into(),
        };
        let r = enforce_owner(&store, &bob, "r").await;
        assert!(matches!(r, Err(Error::Forbidden(_))));
    }

    #[tokio::test]
    async fn enforce_user_rejects_admin_owned() {
        let (_d, store) = fresh_store();
        store.record_owner("r", None).await.unwrap();
        let alice = Principal::User {
            subject: "alice".into(),
        };
        let r = enforce_owner(&store, &alice, "r").await;
        assert!(matches!(r, Err(Error::Forbidden(_))));
    }

    #[tokio::test]
    async fn enforce_user_rejects_unregistered() {
        // A repo that was never registered in the ownership store (legacy
        // / pre-feature data) is treated as non-user-accessible.
        let (_d, store) = fresh_store();
        let alice = Principal::User {
            subject: "alice".into(),
        };
        let r = enforce_owner(&store, &alice, "ghost").await;
        assert!(matches!(r, Err(Error::Forbidden(_))));
    }

    #[tokio::test]
    async fn count_by_owner_is_zero_without_rows() {
        let (_d, store) = fresh_store();
        assert_eq!(store.count_by_owner("nobody").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn count_by_owner_tracks_inserts_and_deletes() {
        let (_d, store) = fresh_store();
        store.record_owner("r1", Some("alice")).await.unwrap();
        store.record_owner("r2", Some("alice")).await.unwrap();
        store.record_owner("r3", Some("bob")).await.unwrap();
        assert_eq!(store.count_by_owner("alice").await.unwrap(), 2);
        assert_eq!(store.count_by_owner("bob").await.unwrap(), 1);
        store.delete("r1").await.unwrap();
        assert_eq!(store.count_by_owner("alice").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn count_ignores_admin_owned() {
        // Admin-owned rows have owner_subject = NULL. They must not
        // count toward any user's quota.
        let (_d, store) = fresh_store();
        store.record_owner("a1", None).await.unwrap();
        store.record_owner("a2", None).await.unwrap();
        store.record_owner("u1", Some("alice")).await.unwrap();
        assert_eq!(store.count_by_owner("alice").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn quota_admin_bypasses() {
        let (_d, store) = fresh_store();
        // Record 5 admin-owned repos and check the admin's own principal
        // is still OK against a limit of 0.
        for i in 0..5 {
            store.record_owner(&format!("r{i}"), None).await.unwrap();
        }
        check_repo_quota(&store, &Principal::Admin, 0).await.unwrap();
    }

    #[tokio::test]
    async fn quota_user_allowed_under_limit() {
        let (_d, store) = fresh_store();
        store.record_owner("r1", Some("alice")).await.unwrap();
        let alice = Principal::User { subject: "alice".into() };
        check_repo_quota(&store, &alice, 5).await.unwrap();
    }

    #[tokio::test]
    async fn quota_user_rejected_at_limit() {
        let (_d, store) = fresh_store();
        for i in 0..3u32 {
            store.record_owner(&format!("r{i}"), Some("alice")).await.unwrap();
        }
        let alice = Principal::User { subject: "alice".into() };
        let r = check_repo_quota(&store, &alice, 3).await;
        assert!(matches!(
            r,
            Err(Error::QuotaExceeded { ref subject, limit: 3 }) if subject == "alice"
        ));
    }

    #[tokio::test]
    async fn get_row_returns_none_for_unknown_repo() {
        let (_d, store) = fresh_store();
        assert!(store.get_row("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_row_returns_owner_and_created_at() {
        let (_d, store) = fresh_store();
        store.record_owner("r1", Some("alice")).await.unwrap();
        let row = store.get_row("r1").await.unwrap().expect("row present");
        assert_eq!(row.id, "r1");
        assert_eq!(row.owner.as_deref(), Some("alice"));
        assert!(row.created_at > 0);
    }

    #[tokio::test]
    async fn get_row_distinguishes_admin_owned_from_missing() {
        let (_d, store) = fresh_store();
        store.record_owner("admin-repo", None).await.unwrap();
        let row = store.get_row("admin-repo").await.unwrap().expect("row");
        assert!(row.owner.is_none());
        assert!(store.get_row("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_all_returns_rows_newest_first() {
        let (_d, store) = fresh_store();
        // Insert in a specific order and rely on created_at DESC to
        // return newest first. SQLite's CURRENT_TIMESTAMP resolution is
        // second-level; `record_owner` uses epoch seconds via `now_secs()`,
        // so we sleep a beat to guarantee a distinct timestamp.
        store.record_owner("old", Some("u")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        store.record_owner("new", Some("u")).await.unwrap();
        let rows = store.list_all().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "new");
        assert_eq!(rows[1].id, "old");
    }

    #[tokio::test]
    async fn list_all_empty_when_no_rows() {
        let (_d, store) = fresh_store();
        assert!(store.list_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_paginated_slices_under_full_list_order() {
        // Insert four rows with distinct creation timestamps so the
        // newest-first ordering is unambiguous, then verify that
        // `list_paginated(2, 1)` is exactly the second-and-third-newest
        // — the same slice the caller would compute by hand from
        // `list_all()`.
        let (_d, store) = fresh_store();
        store.record_owner("oldest", Some("u")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        store.record_owner("older", Some("u")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        store.record_owner("newer", Some("u")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        store.record_owner("newest", Some("u")).await.unwrap();

        let page = store.list_paginated(2, 1).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["newer", "older"]);
    }

    #[tokio::test]
    async fn list_paginated_offset_past_end_returns_empty() {
        let (_d, store) = fresh_store();
        store.record_owner("only", Some("u")).await.unwrap();
        let page = store.list_paginated(10, 5).await.unwrap();
        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn count_all_matches_list_all_len() {
        // The whole point of `count_all` is to be cheaper than
        // `list_all().len()` while returning the same number — so this
        // test pins the equivalence rather than the implementation.
        let (_d, store) = fresh_store();
        assert_eq!(store.count_all().await.unwrap(), 0);
        store.record_owner("a", Some("u")).await.unwrap();
        store.record_owner("b", None).await.unwrap();
        store.record_owner("c", Some("v")).await.unwrap();
        assert_eq!(store.count_all().await.unwrap(), 3);
        assert_eq!(
            store.count_all().await.unwrap() as usize,
            store.list_all().await.unwrap().len()
        );
    }

    #[tokio::test]
    async fn list_all_includes_admin_owned_as_none() {
        let (_d, store) = fresh_store();
        store.record_owner("admin-repo", None).await.unwrap();
        let rows = store.list_all().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "admin-repo");
        assert!(rows[0].owner.is_none());
    }

    #[tokio::test]
    async fn list_by_owner_filters_to_subject() {
        let (_d, store) = fresh_store();
        store.record_owner("a1", Some("alice")).await.unwrap();
        store.record_owner("b1", Some("bob")).await.unwrap();
        store.record_owner("a2", Some("alice")).await.unwrap();
        store.record_owner("admin", None).await.unwrap();
        let alice = store.list_by_owner("alice").await.unwrap();
        let ids: Vec<&str> = alice.iter().map(|r| r.id.as_str()).collect();
        // Alice sees her own repos, nothing else. Admin-owned rows never
        // show up on a user's list.
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"a1"));
        assert!(ids.contains(&"a2"));
        assert!(!ids.contains(&"b1"));
        assert!(!ids.contains(&"admin"));
    }

    #[tokio::test]
    async fn list_by_owner_empty_when_no_rows() {
        let (_d, store) = fresh_store();
        assert!(store.list_by_owner("nobody").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_by_owner_returns_newest_first() {
        let (_d, store) = fresh_store();
        store.record_owner("old", Some("alice")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        store.record_owner("new", Some("alice")).await.unwrap();
        let rows = store.list_by_owner("alice").await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "new");
        assert_eq!(rows[1].id, "old");
    }

    #[tokio::test]
    async fn pagination_walks_full_dataset_without_overlap() {
        // Pin the contract paginating-callers depend on: paging
        // through the full dataset in `limit`-sized chunks must
        // visit every row exactly once. This is what the SQLite
        // override of `list_paginated` makes efficient (push-down
        // `LIMIT/OFFSET`) — but the contract is independent of
        // pushdown vs. default-impl-slice. A future refactor that
        // breaks the override will at minimum still need to
        // satisfy this assertion.
        //
        // count_all must agree with the rows we actually inserted —
        // separately exercises the `SELECT COUNT(*)` override.
        let (_d, store) = fresh_store();
        let total: u32 = 100;
        for i in 0..total {
            store
                .record_owner(&format!("repo-{i:03}"), Some("alice"))
                .await
                .unwrap();
        }
        assert_eq!(store.count_all().await.unwrap(), total as u64);

        // Walk in chunks of 25 and accumulate every id we see.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let chunk: u32 = 25;
        let mut offset: u32 = 0;
        loop {
            let page = store.list_paginated(chunk, offset).await.unwrap();
            if page.is_empty() {
                break;
            }
            for row in &page {
                assert!(
                    seen.insert(row.id.clone()),
                    "row {} appeared on more than one page (offset bug?)",
                    row.id,
                );
            }
            offset += chunk;
            // Cheap guard against an off-by-N that keeps returning
            // forever — we never need more pages than rows.
            assert!(offset <= total + chunk, "paged past the dataset");
        }
        assert_eq!(seen.len(), total as usize);

        // Offset past the end must terminate cleanly.
        assert!(store.list_paginated(10, total).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_paginated_by_owner_walks_owner_subset() {
        // Same contract as the admin-list walk, but scoped to one
        // owner — the user-facing `/v1/repos` endpoint relies on
        // this. A buggy `WHERE owner_subject = ?` would either drop
        // owner filtering (returning bob's rows to alice) or break
        // pagination ordering.
        let (_d, store) = fresh_store();
        let owned: u32 = 60;
        let other: u32 = 40;
        for i in 0..owned {
            store
                .record_owner(&format!("alice-{i:03}"), Some("alice"))
                .await
                .unwrap();
        }
        for i in 0..other {
            store
                .record_owner(&format!("bob-{i:03}"), Some("bob"))
                .await
                .unwrap();
        }
        assert_eq!(store.count_by_owner("alice").await.unwrap(), owned as u64);

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let chunk: u32 = 20;
        let mut offset: u32 = 0;
        loop {
            let page = store
                .list_paginated_by_owner("alice", chunk, offset)
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            for row in &page {
                assert!(row.id.starts_with("alice-"), "bob's row leaked: {}", row.id);
                assert!(
                    seen.insert(row.id.clone()),
                    "row {} appeared on more than one page",
                    row.id,
                );
            }
            offset += chunk;
            assert!(offset <= owned + chunk, "paged past the dataset");
        }
        assert_eq!(seen.len(), owned as usize);
        assert!(store
            .list_paginated_by_owner("alice", 10, owned)
            .await
            .unwrap()
            .is_empty());
    }

    // Property tests live in a sub-module so the proptest macros don't
    // expand inside the existing `tests` namespace.
    mod prop {
        //! Pagination invariants checked across a randomized parameter
        //! space:
        //!
        //!   - Walking pages of size L over N rows returns exactly N
        //!     distinct rows; no duplicates, no gaps.
        //!   - `count_all` agrees with the row count we just inserted.
        //!   - The first page (`offset = 0`) plus a non-overlapping
        //!     second page (`offset = L`) cover the start of the table
        //!     without intersection.
        //!
        //! These complement the hand-written cases above by sweeping
        //! the parameter space — small N, large N, L > N, L equal to N,
        //! and so on. Case count is capped low so the SQLite-per-case
        //! cost doesn't blow up the test runtime.
        use super::super::SqliteOwnershipStore;
        use super::super::OwnershipStore;
        use proptest::prelude::*;
        use std::collections::HashSet;
        use tempfile::TempDir;
        use tokio::runtime::Runtime;

        fn fresh_blocking() -> (TempDir, SqliteOwnershipStore) {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("artifacts.db");
            let store = SqliteOwnershipStore::open(&path).unwrap();
            (dir, store)
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 24,
                ..ProptestConfig::default()
            })]

            #[test]
            fn page_walk_returns_every_row_exactly_once(
                n in 0u32..40,
                limit in 1u32..15,
            ) {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let (_d, store) = fresh_blocking();
                    for i in 0..n {
                        store.record_owner(&format!("r{i:03}"), Some("u")).await.unwrap();
                    }
                    let total = store.count_all().await.unwrap();
                    prop_assert_eq!(total, n as u64);

                    let mut seen: HashSet<String> = HashSet::new();
                    let mut offset = 0u32;
                    loop {
                        let page = store.list_paginated(limit, offset).await.unwrap();
                        if page.is_empty() {
                            break;
                        }
                        for row in &page {
                            prop_assert!(
                                seen.insert(row.id.clone()),
                                "duplicate row across pages: {}",
                                row.id,
                            );
                        }
                        prop_assert!(
                            page.len() as u32 <= limit,
                            "page exceeded requested limit",
                        );
                        offset += limit;
                        // Defensive: should never overshoot. The page-empty
                        // break is the real termination condition.
                        prop_assert!(offset <= n + limit, "ran past the dataset");
                    }
                    prop_assert_eq!(seen.len() as u32, n);
                    Ok(())
                })?;
            }

            #[test]
            fn two_disjoint_pages_dont_intersect(
                n in 5u32..40,
                limit in 1u32..15,
            ) {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let (_d, store) = fresh_blocking();
                    for i in 0..n {
                        store.record_owner(&format!("r{i:03}"), Some("u")).await.unwrap();
                    }
                    let p0 = store.list_paginated(limit, 0).await.unwrap();
                    let p1 = store.list_paginated(limit, limit).await.unwrap();
                    let s0: HashSet<&str> = p0.iter().map(|r| r.id.as_str()).collect();
                    let s1: HashSet<&str> = p1.iter().map(|r| r.id.as_str()).collect();
                    prop_assert!(
                        s0.is_disjoint(&s1),
                        "page 0 and page 1 must not share rows",
                    );
                    Ok(())
                })?;
            }
        }
    }
}
