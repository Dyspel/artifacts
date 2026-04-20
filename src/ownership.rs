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
use std::time::{SystemTime, UNIX_EPOCH};
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

impl SqliteOwnershipStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS repos (
                 id             TEXT PRIMARY KEY,
                 owner_subject  TEXT,
                 created_at     INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_repos_owner ON repos(owner_subject);",
        )?;
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
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO repos (id, owner_subject, created_at)
             VALUES (?1, ?2, ?3)",
            params![repo_id, owner, now_secs()],
        )?;
        Ok(())
    }

    async fn get_owner(&self, repo_id: &str) -> Result<Option<Option<String>>> {
        let conn = self.conn.lock().await;
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
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM repos WHERE id = ?1", params![repo_id])?;
        Ok(())
    }

    async fn count_by_owner(&self, subject: &str) -> Result<u64> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare_cached("SELECT COUNT(*) FROM repos WHERE owner_subject = ?1")?;
        let mut rows = stmt.query(params![subject])?;
        let row = rows.next()?.expect("COUNT(*) always returns one row");
        let n: i64 = row.get(0)?;
        Ok(n as u64)
    }

    async fn list_all(&self) -> Result<Vec<RepoRow>> {
        let conn = self.conn.lock().await;
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
    async fn list_all_includes_admin_owned_as_none() {
        let (_d, store) = fresh_store();
        store.record_owner("admin-repo", None).await.unwrap();
        let rows = store.list_all().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "admin-repo");
        assert!(rows[0].owner.is_none());
    }
}
