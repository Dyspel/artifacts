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
}
