//! Token issuance, lookup, and revocation.
//!
//! A token authorizes one caller to act on one repo at one scope (read or
//! write). Clients present tokens via HTTP Basic with username `x`
//! (matching how `git clone https://x:TOKEN@host/...` sends them).
//!
//! ## Trait
//!
//! `TokenStore` is the abstraction boundary. Handlers call `mint`,
//! `lookup`, and `revoke` through it; the concrete backend can be
//! in-memory (tests) or SQLite (default). Adding a distributed backend —
//! a real issuer service in M4b — means writing one impl of the trait.
//!
//! ## SQLite backend
//!
//! `SqliteTokenStore` stores each token as a SHA-256 hash, not the raw
//! value. If the database file leaks, nobody gets a usable token out of
//! it. Expiry and revocation are cheap column checks at lookup time
//! (`WHERE expires_at IS NULL OR expires_at > now AND revoked_at IS NULL`),
//! so a revoked token stops working on the next request with no cache
//! invalidation needed.
//!
//! Schema is created on open if absent, so there's no separate
//! migration step for M4. Future schema changes will need real
//! migrations; for now the tokens table is the only state.

use crate::error::{Error, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as TokioMutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Read,
    Write,
}

impl Scope {
    fn as_str(&self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Write => "write",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "read" => Ok(Scope::Read),
            "write" => Ok(Scope::Write),
            other => Err(Error::Other(anyhow::anyhow!("invalid scope {other:?}"))),
        }
    }
}

/// What a successful lookup tells the caller.
#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub repo_id: String,
    pub scope: Scope,
    /// Unix epoch seconds. `None` means the token never expires.
    pub expires_at: Option<u64>,
}

/// The token-store contract.
///
/// Methods are `async` because any production backend worth having is going
/// to do I/O (SQLite, network KV, secret-manager lookups). Making the
/// in-memory impl async is a trivial wrapper; it costs us nothing and
/// prevents the "the trait is sync but one impl needs to block" tension
/// that hit us at review.
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Mint a new token authorizing `scope` on `repo_id`, optionally
    /// expiring after `ttl`. Returns the raw token (clients get this once
    /// and only once — the store holds only the hash).
    async fn mint(&self, repo_id: &str, scope: Scope, ttl: Option<Duration>) -> Result<String>;

    /// Resolve a token. `Ok(None)` means unknown, revoked, or expired —
    /// no distinction is made, since from the caller's perspective all
    /// three should fail closed as 401.
    async fn lookup(&self, token: &str) -> Result<Option<TokenRecord>>;

    /// Revoke a token. Returns `Ok(true)` if the token existed and wasn't
    /// already revoked, `Ok(false)` otherwise. Idempotent.
    async fn revoke(&self, token: &str) -> Result<bool>;
}

/// SQLite-backed `TokenStore`.
///
/// SQLite is single-writer-multi-reader under WAL, and the C API isn't
/// `Send + Sync` to begin with, so we serialize access with a mutex. This
/// used to be a `std::sync::Mutex`, which blocked the *tokio worker
/// thread* while held — fine for a prototype at low qps, wrong under
/// load. We now use `tokio::sync::Mutex`: holding it suspends only the
/// single task awaiting the lock, not a worker.
///
/// The SQLite operations themselves are sync + fast (microseconds for the
/// hashed-key lookup). If we later see contention at thousands of qps,
/// the right next step is `deadpool-sqlite` with a connection pool — but
/// the `TokenStore` trait doesn't change.
///
/// Tokens are stored as SHA-256 hashes. If the DB file leaks, a reader
/// cannot present any of the stored rows as a token — they'd have to
/// preimage the hash.
pub struct SqliteTokenStore {
    conn: Arc<TokioMutex<Connection>>,
}

impl SqliteTokenStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS tokens (
                 token_hash TEXT PRIMARY KEY,
                 repo_id    TEXT NOT NULL,
                 scope      TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER,
                 revoked_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_tokens_repo_id ON tokens(repo_id);",
        )?;
        Ok(Self {
            conn: Arc::new(TokioMutex::new(conn)),
        })
    }

    /// Delete rows that are guaranteed to never authorize a request again:
    /// revoked tokens, and tokens whose expiry has passed by more than a
    /// grace window. Returns the number of rows removed.
    ///
    /// Why not "everything expired"? A short grace window means a
    /// recently-expired token briefly sticks around with a NULL-only
    /// row; lets admin/audit tooling see "this token existed and was
    /// valid until T" for a bit before it's hard-deleted. Default 24h
    /// is well beyond any normal session turnover.
    ///
    /// Called on a timer by `spawn_prune_task` at startup. Also safe to
    /// invoke manually (e.g., from an admin CLI) — just lock + prune.
    pub async fn prune(&self, expiry_grace: Duration) -> Result<u64> {
        let now = now_secs() as i64;
        let expiry_cutoff = now.saturating_sub(expiry_grace.as_secs() as i64);
        let conn = self.conn.lock().await;
        // `<=` not `<` mirrors lookup semantics: a row with
        // `expires_at == now` is already unusable (lookup uses
        // `expires_at > now`), so it's logically expired and prunable.
        let affected = conn.execute(
            "DELETE FROM tokens
             WHERE revoked_at IS NOT NULL
                OR (expires_at IS NOT NULL AND expires_at <= ?1)",
            params![expiry_cutoff],
        )?;
        Ok(affected as u64)
    }
}

/// Spawn a background task that calls `prune()` every `tick`. Task
/// lives for the full process lifetime; first prune fires after the
/// first `tick` (not immediately) so it doesn't contend with startup.
pub fn spawn_prune_task(
    store: Arc<SqliteTokenStore>,
    tick: Duration,
    expiry_grace: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        // Skip the first tick so we don't fire immediately on startup.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match store.prune(expiry_grace).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(pruned = n, "token prune"),
                Err(e) => tracing::error!(error = %e, "token prune failed"),
            }
        }
    });
}

#[async_trait]
impl TokenStore for SqliteTokenStore {
    async fn mint(&self, repo_id: &str, scope: Scope, ttl: Option<Duration>) -> Result<String> {
        let token = random_token();
        let hash = sha256_hex(&token);
        let now = now_secs() as i64;
        let expires_at = ttl.map(|d| (now as u64 + d.as_secs()) as i64);
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO tokens (token_hash, repo_id, scope, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![hash, repo_id, scope.as_str(), now, expires_at],
        )?;
        Ok(token)
    }

    async fn lookup(&self, token: &str) -> Result<Option<TokenRecord>> {
        let hash = sha256_hex(token);
        let now = now_secs() as i64;
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare_cached(
            "SELECT repo_id, scope, expires_at FROM tokens
             WHERE token_hash = ?1
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?2)",
        )?;
        let mut rows = stmt.query(params![hash, now])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let repo_id: String = row.get(0)?;
        let scope: String = row.get(1)?;
        let expires_at: Option<i64> = row.get(2)?;
        Ok(Some(TokenRecord {
            repo_id,
            scope: Scope::parse(&scope)?,
            expires_at: expires_at.map(|v| v as u64),
        }))
    }

    async fn revoke(&self, token: &str) -> Result<bool> {
        let hash = sha256_hex(token);
        let now = now_secs() as i64;
        let conn = self.conn.lock().await;
        let affected = conn.execute(
            "UPDATE tokens SET revoked_at = ?1
             WHERE token_hash = ?2 AND revoked_at IS NULL",
            params![now, hash],
        )?;
        Ok(affected > 0)
    }
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_store() -> (tempfile::TempDir, SqliteTokenStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn mint_then_lookup_roundtrip() {
        let (_d, store) = open_store();
        let t = store.mint("repo-a", Scope::Write, None).await.unwrap();
        let rec = store.lookup(&t).await.unwrap().unwrap();
        assert_eq!(rec.repo_id, "repo-a");
        assert_eq!(rec.scope, Scope::Write);
        assert!(rec.expires_at.is_none());
    }

    #[tokio::test]
    async fn lookup_of_unknown_is_none() {
        let (_d, store) = open_store();
        assert!(store.lookup("never-minted").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_makes_lookup_return_none() {
        let (_d, store) = open_store();
        let t = store.mint("r", Scope::Read, None).await.unwrap();
        assert!(store.lookup(&t).await.unwrap().is_some());
        assert!(store.revoke(&t).await.unwrap());
        assert!(store.lookup(&t).await.unwrap().is_none());
        // Second revoke is a no-op (idempotent).
        assert!(!store.revoke(&t).await.unwrap());
    }

    #[tokio::test]
    async fn expired_tokens_do_not_resolve() {
        let (_d, store) = open_store();
        // TTL of zero seconds means "expires_at = created_at", and the
        // lookup predicate is `expires_at > now`, so it's immediately dead.
        let t = store.mint("r", Scope::Read, Some(Duration::from_secs(0))).await.unwrap();
        assert!(
            store.lookup(&t).await.unwrap().is_none(),
            "expected TTL=0 token to be unresolvable"
        );
    }

    #[tokio::test]
    async fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let t = {
            let s = SqliteTokenStore::open(&path).unwrap();
            s.mint("persistent", Scope::Write, None).await.unwrap()
        };
        // Drop the first store, reopen on the same path.
        let s2 = SqliteTokenStore::open(&path).unwrap();
        let rec = s2.lookup(&t).await.unwrap().expect("token survived reopen");
        assert_eq!(rec.repo_id, "persistent");
    }

    #[tokio::test]
    async fn stored_value_is_not_the_raw_token() {
        // Belt-and-suspenders: verify we never write the raw token into
        // the db, only its hash.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        let t = store.mint("r", Scope::Read, None).await.unwrap();

        let conn = Connection::open(&path).unwrap();
        let mut stmt = conn
            .prepare("SELECT token_hash FROM tokens WHERE repo_id = 'r'")
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 1);
        let stored = &rows[0];
        assert_ne!(stored, &t, "raw token must not appear in db");
        assert_eq!(stored, &sha256_hex(&t));
    }

    fn count_rows(path: &std::path::Path) -> i64 {
        let conn = Connection::open(path).unwrap();
        conn.query_row("SELECT COUNT(*) FROM tokens", [], |r| r.get(0)).unwrap()
    }

    #[tokio::test]
    async fn prune_removes_revoked_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        let t_live = store.mint("live", Scope::Read, None).await.unwrap();
        let t_dead = store.mint("dead", Scope::Read, None).await.unwrap();
        store.revoke(&t_dead).await.unwrap();
        assert_eq!(count_rows(&path), 2);

        // Grace doesn't apply to revokes — revoked rows are always prunable.
        let pruned = store.prune(Duration::from_secs(86400)).await.unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(count_rows(&path), 1);
        // The live token still resolves.
        assert!(store.lookup(&t_live).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn prune_honors_expiry_grace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        // Ttl=0 → immediately expired (rows' expires_at == created_at).
        let _t = store.mint("r", Scope::Read, Some(Duration::from_secs(0))).await.unwrap();
        assert_eq!(count_rows(&path), 1);

        // With a generous grace, the row survives.
        let pruned = store.prune(Duration::from_secs(86400)).await.unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(count_rows(&path), 1);

        // With zero grace, the expired row is fair game.
        let pruned = store.prune(Duration::from_secs(0)).await.unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(count_rows(&path), 0);
    }

    #[tokio::test]
    async fn prune_leaves_live_never_expiring_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        let _t = store.mint("r", Scope::Read, None).await.unwrap();
        store.prune(Duration::from_secs(0)).await.unwrap();
        assert_eq!(count_rows(&path), 1);
    }
}
