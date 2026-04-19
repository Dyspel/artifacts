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
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::DashMap;
use rand::Rng;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

pub trait TokenStore: Send + Sync {
    /// Mint a new token authorizing `scope` on `repo_id`, optionally
    /// expiring after `ttl`. Returns the raw token (clients get this once
    /// and only once — the store holds only the hash).
    fn mint(&self, repo_id: &str, scope: Scope, ttl: Option<Duration>) -> Result<String>;

    /// Resolve a token. `Ok(None)` means unknown, revoked, or expired —
    /// no distinction is made, since from the caller's perspective all
    /// three should fail closed as 401.
    fn lookup(&self, token: &str) -> Result<Option<TokenRecord>>;

    /// Revoke a token. Returns `Ok(true)` if the token existed and wasn't
    /// already revoked, `Ok(false)` otherwise. Idempotent.
    fn revoke(&self, token: &str) -> Result<bool>;
}

/// In-memory `TokenStore` for tests. State evaporates on drop.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTokenStore {
    inner: Arc<DashMap<String, InMemoryEntry>>,
}

#[derive(Debug, Clone)]
struct InMemoryEntry {
    record: TokenRecord,
    revoked: bool,
}

impl InMemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenStore for InMemoryTokenStore {
    fn mint(&self, repo_id: &str, scope: Scope, ttl: Option<Duration>) -> Result<String> {
        let token = random_token();
        let expires_at = ttl.map(|d| now_secs() + d.as_secs());
        self.inner.insert(
            sha256_hex(&token),
            InMemoryEntry {
                record: TokenRecord {
                    repo_id: repo_id.to_string(),
                    scope,
                    expires_at,
                },
                revoked: false,
            },
        );
        Ok(token)
    }

    fn lookup(&self, token: &str) -> Result<Option<TokenRecord>> {
        let Some(entry) = self.inner.get(&sha256_hex(token)) else {
            return Ok(None);
        };
        if entry.revoked {
            return Ok(None);
        }
        if let Some(exp) = entry.record.expires_at {
            if now_secs() >= exp {
                return Ok(None);
            }
        }
        Ok(Some(entry.record.clone()))
    }

    fn revoke(&self, token: &str) -> Result<bool> {
        let key = sha256_hex(token);
        match self.inner.get_mut(&key) {
            Some(mut entry) if !entry.revoked => {
                entry.revoked = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// SQLite-backed `TokenStore`. Single writer; multiple readers can proceed
/// under WAL. The mutex around the connection keeps SQLite's "one writer
/// at a time" invariant honest across tokio tasks.
///
/// Tokens are stored as SHA-256 hashes. If the DB file leaks, a reader
/// cannot present any of the stored rows as a token — they'd have to
/// preimage the hash.
pub struct SqliteTokenStore {
    conn: Arc<Mutex<Connection>>,
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
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

impl TokenStore for SqliteTokenStore {
    fn mint(&self, repo_id: &str, scope: Scope, ttl: Option<Duration>) -> Result<String> {
        let token = random_token();
        let hash = sha256_hex(&token);
        let now = now_secs() as i64;
        let expires_at = ttl.map(|d| (now as u64 + d.as_secs()) as i64);
        let conn = self.conn.lock().expect("tokens mutex poisoned");
        conn.execute(
            "INSERT INTO tokens (token_hash, repo_id, scope, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![hash, repo_id, scope.as_str(), now, expires_at],
        )?;
        Ok(token)
    }

    fn lookup(&self, token: &str) -> Result<Option<TokenRecord>> {
        let hash = sha256_hex(token);
        let now = now_secs() as i64;
        let conn = self.conn.lock().expect("tokens mutex poisoned");
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

    fn revoke(&self, token: &str) -> Result<bool> {
        let hash = sha256_hex(token);
        let now = now_secs() as i64;
        let conn = self.conn.lock().expect("tokens mutex poisoned");
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

    #[test]
    fn mint_then_lookup_roundtrip() {
        let (_d, store) = open_store();
        let t = store.mint("repo-a", Scope::Write, None).unwrap();
        let rec = store.lookup(&t).unwrap().unwrap();
        assert_eq!(rec.repo_id, "repo-a");
        assert_eq!(rec.scope, Scope::Write);
        assert!(rec.expires_at.is_none());
    }

    #[test]
    fn lookup_of_unknown_is_none() {
        let (_d, store) = open_store();
        assert!(store.lookup("never-minted").unwrap().is_none());
    }

    #[test]
    fn revoke_makes_lookup_return_none() {
        let (_d, store) = open_store();
        let t = store.mint("r", Scope::Read, None).unwrap();
        assert!(store.lookup(&t).unwrap().is_some());
        assert!(store.revoke(&t).unwrap());
        assert!(store.lookup(&t).unwrap().is_none());
        // Second revoke is a no-op (idempotent).
        assert!(!store.revoke(&t).unwrap());
    }

    #[test]
    fn expired_tokens_do_not_resolve() {
        let (_d, store) = open_store();
        // TTL of zero seconds means "expires_at = created_at", and the
        // lookup predicate is `expires_at > now`, so it's immediately dead.
        let t = store.mint("r", Scope::Read, Some(Duration::from_secs(0))).unwrap();
        assert!(
            store.lookup(&t).unwrap().is_none(),
            "expected TTL=0 token to be unresolvable"
        );
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let t = {
            let s = SqliteTokenStore::open(&path).unwrap();
            s.mint("persistent", Scope::Write, None).unwrap()
        };
        // Drop the first store, reopen on the same path.
        let s2 = SqliteTokenStore::open(&path).unwrap();
        let rec = s2.lookup(&t).unwrap().expect("token survived reopen");
        assert_eq!(rec.repo_id, "persistent");
    }

    #[test]
    fn stored_value_is_not_the_raw_token() {
        // Belt-and-suspenders: verify we never write the raw token into
        // the db, only its hash.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        let t = store.mint("r", Scope::Read, None).unwrap();

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
}
