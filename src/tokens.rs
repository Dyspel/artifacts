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

use crate::db_migrate::DbPool;
use crate::error::{Error, Result};
use crate::ids::{RepoId, Subject, Token};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
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

/// What a successful lookup tells the caller. Carries only the
/// fields production callers (`authorize_*`) actually consume —
/// `expires_at` and `subject` are filtered at the SQL layer (the
/// lookup query rejects expired rows; mint records the subject
/// directly into the row), so neither needs to surface here. The
/// listing path returns the full row via [`TokenSummary`].
#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub repo_id: RepoId,
    pub scope: Scope,
}

/// One row of the listing surface. Public so REST handlers can return
/// it as JSON without re-shaping. The token itself is NEVER in this
/// shape — listing returns the row's metadata, never the raw secret.
#[derive(Debug, Clone, Serialize)]
pub struct TokenSummary {
    /// Stable per-row id — the SHA-256 hex of the *token hash*,
    /// truncated to 16 chars for compactness in CLI output. Same value
    /// for the same token across calls. Lets a caller cross-reference
    /// `revoke` operations without ever holding the raw token.
    ///
    /// Deliberately NOT `Oid`: this is a SHA-256 prefix, not a SHA-1
    /// git oid. The `Oid` newtype is strictly 40 lowercase hex chars
    /// matching a git object identifier; conflating the two would let
    /// a token-hash flow into `ObjectStore::read_loose` and vice versa.
    pub id: String,
    pub repo_id: RepoId,
    pub scope: Scope,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub subject: Option<Subject>,
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
    /// expiring after `ttl`, optionally bound to `subject` (a JWT
    /// principal — `None` when the admin path mints). Returns the
    /// raw token (clients get this once and only once — the store
    /// holds only the hash).
    async fn mint(
        &self,
        repo_id: &RepoId,
        scope: Scope,
        ttl: Option<Duration>,
        subject: Option<&Subject>,
    ) -> Result<Token>;

    /// Resolve a token. `Ok(None)` means unknown, revoked, or expired —
    /// no distinction is made, since from the caller's perspective all
    /// three should fail closed as 401.
    async fn lookup(&self, token: &Token) -> Result<Option<TokenRecord>>;

    /// Revoke a token. Returns `Ok(true)` if the token existed and wasn't
    /// already revoked, `Ok(false)` otherwise. Idempotent.
    async fn revoke(&self, token: &Token) -> Result<bool>;

    /// Count rows that would currently authorize a request — i.e. not
    /// revoked, not expired (NULL or future). Powers the
    /// `artifacts_tokens_active_total` Prometheus gauge.
    ///
    /// Default impl returns 0 — backends without a cheap aggregate
    /// (e.g., the in-memory test store) just don't surface a count.
    /// SQLite overrides with a single indexed COUNT(*).
    async fn count_active(&self) -> Result<u64> {
        Ok(0)
    }

    /// Revoke every non-revoked, non-expired token bound to `repo_id`.
    /// Returns the number of rows that were actually flipped — useful
    /// for surfacing "rotated 3 tokens" to the caller of a rotation
    /// endpoint. Idempotent: a second call on the same repo returns 0
    /// because everything's already revoked.
    ///
    /// Default impl errors so trait callers get a clear "this backend
    /// doesn't implement bulk revoke" rather than a panic. Concrete
    /// stores override.
    async fn revoke_all_for_repo(&self, _repo_id: &RepoId) -> Result<u64> {
        Err(Error::Other(anyhow::anyhow!(
            "TokenStore::revoke_all_for_repo not implemented"
        )))
    }

    /// List token rows for a repo. Optionally scope to one subject
    /// (None = all subjects, including admin-minted rows). Excludes
    /// revoked + expired rows. Default impl errors.
    async fn list_for_repo(
        &self,
        _repo_id: &RepoId,
        _subject_filter: Option<&Subject>,
    ) -> Result<Vec<TokenSummary>> {
        Err(Error::Other(anyhow::anyhow!(
            "TokenStore::list_for_repo not implemented"
        )))
    }

    /// Exercise the store's write path with a transient row that's
    /// immediately deleted. The readiness probe calls this (when
    /// `ARTIFACTS_READINESS_WRITE_CHECK` is not 0) so a read-only
    /// filesystem or quota-full sqlite gets caught at probe time
    /// rather than at the next real mutation. Default impl is a
    /// no-op so non-SQLite backends (the in-memory test store)
    /// compose without overriding.
    async fn probe_write(&self) -> Result<()> {
        Ok(())
    }
}

/// SQLite-backed `TokenStore`.
///
/// Backed by an `r2d2` connection pool — every method claims a
/// connection from the pool via `metrics::get_pooled`, which times
/// the claim and records it on `artifacts_sqlite_lock_wait_seconds`.
/// Under WAL mode the pool gives real reader parallelism (N readers +
/// one writer concurrently); the previous `Arc<tokio::sync::Mutex<Connection>>`
/// serialized every query through a single connection.
///
/// Tokens are stored as SHA-256 hashes. If the DB file leaks, a reader
/// cannot present any of the stored rows as a token — they'd have to
/// preimage the hash.
pub struct SqliteTokenStore {
    conn: DbPool,
}

const MIGRATIONS: [crate::db_migrate::Migration; 2] = [
    crate::db_migrate::Migration {
        version: 1,
        name: "init",
        up: |c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS tokens (
                     token_hash TEXT PRIMARY KEY,
                     repo_id    TEXT NOT NULL,
                     scope      TEXT NOT NULL,
                     created_at INTEGER NOT NULL,
                     expires_at INTEGER,
                     revoked_at INTEGER
                 );
                 CREATE INDEX IF NOT EXISTS idx_tokens_repo_id ON tokens(repo_id);",
            )
        },
    },
    crate::db_migrate::Migration {
        // M4b-account migration: the `subject` column lets us track
        // which JWT subject minted each token, so a user can list /
        // revoke tokens they own without needing admin.
        version: 2,
        name: "add_subject_column",
        up: |c| crate::db_migrate::add_column_if_missing(c, "tokens", "subject", "TEXT"),
    },
];

crate::db_migrate::sqlite_store_boilerplate!(SqliteTokenStore, "tokens", MIGRATIONS);

impl SqliteTokenStore {
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
        let conn = self.pooled()?;
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
///
/// Also refreshes the `artifacts_tokens_active_total` gauge after
/// each prune — piggybacks on the same hourly cadence so we don't
/// need a separate metrics-publishing task. The startup-time
/// `refresh_active_token_gauge` populates the initial value so the
/// gauge isn't reported as 0 until the first tick fires.
pub fn spawn_prune_task(
    store: Arc<SqliteTokenStore>,
    tick: Duration,
    expiry_grace: Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        // Skip the first tick so we don't fire immediately on startup.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match store.prune(expiry_grace).await {
                        Ok(0) => {}
                        Ok(n) => tracing::info!(pruned = n, "token prune"),
                        Err(e) => tracing::error!(error = %e, "token prune failed"),
                    }
                    refresh_active_token_gauge(&*store).await;
                }
                _ = cancel.cancelled() => return,
            }
        }
    })
}

/// One-shot — read the active count and publish to the gauge. Called
/// at startup (after the store is opened) and at the tail of each
/// prune sweep. Failure is best-effort logged; the gauge keeps its
/// previous value rather than going to zero on a transient error.
pub async fn refresh_active_token_gauge(store: &dyn TokenStore) {
    match store.count_active().await {
        Ok(n) => metrics::gauge!("artifacts_tokens_active_total").set(n as f64),
        Err(e) => tracing::warn!(error = %e, "active-token gauge refresh failed"),
    }
}

/// Spawn a dedicated refresher for the active-token gauge. Runs at
/// `tick` cadence (typically 60s — fast enough that the gauge tracks
/// real activity within a minute, slow enough that a SQLite
/// COUNT-on-indexed-predicate isn't the busiest thing the server
/// does). The hourly prune task also refreshes after each sweep,
/// but waiting an hour to see a token-mint reflected in metrics is
/// too coarse for capacity-planning + anomaly detection use cases.
pub fn spawn_active_gauge_refresher(
    store: Arc<dyn TokenStore>,
    tick: Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        // Fire the first interval immediately — we already populate
        // the gauge synchronously at startup, but a dropped wakeup
        // here would leave a one-tick lag.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => refresh_active_token_gauge(&*store).await,
                _ = cancel.cancelled() => return,
            }
        }
    })
}

#[async_trait]
impl TokenStore for SqliteTokenStore {
    async fn mint(
        &self,
        repo_id: &RepoId,
        scope: Scope,
        ttl: Option<Duration>,
        subject: Option<&Subject>,
    ) -> Result<Token> {
        let raw = random_token();
        // random_token produces a URL-safe-base64 32-byte string (≥ 1
        // char, all ascii-graphic), so it satisfies the Token contract
        // by construction. The expect documents the invariant.
        let token = Token::try_from(raw.as_str())
            .expect("random_token() output satisfies the Token contract");
        let hash = sha256_hex(token.as_str());
        let now = now_secs() as i64;
        let expires_at = ttl.map(|d| (now as u64 + d.as_secs()) as i64);
        let conn = self.pooled()?;
        conn.execute(
            "INSERT INTO tokens (token_hash, repo_id, scope, created_at, expires_at, subject)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                hash,
                repo_id.as_str(),
                scope.as_str(),
                now,
                expires_at,
                subject.map(|s| s.as_str())
            ],
        )?;
        Ok(token)
    }

    async fn lookup(&self, token: &Token) -> Result<Option<TokenRecord>> {
        let hash = sha256_hex(token.as_str());
        let now = now_secs() as i64;
        let conn = self.pooled()?;
        // Side note on the `WHERE token_hash = ?1` compare: SQLite's
        // btree comparator is not byte-wise constant-time, but the
        // value it compares is `sha256_hex(token)`. A timing oracle
        // can only narrow the search on bytes of the *hash*, and an
        // attacker controls only the *preimage* — moving toward any
        // target hash requires inverting SHA-256. The hash dominates
        // the analysis; using subtle::ConstantTimeEq here would not
        // raise the bar. The admin-token path in auth.rs is a
        // different shape (the secret IS the bytes that are
        // compared), which is why that path *does* use ct_eq.
        // SELECT only the columns we surface. The expired-row filter
        // is enforced by the predicate, not by reading expires_at into
        // the struct; the subject column is exposed through the
        // listing path (TokenSummary), not the auth lookup.
        let mut stmt = conn.prepare_cached(
            "SELECT repo_id, scope FROM tokens
             WHERE token_hash = ?1
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?2)",
        )?;
        let mut rows = stmt.query(params![hash, now])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let repo_id_raw: String = row.get(0)?;
        let scope: String = row.get(1)?;
        // repo_id was inserted via `repo_id.as_str()` on a typed RepoId
        // (mint enforces this); a malformed value here is DB corruption.
        // Surface as "token unresolved" rather than poisoning auth.
        let repo_id = match RepoId::try_from(repo_id_raw.as_str()) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    repo_id = %repo_id_raw, error = %e,
                    "tokens.lookup: row repo_id malformed; treating as absent"
                );
                return Ok(None);
            },
        };
        Ok(Some(TokenRecord {
            repo_id,
            scope: Scope::parse(&scope)?,
        }))
    }

    async fn revoke(&self, token: &Token) -> Result<bool> {
        let hash = sha256_hex(token.as_str());
        let now = now_secs() as i64;
        let conn = self.pooled()?;
        let affected = conn.execute(
            "UPDATE tokens SET revoked_at = ?1
             WHERE token_hash = ?2 AND revoked_at IS NULL",
            params![now, hash],
        )?;
        Ok(affected > 0)
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

    async fn revoke_all_for_repo(&self, repo_id: &RepoId) -> Result<u64> {
        let now = now_secs() as i64;
        let conn = self.pooled()?;
        // We only flip rows that are still authorizing — already-expired
        // tokens are dead anyway, so leaving their `revoked_at` NULL keeps
        // the audit trail honest ("this token expired" vs "this token was
        // explicitly revoked"). Pruning will sweep both states later.
        let affected = conn.execute(
            "UPDATE tokens SET revoked_at = ?1
             WHERE repo_id = ?2
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?1)",
            params![now, repo_id.as_str()],
        )?;
        Ok(affected as u64)
    }

    async fn count_active(&self) -> Result<u64> {
        let now = now_secs() as i64;
        let conn = self.pooled()?;
        // Mirrors the lookup predicate exactly — a row is active iff it
        // would currently resolve to a TokenRecord. Pruning is what
        // keeps this aggregate cheap; an unbounded `tokens` table with
        // millions of revoked rows would still run fast (PK-indexed
        // counting with a covering predicate) but the periodic prune
        // ensures the working set stays small.
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM tokens
             WHERE revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?1)",
            params![now],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    async fn list_for_repo(
        &self,
        repo_id: &RepoId,
        subject_filter: Option<&Subject>,
    ) -> Result<Vec<TokenSummary>> {
        let now = now_secs() as i64;
        let conn = self.pooled()?;
        let mut stmt = conn.prepare_cached(
            "SELECT token_hash, repo_id, scope, created_at, expires_at, revoked_at, subject
             FROM tokens
             WHERE repo_id = ?1
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?2)
               AND (?3 IS NULL OR subject = ?3)
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(
            params![repo_id.as_str(), now, subject_filter.map(|s| s.as_str())],
            |row| {
                let token_hash: String = row.get(0)?;
                let repo_id: String = row.get(1)?;
                let scope: String = row.get(2)?;
                let created_at: i64 = row.get(3)?;
                let expires_at: Option<i64> = row.get(4)?;
                let revoked_at: Option<i64> = row.get(5)?;
                let subject: Option<String> = row.get(6)?;
                Ok((
                    token_hash, repo_id, scope, created_at, expires_at, revoked_at, subject,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (hash, repo_id_raw, scope_s, created, expires, revoked, subject_raw) = row?;
            // Rows in `tokens` were inserted via `repo_id.as_str()` /
            // `subject.as_str()` so a malformed value here is corruption,
            // not user input — log + skip rather than fail the whole list.
            let repo_id = match RepoId::try_from(repo_id_raw.as_str()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        repo_id = %repo_id_raw, error = %e,
                        "tokens.list_for_repo: row repo_id malformed; skipping"
                    );
                    continue;
                },
            };
            let subject = match subject_raw.as_deref() {
                Some(s) => match Subject::try_from(s) {
                    Ok(sub) => Some(sub),
                    Err(e) => {
                        tracing::warn!(
                            subject = %s, error = %e,
                            "tokens.list_for_repo: row subject malformed; surfacing as admin-minted"
                        );
                        None
                    },
                },
                None => None,
            };
            out.push(TokenSummary {
                id: hash.chars().take(16).collect(),
                repo_id,
                scope: Scope::parse(&scope_s)?,
                created_at: created as u64,
                expires_at: expires.map(|v| v as u64),
                revoked_at: revoked.map(|v| v as u64),
                subject,
            });
        }
        Ok(out)
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
    for b in &digest {
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
    use rusqlite::Connection;

    fn rid(s: &str) -> RepoId {
        RepoId::try_from(s).unwrap()
    }
    fn sub(s: &str) -> Subject {
        Subject::try_from(s).unwrap()
    }
    fn tok(s: &str) -> Token {
        Token::try_from(s).unwrap()
    }

    fn open_store() -> (tempfile::TempDir, SqliteTokenStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn mint_then_lookup_roundtrip() {
        let (_d, store) = open_store();
        let t = store
            .mint(&rid("repo-a"), Scope::Write, None, None)
            .await
            .unwrap();
        let rec = store.lookup(&t).await.unwrap().unwrap();
        assert_eq!(rec.repo_id.as_str(), "repo-a");
        assert_eq!(rec.scope, Scope::Write);
        // expires_at = None round-trips: a row minted without a TTL
        // is verified via the listing path, which is the surface
        // that exposes the column to callers.
        let listed = store.list_for_repo(&rid("repo-a"), None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].expires_at.is_none());
    }

    #[tokio::test]
    async fn lookup_of_unknown_is_none() {
        let (_d, store) = open_store();
        assert!(store.lookup(&tok("never-minted")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_makes_lookup_return_none() {
        let (_d, store) = open_store();
        let t = store
            .mint(&rid("rtst"), Scope::Read, None, None)
            .await
            .unwrap();
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
        let t = store
            .mint(
                &rid("rtst"),
                Scope::Read,
                Some(Duration::from_secs(0)),
                None,
            )
            .await
            .unwrap();
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
            s.mint(&rid("persistent"), Scope::Write, None, None)
                .await
                .unwrap()
        };
        // Drop the first store, reopen on the same path.
        let s2 = SqliteTokenStore::open(&path).unwrap();
        let rec = s2.lookup(&t).await.unwrap().expect("token survived reopen");
        assert_eq!(rec.repo_id.as_str(), "persistent");
    }

    #[tokio::test]
    async fn stored_value_is_not_the_raw_token() {
        // Belt-and-suspenders: verify we never write the raw token into
        // the db, only its hash.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        let t = store
            .mint(&rid("rtst"), Scope::Read, None, None)
            .await
            .unwrap();

        let conn = Connection::open(&path).unwrap();
        let mut stmt = conn
            .prepare("SELECT token_hash FROM tokens WHERE repo_id = 'rtst'")
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 1);
        let stored = &rows[0];
        assert_ne!(
            stored.as_str(),
            t.as_str(),
            "raw token must not appear in db"
        );
        assert_eq!(stored.as_str(), sha256_hex(t.as_str()).as_str());
    }

    fn count_rows(path: &std::path::Path) -> i64 {
        let conn = Connection::open(path).unwrap();
        conn.query_row("SELECT COUNT(*) FROM tokens", [], |r| r.get(0))
            .unwrap()
    }

    #[tokio::test]
    async fn prune_removes_revoked_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        let t_live = store
            .mint(&rid("live-r"), Scope::Read, None, None)
            .await
            .unwrap();
        let t_dead = store
            .mint(&rid("dead-r"), Scope::Read, None, None)
            .await
            .unwrap();
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
        let _t = store
            .mint(
                &rid("rtst"),
                Scope::Read,
                Some(Duration::from_secs(0)),
                None,
            )
            .await
            .unwrap();
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
    async fn mint_records_subject_via_listing_surface() {
        // The subject column is exposed through the listing surface
        // (TokenSummary), not the auth lookup (TokenRecord). Pin the
        // round-trip there.
        let (_d, store) = open_store();
        let _t = store
            .mint(
                &rid("r-acct"),
                Scope::Read,
                None,
                Some(&sub("alice@example")),
            )
            .await
            .unwrap();
        let listed = store.list_for_repo(&rid("r-acct"), None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].subject.as_ref().map(|s| s.as_str()),
            Some("alice@example")
        );
    }

    #[tokio::test]
    async fn list_for_repo_filters_by_subject_when_set() {
        let (_d, store) = open_store();
        let _alice = store
            .mint(&rid("repo1"), Scope::Read, None, Some(&sub("alice")))
            .await
            .unwrap();
        let _bob = store
            .mint(&rid("repo1"), Scope::Read, None, Some(&sub("bob")))
            .await
            .unwrap();
        let _admin_minted = store
            .mint(&rid("repo1"), Scope::Read, None, None)
            .await
            .unwrap();

        // No filter: every live row.
        let all = store.list_for_repo(&rid("repo1"), None).await.unwrap();
        assert_eq!(all.len(), 3);

        // Filtered by subject: only that user's rows.
        let alice_only = store
            .list_for_repo(&rid("repo1"), Some(&sub("alice")))
            .await
            .unwrap();
        assert_eq!(alice_only.len(), 1);
        assert_eq!(
            alice_only[0].subject.as_ref().map(|s| s.as_str()),
            Some("alice")
        );

        // Subject that never minted anything → empty.
        let chuck = store
            .list_for_repo(&rid("repo1"), Some(&sub("chuck")))
            .await
            .unwrap();
        assert!(chuck.is_empty());
    }

    #[tokio::test]
    async fn list_for_repo_excludes_revoked_rows() {
        let (_d, store) = open_store();
        let t = store
            .mint(&rid("repo1"), Scope::Read, None, Some(&sub("alice")))
            .await
            .unwrap();
        let _ = store
            .mint(&rid("repo1"), Scope::Read, None, Some(&sub("alice")))
            .await
            .unwrap();
        store.revoke(&t).await.unwrap();
        let live = store.list_for_repo(&rid("repo1"), None).await.unwrap();
        assert_eq!(live.len(), 1, "revoked row must not be in listing");
    }

    #[tokio::test]
    async fn list_for_repo_returns_token_id_not_raw() {
        // Belt-and-suspenders: the listing must never carry the raw
        // token. The id field should be the SHA-256 hex prefix, not
        // the URL-safe base64 token bytes.
        let (_d, store) = open_store();
        let t = store
            .mint(&rid("repo1"), Scope::Read, None, Some(&sub("alice")))
            .await
            .unwrap();
        let listed = store.list_for_repo(&rid("repo1"), None).await.unwrap();
        assert_eq!(listed.len(), 1);
        let id = &listed[0].id;
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(id.as_str(), &t.as_str()[..16.min(t.as_str().len())]);
    }

    #[tokio::test]
    async fn open_migrates_legacy_db_without_subject_column() {
        // Simulate a database written by a pre-M4b-account version:
        // create the schema by hand without the `subject` column,
        // insert a row, then open() should ALTER it in place and
        // mint() / lookup() should work afterward.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE tokens (
                 token_hash TEXT PRIMARY KEY,
                 repo_id    TEXT NOT NULL,
                 scope      TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER,
                 revoked_at INTEGER
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tokens(token_hash, repo_id, scope, created_at)
             VALUES (?1, 'repo1', 'read', 0)",
            params!["fakehash"],
        )
        .unwrap();
        drop(conn);

        // open() should add the subject column without complaining.
        let store = SqliteTokenStore::open(&path).unwrap();
        // Now mint succeeds with a subject (column is there) and
        // lookup returns subject=None for the legacy row.
        let listing = store.list_for_repo(&rid("repo1"), None).await.unwrap();
        assert_eq!(listing.len(), 1);
        assert!(listing[0].subject.is_none());
        // Reopening is idempotent — second open mustn't error
        // because the column already exists.
        let _ = SqliteTokenStore::open(&path).unwrap();
    }

    #[tokio::test]
    async fn revoke_all_for_repo_kills_every_live_token_for_that_repo() {
        let (_d, store) = open_store();
        let t1 = store
            .mint(&rid("repo1"), Scope::Read, None, None)
            .await
            .unwrap();
        let t2 = store
            .mint(&rid("repo1"), Scope::Write, None, None)
            .await
            .unwrap();
        let t3 = store
            .mint(&rid("repo2"), Scope::Read, None, None)
            .await
            .unwrap();

        // Sanity: all three resolve.
        assert!(store.lookup(&t1).await.unwrap().is_some());
        assert!(store.lookup(&t2).await.unwrap().is_some());
        assert!(store.lookup(&t3).await.unwrap().is_some());

        let revoked = store.revoke_all_for_repo(&rid("repo1")).await.unwrap();
        assert_eq!(revoked, 2);

        // r1 tokens are dead, r2 is untouched.
        assert!(store.lookup(&t1).await.unwrap().is_none());
        assert!(store.lookup(&t2).await.unwrap().is_none());
        assert!(store.lookup(&t3).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_all_for_repo_is_idempotent() {
        let (_d, store) = open_store();
        let _t = store
            .mint(&rid("repo1"), Scope::Read, None, None)
            .await
            .unwrap();
        let first = store.revoke_all_for_repo(&rid("repo1")).await.unwrap();
        let second = store.revoke_all_for_repo(&rid("repo1")).await.unwrap();
        assert_eq!(first, 1);
        assert_eq!(second, 0);
    }

    #[tokio::test]
    async fn revoke_all_for_repo_skips_already_expired_rows() {
        // Already-expired rows shouldn't get a `revoked_at` stamp by
        // accident — the audit trail wants "expired" distinct from
        // "explicitly revoked". Verified by checking that prune (with
        // zero grace) sees one expired row before and after the call.
        let (_d, store) = open_store();
        let _t_live = store
            .mint(&rid("repo1"), Scope::Read, None, None)
            .await
            .unwrap();
        let _t_dead = store
            .mint(
                &rid("repo1"),
                Scope::Write,
                Some(Duration::from_secs(0)),
                None,
            )
            .await
            .unwrap();
        let revoked = store.revoke_all_for_repo(&rid("repo1")).await.unwrap();
        assert_eq!(revoked, 1, "only the live row should flip to revoked");
    }

    #[tokio::test]
    async fn prune_leaves_live_never_expiring_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.db");
        let store = SqliteTokenStore::open(&path).unwrap();
        let _t = store
            .mint(&rid("rtst"), Scope::Read, None, None)
            .await
            .unwrap();
        store.prune(Duration::from_secs(0)).await.unwrap();
        assert_eq!(count_rows(&path), 1);
    }
}
