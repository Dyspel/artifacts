//! Forward-only schema migrations for the SQLite stores.
//!
//! Each store calls [`run`] at `open()` time with its own static list
//! of migrations. The framework records applied versions in a
//! per-database `schema_version` table (namespaced by store name, so
//! two stores sharing one SQLite file — tokens + ownership today —
//! don't collide). On startup, only migrations whose version is
//! greater than the recorded high-water mark run.
//!
//! ## Why a framework at all
//!
//! Before this module, every store's `open()` ran `CREATE TABLE IF
//! NOT EXISTS` followed by an ad-hoc `ALTER TABLE … ADD COLUMN …`
//! that swallowed the duplicate-column error. That worked for one
//! migration per store but composes badly: a third migration on
//! the same table needs the same swallow-on-error dance, the version
//! history is invisible at runtime, and a typo in one migration's
//! SQL silently runs again on every restart with no audit trail.
//!
//! The framework gives us:
//!   - one `schema_version` row per applied migration → audit trail
//!   - migrations only run once → no swallowed errors
//!   - a fast skip-already-applied check on every restart
//!
//! ## What it deliberately doesn't do
//!
//! - **No down migrations.** Rollback is a separate problem (restore
//!   from backup, copy data into a new DB). Forward-only keeps the
//!   surface small.
//! - **No version-skipping.** Migrations apply in order; you can't
//!   request "skip v2, go straight to v3."
//! - **No transactions across migrations.** Each migration's SQL is
//!   responsible for its own atomicity. SQLite's `BEGIN…COMMIT` would
//!   compose poorly with `CREATE TABLE`/`ALTER TABLE`, which auto-commit
//!   on most platforms.

use crate::error::{Error, Result};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use std::path::Path;

/// Pool type alias used across every SQLite-backed store. r2d2's
/// `Pool` is internally `Arc<Inner>` so cloning is cheap; no outer
/// `Arc` wrapper is needed.
pub type DbPool = r2d2::Pool<SqliteConnectionManager>;

/// One forward-only schema migration. `version` numbers within a
/// namespace must be strictly increasing and contiguous; gaps are
/// allowed but `up()` will run in numeric order regardless.
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub up: fn(&Connection) -> rusqlite::Result<()>,
}

/// Apply every pending migration in `migrations` to `conn`, recording
/// each in the `schema_version` table under `namespace`. Idempotent —
/// already-applied migrations are skipped.
///
/// `namespace` is a stable string that identifies a logical schema
/// owner. Two owners can share one SQLite file (tokens.db has both
/// `tokens` and `ownership` namespaces today); the version counter is
/// per-namespace.
pub fn run(conn: &Connection, namespace: &str, migrations: &[Migration]) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
             namespace  TEXT    NOT NULL,
             version    INTEGER NOT NULL,
             name       TEXT    NOT NULL,
             applied_at INTEGER NOT NULL,
             PRIMARY KEY (namespace, version)
         )",
    )?;
    let current: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version WHERE namespace = ?1",
            [namespace],
            |row| row.get::<_, i64>(0).map(|v| v as u32),
        )
        .unwrap_or(0);
    for m in migrations {
        if m.version <= current {
            continue;
        }
        (m.up)(conn)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        conn.execute(
            "INSERT INTO schema_version (namespace, version, name, applied_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![namespace, m.version, m.name, now],
        )?;
        tracing::info!(
            namespace,
            version = m.version,
            name = m.name,
            "migration applied",
        );
    }
    Ok(())
}

/// Open a SQLite database, set the WAL pragmas every store wants,
/// and apply the given migrations. One helper instead of five
/// hand-rolled `open()` bodies, each three lines of WAL boilerplate
/// preceded by `Connection::open` and followed by `db_migrate::run`.
///
/// Each store still owns its own `Arc<…Mutex<Connection>>` wrapper —
/// some pick the tokio mutex (so `metrics::lock_sqlite` can observe
/// the wait), some pick the std mutex (because the surrounding trait
/// is sync). The wrapper choice belongs to the store; the open +
/// pragma + migration sequence is the shared part.
pub fn open_with_migrations(
    path: &Path,
    namespace: &str,
    migrations: &[Migration],
) -> Result<Connection> {
    let conn = Connection::open(path)?;
    // WAL gives concurrent readers while a writer is in progress;
    // synchronous=NORMAL trades a small durability window (you can
    // lose the last few transactions on power loss, vs FULL which
    // fsyncs every commit) for ~10× write throughput. Acceptable for
    // every store today — tokens, audit, ownership, webhooks all
    // tolerate the loss-of-last-few-txns window.
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;",
    )?;
    run(&conn, namespace, migrations)?;
    Ok(conn)
}

/// Default max pool size. SQLite under WAL allows N readers + 1
/// writer concurrently; 8 is generous for a single-node prototype
/// and well below the per-process FD budget. Tune via the (unwritten)
/// `ARTIFACTS_SQLITE_POOL_SIZE` env var if a benchmark needs it.
const DEFAULT_POOL_SIZE: u32 = 8;

/// Open an `r2d2` connection pool backed by SQLite at `path`, with
/// each connection initialized to WAL mode + the same migrations
/// `open_with_migrations` applies. Migrations run **once** on a
/// scratch connection at pool creation, not every connection — the
/// `schema_version` rows are reused after that.
///
/// Returns a `DbPool`. The store keeps the pool by value (no `Arc`
/// wrapper; r2d2's `Pool` is already `Arc<Inner>` internally).
pub fn open_pool_with_migrations(
    path: &Path,
    namespace: &str,
    migrations: &[Migration],
) -> Result<DbPool> {
    // Apply migrations once on a one-shot connection. Doing this here
    // (rather than from `with_init`) avoids re-running the migrator
    // on every pooled connection — migrations are idempotent but the
    // `schema_version` reads still cost a query per connection.
    open_with_migrations(path, namespace, migrations)?;

    let manager = SqliteConnectionManager::file(path).with_init(|c| {
        // Every newly-opened pooled connection gets the same WAL
        // pragmas the migrator's one-shot connection set. WAL mode
        // is a per-file mode (persists in the SQLite header), so
        // it's already set after the first open; synchronous=NORMAL
        // is per-connection and must be re-applied.
        c.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;",
        )
    });
    r2d2::Pool::builder()
        .max_size(DEFAULT_POOL_SIZE)
        .build(manager)
        .map_err(|e| Error::Other(anyhow::anyhow!("build sqlite pool: {e}")))
}

/// Generate the boilerplate every single-pool SQLite store shares:
/// the migration-running `open()` constructor, a `pool()` accessor for
/// the periodic gauge refreshers, and a metrics-labelled `pooled()`
/// connection checkout. The store `struct` (with its own doc comment)
/// is still declared by hand; this only fills in the three methods that
/// are character-for-character identical across stores apart from the
/// label string. The label lived inline at ~26 call sites before this —
/// now it's named exactly once, at the invocation.
///
/// Requires the type to have a single `conn: DbPool` field. Stores with
/// extra state (e.g. `SqliteWebhookRegistry`, which also holds a master
/// key) keep their hand-written versions.
///
/// Invoke at module scope after the struct:
/// `sqlite_store_boilerplate!(SqliteTokenStore, "tokens", MIGRATIONS);`
macro_rules! sqlite_store_boilerplate {
    ($store:ty, $label:literal, $migrations:path) => {
        impl $store {
            /// Open (or create) the backing SQLite database at `path`
            /// and apply all pending migrations.
            ///
            /// # Errors
            /// Returns an error if the database can't be opened, a
            /// migration fails, or the pool can't be built.
            pub fn open(path: &::std::path::Path) -> $crate::error::Result<Self> {
                Ok(Self {
                    conn: $crate::db_migrate::open_pool_with_migrations(
                        path,
                        $label,
                        &$migrations,
                    )?,
                })
            }

            /// The connection pool, exposed for the periodic
            /// active-rows gauge refreshers.
            pub(crate) fn pool(&self) -> &$crate::db_migrate::DbPool {
                &self.conn
            }

            /// Check out a pooled connection, recording the wait under
            /// this store's metrics label. `Err` on pool exhaustion.
            fn pooled(
                &self,
            ) -> $crate::error::Result<r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>>
            {
                $crate::metrics::get_pooled(&self.conn, $label)
            }
        }
    };
}
pub(crate) use sqlite_store_boilerplate;

/// Helper for migrations that add a column to an existing table.
/// `PRAGMA table_info(<table>)` is consulted up front; the ALTER only
/// fires if `column` is missing. Cleaner than running the ALTER and
/// swallowing the duplicate-column error, and gives the migration a
/// well-defined "this is a no-op" branch for re-runs against legacy
/// databases that ran the ad-hoc pre-framework ALTER on a previous
/// boot.
///
/// `table`, `column`, and `decl` come from static migration code —
/// not user input — so the inline format-string SQL is safe.
pub fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    decl: &str,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let has_col: bool = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .any(|n| n == column);
    if !has_col {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
            [],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open_mem() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn first_run_applies_all_migrations() {
        let conn = open_mem();
        let migs = &[
            Migration {
                version: 1,
                name: "init",
                up: |c| c.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)"),
            },
            Migration {
                version: 2,
                name: "add_col",
                up: |c| add_column_if_missing(c, "t", "extra", "TEXT"),
            },
        ];
        run(&conn, "test", migs).unwrap();
        // Both migrations recorded.
        let rows: Vec<(u32, String)> = conn
            .prepare("SELECT version, name FROM schema_version WHERE namespace = 'test' ORDER BY version")
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)? as u32, row.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![(1, "init".to_string()), (2, "add_col".to_string())]
        );
        // Schema is the expected shape.
        conn.execute("INSERT INTO t (v, extra) VALUES ('a', 'b')", [])
            .unwrap();
    }

    #[test]
    fn second_run_skips_already_applied() {
        let conn = open_mem();
        let migs = &[Migration {
            version: 1,
            name: "init",
            up: |c| c.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)"),
        }];
        run(&conn, "test", migs).unwrap();
        // Second run is a no-op — CREATE TABLE without IF NOT EXISTS
        // would error on a re-apply, so this proves the skip works.
        run(&conn, "test", migs).unwrap();
    }

    #[test]
    fn add_column_if_missing_is_idempotent() {
        let conn = open_mem();
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .unwrap();
        // Both calls succeed; second is the "already there" branch.
        add_column_if_missing(&conn, "t", "c", "TEXT").unwrap();
        add_column_if_missing(&conn, "t", "c", "TEXT").unwrap();
        // Verify the column actually exists.
        conn.execute("INSERT INTO t (c) VALUES ('x')", []).unwrap();
    }

    #[test]
    fn separate_namespaces_dont_collide() {
        let conn = open_mem();
        run(
            &conn,
            "alpha",
            &[Migration {
                version: 1,
                name: "a1",
                up: |c| c.execute_batch("CREATE TABLE a (id INTEGER PRIMARY KEY)"),
            }],
        )
        .unwrap();
        run(
            &conn,
            "beta",
            &[Migration {
                version: 1,
                name: "b1",
                up: |c| c.execute_batch("CREATE TABLE b (id INTEGER PRIMARY KEY)"),
            }],
        )
        .unwrap();
        // Both v1 rows present, one per namespace.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
}
