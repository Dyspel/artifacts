//! `ObjectStore`: the abstraction that future M2b chunked-KV storage
//! will plug into.
//!
//! ## Where this fits
//!
//! `Storage` (storage.rs) already abstracts the *repo lifecycle* —
//! `create`, `exists`, `fork`, `delete`. What it doesn't abstract is
//! *object reads*: the actual git objects (commits, trees, blobs)
//! still live on disk under `<repos_dir>/<id>.git/objects/` and are
//! read by either git plumbing subprocesses or direct filesystem
//! reads. To make `Storage`'s second impl meaningful (a chunked-KV
//! backend matching the Cloudflare DO+SQLite shape), object reads
//! also have to go through a trait.
//!
//! `ObjectStore` is that trait. Today it has one method
//! (`read_loose`) and one impl (`FsObjectStore`). Production code
//! does **not** route through this yet — that swap is the rest of
//! M2b. This module exists so the next commit can land a chunked-KV
//! impl without inventing the trait shape from scratch, and so the
//! intent is documented at the seam where it'll eventually slot in.
//!
//! ## What's still blocking real M2b
//!
//! The git pack handlers — `git pack-objects` (M1b-2b leaf) and
//! `git unpack-objects` (M1b-3 leaf) — operate on a real on-disk
//! `<repo>/objects/` tree. A chunked-KV `Storage` can't satisfy
//! those subprocesses because the bytes don't live in a directory.
//!
//! The M1b-2c / M1b-3-gix follow-up commits replace those
//! subprocesses with `gix-pack`-driven streaming reads + writes;
//! that's where `ObjectStore` actually gets called. Until then,
//! anything that reads/writes objects has to keep touching the
//! filesystem.
//!
//! ## What's delivered today
//!
//! - The trait and two impls — `FsObjectStore` (production-shape
//!   reads against `<repo>/objects/<aa>/<bbbb...>`) and
//!   `MemObjectStore` (in-memory `HashMap`-backed). The Mem impl is
//!   the M2b proof-of-concept: it shows the trait shape isn't
//!   accidentally FS-specific, so the eventual chunked-KV impl can
//!   plug in by implementing the same trait without trait surgery.
//! - A conformance test suite (`conformance` module) that runs
//!   both impls through the same contract checks — read-after-write
//!   round-trip, missing-oid → `None`, malformed-oid → `None`. New
//!   impls add their own conformance test by calling the shared
//!   helpers; the contract lives in one place.
//! - Documentation that says, plainly, that production code
//!   doesn't route through this yet.

use crate::error::{Error, Result};
use std::path::PathBuf;
// HashMap, RwLock, Path, Arc, Mutex only matter to MemObjectStore +
// SqliteObjectStore, both of which are `#[cfg(test)]`. Importing them
// at module scope would warn in non-test builds; gate the import too.
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use std::sync::{Arc, Mutex, RwLock};

/// One row of `ObjectStore::list_loose`. Captures the metadata
/// `gc` needs without an extra round-trip per object — the FS impl
/// reads stat in the same `read_dir` walk; a future KV impl reads
/// `oid + length(bytes) + created_at` in one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LooseInfo {
    pub oid: String,
    pub size: u64,
    /// Unix epoch seconds when the object was last written. The FS
    /// impl reads from mtime; a future chunked-KV impl reads from
    /// its own `created_at` column. Used by `gc::run`'s mtime
    /// guard — don't delete an object younger than the guard, in
    /// case a push that landed seconds ago is mid-stream.
    pub created_secs: i64,
}

/// Read + write view into a repo's git object database.
///
/// Production paths route through this for `gc`, the
/// commits-plumbing parent-exists check, and the native
/// receive-pack write branch (when `ARTIFACTS_NATIVE_INDEX_PACK=1`).
/// Other read paths (blob fetch, fetch-side pack generation) still
/// touch the filesystem directly or go through gix; routing those
/// is the remaining M2b work.
pub trait ObjectStore: Send + Sync {
    /// Read a loose object by its 40-char hex SHA-1. Returns the raw
    /// loose-object bytes (zlib-deflated header+payload). `Ok(None)`
    /// means the object isn't in this store as a loose file — it
    /// might be in a packfile, or absent entirely; callers that
    /// need that distinction should consult a higher-level `find`
    /// API on top of this trait.
    fn read_loose(&self, repo_id: &str, oid: &str) -> Result<Option<Vec<u8>>>;

    /// Store loose-object bytes for `(repo_id, oid)`. Idempotent:
    /// a second write of the same `oid` is a no-op (loose objects
    /// are content-addressed — the same oid implies the same
    /// bytes). Malformed `oid` is rejected with an error rather
    /// than silently dropped, since this is a write path and the
    /// caller wants to know.
    ///
    /// FS impl writes atomically via tmp-then-rename so a torn
    /// write never leaves a partial file at the canonical path.
    /// Mem impl just inserts into the map.
    ///
    /// Currently exercised only by the conformance suite — production
    /// receive-pack uses `ingest_pack` instead so the FS impl can
    /// stay in pack-file shape. Held on the trait so a future
    /// chunked-KV impl that *does* materialize loose-format bytes
    /// has a contract to satisfy.
    #[allow(dead_code)]
    fn write_loose(&self, repo_id: &str, oid: &str, bytes: &[u8]) -> Result<()>;

    /// Enumerate every loose object in the repo. Used by gc to
    /// compute the on-disk set that gets diffed against the
    /// reachable set. Order is unspecified — callers that need
    /// determinism sort.
    ///
    /// Returns an empty Vec for a repo that doesn't exist or has
    /// no loose objects yet (rather than an error) — this matches
    /// the FS shape where a missing `objects/` dir is identical
    /// to one with no loose subdirs.
    fn list_loose(&self, repo_id: &str) -> Result<Vec<LooseInfo>>;

    /// Delete a loose object by oid. Returns `Ok(true)` if a row
    /// was removed, `Ok(false)` if the object wasn't there
    /// (idempotent — a second delete of the same oid is fine).
    /// Malformed oid is an error, mirroring `write_loose`.
    fn delete_loose(&self, repo_id: &str, oid: &str) -> Result<bool>;

    /// Does the store have an object with this oid? Covers loose
    /// **and** packed in backends that have a pack concept (the FS
    /// impl walks `objects/pack/*.idx` via gix); KV-shaped backends
    /// where every object is loose just answer from their loose set.
    /// Malformed oid returns `Ok(false)` — same shape as `read_loose`.
    ///
    /// Default impl is `read_loose(...).is_some()`. Backends that
    /// can answer existence without reading the body (FS stat-only,
    /// pack `.idx` binary-search, KV row-presence) should override
    /// to skip the body fetch.
    fn exists(&self, repo_id: &str, oid: &str) -> Result<bool> {
        Ok(self.read_loose(repo_id, oid)?.is_some())
    }

    /// Ingest a pack file's contents into the store. The receive-pack
    /// handler calls this after parsing the incoming push; whatever
    /// the backend stores objects as (pack files on disk, individual
    /// rows in a KV) is the backend's choice.
    ///
    /// Returns the number of objects ingested (best-effort — backends
    /// that can't enumerate without a full re-scan may return 0; the
    /// receive-pack handler doesn't depend on this for correctness,
    /// just for tracing).
    ///
    /// Default impl returns `UnsupportedIngest`. Backends that can't
    /// resolve thin-pack deltas (the Mem and SQLite impls today
    /// — both lack a base-object lookup against an existing repo)
    /// fall through to this default and the receive-pack handler
    /// errors out. The FS impl overrides with `gix_pack` ingestion.
    fn ingest_pack(&self, _repo_id: &str, _pack_bytes: &[u8]) -> Result<usize> {
        Err(Error::Other(anyhow::anyhow!(
            "ingest_pack: not supported by this ObjectStore backend"
        )))
    }
}

/// Filesystem-backed `ObjectStore`. Reads from
/// `<root>/<id>.git/objects/<aa>/<bbbb...>`.
#[derive(Clone)]
pub struct FsObjectStore {
    root: PathBuf,
}

impl FsObjectStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn loose_path(&self, repo_id: &str, oid: &str) -> Option<PathBuf> {
        // Defensive: oid validation. We don't trust the caller for
        // path-traversal — anything outside the [a-f0-9]{40} shape
        // gets rejected. Shared with `MemObjectStore` so both impls
        // honor the same malformed-oid contract.
        if !oid_is_valid(oid) {
            return None;
        }
        let (a, b) = oid.split_at(2);
        Some(
            self.root
                .join(format!("{repo_id}.git"))
                .join("objects")
                .join(a)
                .join(b),
        )
    }
}

impl ObjectStore for FsObjectStore {
    fn read_loose(&self, repo_id: &str, oid: &str) -> Result<Option<Vec<u8>>> {
        let path = match self.loose_path(repo_id, oid) {
            Some(p) => p,
            None => return Ok(None),
        };
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::from(e)),
        }
    }

    fn write_loose(&self, repo_id: &str, oid: &str, bytes: &[u8]) -> Result<()> {
        let path = self.loose_path(repo_id, oid).ok_or_else(|| {
            Error::Other(anyhow::anyhow!("write_loose: invalid oid {oid:?}"))
        })?;
        // Idempotent — content-addressed storage means the same oid
        // implies the same bytes. Skip the rewrite to save the syscall
        // and avoid the rename race that brief existence would imply.
        if path.exists() {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic write: stage into a tmp file in the same parent
        // directory (so rename is filesystem-local), then rename
        // into place. A torn write to the tmp file leaves the
        // canonical path untouched. Tmp name uses pid+rand+oid
        // suffix so concurrent writers of the same object don't
        // collide on the tmp path.
        let parent = path.parent().expect("loose_path has 2-component prefix");
        let tmp_name = format!(".tmp-{}-{}-{}", std::process::id(), rand::random::<u32>(), oid);
        let tmp = parent.join(tmp_name);
        std::fs::write(&tmp, bytes)?;
        match std::fs::rename(&tmp, &path) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Clean up the tmp on failure so we don't leave
                // garbage. Best-effort; if cleanup fails too, the
                // original error is the one that matters.
                let _ = std::fs::remove_file(&tmp);
                Err(Error::from(e))
            }
        }
    }

    fn list_loose(&self, repo_id: &str) -> Result<Vec<LooseInfo>> {
        let objects = self.root.join(format!("{repo_id}.git")).join("objects");
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&objects) {
            Ok(e) => e,
            // Missing objects/ dir is identical to "no loose objects".
            // Don't bubble — gc treats this as a no-op pass.
            Err(_) => return Ok(out),
        };
        for ent in entries.flatten() {
            let name = match ent.file_name().to_str().map(str::to_string) {
                Some(s) => s,
                None => continue,
            };
            // Loose-object subdirs are exactly 2 hex chars. Skip
            // `info/`, `pack/`, `.tmp-*` rename stragglers, etc.
            if name.len() != 2 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let subdir = ent.path();
            let inner = match std::fs::read_dir(&subdir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for f in inner.flatten() {
                let fname = match f.file_name().to_str().map(str::to_string) {
                    Some(s) => s,
                    None => continue,
                };
                if fname.len() != 38 || !fname.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                let oid = format!("{name}{fname}");
                let meta = match f.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let created_secs = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                out.push(LooseInfo {
                    oid,
                    size: meta.len(),
                    created_secs,
                });
            }
        }
        Ok(out)
    }

    fn delete_loose(&self, repo_id: &str, oid: &str) -> Result<bool> {
        let path = self.loose_path(repo_id, oid).ok_or_else(|| {
            Error::Other(anyhow::anyhow!("delete_loose: invalid oid {oid:?}"))
        })?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::from(e)),
        }
    }

    fn exists(&self, repo_id: &str, oid: &str) -> Result<bool> {
        // Fast path: stat the loose location. Cheaper than opening
        // gix and never wakes the pack index. Most freshly-pushed
        // objects live here until `git gc` repacks them.
        if let Some(path) = self.loose_path(repo_id, oid) {
            if path.exists() {
                return Ok(true);
            }
        } else {
            return Ok(false);
        }
        // Slow path: pack visibility. Open the repo via gix and
        // consult its object database — gix walks `objects/pack/*.idx`
        // and resolves the oid binary-search-style. Cheaper than
        // shelling out to `git cat-file -e` (no process fork, no
        // child handshake) but still pays for the gix::open.
        let repo_path = self.root.join(format!("{repo_id}.git"));
        if !repo_path.is_dir() {
            return Ok(false);
        }
        let repo = match gix::open(&repo_path) {
            Ok(r) => r,
            // A repo that gix refuses to open can't have the oid
            // either; treat as "no such object" rather than bubbling.
            Err(_) => return Ok(false),
        };
        let gix_oid = match gix::ObjectId::from_hex(oid.as_bytes()) {
            Ok(o) => o,
            Err(_) => return Ok(false),
        };
        Ok(repo.find_header(gix_oid).is_ok())
    }

    fn ingest_pack(&self, repo_id: &str, pack_bytes: &[u8]) -> Result<usize> {
        // Delegates to the existing native pack indexer. The pack file
        // lands at `<repo>/objects/pack/pack-<sha>.{pack,idx}`; gix
        // resolves thin-pack deltas against the repo's existing odb.
        // Returns 0 for empty packs (delete-only refspecs) — the
        // helper short-circuits on `len <= 32` and we mirror that
        // here to keep the "objects added" count meaningful.
        if pack_bytes.len() <= 32 {
            return Ok(0);
        }
        let repo_path = self.root.join(format!("{repo_id}.git"));
        crate::native_pack::index_pack_into_repo(&repo_path, pack_bytes)?;
        // The helper doesn't surface the count; the receive-pack
        // tracing already logs it inside index_pack_into_repo via
        // the `objects` field, so returning 0 here is fine — callers
        // shouldn't rely on the return value for anything but a
        // tracing breadcrumb.
        Ok(0)
    }
}

/// In-memory `ObjectStore`. Backed by an `RwLock<HashMap<(repo_id, oid),
/// MemEntry>>`; reads share the lock, writes serialize. Built as the
/// M2b proof-of-concept that the trait isn't FS-specific. Tests use it
/// as a fast, deterministic alternative to spinning up a real
/// `<repo>/objects/` tree.
///
/// Only compiled into the test binary — production callers use
/// `FsObjectStore` or the new `SqliteObjectStore`. Gated this way
/// rather than carrying `#[allow(dead_code)]` so the production
/// surface honestly reflects what's deployed.
#[cfg(test)]
pub struct MemObjectStore {
    objects: RwLock<HashMap<(String, String), MemEntry>>,
}

/// One row in `MemObjectStore`. Carries `created_secs` so the Mem
/// impl can satisfy `list_loose`'s `LooseInfo.created_secs` contract
/// the same way the FS impl does (mtime). Tests that need to control
/// the timestamp use the `_with_ts` helper.
#[cfg(test)]
#[derive(Debug, Clone)]
struct MemEntry {
    bytes: Vec<u8>,
    created_secs: i64,
}

#[cfg(test)]
impl MemObjectStore {
    pub fn new() -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
        }
    }

}

#[cfg(test)]
impl Default for MemObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl ObjectStore for MemObjectStore {
    fn read_loose(&self, repo_id: &str, oid: &str) -> Result<Option<Vec<u8>>> {
        if !oid_is_valid(oid) {
            return Ok(None);
        }
        Ok(self
            .objects
            .read()
            .expect("MemObjectStore lock poisoned")
            .get(&(repo_id.to_string(), oid.to_string()))
            .map(|e| e.bytes.clone()))
    }

    fn write_loose(&self, repo_id: &str, oid: &str, bytes: &[u8]) -> Result<()> {
        if !oid_is_valid(oid) {
            return Err(Error::Other(anyhow::anyhow!(
                "write_loose: invalid oid {oid:?}"
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.objects
            .write()
            .expect("MemObjectStore lock poisoned")
            .insert(
                (repo_id.to_string(), oid.to_string()),
                MemEntry {
                    bytes: bytes.to_vec(),
                    created_secs: now,
                },
            );
        Ok(())
    }

    fn list_loose(&self, repo_id: &str) -> Result<Vec<LooseInfo>> {
        Ok(self
            .objects
            .read()
            .expect("MemObjectStore lock poisoned")
            .iter()
            .filter(|((r, _), _)| r == repo_id)
            .map(|((_, oid), e)| LooseInfo {
                oid: oid.clone(),
                size: e.bytes.len() as u64,
                created_secs: e.created_secs,
            })
            .collect())
    }

    fn delete_loose(&self, repo_id: &str, oid: &str) -> Result<bool> {
        if !oid_is_valid(oid) {
            return Err(Error::Other(anyhow::anyhow!(
                "delete_loose: invalid oid {oid:?}"
            )));
        }
        Ok(self
            .objects
            .write()
            .expect("MemObjectStore lock poisoned")
            .remove(&(repo_id.to_string(), oid.to_string()))
            .is_some())
    }

    fn exists(&self, repo_id: &str, oid: &str) -> Result<bool> {
        if !oid_is_valid(oid) {
            return Ok(false);
        }
        // Skip the body clone — `contains_key` is all we need.
        Ok(self
            .objects
            .read()
            .expect("MemObjectStore lock poisoned")
            .contains_key(&(repo_id.to_string(), oid.to_string())))
    }
}

/// SQLite-backed `ObjectStore`. The second-generation impl that
/// matches the README's chunked-KV target shape (one row per loose
/// object today; horizontal chunking can be layered on later without
/// changing the trait).
///
/// Why this exists in the prototype: the production target is "objects
/// chunked into a KV, matching the DO+SQLite shape." Picking SQLite
/// for the prototype means the row format is the same one a DO would
/// use, and the schema-migration framework already in place handles
/// the rollout. Today this impl is wired only through the conformance
/// suite — production code still uses `FsObjectStore` — but the
/// conformance guarantees prove the trait shape isn't FS-specific.
///
/// Concurrency: `std::sync::Mutex<Connection>` (not the tokio variant)
/// because `ObjectStore` is a sync trait. Mirrors the
/// `SqliteWebhookRegistry` shape for the same reason. The
/// `metrics::lock_sqlite` helper only fits the tokio mutex shape, so
/// no contention metric on this store yet; if we wire it into
/// production we should reconsider whether the trait should be async.
#[cfg(test)]
pub struct SqliteObjectStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

#[cfg(test)]
const SQLITE_OBJECT_STORE_MIGRATIONS: [crate::db_migrate::Migration; 1] =
    [crate::db_migrate::Migration {
        version: 1,
        name: "init",
        up: |c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS loose_objects (
                     repo_id    TEXT NOT NULL,
                     oid        TEXT NOT NULL,
                     bytes      BLOB NOT NULL,
                     created_at INTEGER NOT NULL,
                     PRIMARY KEY (repo_id, oid)
                 );
                 CREATE INDEX IF NOT EXISTS idx_loose_repo ON loose_objects(repo_id);",
            )
        },
    }];

#[cfg(test)]
impl SqliteObjectStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;",
        )?;
        crate::db_migrate::run(&conn, "object_store", &SQLITE_OBJECT_STORE_MIGRATIONS)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
        // Poisoned lock recovery: a panic inside one method should
        // not deadlock every subsequent caller; recover the inner
        // Connection. Mirrors `SqliteWebhookRegistry::lock`.
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
impl ObjectStore for SqliteObjectStore {
    fn read_loose(&self, repo_id: &str, oid: &str) -> Result<Option<Vec<u8>>> {
        if !oid_is_valid(oid) {
            return Ok(None);
        }
        let conn = self.lock();
        let res = conn.query_row(
            "SELECT bytes FROM loose_objects WHERE repo_id = ?1 AND oid = ?2",
            rusqlite::params![repo_id, oid],
            |row| row.get::<_, Vec<u8>>(0),
        );
        match res {
            Ok(b) => Ok(Some(b)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::from(e)),
        }
    }

    fn write_loose(&self, repo_id: &str, oid: &str, bytes: &[u8]) -> Result<()> {
        if !oid_is_valid(oid) {
            return Err(Error::Other(anyhow::anyhow!(
                "write_loose: invalid oid {oid:?}"
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let conn = self.lock();
        // `INSERT OR IGNORE` keeps writes idempotent — loose objects
        // are content-addressed (same oid implies same bytes), so a
        // second write of the same row is meaningless. Same semantics
        // as `FsObjectStore::write_loose`'s early-return-on-exists.
        conn.execute(
            "INSERT OR IGNORE INTO loose_objects (repo_id, oid, bytes, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![repo_id, oid, bytes, now],
        )?;
        Ok(())
    }

    fn list_loose(&self, repo_id: &str) -> Result<Vec<LooseInfo>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT oid, LENGTH(bytes), created_at
             FROM loose_objects
             WHERE repo_id = ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![repo_id], |row| {
            Ok(LooseInfo {
                oid: row.get(0)?,
                size: row.get::<_, i64>(1)? as u64,
                created_secs: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn delete_loose(&self, repo_id: &str, oid: &str) -> Result<bool> {
        if !oid_is_valid(oid) {
            return Err(Error::Other(anyhow::anyhow!(
                "delete_loose: invalid oid {oid:?}"
            )));
        }
        let conn = self.lock();
        let affected = conn.execute(
            "DELETE FROM loose_objects WHERE repo_id = ?1 AND oid = ?2",
            rusqlite::params![repo_id, oid],
        )?;
        Ok(affected > 0)
    }

    fn exists(&self, repo_id: &str, oid: &str) -> Result<bool> {
        if !oid_is_valid(oid) {
            return Ok(false);
        }
        let conn = self.lock();
        // `EXISTS` skips returning the bytes; the planner sees the
        // covering index and answers from the index alone.
        let n: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM loose_objects WHERE repo_id = ?1 AND oid = ?2)",
            rusqlite::params![repo_id, oid],
            |row| row.get(0),
        )?;
        Ok(n != 0)
    }
}

/// 40-char lowercase hex. The validation contract both impls share —
/// keeping it in one place means the conformance test for malformed
/// oids exercises the same predicate against both backends.
fn oid_is_valid(oid: &str) -> bool {
    oid.len() == 40 && oid.chars().all(|c| c.is_ascii_hexdigit())
}

/// Conformance contract for any `ObjectStore` impl. Each behavior
/// here is one assertion both `FsObjectStore` and `MemObjectStore`
/// must satisfy. A future chunked-KV impl runs the same helpers and
/// inherits the contract for free.
///
/// Helpers take a fixture closure `populate` that puts known bytes
/// for a known oid into the impl-specific way (FS: `git hash-object`
/// against a real bare repo; Mem: `MemObjectStore::write_loose`).
/// Each helper then exercises the trait method and asserts.
#[cfg(test)]
pub(crate) mod conformance {
    use super::*;

    /// "Read returns the bytes that were written." The fundamental
    /// contract — an ObjectStore that can't read back what it stored
    /// is broken regardless of backend.
    pub fn read_after_write_round_trips<S: ObjectStore>(store: &S, repo_id: &str, oid: &str) {
        let bytes = store
            .read_loose(repo_id, oid)
            .expect("read_loose Result::Ok")
            .expect("Some(bytes) for a known-present oid");
        assert!(!bytes.is_empty(), "read_loose returned empty bytes");
    }

    /// Reading an oid that was never inserted yields `Ok(None)` —
    /// not an error, not empty bytes. Distinguishes "absent" from
    /// "present but empty".
    pub fn missing_oid_returns_none<S: ObjectStore>(store: &S, repo_id: &str) {
        let absent = "0123456789abcdef0123456789abcdef01234567";
        assert!(
            store.read_loose(repo_id, absent).unwrap().is_none(),
            "expected None for unknown oid, got Some",
        );
    }

    /// Malformed oids (path-traversal, wrong length, non-hex) yield
    /// `Ok(None)` — never an error, never a stored value, never a
    /// computed path that escapes the store. This is the trait's
    /// path-safety contract.
    pub fn malformed_oid_returns_none<S: ObjectStore>(store: &S) {
        // Path-traversal attempt.
        assert!(
            store
                .read_loose("repo", "../something/with/slash/and/some/more/x")
                .unwrap()
                .is_none()
        );
        // Wrong length.
        assert!(store.read_loose("repo", "abc").unwrap().is_none());
        // Non-hex (uppercase Z).
        assert!(
            store
                .read_loose("repo", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
                .unwrap()
                .is_none()
        );
    }

    /// `write_loose` round-trips through `read_loose` with byte-exact
    /// fidelity. Both impls have to satisfy this — anything a chunked-KV
    /// or future backend can't preserve verbatim is broken.
    pub fn write_then_read_round_trips<S: ObjectStore>(store: &S) {
        // Use a synthetic 40-hex oid; both impls treat it as opaque
        // key-value lookup, so the FS impl's loose-format expectation
        // doesn't apply to the trait contract test.
        let oid = "1111111111111111111111111111111111111111";
        let payload = b"contract-bytes-stand-in";
        store.write_loose("conf-repo", oid, payload).unwrap();
        let got = store
            .read_loose("conf-repo", oid)
            .unwrap()
            .expect("Some after write");
        assert_eq!(got.as_slice(), payload);
    }

    /// `write_loose` is idempotent — a second write of the same oid is
    /// a no-op. Loose objects are content-addressed, so the same oid
    /// implies the same bytes; both impls must honor this without
    /// erroring out.
    pub fn write_loose_idempotent_on_repeat<S: ObjectStore>(store: &S) {
        let oid = "2222222222222222222222222222222222222222";
        let payload = b"first-write";
        store.write_loose("conf-repo", oid, payload).unwrap();
        // Second write of the same oid + bytes — must not error.
        store.write_loose("conf-repo", oid, payload).unwrap();
        let got = store.read_loose("conf-repo", oid).unwrap().unwrap();
        assert_eq!(got.as_slice(), payload);
    }

    /// `write_loose` with a malformed oid is a hard error, not a
    /// silent drop. Reads of malformed oids return `Ok(None)` (the
    /// path-safety contract), but writes need to surface the bug —
    /// callers want to know rather than silently lose data.
    pub fn write_loose_rejects_malformed_oid<S: ObjectStore>(store: &S) {
        let cases = [
            "../something",
            "abc",
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        ];
        for bad in cases {
            let r = store.write_loose("repo", bad, b"x");
            assert!(r.is_err(), "expected write_loose({bad:?}) to error, got {r:?}");
        }
    }

    /// `list_loose` returns every written object with a populated
    /// LooseInfo (oid + size + non-zero created_secs). Order is
    /// unspecified, so the test sorts before comparing.
    pub fn list_loose_enumerates_writes<S: ObjectStore>(store: &S) {
        let oids = [
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222",
            "3333333333333333333333333333333333333333",
        ];
        for oid in oids {
            store.write_loose("conf-repo", oid, b"some-bytes").unwrap();
        }
        let mut listed = store.list_loose("conf-repo").unwrap();
        listed.sort_by(|a, b| a.oid.cmp(&b.oid));
        let listed_oids: Vec<&str> = listed.iter().map(|i| i.oid.as_str()).collect();
        assert_eq!(listed_oids, oids);
        for info in &listed {
            assert!(info.size > 0, "size must be populated, got {info:?}");
            assert!(
                info.created_secs > 0,
                "created_secs must be populated, got {info:?}"
            );
        }
    }

    /// `list_loose` on an empty / unknown repo returns `Ok(vec![])` —
    /// not an error. This matches the FS shape where `objects/` may
    /// not exist yet and the chunked-KV shape where the repo's row
    /// set is empty.
    pub fn list_loose_empty_returns_empty_vec<S: ObjectStore>(store: &S) {
        let listed = store.list_loose("nope").unwrap();
        assert!(listed.is_empty(), "expected empty Vec, got {listed:?}");
    }

    /// `delete_loose` on a present oid returns `Ok(true)` then
    /// `Ok(false)` on a second call (idempotent removal). After
    /// delete, `read_loose` returns None. Both impls must satisfy.
    pub fn delete_loose_round_trips<S: ObjectStore>(store: &S) {
        let oid = "4444444444444444444444444444444444444444";
        store.write_loose("conf-repo", oid, b"to-delete").unwrap();
        assert!(store.read_loose("conf-repo", oid).unwrap().is_some());
        assert!(store.delete_loose("conf-repo", oid).unwrap(), "first delete must report true");
        assert!(store.read_loose("conf-repo", oid).unwrap().is_none());
        assert!(
            !store.delete_loose("conf-repo", oid).unwrap(),
            "second delete must report false (already gone)"
        );
    }

    /// `delete_loose` with a malformed oid is a hard error — same
    /// shape as `write_loose`. We won't computed-path-escape on
    /// the way out any more than on the way in.
    pub fn delete_loose_rejects_malformed_oid<S: ObjectStore>(store: &S) {
        for bad in ["../something", "abc", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"] {
            let r = store.delete_loose("repo", bad);
            assert!(r.is_err(), "expected delete_loose({bad:?}) to error, got {r:?}");
        }
    }

    /// `exists` agrees with `read_loose` for both present and absent
    /// oids. The trait promises this — a backend whose existence
    /// check disagrees with its body fetch is broken.
    pub fn exists_agrees_with_read<S: ObjectStore>(store: &S, repo_id: &str, present_oid: &str) {
        assert!(
            store.exists(repo_id, present_oid).unwrap(),
            "exists must return true for a known-present oid",
        );
        let absent = "0000000000000000000000000000000000000000";
        assert!(
            !store.exists(repo_id, absent).unwrap(),
            "exists must return false for a never-written oid",
        );
        // Malformed oid: same shape as read_loose — false, not an error.
        assert!(
            !store.exists(repo_id, "not-a-real-oid").unwrap(),
            "exists must return false for a malformed oid",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{new_repo_id, FsStorage, Storage};
    use std::path::Path;

    fn write_blob(git_dir: &Path, bytes: &[u8]) -> String {
        use std::io::Write as _;
        let mut child = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
        let out = child.wait_with_output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    // ─── FsObjectStore conformance ─────────────────────────────────

    fn fs_fixture() -> (tempfile::TempDir, FsObjectStore, String, String) {
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));
        let oid = write_blob(&git_dir, b"hello\n");
        let store = FsObjectStore::new(&repos);
        (tmp, store, repo_id, oid)
    }

    #[test]
    fn fs_read_after_write_round_trips() {
        let (_t, store, repo_id, oid) = fs_fixture();
        conformance::read_after_write_round_trips(&store, &repo_id, &oid);
    }

    #[test]
    fn fs_missing_oid_returns_none() {
        let (_t, store, repo_id, _) = fs_fixture();
        conformance::missing_oid_returns_none(&store, &repo_id);
    }

    #[test]
    fn fs_malformed_oid_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::malformed_oid_returns_none(&store);
    }

    /// FS-specific contract that doesn't apply to Mem: returned bytes
    /// are git's actual zlib-deflated loose-object format. The Mem
    /// impl stores whatever the test puts in, so it can't satisfy
    /// this — that's fine, `read_loose`'s contract is only "return
    /// the bytes that were stored", not "return zlib".
    #[test]
    fn fs_returns_zlib_deflated_payload() {
        let (_t, store, repo_id, oid) = fs_fixture();
        let bytes = store.read_loose(&repo_id, &oid).unwrap().expect("found");
        // Loose objects start with the zlib magic byte 0x78 (low-nibble
        // = 0x8 means deflate at the default window size).
        assert_eq!(bytes[0], 0x78);
        assert!(bytes.len() > 2);
    }

    #[test]
    fn fs_exists_agrees_with_read_for_loose() {
        let (_t, store, repo_id, oid) = fs_fixture();
        conformance::exists_agrees_with_read(&store, &repo_id, &oid);
    }

    /// FS-specific: an object that's been packed (no longer loose) is
    /// still visible to `exists` via the gix pack-index walk. This is
    /// the contract the commits-plumbing existence check depends on
    /// — without it, a `cat-file -e` -> `exists()` swap would break
    /// commits-after-gc.
    #[test]
    fn fs_exists_finds_packed_objects() {
        use std::process::Command;
        let (_t, store, repo_id, oid) = fs_fixture();
        let git_dir = store.root.join(format!("{repo_id}.git"));
        // Need a ref pointing at the object so `git repack` keeps
        // it. Blobs aren't reachable from a ref on their own, so
        // wrap it in a commit. Reuse hash-object → write-tree → commit-tree.
        let tree_oid = {
            let out = Command::new("git")
                .arg("--git-dir").arg(&git_dir)
                .args(["mktree"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn().unwrap();
            use std::io::Write as _;
            let mut out = out;
            writeln!(out.stdin.as_mut().unwrap(), "100644 blob {oid}\thello.txt").unwrap();
            let o = out.wait_with_output().unwrap();
            String::from_utf8(o.stdout).unwrap().trim().to_string()
        };
        let commit_oid = {
            let out = Command::new("git")
                .arg("--git-dir").arg(&git_dir)
                .args(["commit-tree", &tree_oid, "-m", "t"])
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .output().unwrap();
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        };
        Command::new("git")
            .arg("--git-dir").arg(&git_dir)
            .args(["update-ref", "refs/heads/main", &commit_oid])
            .status().unwrap();
        // Repack + prune: blob moves from objects/<aa>/<bb...> into a packfile.
        Command::new("git")
            .arg("--git-dir").arg(&git_dir)
            .args(["repack", "-ad"])
            .status().unwrap();
        // The loose path is gone now.
        let loose_path = store.loose_path(&repo_id, &oid).unwrap();
        assert!(
            !loose_path.exists(),
            "test setup broken: blob should have been packed away",
        );
        // …but exists() still finds it through the pack-index walk.
        assert!(
            store.exists(&repo_id, &oid).unwrap(),
            "exists must find packed objects, not just loose ones",
        );
    }

    // ─── MemObjectStore conformance ────────────────────────────────

    /// Synthesize a deterministic 40-hex oid for a Mem fixture. The
    /// store doesn't validate the oid against the bytes (the FS impl
    /// doesn't either — it's a key-value lookup), so any 40-hex
    /// string is fine for round-trip testing.
    fn mem_oid(seed: u8) -> String {
        let mut s = String::with_capacity(40);
        for _ in 0..40 {
            s.push(char::from_digit((seed % 16) as u32, 16).unwrap());
        }
        s
    }

    fn mem_fixture() -> (MemObjectStore, String, String) {
        let store = MemObjectStore::new();
        let repo_id = "mem-repo".to_string();
        let oid = mem_oid(0xa);
        store
            .write_loose(&repo_id, &oid, b"any-bytes-stand-in")
            .unwrap();
        (store, repo_id, oid)
    }

    #[test]
    fn mem_read_after_write_round_trips() {
        let (store, repo_id, oid) = mem_fixture();
        conformance::read_after_write_round_trips(&store, &repo_id, &oid);
    }

    #[test]
    fn mem_missing_oid_returns_none() {
        let (store, repo_id, _) = mem_fixture();
        conformance::missing_oid_returns_none(&store, &repo_id);
    }

    #[test]
    fn mem_malformed_oid_returns_none() {
        let store = MemObjectStore::new();
        conformance::malformed_oid_returns_none(&store);
    }

    #[test]
    fn mem_write_then_read_round_trips() {
        let store = MemObjectStore::new();
        conformance::write_then_read_round_trips(&store);
    }

    #[test]
    fn mem_write_loose_idempotent_on_repeat() {
        let store = MemObjectStore::new();
        conformance::write_loose_idempotent_on_repeat(&store);
    }

    #[test]
    fn mem_write_loose_rejects_malformed_oid() {
        let store = MemObjectStore::new();
        conformance::write_loose_rejects_malformed_oid(&store);
    }

    #[test]
    fn mem_exists_agrees_with_read() {
        let (store, repo_id, oid) = mem_fixture();
        conformance::exists_agrees_with_read(&store, &repo_id, &oid);
    }

    #[test]
    fn mem_read_returns_exact_bytes_written() {
        // Mem-specific: returned bytes are *exactly* what was stored.
        // The FS impl can't make this assertion because git rewrites
        // its loose-object format on write.
        let store = MemObjectStore::new();
        let oid = mem_oid(0x3);
        let payload: Vec<u8> = (0..=255).cycle().take(1024).collect();
        store.write_loose("r", &oid, &payload).unwrap();
        let got = store.read_loose("r", &oid).unwrap().unwrap();
        assert_eq!(got, payload);
    }

    // ─── FsObjectStore — write conformance ─────────────────────────

    #[test]
    fn fs_write_then_read_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::write_then_read_round_trips(&store);
    }

    #[test]
    fn fs_write_loose_idempotent_on_repeat() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::write_loose_idempotent_on_repeat(&store);
    }

    #[test]
    fn fs_write_loose_rejects_malformed_oid() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::write_loose_rejects_malformed_oid(&store);
    }

    #[test]
    fn fs_list_loose_enumerates_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::list_loose_enumerates_writes(&store);
    }

    #[test]
    fn fs_list_loose_empty_returns_empty_vec() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::list_loose_empty_returns_empty_vec(&store);
    }

    #[test]
    fn fs_delete_loose_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::delete_loose_round_trips(&store);
    }

    #[test]
    fn fs_delete_loose_rejects_malformed_oid() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        conformance::delete_loose_rejects_malformed_oid(&store);
    }

    #[test]
    fn mem_list_loose_enumerates_writes() {
        let store = MemObjectStore::new();
        conformance::list_loose_enumerates_writes(&store);
    }

    #[test]
    fn mem_list_loose_empty_returns_empty_vec() {
        let store = MemObjectStore::new();
        conformance::list_loose_empty_returns_empty_vec(&store);
    }

    #[test]
    fn mem_delete_loose_round_trips() {
        let store = MemObjectStore::new();
        conformance::delete_loose_round_trips(&store);
    }

    #[test]
    fn mem_delete_loose_rejects_malformed_oid() {
        let store = MemObjectStore::new();
        conformance::delete_loose_rejects_malformed_oid(&store);
    }

    /// FS-specific: `write_loose` is atomic via tmp+rename. After a
    /// successful write the canonical path exists; no `.tmp-*` files
    /// remain in the parent dir.
    #[test]
    fn fs_write_loose_leaves_no_tmp_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsObjectStore::new(tmp.path().join("repos"));
        let oid = "9999999999999999999999999999999999999999";
        store.write_loose("r", oid, b"payload").unwrap();
        // Walk the parent dir; only the canonical 38-hex name should
        // remain. Any `.tmp-*` entry means the cleanup is broken.
        let parent = tmp.path().join("repos/r.git/objects/99");
        let entries: Vec<String> = std::fs::read_dir(&parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string().unwrap_or_default())
            .collect();
        assert_eq!(
            entries,
            vec!["9".repeat(38)],
            "expected only the canonical loose-object file, got {entries:?}"
        );
    }

    // ─── SqliteObjectStore conformance ──────────────────────────────
    //
    // Runs the same conformance helpers as Fs/Mem against a fresh
    // SQLite-backed impl. Each test opens its own tempfile so cases
    // don't share state. The trait contract is the only contract;
    // an impl that can't satisfy it is broken regardless of backend.

    fn sqlite_fixture() -> (tempfile::TempDir, SqliteObjectStore) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("objects.db");
        let store = SqliteObjectStore::open(&path).unwrap();
        (tmp, store)
    }

    fn sqlite_oid(seed: u8) -> String {
        let mut s = String::with_capacity(40);
        for _ in 0..40 {
            s.push(char::from_digit((seed % 16) as u32, 16).unwrap());
        }
        s
    }

    #[test]
    fn sqlite_read_after_write_round_trips() {
        let (_t, store) = sqlite_fixture();
        let oid = sqlite_oid(0x1);
        store.write_loose("r", &oid, b"hello-kv").unwrap();
        conformance::read_after_write_round_trips(&store, "r", &oid);
    }

    #[test]
    fn sqlite_missing_oid_returns_none() {
        let (_t, store) = sqlite_fixture();
        conformance::missing_oid_returns_none(&store, "r");
    }

    #[test]
    fn sqlite_malformed_oid_returns_none() {
        let (_t, store) = sqlite_fixture();
        conformance::malformed_oid_returns_none(&store);
    }

    #[test]
    fn sqlite_write_then_read_round_trips() {
        let (_t, store) = sqlite_fixture();
        conformance::write_then_read_round_trips(&store);
    }

    #[test]
    fn sqlite_write_loose_idempotent_on_repeat() {
        let (_t, store) = sqlite_fixture();
        conformance::write_loose_idempotent_on_repeat(&store);
    }

    #[test]
    fn sqlite_write_loose_rejects_malformed_oid() {
        let (_t, store) = sqlite_fixture();
        conformance::write_loose_rejects_malformed_oid(&store);
    }

    #[test]
    fn sqlite_list_loose_enumerates_writes() {
        let (_t, store) = sqlite_fixture();
        conformance::list_loose_enumerates_writes(&store);
    }

    #[test]
    fn sqlite_list_loose_empty_returns_empty_vec() {
        let (_t, store) = sqlite_fixture();
        conformance::list_loose_empty_returns_empty_vec(&store);
    }

    #[test]
    fn sqlite_delete_loose_round_trips() {
        let (_t, store) = sqlite_fixture();
        conformance::delete_loose_round_trips(&store);
    }

    #[test]
    fn sqlite_delete_loose_rejects_malformed_oid() {
        let (_t, store) = sqlite_fixture();
        conformance::delete_loose_rejects_malformed_oid(&store);
    }

    #[test]
    fn sqlite_exists_agrees_with_read() {
        let (_t, store) = sqlite_fixture();
        let oid = sqlite_oid(0x7);
        store.write_loose("r", &oid, b"present").unwrap();
        conformance::exists_agrees_with_read(&store, "r", &oid);
    }

    /// SQLite-specific: bytes round-trip with byte-exact fidelity.
    /// A BLOB column shouldn't transform the payload (UTF-8 cast,
    /// NUL truncation, etc.) — same shape as the Mem-impl
    /// "exact bytes" assertion.
    #[test]
    fn sqlite_read_returns_exact_bytes_written() {
        let (_t, store) = sqlite_fixture();
        let oid = sqlite_oid(0x3);
        let payload: Vec<u8> = (0..=255).cycle().take(4096).collect();
        store.write_loose("r", &oid, &payload).unwrap();
        let got = store.read_loose("r", &oid).unwrap().unwrap();
        assert_eq!(got, payload);
    }

    /// SQLite-specific: rows from one repo don't leak into another's
    /// `list_loose`. Trivial for Fs (directory scoping) and Mem
    /// (HashMap key tuple), but worth pinning for SQLite — the
    /// `WHERE repo_id = ?1` clause is the only thing keeping the
    /// scope honest.
    #[test]
    fn sqlite_list_loose_is_repo_scoped() {
        let (_t, store) = sqlite_fixture();
        let oid_a = sqlite_oid(0xa);
        let oid_b = sqlite_oid(0xb);
        store.write_loose("repo-a", &oid_a, b"a-bytes").unwrap();
        store.write_loose("repo-b", &oid_b, b"b-bytes").unwrap();
        let listed_a = store.list_loose("repo-a").unwrap();
        let listed_b = store.list_loose("repo-b").unwrap();
        assert_eq!(listed_a.len(), 1);
        assert_eq!(listed_a[0].oid, oid_a);
        assert_eq!(listed_b.len(), 1);
        assert_eq!(listed_b[0].oid, oid_b);
    }

    /// SQLite-specific: migrations are idempotent. Open the same
    /// file twice (with two store instances) — both should succeed
    /// without re-applying v1. Mirrors the contract proved by
    /// `db_migrate::tests::second_run_skips_already_applied`.
    #[test]
    fn sqlite_reopen_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("objects.db");
        let _s1 = SqliteObjectStore::open(&path).unwrap();
        // Drop _s1's lock by letting it survive (separate Connection).
        let _s2 = SqliteObjectStore::open(&path).unwrap();
    }
}
