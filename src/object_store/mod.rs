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
use std::path::{Path, PathBuf};
// HashMap, RwLock, Arc, Mutex only matter to MemObjectStore +
// SqliteObjectStore, both of which are `#[cfg(test)]`. Importing them
// at module scope would warn in non-test builds; gate the import too.
#[cfg(test)]
use std::collections::HashMap;
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

/// The four git object kinds. Returned alongside the uncompressed
/// payload from [`ObjectStore::read_object`] so callers can verify
/// the kind matches what they asked for (a blob read that returns a
/// tree is a bug, not a malformed body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

/// Read + write view into a repo's git object database.
///
/// Production paths route through this for `gc`, the
/// commits-plumbing parent-exists check, the native receive-pack
/// write branch (when `ARTIFACTS_NATIVE_INDEX_PACK=1`), and the
/// blob-read endpoint. Fetch-side pack generation still touches
/// gix directly; routing that is the remaining M2b work.
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

    /// Read an object's uncompressed payload + kind, regardless of
    /// whether the backend stores it loose or packed. `None` means
    /// the object isn't in this store. Malformed oid returns
    /// `Ok(None)` — same shape as `read_loose` / `exists`.
    ///
    /// Default impl returns an unsupported error. The FS impl
    /// overrides using gix (which transparently walks both loose +
    /// pack stores). Test impls (Mem/Sqlite) fall through to the
    /// default since the production blob-read path doesn't exercise
    /// them; if a future production KV backend needs it, override
    /// there too.
    fn read_object(&self, _repo_id: &str, _oid: &str) -> Result<Option<(ObjectKind, Vec<u8>)>> {
        Err(Error::Other(anyhow::anyhow!(
            "read_object: not supported by this ObjectStore backend"
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
        let path = self
            .loose_path(repo_id, oid)
            .ok_or_else(|| Error::Other(anyhow::anyhow!("write_loose: invalid oid {oid:?}")))?;
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
        let tmp_name = format!(
            ".tmp-{}-{}-{}",
            std::process::id(),
            rand::random::<u32>(),
            oid
        );
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
        let path = self
            .loose_path(repo_id, oid)
            .ok_or_else(|| Error::Other(anyhow::anyhow!("delete_loose: invalid oid {oid:?}")))?;
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

    fn read_object(&self, repo_id: &str, oid: &str) -> Result<Option<(ObjectKind, Vec<u8>)>> {
        // Override the loose-only default so packed objects resolve
        // too. Mirrors `exists()`'s shape: cheap path-validity check
        // first, then open the repo through gix and let its object
        // database walk both loose + pack stores. gix returns the
        // uncompressed payload directly — no zlib step needed in our
        // code.
        let start = std::time::Instant::now();
        let outcome = read_object_fs_inner(&self.root, repo_id, oid);
        record_read_object_metrics("fs", &outcome, start.elapsed());
        outcome
    }
}

fn read_object_fs_inner(
    root: &Path,
    repo_id: &str,
    oid: &str,
) -> Result<Option<(ObjectKind, Vec<u8>)>> {
    if !oid_is_valid(oid) {
        return Ok(None);
    }
    let repo_path = root.join(format!("{repo_id}.git"));
    if !repo_path.is_dir() {
        return Ok(None);
    }
    let repo = match gix::open(&repo_path) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let gix_oid = match gix::ObjectId::from_hex(oid.as_bytes()) {
        Ok(o) => o,
        Err(_) => return Ok(None),
    };
    let result = match repo.find_object(gix_oid) {
        Ok(obj) => Ok(Some((gix_kind_to_ours(obj.kind), obj.data.clone()))),
        // `Find::NotFound` for absent objects — translate to None.
        // Any other error (corruption, IO) bubbles.
        Err(gix::object::find::existing::Error::Find(_)) => Ok(None),
        Err(e) => Err(Error::Other(anyhow::anyhow!("gix find_object({oid}): {e}"))),
    };
    result
}

/// Emit `artifacts_object_reads_total{backend, outcome}` +
/// `artifacts_object_read_duration_seconds{backend}` for one
/// `read_object` call. Centralized so every backend that overrides
/// the trait method gets identical label semantics — outcome is
/// derived from the Result the same way for `fs`, a future
/// chunked-KV impl, or anything else.
fn record_read_object_metrics(
    backend: &'static str,
    outcome: &Result<Option<(ObjectKind, Vec<u8>)>>,
    elapsed: std::time::Duration,
) {
    let outcome_label = match outcome {
        Ok(Some(_)) => "hit",
        Ok(None) => "miss",
        Err(_) => "error",
    };
    metrics::counter!(
        "artifacts_object_reads_total",
        "backend" => backend,
        "outcome" => outcome_label,
    )
    .increment(1);
    metrics::histogram!(
        "artifacts_object_read_duration_seconds",
        "backend" => backend,
    )
    .record(elapsed.as_secs_f64());
}

fn gix_kind_to_ours(k: gix::object::Kind) -> ObjectKind {
    match k {
        gix::object::Kind::Commit => ObjectKind::Commit,
        gix::object::Kind::Tree => ObjectKind::Tree,
        gix::object::Kind::Blob => ObjectKind::Blob,
        gix::object::Kind::Tag => ObjectKind::Tag,
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
        let conn = crate::db_migrate::open_with_migrations(
            path,
            "object_store",
            &SQLITE_OBJECT_STORE_MIGRATIONS,
        )?;
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

    /// **Stopgap ingest**. The chunked-KV path needs `ingest_pack` to
    /// work without a filesystem under it, but `gix_pack`'s public
    /// delta-application surface (`File::decode_entry`) is gated on
    /// having a real pack file on disk. To bridge the gap, we
    /// materialize the incoming pack into a tempdir, hand it to
    /// `gix_pack::Bundle::write_to_directory` for indexing, then
    /// iterate the indexed pack and copy each fully-resolved object
    /// into the KV's `loose_objects` table.
    ///
    /// **Limitation**: this momentarily touches the local filesystem
    /// (under `tempfile::tempdir()`, gone the moment `tmp` drops)
    /// even though the chunked-KV's eventual production answer is
    /// "no filesystem." For the prototype it's a working seam; the
    /// honest follow-up is a hand-rolled pack-delta resolver against
    /// the KV's own rows.
    ///
    /// **Thin packs**: we pass `gix_object::find::Never` as the base
    /// resolver, so any ref-delta whose base lives outside the pack
    /// fails the index step. Receive-pack today produces thick packs
    /// in the cases the chunked-KV path needs to cover; we'd revisit
    /// if/when fetch-side thin packs land on this backend.
    fn ingest_pack(&self, repo_id: &str, pack_bytes: &[u8]) -> Result<usize> {
        if pack_bytes.len() <= 32 {
            return Ok(0);
        }
        let tmp = tempfile::tempdir()
            .map_err(|e| Error::Other(anyhow::anyhow!("ingest_pack tempdir: {e}")))?;
        let pack_dir = tmp.path();
        let mut cursor = std::io::Cursor::new(pack_bytes);
        let mut progress = prodash::progress::Discard;
        let interrupt = std::sync::atomic::AtomicBool::new(false);
        let outcome = gix_pack::Bundle::write_to_directory(
            &mut cursor,
            Some(pack_dir),
            &mut progress,
            &interrupt,
            // The Never resolver matches the `gix_object::Find` version
            // that gix-pack expects (the umbrella `gix` crate's, not
            // our direct `gix-object = "0.51"` dep). Re-routes through
            // `gix::objs` so the types line up.
            None::<gix::objs::find::Never>,
            gix_pack::bundle::write::Options {
                thread_limit: Some(1),
                iteration_mode: gix_pack::data::input::Mode::Verify,
                index_version: gix_pack::index::Version::default(),
                object_hash: gix_hash::Kind::Sha1,
            },
        )
        .map_err(|e| Error::Other(anyhow::anyhow!("ingest_pack write_to_directory: {e}")))?;
        let index_path = outcome
            .index_path
            .ok_or_else(|| Error::Other(anyhow::anyhow!("ingest_pack: write produced no index")))?;
        let bundle = gix_pack::Bundle::at(&index_path, gix_hash::Kind::Sha1)
            .map_err(|e| Error::Other(anyhow::anyhow!("ingest_pack Bundle::at: {e}")))?;

        let num_objects = bundle.index.num_objects();
        let mut decode_buf = Vec::new();
        let mut inflate = gix_features::zlib::Inflate::default();
        let mut cache = gix_pack::cache::Never;
        let mut count = 0usize;
        for idx in 0..num_objects {
            let oid_hex = bundle.index.oid_at_index(idx).to_hex().to_string();
            decode_buf.clear();
            let (data, _location) = bundle
                .get_object_by_index(idx, &mut decode_buf, &mut inflate, &mut cache)
                .map_err(|e| Error::Other(anyhow::anyhow!("decode pack entry {oid_hex}: {e}")))?;
            // Re-encode as the canonical loose-object format
            // (`<kind> <size>\0<payload>`, zlib-deflated) so a future
            // `read_object` impl can inflate + parse the header the
            // same way as for FsObjectStore-shaped backends.
            let kind_str = match data.kind {
                gix::object::Kind::Commit => "commit",
                gix::object::Kind::Tree => "tree",
                gix::object::Kind::Blob => "blob",
                gix::object::Kind::Tag => "tag",
            };
            let mut header_and_payload = Vec::with_capacity(20 + data.data.len());
            header_and_payload
                .extend_from_slice(format!("{kind_str} {}\0", data.data.len()).as_bytes());
            header_and_payload.extend_from_slice(data.data);
            let compressed = zlib_deflate_loose(&header_and_payload)?;
            self.write_loose(repo_id, &oid_hex, &compressed)?;
            count += 1;
        }
        Ok(count)
    }
}

/// Compress `input` as zlib (the same shape git's loose-object files
/// use). Used by `SqliteObjectStore::ingest_pack`; not exposed
/// publicly because the only caller is one level above.
#[cfg(test)]
fn zlib_deflate_loose(input: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write as _;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(input)
        .map_err(|e| Error::Other(anyhow::anyhow!("zlib write: {e}")))?;
    encoder
        .finish()
        .map_err(|e| Error::Other(anyhow::anyhow!("zlib finish: {e}")))
}

/// 40-char lowercase hex. The validation contract both impls share —
/// keeping it in one place means the conformance test for malformed
/// oids exercises the same predicate against both backends.
fn oid_is_valid(oid: &str) -> bool {
    oid.len() == 40 && oid.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod tests;
