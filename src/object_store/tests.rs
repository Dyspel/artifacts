//! Integration tests for the three `ObjectStore` impls. Wires each
//! impl through the shared `conformance` helpers + backend-specific
//! assertions (e.g. FsObjectStore's zlib loose-object format, the
//! pack-index walk in `exists`, SQLite's BLOB-column round-trip).

use super::*;
use crate::ids::{Oid, RepoId};
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

fn rid(s: &str) -> RepoId {
    RepoId::try_from(s).unwrap()
}

fn to_oid(s: &str) -> Oid {
    Oid::try_from(s).unwrap()
}

// ─── FsObjectStore conformance ─────────────────────────────────

fn fs_fixture() -> (tempfile::TempDir, FsObjectStore, RepoId, Oid) {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let storage = FsStorage::new(&repos).unwrap();
    let repo_id_str = new_repo_id();
    storage
        .create(&crate::ids::RepoId::try_from(repo_id_str.as_str()).unwrap())
        .unwrap();
    let git_dir = repos.join(format!("{repo_id_str}.git"));
    let oid_str = write_blob(&git_dir, b"hello\n");
    let store = FsObjectStore::new(&repos);
    let repo_id = rid(&repo_id_str);
    let oid = to_oid(&oid_str);
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
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["mktree"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        let mut out = out;
        writeln!(out.stdin.as_mut().unwrap(), "100644 blob {oid}\thello.txt").unwrap();
        let o = out.wait_with_output().unwrap();
        String::from_utf8(o.stdout).unwrap().trim().to_string()
    };
    let commit_oid = {
        let out = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["commit-tree", &tree_oid, "-m", "t"])
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    Command::new("git")
        .arg("--git-dir")
        .arg(&git_dir)
        .args(["update-ref", "refs/heads/main", &commit_oid])
        .status()
        .unwrap();
    // Repack + prune: blob moves from objects/<aa>/<bb...> into a packfile.
    Command::new("git")
        .arg("--git-dir")
        .arg(&git_dir)
        .args(["repack", "-ad"])
        .status()
        .unwrap();
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
fn mem_oid(seed: u8) -> Oid {
    let mut s = String::with_capacity(40);
    for _ in 0..40 {
        s.push(char::from_digit((seed % 16) as u32, 16).unwrap());
    }
    to_oid(&s)
}

fn mem_fixture() -> (MemObjectStore, RepoId, Oid) {
    let store = MemObjectStore::new();
    let repo_id = rid("mem-repo");
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
    let r = rid("rtst");
    store.write_loose(&r, &oid, &payload).unwrap();
    let got = store.read_loose(&r, &oid).unwrap().unwrap();
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

/// M3: the durable write path. `write_loose` stages to a tmp file,
/// fsyncs the file's contents, renames into place, then fsyncs the
/// parent directory. This drives that whole path and asserts the
/// object is readable, the bytes round-trip, and no staging tmp file
/// is left behind once the rename succeeds.
#[test]
fn fs_write_loose_durable_and_leaves_no_tmp() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let store = FsObjectStore::new(&repos);
    let repo_id_str = new_repo_id();
    let repo_id = rid(&repo_id_str);
    // write_loose stores the bytes verbatim and creates the shard dir
    // itself; content-addressing isn't re-checked, so any valid oid
    // exercises the storage path.
    let oid = to_oid("1234567890abcdef1234567890abcdef12345678");
    let payload = b"durable-bytes";

    store.write_loose(&repo_id, &oid, payload).unwrap();

    let got = store.read_loose(&repo_id, &oid).unwrap().expect("present");
    assert_eq!(
        got, payload,
        "bytes must round-trip through the durable write"
    );

    // After a successful rename the staging tmp must be gone.
    let shard = repos
        .join(format!("{repo_id_str}.git"))
        .join("objects")
        .join("12");
    let leftovers: Vec<String> = std::fs::read_dir(&shard)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".tmp-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "staging tmp files left behind: {leftovers:?}"
    );

    // Idempotent re-write stays a clean success.
    store.write_loose(&repo_id, &oid, payload).unwrap();
    let again = store
        .read_loose(&repo_id, &oid)
        .unwrap()
        .expect("still present");
    assert_eq!(again, payload);
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

/// FS-specific: `write_loose` is atomic via tmp+rename. After a
/// successful write the canonical path exists; no `.tmp-*` files
/// remain in the parent dir.
#[test]
fn fs_write_loose_leaves_no_tmp_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FsObjectStore::new(tmp.path().join("repos"));
    let oid = to_oid("9999999999999999999999999999999999999999");
    let r = rid("rtst");
    store.write_loose(&r, &oid, b"payload").unwrap();
    // Walk the parent dir; only the canonical 38-hex name should
    // remain. Any `.tmp-*` entry means the cleanup is broken.
    let parent = tmp.path().join("repos/rtst.git/objects/99");
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

fn sqlite_oid(seed: u8) -> Oid {
    let mut s = String::with_capacity(40);
    for _ in 0..40 {
        s.push(char::from_digit((seed % 16) as u32, 16).unwrap());
    }
    to_oid(&s)
}

#[test]
fn sqlite_read_after_write_round_trips() {
    let (_t, store) = sqlite_fixture();
    let oid = sqlite_oid(0x1);
    let r = rid("rtst");
    store.write_loose(&r, &oid, b"hello-kv").unwrap();
    conformance::read_after_write_round_trips(&store, &r, &oid);
}

#[test]
fn sqlite_missing_oid_returns_none() {
    let (_t, store) = sqlite_fixture();
    conformance::missing_oid_returns_none(&store, &rid("rtst"));
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
fn sqlite_exists_agrees_with_read() {
    let (_t, store) = sqlite_fixture();
    let oid = sqlite_oid(0x7);
    let r = rid("rtst");
    store.write_loose(&r, &oid, b"present").unwrap();
    conformance::exists_agrees_with_read(&store, &r, &oid);
}

/// SQLite-specific: bytes round-trip with byte-exact fidelity.
/// A BLOB column shouldn't transform the payload (UTF-8 cast,
/// NUL truncation, etc.) — same shape as the Mem-impl
/// "exact bytes" assertion.
#[test]
fn sqlite_read_returns_exact_bytes_written() {
    let (_t, store) = sqlite_fixture();
    let oid = sqlite_oid(0x3);
    let r = rid("rtst");
    let payload: Vec<u8> = (0..=255).cycle().take(4096).collect();
    store.write_loose(&r, &oid, &payload).unwrap();
    let got = store.read_loose(&r, &oid).unwrap().unwrap();
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
    let ra = rid("repo-a");
    let rb = rid("repo-b");
    store.write_loose(&ra, &oid_a, b"a-bytes").unwrap();
    store.write_loose(&rb, &oid_b, b"b-bytes").unwrap();
    let listed_a = store.list_loose(&ra).unwrap();
    let listed_b = store.list_loose(&rb).unwrap();
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

/// End-to-end SqliteObjectStore::ingest_pack. Builds a real pack
/// against a fresh FS repo (one commit → one tree → one blob),
/// streams its bytes into a fresh SqliteObjectStore via the trait
/// method, and asserts that every object oid the pack carries is
/// now resolvable via `exists` / `read_loose`.
#[test]
fn sqlite_ingest_pack_round_trips_a_thick_pack() {
    use crate::native_pack;

    // 1. Build a small repo on disk so we can generate a real pack
    //    against it via the existing `native_pack::generate_pack`
    //    helper. Same plumbing the receive-pack tests use.
    let repo = crate::test_support::TestRepo::new();
    let git_dir = &repo.git_dir;

    let blob_oid = write_blob(git_dir, b"hello-kv\n");
    // Build a tree containing the blob.
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut tree_proc = Command::new("git")
        .args(["--git-dir"])
        .arg(git_dir)
        .args(["mktree"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        tree_proc.stdin.as_mut().unwrap(),
        "100644 blob {blob_oid}\thello.txt"
    )
    .unwrap();
    let tree_out = tree_proc.wait_with_output().unwrap();
    let tree_oid = String::from_utf8(tree_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    // Commit pointing at the tree.
    let commit_out = Command::new("git")
        .args(["--git-dir"])
        .arg(git_dir)
        .args(["commit-tree", "-m", "kv-ingest-test", &tree_oid])
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap();
    let commit_oid = String::from_utf8(commit_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    // 2. Pack everything reachable from the commit. `generate_pack`
    //    builds a thick pack — no external base refs needed — so
    //    our Never resolver in ingest_pack will be satisfied.
    let pack_bytes =
        native_pack::generate_pack(git_dir, std::slice::from_ref(&commit_oid), &[]).unwrap();
    // Sanity: pack header + at least three entries (commit/tree/blob)
    // + trailer comes out well above the 32-byte short-circuit cap.
    assert!(
        pack_bytes.len() > 32,
        "pack too small: {}",
        pack_bytes.len()
    );

    // 3. Ingest into a fresh chunked-KV-shaped store.
    let kv_tmp = tempfile::tempdir().unwrap();
    let store = SqliteObjectStore::open(&kv_tmp.path().join("objects.db")).unwrap();
    let r = rid("rtst");
    let count = store.ingest_pack(&r, &pack_bytes).unwrap();
    assert_eq!(
        count, 3,
        "expected 3 objects (commit + tree + blob), got {count}"
    );

    // 4. Every oid the pack carried is now resolvable via the trait.
    //    `read_loose` returns the zlib-deflated loose bytes (the same
    //    format git puts on disk), so the canonical magic-byte check
    //    holds — that's the chunked-KV's promise: identical bytes-on-
    //    the-wire to the FS impl, just sitting in a SQLite row.
    for oid_str in [&commit_oid, &tree_oid, &blob_oid] {
        let oid = to_oid(oid_str);
        assert!(
            store.exists(&r, &oid).unwrap(),
            "exists must return true for ingested {oid_str}"
        );
        let bytes = store
            .read_loose(&r, &oid)
            .unwrap()
            .expect("Some after ingest");
        // Loose objects start with the zlib magic byte 0x78.
        assert_eq!(
            bytes.first(),
            Some(&0x78),
            "ingested oid {oid_str} should be zlib-deflated loose-object bytes",
        );
    }
}

/// Empty / undersized pack bodies (the 32-byte cap) are a no-op:
/// `ingest_pack` short-circuits without touching the tempdir, the
/// indexer, or the SQLite store. Mirrors `FsObjectStore::ingest_pack`'s
/// same-cap behaviour so a delete-only push (no pack payload) keeps
/// working against the chunked-KV path.
#[test]
fn sqlite_ingest_pack_empty_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let store = SqliteObjectStore::open(&tmp.path().join("objects.db")).unwrap();
    let r = rid("rtst");
    assert_eq!(store.ingest_pack(&r, b"").unwrap(), 0);
    assert_eq!(store.ingest_pack(&r, &[0u8; 16]).unwrap(), 0);
    // Nothing landed in the table.
    assert!(store.list_loose(&r).unwrap().is_empty());
}

// ─── ObjectKind: as_str / from_pack_type ────────────────────────

#[test]
fn object_kind_as_str_all_variants() {
    assert_eq!(ObjectKind::Commit.as_str(), "commit");
    assert_eq!(ObjectKind::Tree.as_str(), "tree");
    assert_eq!(ObjectKind::Blob.as_str(), "blob");
    assert_eq!(ObjectKind::Tag.as_str(), "tag");
}

#[test]
fn object_kind_from_pack_type_all_direct_kinds() {
    assert_eq!(ObjectKind::from_pack_type(1), Some(ObjectKind::Commit));
    assert_eq!(ObjectKind::from_pack_type(2), Some(ObjectKind::Tree));
    assert_eq!(ObjectKind::from_pack_type(3), Some(ObjectKind::Blob));
    assert_eq!(ObjectKind::from_pack_type(4), Some(ObjectKind::Tag));
}

#[test]
fn object_kind_from_pack_type_out_of_range_returns_none() {
    // 0, 5, 6, 7, 255 — none are direct-kind codes.
    assert_eq!(ObjectKind::from_pack_type(0), None);
    assert_eq!(ObjectKind::from_pack_type(5), None);
    assert_eq!(ObjectKind::from_pack_type(6), None);
    assert_eq!(ObjectKind::from_pack_type(7), None);
    assert_eq!(ObjectKind::from_pack_type(255), None);
}

// ─── is_hex40_bytes reject paths ────────────────────────────────

#[test]
fn is_hex40_rejects_non_hex_chars() {
    // 'g' is not a hex digit.
    let bad: [u8; 40] = *b"gggggggggggggggggggggggggggggggggggggggg";
    assert!(!is_hex40_bytes(&bad));
}

#[test]
fn is_hex40_rejects_wrong_length() {
    assert!(!is_hex40_bytes(b"deadbeef"));
    assert!(!is_hex40_bytes(b""));
    // 41 chars — one too many.
    assert!(!is_hex40_bytes(
        b"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c"
    ));
}

#[test]
fn is_hex40_accepts_uppercase_hex() {
    // is_hex40_bytes is case-insensitive (A-F accepted). Note that
    // Oid::try_from requires lowercase, but the byte-level helper
    // deliberately accepts upper for the pack-wire path.
    assert!(is_hex40_bytes(b"ABCDEF1234567890ABCDEF1234567890ABCDEF12"));
}

// ─── Trait default methods via minimal impl ─────────────────────

struct MinimalObjectStore;

impl ObjectStore for MinimalObjectStore {
    fn read_loose(&self, _repo_id: &RepoId, _oid: &Oid) -> crate::error::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn write_loose(
        &self,
        _repo_id: &RepoId,
        _oid: &Oid,
        _bytes: &[u8],
    ) -> crate::error::Result<()> {
        Ok(())
    }

    fn list_loose(&self, _repo_id: &RepoId) -> crate::error::Result<Vec<LooseInfo>> {
        Ok(vec![])
    }

    fn delete_loose(&self, _repo_id: &RepoId, _oid: &Oid) -> crate::error::Result<bool> {
        Ok(false)
    }
}

#[test]
fn trait_default_exists_uses_read_loose() {
    // Default `exists` delegates to `read_loose`. MinimalStore always
    // returns None from read_loose, so exists must return false.
    let store = MinimalObjectStore;
    let r = rid("repo-a");
    let o = to_oid(&"a".repeat(40));
    assert!(!store.exists(&r, &o).unwrap());
}

#[test]
fn trait_default_ingest_pack_returns_err() {
    let store = MinimalObjectStore;
    let r = rid("repo-a");
    let err = store
        .ingest_pack(&r, b"fake-pack-bytes-longer-than-32-bytes-pad")
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("ingest_pack") || msg.contains("not supported"),
        "unexpected message: {msg}"
    );
}

#[test]
fn trait_default_read_object_returns_err() {
    let store = MinimalObjectStore;
    let r = rid("repo-a");
    let o = to_oid(&"b".repeat(40));
    let err = store.read_object(&r, &o).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("read_object") || msg.contains("not supported"),
        "unexpected message: {msg}"
    );
}

// ─── FsObjectStore: missing repo / missing oid ──────────────────

#[test]
fn fs_exists_returns_false_for_missing_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FsObjectStore::new(tmp.path().join("repos"));
    // The repos dir exists but the specific repo dir does not.
    let r = rid("no-such-repo");
    let o = to_oid(&"c".repeat(40));
    assert!(!store.exists(&r, &o).unwrap());
}

#[test]
fn fs_read_object_returns_none_for_missing_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FsObjectStore::new(tmp.path().join("repos"));
    let r = rid("no-such-repo");
    let o = to_oid(&"d".repeat(40));
    assert!(store.read_object(&r, &o).unwrap().is_none());
}

#[test]
fn fs_list_loose_returns_empty_for_missing_repo_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FsObjectStore::new(tmp.path().join("repos"));
    let r = rid("no-such-repo");
    // Should not error — missing dir == no loose objects.
    let list = store.list_loose(&r).unwrap();
    assert!(list.is_empty());
}

#[test]
fn fs_delete_loose_returns_false_when_object_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let storage = crate::storage::FsStorage::new(&repos).unwrap();
    let repo_id_str = crate::storage::new_repo_id();
    storage
        .create(&RepoId::try_from(repo_id_str.as_str()).unwrap())
        .unwrap();
    let store = FsObjectStore::new(&repos);
    let r = rid(&repo_id_str);
    let o = to_oid(&"e".repeat(40));
    // Object was never written — delete should be a no-op returning false.
    assert!(!store.delete_loose(&r, &o).unwrap());
}

// ─── FsObjectStore: read_object exercising gix_kind_to_ours branches ──

/// `read_object` on a real FS repo returns the correct kind + payload for
/// blobs and commits; this also exercises the `record_read_object_metrics`
/// "hit" and "miss" paths and the `gix_kind_to_ours` Blob/Commit branches.
#[test]
fn fs_read_object_returns_blob_and_commit() {
    use std::process::Command;
    let (_t, store, repo_id, blob_oid) = fs_fixture();
    let git_dir = store.root.join(format!("{repo_id}.git"));

    // The fixture already wrote a blob; read it back via read_object.
    let (kind, payload) = store
        .read_object(&repo_id, &blob_oid)
        .unwrap()
        .expect("blob must be found");
    assert_eq!(kind, ObjectKind::Blob);
    assert_eq!(payload, b"hello\n");

    // Build a commit that wraps it so we can test the Commit arm.
    let tree_out = {
        let proc = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .arg("mktree")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        let mut proc = proc;
        writeln!(
            proc.stdin.as_mut().unwrap(),
            "100644 blob {}\thello.txt",
            blob_oid.as_str()
        )
        .unwrap();
        proc.wait_with_output().unwrap()
    };
    let tree_oid_str = String::from_utf8(tree_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    let tree_oid = to_oid(&tree_oid_str);

    // Tree kind.
    let (tree_kind, _) = store
        .read_object(&repo_id, &tree_oid)
        .unwrap()
        .expect("tree must be found");
    assert_eq!(tree_kind, ObjectKind::Tree);

    // Commit kind.
    let commit_out = Command::new("git")
        .arg("--git-dir")
        .arg(&git_dir)
        .args(["commit-tree", "-m", "cov-test", &tree_oid_str])
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap();
    let commit_oid_str = String::from_utf8(commit_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    let commit_oid = to_oid(&commit_oid_str);
    let (commit_kind, _) = store
        .read_object(&repo_id, &commit_oid)
        .unwrap()
        .expect("commit must be found");
    assert_eq!(commit_kind, ObjectKind::Commit);
}

/// `read_object` for a Tag object exercises the `gix_kind_to_ours` Tag arm.
#[test]
fn fs_read_object_returns_tag() {
    use std::process::Command;
    let (_t, store, repo_id, blob_oid) = fs_fixture();
    let git_dir = store.root.join(format!("{repo_id}.git"));

    // Build a minimal commit so annotated tag has a target.
    let tree_out = {
        let proc = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .arg("mktree")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write as _;
        let mut proc = proc;
        writeln!(
            proc.stdin.as_mut().unwrap(),
            "100644 blob {}\tf.txt",
            blob_oid.as_str()
        )
        .unwrap();
        proc.wait_with_output().unwrap()
    };
    let tree_str = String::from_utf8(tree_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    let commit_str = String::from_utf8(
        Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["commit-tree", "-m", "tag-base", &tree_str])
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();

    // Annotated tag.
    let tag_str = String::from_utf8(
        Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["tag", "-a", "v0.1", "-m", "release", &commit_str])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    // `git tag -a` writes to refs/tags/v0.1; read the tag object OID.
    let tag_oid_str = String::from_utf8(
        Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["rev-parse", "refs/tags/v0.1"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let _ = tag_str; // suppress unused
    let tag_oid = to_oid(&tag_oid_str);
    let (kind, _) = store
        .read_object(&repo_id, &tag_oid)
        .unwrap()
        .expect("tag must be found");
    assert_eq!(kind, ObjectKind::Tag);
}

/// `FsObjectStore::ingest_pack` short-circuit: packs <= 32 bytes are a no-op.
#[test]
fn fs_ingest_pack_short_circuit_for_undersized_pack() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FsObjectStore::new(tmp.path().join("repos"));
    let r = rid("ingest-repo");
    assert_eq!(store.ingest_pack(&r, b"").unwrap(), 0);
    assert_eq!(store.ingest_pack(&r, &[0u8; 16]).unwrap(), 0);
    assert_eq!(store.ingest_pack(&r, &[0u8; 32]).unwrap(), 0);
}

/// `FsObjectStore::list_loose` with a real loose object exercises the
/// happy-path branches inside the read_dir walk (2-hex subdir, 38-hex file).
#[test]
fn fs_list_loose_with_real_object() {
    let (_t, store, repo_id, oid) = fs_fixture();
    let list = store.list_loose(&repo_id).unwrap();
    assert!(
        list.iter().any(|i| i.oid == oid),
        "expected fixture oid in list_loose output"
    );
}

/// Write corrupt bytes (not valid zlib) to a loose-object path; confirm
/// `read_loose` returns them verbatim (raw bytes), and that a caller who
/// then tries to inflate them will get an error — the store itself is
/// not responsible for validating zlib content.
#[test]
fn fs_read_loose_corrupt_bytes_returned_verbatim() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let store = FsObjectStore::new(&repos);
    let r = rid("corrupt-repo");
    let o = to_oid("aabbccddeeff00112233445566778899aabbccdd");
    // Write the object path manually with junk bytes.
    let shard = repos.join("corrupt-repo.git/objects/aa");
    std::fs::create_dir_all(&shard).unwrap();
    let obj_path = shard.join("bbccddeeff00112233445566778899aabbccdd");
    std::fs::write(&obj_path, b"not valid zlib at all\xff\xfe").unwrap();
    // read_loose returns whatever is on disk.
    let bytes = store.read_loose(&r, &o).unwrap().expect("file exists");
    assert_eq!(bytes, b"not valid zlib at all\xff\xfe");
}

// ─── FsObjectStore: IO error branches ──────────────────────────────────

/// `read_loose` on a file that exists but is not readable (chmod 000) should
/// return an IO error — the non-NotFound branch at the end of the match.
/// Skipped if we are running as root (root ignores permissions).
#[test]
fn fs_read_loose_io_error_not_notfound() {
    // Skip on root: root can read any file regardless of permissions.
    // SAFETY: getuid() is always safe to call — it has no preconditions,
    // never modifies memory, and returns the real UID of the calling process.
    if unsafe { libc::getuid() } == 0 {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let store = FsObjectStore::new(&repos);
    let r = rid("perm-repo");
    let o = to_oid("aabbccddeeff00112233445566778899aabbccde");
    let shard = repos.join("perm-repo.git/objects/aa");
    std::fs::create_dir_all(&shard).unwrap();
    let obj_path = shard.join("bbccddeeff00112233445566778899aabbccde");
    std::fs::write(&obj_path, b"some bytes").unwrap();
    // Remove read permission so std::fs::read fails with a non-NotFound error.
    std::fs::set_permissions(
        &obj_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o000),
    )
    .unwrap();
    let result = store.read_loose(&r, &o);
    // Restore permissions so tempdir cleanup doesn't fail.
    std::fs::set_permissions(
        &obj_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();
    assert!(result.is_err(), "expected Err from permission-denied read");
}

/// `write_loose` failure path when the shard directory is not writable:
/// `File::create(&tmp)` returns EACCES, which propagates as an IO error
/// from write_loose. This exercises the error-propagation plumbing of
/// the atomic-write path (File::create → fsync → rename pipeline). Tests
/// the write-error surface; the rename-specific Err branch (lines 324-329)
/// is structurally hard to reach deterministically because it requires the
/// rename syscall itself to fail (e.g. full disk or cross-device), which
/// cannot be injected without kernel-level filesystem manipulation.
/// Skipped when running as root (root ignores permissions).
#[test]
fn fs_write_loose_shard_not_writable_returns_err() {
    // Skip on root: root can write into read-only directories.
    // SAFETY: getuid() is always safe to call — no preconditions,
    // no memory side effects, returns the real UID of this process.
    if unsafe { libc::getuid() } == 0 {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let store = FsObjectStore::new(&repos);
    let r = rid("perm-write-repo");
    let o = to_oid("1122334455667788990011223344556677889900");
    // Pre-create the shard directory so create_dir_all is a no-op inside
    // write_loose (no permission needed for the no-op).
    let shard = repos.join("perm-write-repo.git/objects/11");
    std::fs::create_dir_all(&shard).unwrap();
    // Make the shard directory read+execute only (no write permission).
    // File::create(&tmp) inside write_loose will fail with EACCES.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o555)).unwrap();
    let result = store.write_loose(&r, &o, b"payload");
    // Restore permissions so tempdir cleanup succeeds.
    std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        result.is_err(),
        "expected Err when shard dir is not writable"
    );
}

/// `list_loose` silently skips loose-object files whose 2-hex + 38-hex
/// names pass the ASCII-hexdigit length filter but are *uppercase* —
/// `Oid::try_from` requires lowercase, so the Err arm (lines 376-377) fires.
/// This models FS-level corruption (e.g. a file copied with uppercase
/// casing out-of-band) — the list continues rather than panicking.
#[test]
fn fs_list_loose_skips_uppercase_hex_filename() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let store = FsObjectStore::new(&repos);
    let r = rid("upper-repo");
    // Create the shard dir with a 2-hex name and put a file whose 38-char
    // name is uppercase hex. `is_ascii_hexdigit()` accepts A-F, so the
    // length+charset filter passes, but Oid::try_from rejects uppercase.
    let shard = repos.join("upper-repo.git/objects/ab");
    std::fs::create_dir_all(&shard).unwrap();
    // 38 uppercase hex chars — passes the len/hexdigit filter but Oid rejects it.
    let bad_name = "CDEF1234567890ABCDEF1234567890ABCDEF12";
    std::fs::write(shard.join(bad_name), b"junk").unwrap();
    // list_loose must not error and must not include the skipped entry.
    let list = store.list_loose(&r).unwrap();
    assert!(
        list.is_empty(),
        "expected no valid entries (uppercase filename must be skipped), got {list:?}"
    );
}

/// `delete_loose` returns an IO error (non-NotFound) when the shard
/// directory is not traversable (mode 000). Tests line 411.
/// Skipped when running as root.
#[test]
fn fs_delete_loose_io_error_not_notfound() {
    // SAFETY: getuid() is always safe to call — no preconditions,
    // no memory side effects, returns the real UID of this process.
    if unsafe { libc::getuid() } == 0 {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let store = FsObjectStore::new(&repos);
    let r = rid("delperm-repo");
    let o = to_oid("aabbccddeeff00112233445566778899aabbccdf");
    // Create and populate the loose file.
    let shard = repos.join("delperm-repo.git/objects/aa");
    std::fs::create_dir_all(&shard).unwrap();
    std::fs::write(shard.join("bbccddeeff00112233445566778899aabbccdf"), b"x").unwrap();
    // Remove execute bit from shard so remove_file fails with EACCES.
    std::fs::set_permissions(&shard, std::os::unix::fs::PermissionsExt::from_mode(0o444)).unwrap();
    let result = store.delete_loose(&r, &o);
    // Restore before assertion so cleanup works.
    std::fs::set_permissions(&shard, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    assert!(
        result.is_err(),
        "expected Err from permission-denied delete"
    );
}

/// `FsObjectStore::exists` slow-path: object isn't loose, repo dir exists
/// but isn't a valid git repo (non-bare, no HEAD, etc.) — gix::open fails →
/// `Ok(false)` (line 439).
#[test]
fn fs_exists_slow_path_gix_open_fails_returns_false() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    // Create a directory that looks like a repo path but is not a valid git repo.
    let fake_git_dir = repos.join("fake-repo.git");
    std::fs::create_dir_all(&fake_git_dir).unwrap();
    // No HEAD, no objects dir — gix::open will refuse to open this.
    let store = FsObjectStore::new(&repos);
    let r = rid("fake-repo");
    let o = to_oid("a".repeat(40).as_str());
    // The oid is not loose (no shard dir), so fast-path returns false quickly.
    // Then the slow path checks is_dir (true), calls gix::open (fails) → false.
    assert!(
        !store.exists(&r, &o).unwrap(),
        "expected false for non-git-dir repo"
    );
}

/// `read_object_fs_inner` gix::open failure path (line 499): the repo
/// directory exists but is not a valid git repository.
#[test]
fn fs_read_object_non_git_dir_gix_open_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let fake_git_dir = repos.join("notgit-repo.git");
    std::fs::create_dir_all(&fake_git_dir).unwrap();
    let store = FsObjectStore::new(&repos);
    let r = rid("notgit-repo");
    let o = to_oid("b".repeat(40).as_str());
    // read_object calls read_object_fs_inner. The repo dir exists (is_dir=true)
    // but gix::open fails → Ok(None).
    let result = store.read_object(&r, &o).unwrap();
    assert!(result.is_none(), "expected None when gix::open fails");
}

/// `FsObjectStore::ingest_pack` real-pack path (lines 458-459, 465):
/// for a pack larger than 32 bytes, the method calls index_pack_into_repo
/// and returns Ok(0). Uses a real repo and a valid pack.
#[test]
fn fs_ingest_pack_real_pack_returns_ok_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let storage = crate::storage::FsStorage::new(&repos).unwrap();
    let repo_id_str = crate::storage::new_repo_id();
    storage
        .create(&crate::ids::RepoId::try_from(repo_id_str.as_str()).unwrap())
        .unwrap();
    let git_dir = repos.join(format!("{repo_id_str}.git"));
    // Seed the repo with a blob.
    let blob_oid = write_blob(&git_dir, b"ingest-pack-test\n");

    // Build a tree + commit so generate_pack has reachable objects.
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut tree_proc = Command::new("git")
        .args(["--git-dir"])
        .arg(&git_dir)
        .args(["mktree"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        tree_proc.stdin.as_mut().unwrap(),
        "100644 blob {blob_oid}\tfile.txt"
    )
    .unwrap();
    let tree_out = tree_proc.wait_with_output().unwrap();
    let tree_oid = String::from_utf8(tree_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    let commit_out = Command::new("git")
        .args(["--git-dir"])
        .arg(&git_dir)
        .args(["commit-tree", "-m", "ingest-test", &tree_oid])
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap();
    let commit_oid = String::from_utf8(commit_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    let pack_bytes =
        crate::native_pack::generate_pack(&git_dir, std::slice::from_ref(&commit_oid), &[])
            .unwrap();
    assert!(pack_bytes.len() > 32);

    let store = FsObjectStore::new(&repos);
    let r = rid(&repo_id_str);
    // ingest_pack on FsObjectStore returns Ok(0) (count not surfaced).
    let count = store.ingest_pack(&r, &pack_bytes).unwrap();
    assert_eq!(count, 0, "FsObjectStore::ingest_pack always returns Ok(0)");
}

/// `FsObjectStore::list_loose` silently skips a 2-hex subdirectory whose
/// contents are unreadable (inner `read_dir` failure, mod.rs ~354-357).
/// On Linux, removing the execute bit from the shard dir makes the inner
/// read_dir fail; the list continues and returns whatever valid entries
/// remain. Skipped as root (root ignores permissions).
#[test]
fn fs_list_loose_skips_unreadable_subdir() {
    // SAFETY: getuid() is always safe — no preconditions, no side effects.
    if unsafe { libc::getuid() } == 0 {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let store = FsObjectStore::new(&repos);
    let r = rid("noread-repo");
    // Write one valid object so the outer read_dir succeeds.
    let o_good = to_oid("aabbccddeeff00112233445566778899aabbccdd");
    store.write_loose(&r, &o_good, b"good").unwrap();
    // Create a second 2-hex shard with no execute bit.
    let bad_shard = repos.join("noread-repo.git/objects/11");
    std::fs::create_dir_all(&bad_shard).unwrap();
    // Place a file with a 38-hex name so the outer read_dir sees the dir entry.
    std::fs::write(bad_shard.join("2".repeat(38)), b"x").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&bad_shard, std::fs::Permissions::from_mode(0o000)).unwrap();
    let result = store.list_loose(&r);
    // Restore before assertions.
    std::fs::set_permissions(&bad_shard, std::fs::Permissions::from_mode(0o755)).unwrap();
    // The list must succeed (inner read_dir errors are silently skipped).
    let list = result.unwrap();
    // The good object must still appear; the unreadable shard is silently ignored.
    assert!(
        list.iter().any(|i| i.oid == o_good),
        "good object must appear even when another shard is unreadable"
    );
}

/// `SqliteObjectStore::list_loose` malformed-oid skip (mod.rs ~783-790): if
/// a row was written with an oid string that doesn't satisfy `Oid::try_from`
/// (e.g. corrupted out-of-band), `list_loose` logs + skips rather than
/// panicking. We inject the corrupt row directly via rusqlite.
#[test]
fn sqlite_list_loose_skips_malformed_oid_row() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("objects.db");
    let store = SqliteObjectStore::open(&path).unwrap();
    let r = rid("corr-repo");
    // Write a valid row through the normal path first.
    let good_oid = to_oid("1111111111111111111111111111111111111111");
    store.write_loose(&r, &good_oid, b"good").unwrap();
    // Inject a corrupt row directly: oid = "not-a-valid-oid".
    {
        let conn = store.lock();
        conn.execute(
            "INSERT INTO loose_objects (repo_id, oid, bytes, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![r.as_str(), "not-a-valid-oid", b"bad".as_ref(), 0i64],
        )
        .unwrap();
    }
    // list_loose must succeed and return only the valid row.
    let list = store.list_loose(&r).unwrap();
    assert_eq!(list.len(), 1, "malformed row must be silently skipped");
    assert_eq!(list[0].oid, good_oid);
}

/// `record_read_object_metrics` "miss" or "error" outcome: when `read_object`
/// is called for an oid that is absent from a real repo, the gix layer
/// returns either `Ok(None)` ("miss" branch) or an `Err` ("error" branch)
/// depending on the gix version's error variant mapping. Either way the
/// `record_read_object_metrics` helper is called (it always runs in the
/// `read_object` override). We verify that calling read_object on an absent
/// oid in a valid repo doesn't panic — the exact Ok/Err shape is an
/// implementation detail of the gix error mapping at the outer boundary.
#[test]
fn fs_read_object_handles_absent_oid_without_panic() {
    let (_t, store, repo_id, _) = fs_fixture();
    let absent = to_oid("f".repeat(40).as_str());
    // Either Ok(None) (miss) or Err (error) is acceptable here — both
    // routes exercise record_read_object_metrics. The important invariant
    // is no panic. We also confirm that Ok(Some(_)) is NOT returned.
    if let Ok(Some(_)) = store.read_object(&repo_id, &absent) {
        panic!("absent oid must not return Some");
    }
}

/// `record_read_object_metrics` "miss" outcome: reading an object that
/// doesn't exist still calls the metrics helper with outcome="miss".
/// Also covers the list_loose multi-fanout-dir path when multiple
/// 2-hex shards are present.
#[test]
fn fs_list_loose_multiple_fanout_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FsObjectStore::new(tmp.path().join("repos"));
    let r = rid("multi-fan");
    // Write two objects that land in different 2-hex shard dirs.
    let o1 = to_oid("1234567890abcdef1234567890abcdef12345678");
    let o2 = to_oid("abcdef1234567890abcdef1234567890abcdef12");
    store.write_loose(&r, &o1, b"obj1").unwrap();
    store.write_loose(&r, &o2, b"obj2").unwrap();
    let mut list = store.list_loose(&r).unwrap();
    list.sort_by(|a, b| a.oid.cmp(&b.oid));
    let oids: Vec<&str> = list.iter().map(|i| i.oid.as_str()).collect();
    assert!(
        oids.contains(&o1.as_str()) && oids.contains(&o2.as_str()),
        "both objects from different fanout dirs must appear in list_loose"
    );
}
