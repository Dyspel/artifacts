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
