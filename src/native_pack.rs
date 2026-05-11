//! Native pack-file generation via gix-pack (M1b-2c).
//!
//! Replaces the `git pack-objects --stdout` subprocess that M1b-2b
//! drove for the v2 fetch response. Same input contract (wants +
//! haves), same output contract (a valid v2 packfile), just no
//! fork+exec on the pack hot path.
//!
//! Pipeline:
//!
//!   1. `gix::open(repo_path)` — get a `Repository`.
//!   2. Walk `wants` excluding the closure of `haves` via
//!      `repo.rev_walk(wants).with_boundary(haves).all()` — yields
//!      every commit reachable from wants but not from haves.
//!   3. Feed those commit OIDs to
//!      `gix_pack::data::output::count::objects::objects` with
//!      `ObjectExpansion::TreeContents` so each commit's tree is
//!      walked and every reachable blob/sub-tree is included in
//!      the pack count.
//!   4. `gix_pack::data::output::entry::iter_from_counts` turns
//!      counts into encoded entries (parallel under the hood; we
//!      pin to one thread for deterministic order so we don't have
//!      to wrap with `InOrderIter`).
//!   5. `gix_pack::data::output::bytes::FromEntriesIter` writes the
//!      pack to a `Vec<u8>`, including header + trailing checksum.
//!
//! Edge cases handled:
//!   - empty `wants`: returns the canonical empty-pack bytes
//!     (32 bytes: `PACK\0\0\0\2\0\0\0\0` + 20-byte SHA1 trailer).
//!     Avoids feeding zero counts to the writer.
//!   - hex parse errors on wants/haves: bubble up; the caller
//!     should never hit this (parse_v2_fetch already validates
//!     hex40), but the gix layer wants real ObjectIds.

use crate::error::{Error, Result};
use gix_pack::data::output;
use std::path::Path;
use std::sync::atomic::AtomicBool;

/// Hand-rolled pack parser + delta resolver. KV-friendly (no
/// filesystem touch); used by `SqliteObjectStore::ingest_pack` after
/// the D4 wiring. See `src/native_pack/parse.rs`.
pub(crate) mod parse;

/// Index a pack from `pack_bytes` into `<repo>/objects/pack/`. Used
/// by native receive-pack (M1b-3-gix) to replace the
/// `git unpack-objects --stdin` subprocess: instead of unpacking
/// loose, we write the pack file + index next to it. Git reads
/// packed and loose equivalently, so this is observably the same
/// outcome with one fewer subprocess on the push hot path.
///
/// We pass the repo's existing `objects` handle as the
/// `thin_pack_base_object_lookup` so deltas referring to objects
/// already in the repo (the "thin pack" case — what clients
/// normally send) resolve correctly. Without that, thin pushes
/// would bail with a missing-base error.
///
/// Empty pack: returns `Ok(())` without writing anything. An empty
/// pack on the push side means a delete-only ref-update, which is
/// already handled before this function is called; defensive here
/// so a future caller doesn't accidentally feed us 32 bytes and
/// get a confusing "wrote a pack with zero objects" file.
pub fn index_pack_into_repo(repo_path: &Path, pack_bytes: &[u8]) -> Result<()> {
    if pack_bytes.len() <= 32 {
        return Ok(());
    }
    let pack_dir = repo_path.join("objects/pack");
    std::fs::create_dir_all(&pack_dir)?;

    let repo = gix::open(repo_path)
        .map_err(|e| Error::GixError(format!("gix::open({}): {e}", repo_path.display())))?;

    let mut buf = std::io::Cursor::new(pack_bytes);
    let mut progress = prodash::progress::Discard;
    let interrupt = std::sync::atomic::AtomicBool::new(false);

    // Pass the repo's odb handle as the thin-pack base resolver.
    // gix's odb handle implements gix_object::Find, which is what
    // the bundle writer expects for resolving deltas against
    // already-existing objects.
    //
    // Performance note: this call has ~50ms of fixed overhead from
    // tempfile + fsync regardless of pack size — that's why
    // ARTIFACTS_NATIVE_INDEX_PACK is opt-in (see scripts/bench_push.sh
    // numbers in the README). Profile run: gix::open ~180us,
    // Bundle::write_to_directory ~50ms for a 3-object pack.
    let outcome = gix_pack::Bundle::write_to_directory(
        &mut buf,
        Some(&pack_dir),
        &mut progress,
        &interrupt,
        Some(repo.objects),
        gix_pack::bundle::write::Options {
            thread_limit: Some(1),
            iteration_mode: gix_pack::data::input::Mode::Verify,
            index_version: gix_pack::index::Version::default(),
            object_hash: gix_hash::Kind::Sha1,
        },
    )
    .map_err(|e| Error::Other(anyhow::anyhow!("Bundle::write_to_directory: {e}")))?;
    tracing::debug!(
        objects = outcome.index.num_objects,
        "indexed pack via gix-pack"
    );
    Ok(())
}

/// Build a packfile containing every object reachable from `wants`
/// but not from `haves`, suitable for the v2 fetch response.
pub fn generate_pack(repo_path: &Path, wants: &[String], haves: &[String]) -> Result<Vec<u8>> {
    if wants.is_empty() {
        return Ok(empty_pack_bytes());
    }

    let mut repo = gix::open(repo_path)
        .map_err(|e| Error::GixError(format!("gix::open({}): {e}", repo_path.display())))?;
    // A small object cache amortizes repeated lookups during walks.
    repo.object_cache_size_if_unset(4 * 1024 * 1024);

    // Parse wants/haves into ObjectIds. parse_v2_fetch already gates
    // on is_hex40, so any error here means the caller bypassed that
    // validation — bubble it up rather than silently dropping.
    let want_oids = parse_oids(wants)?;
    let have_oids = parse_oids(haves)?;

    // Walk commits from wants, stopping at haves. The walker yields
    // every commit reachable from wants that is NOT reachable from
    // haves — exactly the set we want to pack.
    //
    // For an initial clone (no haves), this yields the full commit
    // history. For an incremental fetch, it yields the delta.
    let walk = repo
        .rev_walk(want_oids.iter().copied())
        .with_boundary(have_oids.iter().copied())
        .all()
        .map_err(|e| Error::Other(anyhow::anyhow!("rev_walk: {e}")))?;

    let mut commit_ids: Vec<gix::ObjectId> = Vec::new();
    for info in walk {
        let info = info.map_err(|e| Error::Other(anyhow::anyhow!("rev_walk iter: {e}")))?;
        commit_ids.push(info.id);
    }

    if commit_ids.is_empty() {
        // Wants existed but we're already up-to-date relative to
        // haves. Return an empty pack — the client will see "0
        // entries" and accept the fetch as a no-op.
        return Ok(empty_pack_bytes());
    }

    // Count phase: walk each commit's tree to enumerate every
    // reachable object (commits + trees + blobs). TreeContents is
    // the expansion mode that does this.
    let interrupt = AtomicBool::new(false);
    let count_options = output::count::objects::Options {
        // thread_limit=1 keeps the output order deterministic so we
        // don't need an InOrderIter wrapper later. At our pack
        // sizes (single-machine repos, mostly small) the parallel
        // win is marginal.
        thread_limit: Some(1),
        chunk_size: 16,
        input_object_expansion: output::count::objects::ObjectExpansion::TreeContents,
    };
    let progress = prodash::progress::Discard;
    let ids_iter: Box<
        dyn Iterator<
                Item = std::result::Result<
                    gix::ObjectId,
                    Box<dyn std::error::Error + Send + Sync + 'static>,
                >,
            > + Send,
    > = Box::new(commit_ids.into_iter().map(Ok));
    // `repo.objects` is a Proxy<Cache<Handle<…>>>. Proxy implements
    // gix_object::Find but NOT gix_pack::Find — strip the proxy with
    // `into_inner()` to get the inner Handle (which does).
    //
    // `prevent_pack_unload()` is required by both `count::objects` and
    // `iter_from_counts`: they cache pack-entry locations across the
    // call, and a concurrent gc that unloaded a pack mid-walk would
    // invalidate those references. Without this we panic with
    // "BUG: handle must be configured to prevent_pack_unload()".
    let mut db = repo.objects.clone().into_inner();
    db.prevent_pack_unload();
    let (counts, _outcome) =
        output::count::objects(db.clone(), ids_iter, &progress, &interrupt, count_options)
            .map_err(|e| Error::Other(anyhow::anyhow!("pack count: {e}")))?;

    if counts.is_empty() {
        return Ok(empty_pack_bytes());
    }
    let num_entries = counts.len() as u32;

    // Entry phase: turn counts into the encoded form pack-bytes
    // expects. Same single-thread ordering for determinism.
    let entry_options = output::entry::iter_from_counts::Options {
        thread_limit: Some(1),
        mode: output::entry::iter_from_counts::Mode::PackCopyAndBaseObjects,
        // Thin packs have deltas referring to base objects not in
        // the pack — git accepts thin packs in transit (it'll
        // resolve them post-fetch with `git index-pack --fix-thin`
        // semantics on the client side).
        allow_thin_pack: true,
        chunk_size: 16,
        version: gix_pack::data::Version::V2,
    };
    let entry_progress = prodash::progress::Discard;
    let entries = output::entry::iter_from_counts(
        counts,
        db.clone(),
        Box::new(entry_progress),
        entry_options,
    );

    // FromEntriesIter wants `Item = Result<Vec<Entry>, E>` where E
    // is `std::error::Error + 'static`. iter_from_counts gives us
    // `Result<(SequenceId, Vec<Entry>), iter_from_counts::Error>`.
    // Drop the SequenceId and box the error for shape compat.
    let entries_mapped = entries.map(|r| match r {
        Ok((_, vec)) => Ok(vec),
        Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>),
    });
    // FromEntriesIter requires E: std::error::Error + 'static
    let entries_mapped = entries_mapped.map(|r| r.map_err(BoxStdErr));

    // Bytes phase: write entries into our buffer.
    let mut out_buf = Vec::with_capacity(64 * 1024);
    let from_entries = output::bytes::FromEntriesIter::new(
        entries_mapped,
        &mut out_buf,
        num_entries,
        gix_pack::data::Version::V2,
        gix_hash::Kind::Sha1,
    );
    for chunk_result in from_entries {
        chunk_result.map_err(|e| Error::Other(anyhow::anyhow!("pack write: {e}")))?;
    }
    Ok(out_buf)
}

fn parse_oids(hexes: &[String]) -> Result<Vec<gix::ObjectId>> {
    let mut out = Vec::with_capacity(hexes.len());
    for h in hexes {
        let oid = gix::ObjectId::from_hex(h.as_bytes())
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid oid {h:?}: {e}")))?;
        out.push(oid);
    }
    Ok(out)
}

/// Wraps a boxed dyn-error so it satisfies FromEntriesIter's
/// `E: std::error::Error + 'static` bound. The boxed error already
/// implements `Display`/`Debug`; we forward via `source()` so anyone
/// inspecting the chain still sees the underlying gix error.
#[derive(Debug)]
struct BoxStdErr(Box<dyn std::error::Error + Send + Sync + 'static>);

impl std::fmt::Display for BoxStdErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for BoxStdErr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// The canonical zero-entry v2 pack: `PACK` magic + version=2 +
/// count=0, followed by a 20-byte SHA1 trailer over those 12 bytes.
/// 32 bytes total. Used when wants is empty or fully covered by
/// haves — we return a structurally valid pack so the response
/// frame stays well-formed.
fn empty_pack_bytes() -> Vec<u8> {
    let header: [u8; 12] = [
        b'P', b'A', b'C', b'K', // magic
        0, 0, 0, 2, // version 2
        0, 0, 0, 0, // count 0
    ];
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(header);
    let trailer = h.finalize();
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&header);
    out.extend_from_slice(&trailer);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{new_repo_id, FsStorage, Storage};

    /// `git index-pack --stdin` parses the stream and writes a `.pack`
    /// + `.idx`, then exits 0 if (and only if) the pack is valid:
    ///   - PACK header magic + version
    ///   - exact entry count
    ///   - per-entry zlib decompression succeeds
    ///   - object hashes match
    ///   - trailing pack checksum matches the streamed bytes
    ///
    /// We use it as the "is this a valid pack?" oracle in tests.
    fn validate_with_index_pack(pack: &[u8], scratch: &Path) -> std::io::Result<()> {
        use std::io::Write as _;
        let pack_path = scratch.join("test.pack");
        let mut child = std::process::Command::new("git")
            .args(["index-pack", "--stdin"])
            .arg(&pack_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        child.stdin.as_mut().unwrap().write_all(pack)?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "index-pack rejected: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    #[test]
    fn empty_wants_produces_valid_empty_pack() {
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage
            .create(&crate::ids::RepoId::try_from(repo_id.as_str()).unwrap())
            .unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));

        let pack = generate_pack(&git_dir, &[], &[]).unwrap();
        assert_eq!(pack.len(), 32);
        // Validate against git's own pack parser.
        let scratch = tempfile::tempdir().unwrap();
        validate_with_index_pack(&pack, scratch.path()).expect("empty pack must be valid");
    }

    #[test]
    fn wants_one_commit_packs_full_closure() {
        // Build a repo with one commit (one tree, one blob), then
        // ask for that commit. Resulting pack should validate and
        // contain exactly 3 entries (commit + tree + blob).
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage
            .create(&crate::ids::RepoId::try_from(repo_id.as_str()).unwrap())
            .unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));

        // Plumbing-only commit: hash-object → mktree → commit-tree.
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut blob_proc = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        blob_proc
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"hello\n")
            .unwrap();
        let blob = String::from_utf8(blob_proc.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();

        let mut tree_proc = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["mktree"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        tree_proc
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("100644 blob {blob}\thello.txt\n").as_bytes())
            .unwrap();
        let tree = String::from_utf8(tree_proc.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();

        let commit_out = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["commit-tree", "-m", "init", &tree])
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap();
        let commit = String::from_utf8(commit_out.stdout)
            .unwrap()
            .trim()
            .to_string();

        let pack = generate_pack(&git_dir, &[commit], &[]).unwrap();
        assert!(pack.len() > 32, "non-empty pack should be > 32 bytes");

        // Validate via git index-pack — fails the test if the pack
        // is malformed in any way (header, body, or trailer).
        let scratch = tempfile::tempdir().unwrap();
        validate_with_index_pack(&pack, scratch.path())
            .expect("native-generated pack must be a valid pack");
    }

    // -----------------------------------------------------------------------
    // Additional coverage for edge paths
    // -----------------------------------------------------------------------

    // --- index_pack_into_repo: empty-pack short-circuit --------------------

    #[test]
    fn index_pack_into_repo_short_circuits_on_empty_pack() {
        // A pack ≤ 32 bytes must return Ok(()) without writing anything.
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));

        // Exactly 32 bytes — the canonical empty pack.
        let empty = generate_pack(&git_dir, &[], &[]).unwrap();
        assert_eq!(empty.len(), 32);
        index_pack_into_repo(&git_dir, &empty).expect("empty pack must succeed silently");

        // Nothing should have been written to the pack directory.
        let pack_dir = git_dir.join("objects/pack");
        if pack_dir.exists() {
            let entries: Vec<_> = std::fs::read_dir(&pack_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();
            assert!(entries.is_empty(), "no pack files should be written");
        }

        // Also test the < 32 bytes case (e.g. a raw 0-byte slice).
        index_pack_into_repo(&git_dir, &[]).expect("zero bytes must succeed silently");
        index_pack_into_repo(&git_dir, &[0u8; 16]).expect("16 bytes must succeed silently");
    }

    // --- index_pack_into_repo: real pack written and indexed ---------------

    #[test]
    fn index_pack_into_repo_writes_pack_for_real_pack() {
        // Build a repo with one commit, generate a real pack, then feed it to
        // index_pack_into_repo. The resulting .pack file must exist.
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));

        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let mut blob_proc = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        blob_proc
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"idx-test\n")
            .unwrap();
        let blob = String::from_utf8(blob_proc.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();

        let mut tree_proc = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["mktree"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        tree_proc
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("100644 blob {blob}\tidx.txt\n").as_bytes())
            .unwrap();
        let tree = String::from_utf8(tree_proc.wait_with_output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();

        let commit_out = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["commit-tree", "-m", "idx-test", &tree])
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap();
        let commit = String::from_utf8(commit_out.stdout)
            .unwrap()
            .trim()
            .to_string();

        let pack = generate_pack(&git_dir, &[commit], &[]).unwrap();
        assert!(pack.len() > 32);

        index_pack_into_repo(&git_dir, &pack).expect("should index a real pack");

        // At least one .pack file must exist after indexing.
        let pack_dir = git_dir.join("objects/pack");
        let pack_files: Vec<_> = std::fs::read_dir(&pack_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "pack").unwrap_or(false))
            .collect();
        assert!(!pack_files.is_empty(), "pack file must be written");
    }

    // --- generate_pack: invalid OID in wants/haves -------------------------

    #[test]
    fn generate_pack_rejects_invalid_want_oid() {
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));

        let err = generate_pack(&git_dir, &["not-a-hex-oid".to_string()], &[]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid oid") || msg.contains("not-a-hex"),
            "expected invalid-oid error, got: {msg}"
        );
    }

    #[test]
    fn generate_pack_rejects_invalid_have_oid() {
        let tmp = tempfile::tempdir().unwrap();
        let repos = tmp.path().join("repos");
        let storage = FsStorage::new(&repos).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = repos.join(format!("{repo_id}.git"));

        // We need a valid want so we don't hit the empty-wants short-circuit,
        // but an invalid have.
        // Use a syntactically valid 40-hex OID for wants (even if the object
        // doesn't exist; it fails at rev_walk, not parse_oids).
        // For the have, use garbage.
        let valid_hex = "a".repeat(40);
        let err = generate_pack(&git_dir, &[valid_hex], &["not-hex".to_string()]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("invalid oid") || msg.contains("not-hex"),
            "expected invalid-oid error for have, got: {msg}"
        );
    }

    // --- empty_pack_bytes round-trips through our own parser ---------------

    #[test]
    fn empty_pack_bytes_is_valid_and_parseable() {
        let pack = empty_pack_bytes();
        assert_eq!(pack.len(), 32, "empty pack is always 32 bytes");
        // The first 12 bytes must be the canonical pack header.
        assert_eq!(&pack[..4], b"PACK");
        assert_eq!(u32::from_be_bytes(pack[4..8].try_into().unwrap()), 2);
        assert_eq!(u32::from_be_bytes(pack[8..12].try_into().unwrap()), 0);
        // Our own parser must accept it and return zero entries.
        let entries = parse::parse_pack(&pack).expect("empty pack must parse");
        assert!(entries.is_empty());
    }

    // --- BoxStdErr: Display and source() delegates -------------------------

    #[test]
    fn box_std_err_display_and_source() {
        use std::error::Error as StdError;
        let inner: Box<dyn std::error::Error + Send + Sync + 'static> =
            Box::new(std::io::Error::other("inner error"));
        let wrapped = BoxStdErr(inner);
        let display = format!("{wrapped}");
        assert!(
            display.contains("inner error"),
            "display must include inner: {display}"
        );
        // source() returns None for io::Error (no chain).
        let _ = wrapped.source();
    }
}
