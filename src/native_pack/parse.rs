//! Hand-rolled git pack-file parser, KV-friendly.
//!
//! Why this exists: `SqliteObjectStore::ingest_pack` used to land a
//! pushed pack via `tempfile::tempdir() +
//! gix_pack::Bundle::write_to_directory`, which is a filesystem
//! detour even for a backend that has no business touching disk. This
//! module is the no-FS replacement — bytes in → resolved objects out.
//!
//! D1 (this commit) handles the non-delta path: header, entry
//! header, zlib-decompressed bodies for the four direct kinds. D2
//! adds REF_DELTA, D3 adds OFS_DELTA, D4 wires the whole thing into
//! `ingest_pack`.
//!
//! ## Pack format reference
//!
//! Pack header (12 bytes):
//!
//!   - 4 bytes "PACK" magic
//!   - 4 bytes big-endian u32 version (we accept v2)
//!   - 4 bytes big-endian u32 object count
//!
//! Per-entry header (variable, MSB-continuation little-endian for
//! the size field):
//!
//!   - Byte 0: \[continuation:1\]\[type:3\]\[size_low:4\]
//!   - While continuation bit set, subsequent bytes contribute 7
//!     bits each of size (LSB-first stream order).
//!
//! Type codes:
//!
//!   - 1 OBJ_COMMIT
//!   - 2 OBJ_TREE
//!   - 3 OBJ_BLOB
//!   - 4 OBJ_TAG
//!   - 6 OBJ_OFS_DELTA  (handled in D3)
//!   - 7 OBJ_REF_DELTA  (handled in D2)
//!
//! For OFS_DELTA: variable-length offset follows the entry header.
//! For REF_DELTA: a 20-byte base SHA-1 follows the entry header.
//! Then a zlib-deflated body of the size declared in the header.
//!
//! Pack trailer: 20-byte SHA-1 of all preceding bytes. We don't
//! verify the trailer here — the caller already trusts the source
//! (a smart-HTTP receive-pack body that passed Basic auth + the
//! receive-pack ref-validation), and the per-object SHA-1 we
//! re-compute at write time is the cryptographic check that matters
//! for storage.

// D1 stages helpers + the non-delta storage entry point; D2/D3 add
// delta resolution and D4 wires it all into `SqliteObjectStore::ingest_pack`.
// Until D4 lands the production callers, the parser is reachable
// only from #[cfg(test)] — silence the unused-code lints crate-wide
// for this module rather than scattering #[allow] attrs on every
// item that lands across two more commits.
#![allow(dead_code)]

use crate::error::{Error, Result};
use crate::object_store::{ObjectKind, ObjectStore};

/// Git pack object-type codes (per the format spec).
const OBJ_COMMIT: u8 = 1;
const OBJ_TREE: u8 = 2;
const OBJ_BLOB: u8 = 3;
const OBJ_TAG: u8 = 4;
const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;

/// One parsed pack entry. `data` is the zlib-decompressed body —
/// for a direct entry that's the object payload; for a delta entry
/// that's the delta instruction stream.
#[derive(Debug, Clone)]
pub(crate) struct ParsedEntry {
    /// Byte offset of this entry's header within the pack. Used by
    /// the OFS_DELTA resolver (D3) to find a base by subtracting
    /// the negative-offset field from this value.
    pub offset: usize,
    pub kind: ParsedKind,
    /// Uncompressed payload (or delta instructions).
    pub data: Vec<u8>,
}

/// What a parsed entry's header says it is.
#[derive(Debug, Clone)]
pub(crate) enum ParsedKind {
    Direct(ObjectKind),
    /// REF_DELTA: 20-byte base SHA-1 captured from the entry preamble.
    RefDelta {
        base_oid: [u8; 20],
    },
    /// OFS_DELTA: positive offset to subtract from `entry.offset` to
    /// locate the base entry.
    OfsDelta {
        base_offset_delta: u64,
    },
}

/// Parse a complete pack body. Returns one [`ParsedEntry`] per
/// object the header advertises; the order matches the on-wire
/// order. Errors on truncated input, unknown object kinds, or zlib
/// stream corruption.
///
/// Doesn't verify the trailing SHA-1. See module docs for the
/// rationale.
pub(crate) fn parse_pack(pack: &[u8]) -> Result<Vec<ParsedEntry>> {
    if pack.len() < 12 {
        return Err(Error::Other(anyhow::anyhow!(
            "pack too short for header: {} bytes",
            pack.len()
        )));
    }
    if &pack[..4] != b"PACK" {
        return Err(Error::Other(anyhow::anyhow!(
            "missing PACK magic at offset 0"
        )));
    }
    let version = u32::from_be_bytes(pack[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::Other(anyhow::anyhow!(
            "unsupported pack version: {version}"
        )));
    }
    let n_objects = u32::from_be_bytes(pack[8..12].try_into().unwrap()) as usize;

    let mut entries = Vec::with_capacity(n_objects);
    let mut cursor = 12usize;

    for i in 0..n_objects {
        let entry_offset = cursor;
        let (kind_byte, _size, header_len) = parse_entry_header(&pack[cursor..]).map_err(|e| {
            Error::Other(anyhow::anyhow!(
                "entry {i} at offset {cursor}: header parse: {e}"
            ))
        })?;
        cursor += header_len;

        let kind = match kind_byte {
            OBJ_COMMIT => ParsedKind::Direct(ObjectKind::Commit),
            OBJ_TREE => ParsedKind::Direct(ObjectKind::Tree),
            OBJ_BLOB => ParsedKind::Direct(ObjectKind::Blob),
            OBJ_TAG => ParsedKind::Direct(ObjectKind::Tag),
            OBJ_REF_DELTA => {
                if pack.len() < cursor + 20 {
                    return Err(Error::Other(anyhow::anyhow!(
                        "entry {i}: truncated REF_DELTA base OID at offset {cursor}"
                    )));
                }
                let mut base_oid = [0u8; 20];
                base_oid.copy_from_slice(&pack[cursor..cursor + 20]);
                cursor += 20;
                ParsedKind::RefDelta { base_oid }
            }
            OBJ_OFS_DELTA => {
                let (base_offset_delta, consumed) = parse_ofs_delta_offset(&pack[cursor..])
                    .map_err(|e| {
                        Error::Other(anyhow::anyhow!(
                            "entry {i}: OFS_DELTA base-offset parse at {cursor}: {e}"
                        ))
                    })?;
                cursor += consumed;
                ParsedKind::OfsDelta { base_offset_delta }
            }
            other => {
                return Err(Error::Other(anyhow::anyhow!(
                    "entry {i}: unknown object type {other}"
                )));
            }
        };

        let (decompressed, compressed_len) = decompress_zlib(&pack[cursor..]).map_err(|e| {
            Error::Other(anyhow::anyhow!(
                "entry {i} at offset {entry_offset}: zlib decompress: {e}"
            ))
        })?;
        cursor += compressed_len;

        entries.push(ParsedEntry {
            offset: entry_offset,
            kind,
            data: decompressed,
        });
    }

    Ok(entries)
}

/// Parse one entry header. Returns `(kind_byte, size, header_len)`.
/// `size` is the declared uncompressed payload size (or the
/// pre-applied size for deltas — the spec uses the same field).
fn parse_entry_header(bytes: &[u8]) -> Result<(u8, u64, usize)> {
    if bytes.is_empty() {
        return Err(Error::Other(anyhow::anyhow!("empty header buffer")));
    }
    let first = bytes[0];
    let kind = (first >> 4) & 0b0111;
    let mut size = u64::from(first & 0b1111);
    let mut shift = 4u32;
    let mut idx = 1usize;
    let mut byte = first;
    while byte & 0x80 != 0 {
        if idx >= bytes.len() {
            return Err(Error::Other(anyhow::anyhow!(
                "truncated entry header (size continuation)"
            )));
        }
        byte = bytes[idx];
        idx += 1;
        size |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if shift > 63 {
            return Err(Error::Other(anyhow::anyhow!(
                "entry header size overflows u64"
            )));
        }
    }
    Ok((kind, size, idx))
}

/// Parse the OFS_DELTA negative-offset field. Returns the positive
/// magnitude (caller subtracts it from the entry's own offset to
/// locate the base) plus the byte count consumed.
///
/// Format is MSB-continuation big-endian, with the quirky "+1 per
/// continuation byte" trick git uses to make the encoding canonical
/// (each additional byte shifts the prior value AND adds 1 so two
/// distinct byte streams can't decode to the same number).
fn parse_ofs_delta_offset(bytes: &[u8]) -> Result<(u64, usize)> {
    if bytes.is_empty() {
        return Err(Error::Other(anyhow::anyhow!("empty OFS_DELTA buffer")));
    }
    let mut idx = 0usize;
    let mut byte = bytes[idx];
    idx += 1;
    let mut value = u64::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        if idx >= bytes.len() {
            return Err(Error::Other(anyhow::anyhow!(
                "truncated OFS_DELTA offset (continuation)"
            )));
        }
        byte = bytes[idx];
        idx += 1;
        value = value
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or_else(|| Error::Other(anyhow::anyhow!("OFS_DELTA offset overflow")))?;
        value |= u64::from(byte & 0x7f);
    }
    Ok((value, idx))
}

/// Decompress a single zlib stream starting at `bytes[0]`. Returns
/// the inflated payload and the number of input bytes consumed —
/// the caller advances its pack cursor by that amount so subsequent
/// entries land at the right offset.
fn decompress_zlib(bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut decoder = Decompress::new(true);
    // Reasonable starting capacity; the loop grows as needed.
    let mut out = Vec::with_capacity(bytes.len().min(4096));
    loop {
        let in_before = decoder.total_in() as usize;
        let out_before = decoder.total_out() as usize;
        let buf = &bytes[in_before..];
        // Grow output buffer so we always have headroom.
        if out.len() <= out_before {
            out.resize((out_before + 4096).max(out.len() + 1), 0);
        }
        let status = decoder
            .decompress(buf, &mut out[out_before..], FlushDecompress::None)
            .map_err(|e| Error::Other(anyhow::anyhow!("zlib: {e}")))?;
        match status {
            Status::Ok | Status::BufError => {
                // BufError means out buffer is full; loop again with
                // more space. Ok with progress also requires more
                // input or output room; loop.
                let progressed = decoder.total_in() as usize > in_before
                    || decoder.total_out() as usize > out_before;
                if !progressed {
                    return Err(Error::Other(anyhow::anyhow!(
                        "zlib stalled (no progress on Ok/BufError)"
                    )));
                }
            }
            Status::StreamEnd => break,
        }
    }
    let consumed = decoder.total_in() as usize;
    out.truncate(decoder.total_out() as usize);
    Ok((out, consumed))
}

/// Hash a (kind, payload) pair under git's canonical loose-object
/// format: SHA-1 over `"<kind> <size>\0<payload>"`. Returns the
/// 40-char hex digest, which is the OID storage key.
pub(crate) fn loose_oid_hex(kind: ObjectKind, payload: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    let header = format!("{} {}\0", kind_str(kind), payload.len());
    h.update(header.as_bytes());
    h.update(payload);
    let digest = h.finalize();
    let mut hex = String::with_capacity(40);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

/// Encode a payload + kind as the zlib-deflated loose-object bytes
/// `ObjectStore::write_loose` expects.
pub(crate) fn loose_format_bytes(kind: ObjectKind, payload: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut buf = Vec::with_capacity(payload.len() + 20);
    {
        let mut enc = ZlibEncoder::new(&mut buf, Compression::default());
        write!(enc, "{} {}\0", kind_str(kind), payload.len())
            .map_err(|e| Error::Other(anyhow::anyhow!("loose header write: {e}")))?;
        enc.write_all(payload)
            .map_err(|e| Error::Other(anyhow::anyhow!("loose payload write: {e}")))?;
        enc.finish()
            .map_err(|e| Error::Other(anyhow::anyhow!("loose zlib finish: {e}")))?;
    }
    Ok(buf)
}

fn kind_str(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Commit => "commit",
        ObjectKind::Tree => "tree",
        ObjectKind::Blob => "blob",
        ObjectKind::Tag => "tag",
    }
}

/// D1 entry point. Parse `pack_bytes`, store every non-delta entry
/// via [`ObjectStore::write_loose`]. Returns the number of objects
/// stored. Errors out if any delta-kind entries are present — D2
/// and D3 add resolution for those.
///
/// Not yet hooked into `ingest_pack` — D4 does that wiring.
pub(crate) fn store_non_delta_entries<S: ObjectStore + ?Sized>(
    pack_bytes: &[u8],
    repo_id: &str,
    store: &S,
) -> Result<usize> {
    let entries = parse_pack(pack_bytes)?;
    let mut count = 0usize;
    for (i, entry) in entries.iter().enumerate() {
        match entry.kind {
            ParsedKind::Direct(kind) => {
                let oid = loose_oid_hex(kind, &entry.data);
                let loose = loose_format_bytes(kind, &entry.data)?;
                store.write_loose(repo_id, &oid, &loose)?;
                count += 1;
            }
            ParsedKind::RefDelta { .. } | ParsedKind::OfsDelta { .. } => {
                return Err(Error::Other(anyhow::anyhow!(
                    "entry {i}: delta entries not yet supported (D2/D3)"
                )));
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_store::{MemObjectStore, ObjectKind};

    /// Encode a git loose-object payload (just the payload —
    /// `<kind> <size>\0` header isn't baked in; the pack format
    /// stores the payload directly).
    fn build_minimal_pack(entries: &[(ObjectKind, &[u8])]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use sha1::{Digest, Sha1};
        use std::io::Write;

        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());

        for (kind, payload) in entries {
            let type_byte = match kind {
                ObjectKind::Commit => OBJ_COMMIT,
                ObjectKind::Tree => OBJ_TREE,
                ObjectKind::Blob => OBJ_BLOB,
                ObjectKind::Tag => OBJ_TAG,
            };
            let mut size = payload.len() as u64;
            // First byte: continuation:1 | type:3 | size_low:4
            let mut header = Vec::new();
            let low = (size & 0b1111) as u8;
            size >>= 4;
            let first = (if size > 0 { 0x80 } else { 0 }) | (type_byte << 4) | low;
            header.push(first);
            while size > 0 {
                let byte = (size & 0x7f) as u8;
                size >>= 7;
                let continuation = if size > 0 { 0x80 } else { 0 };
                header.push(continuation | byte);
            }
            out.extend_from_slice(&header);

            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(payload).unwrap();
            let compressed = enc.finish().unwrap();
            out.extend_from_slice(&compressed);
        }

        // Pack trailer: SHA-1 over preceding bytes.
        let mut h = Sha1::new();
        h.update(&out);
        out.extend_from_slice(&h.finalize());
        out
    }

    #[test]
    fn parses_a_single_blob_entry() {
        let payload = b"hello, pack\n";
        let pack = build_minimal_pack(&[(ObjectKind::Blob, payload)]);
        let entries = parse_pack(&pack).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].kind,
            ParsedKind::Direct(ObjectKind::Blob)
        ));
        assert_eq!(entries[0].data, payload);
        assert_eq!(
            entries[0].offset, 12,
            "first entry follows the 12-byte header"
        );
    }

    #[test]
    fn parses_three_entries_of_mixed_kinds() {
        let pack = build_minimal_pack(&[
            (ObjectKind::Blob, b"first blob"),
            (ObjectKind::Tree, b"tree-bytes-x"),
            (ObjectKind::Commit, b"commit msg"),
        ]);
        let entries = parse_pack(&pack).unwrap();
        assert_eq!(entries.len(), 3);
        let kinds: Vec<ObjectKind> = entries
            .iter()
            .map(|e| match e.kind {
                ParsedKind::Direct(k) => k,
                _ => panic!("expected Direct"),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![ObjectKind::Blob, ObjectKind::Tree, ObjectKind::Commit]
        );
        // Offsets must be monotonic and consistent with header lengths.
        for w in entries.windows(2) {
            assert!(
                w[0].offset < w[1].offset,
                "entry offsets must monotonically increase"
            );
        }
    }

    #[test]
    fn rejects_truncated_header() {
        let mut pack = build_minimal_pack(&[(ObjectKind::Blob, b"x")]);
        pack.truncate(8);
        let err = parse_pack(&pack).unwrap_err();
        assert!(format!("{err}").contains("pack too short"));
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut pack = build_minimal_pack(&[(ObjectKind::Blob, b"x")]);
        pack[0] = b'X';
        let err = parse_pack(&pack).unwrap_err();
        assert!(format!("{err}").contains("PACK magic"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut pack = build_minimal_pack(&[(ObjectKind::Blob, b"x")]);
        pack[4..8].copy_from_slice(&3u32.to_be_bytes());
        let err = parse_pack(&pack).unwrap_err();
        assert!(format!("{err}").contains("version"));
    }

    #[test]
    fn store_non_delta_round_trips_through_mem() {
        let payload_blob = b"the quick brown fox\n";
        let payload_commit =
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor x x 0 +0000\ncommitter x x 0 +0000\n\nmsg\n";
        let pack = build_minimal_pack(&[
            (ObjectKind::Blob, payload_blob),
            (ObjectKind::Commit, payload_commit),
        ]);
        let store = MemObjectStore::new();
        let n = store_non_delta_entries(&pack, "r", &store).unwrap();
        assert_eq!(n, 2);

        // Each object retrievable by its canonical OID, and the
        // bytes match what was inflated from the pack.
        let blob_oid = loose_oid_hex(ObjectKind::Blob, payload_blob);
        let commit_oid = loose_oid_hex(ObjectKind::Commit, payload_commit);
        assert!(store.exists("r", &blob_oid).unwrap());
        assert!(store.exists("r", &commit_oid).unwrap());

        // The bytes we wrote back are zlib(`<kind> <size>\0<payload>`).
        // Sanity-check that the read_loose body starts with the zlib
        // magic (0x78) so we didn't accidentally write raw bytes,
        // then inflate locally and confirm the round-trip — Mem's
        // read_object isn't implemented, but the storage format is
        // what we care about.
        let bytes = store.read_loose("r", &blob_oid).unwrap().unwrap();
        assert_eq!(bytes[0], 0x78, "loose object must start with zlib magic");

        let mut d = flate2::read::ZlibDecoder::new(bytes.as_slice());
        let mut inflated = Vec::new();
        std::io::Read::read_to_end(&mut d, &mut inflated).unwrap();
        let nul = inflated
            .iter()
            .position(|&b| b == 0)
            .expect("nul terminator in header");
        let header = std::str::from_utf8(&inflated[..nul]).unwrap();
        assert_eq!(header, format!("blob {}", payload_blob.len()));
        assert_eq!(&inflated[nul + 1..], payload_blob);
    }

    #[test]
    fn parses_a_pack_produced_by_gix_pack() {
        // Build a tiny real repo with `native_pack::generate_pack`
        // (the production fetch path) and confirm our parser walks
        // its output without choking. Catches off-by-one bugs in
        // the entry header that hand-rolled tests above might miss
        // — gix produces canonical-form size encodings that span
        // multiple bytes for any payload over 16 bytes.
        use crate::storage::{new_repo_id, FsStorage, Storage};
        let tmp = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(tmp.path()).unwrap();
        let repo_id = new_repo_id();
        storage.create(&repo_id).unwrap();
        let git_dir = tmp.path().join(format!("{repo_id}.git"));

        // Seed the repo with one commit via plumbing so there's
        // something for `generate_pack` to encode. Three test
        // packs in the existing codebase do this dance; we mirror it
        // here cheaply.
        let mut blob_proc = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["hash-object", "-w", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            blob_proc
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"a real blob with some bytes that should compress well\n")
                .unwrap();
        }
        let blob_out = blob_proc.wait_with_output().unwrap();
        let blob = String::from_utf8(blob_out.stdout)
            .unwrap()
            .trim()
            .to_string();

        let mut tree_proc = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .arg("mktree")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            tree_proc
                .stdin
                .as_mut()
                .unwrap()
                .write_all(format!("100644 blob {blob}\tREADME.md\n").as_bytes())
                .unwrap();
        }
        let tree_out = tree_proc.wait_with_output().unwrap();
        let tree = String::from_utf8(tree_out.stdout)
            .unwrap()
            .trim()
            .to_string();

        let commit_out = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["commit-tree", "-m", "x", &tree])
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

        let pack = crate::native_pack::generate_pack(&git_dir, &[commit.clone()], &[]).unwrap();
        let entries = parse_pack(&pack).expect("gix-produced pack should parse");
        assert_eq!(entries.len(), 3, "commit + tree + blob");
        // Every entry is a direct kind (gix doesn't deltify a
        // single-commit pack); confirm we see one of each kind.
        let mut have_commit = false;
        let mut have_tree = false;
        let mut have_blob = false;
        for e in &entries {
            match e.kind {
                ParsedKind::Direct(ObjectKind::Commit) => have_commit = true,
                ParsedKind::Direct(ObjectKind::Tree) => have_tree = true,
                ParsedKind::Direct(ObjectKind::Blob) => have_blob = true,
                _ => {}
            }
        }
        assert!(have_commit && have_tree && have_blob);

        // Hash-equivalence: re-hash each Direct entry's payload and
        // confirm one of them matches our known blob/tree/commit OID.
        let mut hashes: Vec<String> = entries
            .iter()
            .filter_map(|e| match e.kind {
                ParsedKind::Direct(k) => Some(loose_oid_hex(k, &e.data)),
                _ => None,
            })
            .collect();
        hashes.sort();
        let mut expected = vec![blob, tree, commit];
        expected.sort();
        assert_eq!(hashes, expected, "hashes from parser must match git's");
    }

    #[test]
    fn store_non_delta_refuses_delta_entries() {
        // Hand-construct a REF_DELTA entry (type=7) so we don't have
        // to wire a real base. parse_pack will succeed; the storer
        // must refuse.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        // Entry header: type=7 REF_DELTA, size=0 (fits in 4 bits, no continuation).
        pack.push(7 << 4);
        // 20-byte base OID (all zeros — won't be looked up because
        // the storer rejects deltas before trying to apply them).
        pack.extend_from_slice(&[0u8; 20]);
        // Zlib-encoded empty delta body so parse_pack succeeds.
        {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(b"").unwrap();
            pack.extend_from_slice(&enc.finish().unwrap());
        }
        // 20-byte trailer.
        pack.extend_from_slice(&[0u8; 20]);

        let store = MemObjectStore::new();
        let err = store_non_delta_entries(&pack, "r", &store).unwrap_err();
        assert!(
            format!("{err}").contains("delta entries not yet supported"),
            "got: {err}"
        );
    }
}
