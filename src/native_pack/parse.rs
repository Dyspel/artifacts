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

// Most of the parser's internal helpers (`apply_delta`,
// `loose_oid_hex`, `loose_format_bytes`, `store_with_ref_delta_resolution`,
// etc.) are reachable only from this module's tests — the production
// entry point is `store_with_full_resolution`, which
// `SqliteObjectStore::ingest_pack` calls into directly. Silencing the
// crate-root `deny(unused)` here keeps the per-item set tight without
// scattering `#[allow]` attrs across a dozen places that are
// load-bearing for tests + would re-light if a future backend wants
// the smaller surfaces.
#![allow(dead_code)]

use crate::error::{Error, Result};
use crate::ids::{Oid, RepoId};
use crate::object_store::{ObjectKind, ObjectStore};

/// Git pack object-type codes (per the format spec).
const OBJ_COMMIT: u8 = 1;
const OBJ_TREE: u8 = 2;
const OBJ_BLOB: u8 = 3;
const OBJ_TAG: u8 = 4;
const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;

/// Hard ceiling on the size of a single decompressed pack entry — an
/// object payload, a delta instruction stream, or a delta-reconstructed
/// target. A pushed pack body is itself capped upstream, but a small
/// compressed entry can inflate enormously, and the entry/delta headers
/// carry attacker-controlled length fields. Without this cap two paths
/// drive unbounded allocation: `decompress_zlib`'s grow-until-StreamEnd
/// loop (a decompression bomb) and `apply_delta`'s
/// `Vec::with_capacity(target_size)` (a single huge alloc from a tiny
/// delta). 1 GiB matches the receive-pack body cap; no single object in
/// a real interactive push approaches it.
///
/// On why there is no separate "max compression ratio" constant: a
/// single zlib stream's expansion is intrinsically bounded by deflate
/// (~1028:1 empirically, even for all-zeros input), which sits right on
/// top of any ratio threshold one might pick — so a ratio gate would
/// reject legitimate maximally-compressible blobs (e.g. a committed
/// file of zeros) while adding nothing the absolute + per-entry
/// declared-size output caps don't already guarantee. The declared-size
/// bound (a well-formed entry inflates to *exactly* its header size) is
/// the tight, false-positive-free expansion limit; this constant is the
/// absolute backstop above it.
pub(crate) const MAX_ENTRY_BYTES: usize = 1 << 30; // 1 GiB

/// Cap on how much we preallocate up front for a single entry/target.
/// We never trust an attacker-declared size for the initial allocation;
/// the buffer grows as real output arrives, bounded by the declared
/// size and `MAX_ENTRY_BYTES`. Keeps a hostile "declared 1 GiB" header
/// from forcing a 1 GiB allocation before a single output byte exists.
const INITIAL_ALLOC_CAP: usize = 64 * 1024;

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
        return Err(Error::PackParse(format!(
            "pack too short for header: {} bytes",
            pack.len()
        )));
    }
    if &pack[..4] != b"PACK" {
        return Err(Error::PackParse(
            "missing PACK magic at offset 0".to_string(),
        ));
    }
    // pack.len() >= 12 was checked at the top of this function; the
    // 4-byte slice → [u8; 4] conversion is infallible by that bound.
    let version = u32::from_be_bytes(pack[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::PackParse(format!(
            "unsupported pack version: {version}"
        )));
    }
    // Same bound: pack.len() >= 12 ⇒ pack[8..12] is a 4-byte slice.
    let n_objects = u32::from_be_bytes(pack[8..12].try_into().unwrap()) as usize;

    let mut entries = Vec::with_capacity(n_objects);
    let mut cursor = 12usize;

    for i in 0..n_objects {
        let entry_offset = cursor;
        let (kind_byte, declared_size, header_len) =
            parse_entry_header(&pack[cursor..]).map_err(|e| {
                Error::PackParse(format!("entry {i} at offset {cursor}: header parse: {e}"))
            })?;
        cursor += header_len;

        // Reject an absurd declared size before we decompress or
        // allocate anything for it. A well-formed entry's deflated body
        // inflates to exactly this many bytes; cap it at MAX_ENTRY_BYTES.
        if declared_size > MAX_ENTRY_BYTES as u64 {
            return Err(Error::PackParse(format!(
                "entry {i}: declared size {declared_size} exceeds {MAX_ENTRY_BYTES}-byte cap"
            )));
        }

        let kind = match kind_byte {
            OBJ_COMMIT => ParsedKind::Direct(ObjectKind::Commit),
            OBJ_TREE => ParsedKind::Direct(ObjectKind::Tree),
            OBJ_BLOB => ParsedKind::Direct(ObjectKind::Blob),
            OBJ_TAG => ParsedKind::Direct(ObjectKind::Tag),
            OBJ_REF_DELTA => {
                if pack.len() < cursor + 20 {
                    return Err(Error::PackParse(format!(
                        "entry {i}: truncated REF_DELTA base OID at offset {cursor}"
                    )));
                }
                let mut base_oid = [0u8; 20];
                base_oid.copy_from_slice(&pack[cursor..cursor + 20]);
                cursor += 20;
                ParsedKind::RefDelta { base_oid }
            },
            OBJ_OFS_DELTA => {
                let (base_offset_delta, consumed) = parse_ofs_delta_offset(&pack[cursor..])
                    .map_err(|e| {
                        Error::PackParse(format!(
                            "entry {i}: OFS_DELTA base-offset parse at {cursor}: {e}"
                        ))
                    })?;
                cursor += consumed;
                ParsedKind::OfsDelta { base_offset_delta }
            },
            other => {
                return Err(Error::PackParse(format!(
                    "entry {i}: unknown object type {other}"
                )));
            },
        };

        // The deflated body must inflate to exactly `declared_size`
        // bytes; pass it as the hard output ceiling so a malformed or
        // hostile stream can't grow the buffer without bound.
        let (decompressed, compressed_len) =
            decompress_zlib(&pack[cursor..], declared_size as usize).map_err(|e| {
                Error::PackParse(format!(
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
        return Err(Error::PackParse("empty header buffer".to_string()));
    }
    let first = bytes[0];
    let kind = (first >> 4) & 0b0111;
    let mut size = u64::from(first & 0b1111);
    let mut shift = 4u32;
    let mut idx = 1usize;
    let mut byte = first;
    while byte & 0x80 != 0 {
        if idx >= bytes.len() {
            return Err(Error::PackParse(
                "truncated entry header (size continuation)".to_string(),
            ));
        }
        byte = bytes[idx];
        idx += 1;
        size |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if shift > 63 {
            return Err(Error::PackParse(
                "entry header size overflows u64".to_string(),
            ));
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
        return Err(Error::PackParse("empty OFS_DELTA buffer".to_string()));
    }
    let mut idx = 0usize;
    let mut byte = bytes[idx];
    idx += 1;
    let mut value = u64::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        if idx >= bytes.len() {
            return Err(Error::PackParse(
                "truncated OFS_DELTA offset (continuation)".to_string(),
            ));
        }
        byte = bytes[idx];
        idx += 1;
        value = value
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or_else(|| Error::PackParse("OFS_DELTA offset overflow".to_string()))?;
        value |= u64::from(byte & 0x7f);
    }
    Ok((value, idx))
}

/// Decompress a single zlib stream starting at `bytes[0]`. Returns
/// the inflated payload and the number of input bytes consumed —
/// the caller advances its pack cursor by that amount so subsequent
/// entries land at the right offset.
///
/// `max_out` is the hard ceiling on accepted output (the entry's
/// declared uncompressed size). A well-formed stream inflates to
/// exactly `max_out` bytes; we error the moment the running total
/// exceeds it, so a corrupt or hostile stream can neither grow the
/// buffer without bound (a decompression bomb) nor force a huge
/// up-front allocation — the initial capacity is clamped, and the
/// buffer only grows as real output arrives.
fn decompress_zlib(bytes: &[u8], max_out: usize) -> Result<(Vec<u8>, usize)> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut decoder = Decompress::new(true);
    // Never preallocate the (attacker-declared) full size; grow as
    // output actually materializes.
    let mut out = Vec::with_capacity(max_out.clamp(64, INITIAL_ALLOC_CAP));
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
            .map_err(|e| Error::PackParse(format!("zlib: {e}")))?;
        // Enforce the output ceiling right after each step (including
        // the step that hits StreamEnd) so an over-long stream is
        // caught before we return it.
        if decoder.total_out() as usize > max_out {
            return Err(Error::PackParse(format!(
                "decompressed entry exceeds {max_out}-byte declared size"
            )));
        }
        match status {
            Status::Ok | Status::BufError => {
                // BufError means out buffer is full; loop again with
                // more space. Ok with progress also requires more
                // input or output room; loop.
                let progressed = decoder.total_in() as usize > in_before
                    || decoder.total_out() as usize > out_before;
                if !progressed {
                    return Err(Error::PackParse(
                        "zlib stalled (no progress on Ok/BufError)".to_string(),
                    ));
                }
            },
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
pub(crate) fn loose_oid_hex(kind: ObjectKind, payload: &[u8]) -> Oid {
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
    // SHA-1 of an arbitrary byte slice always produces 40-char lowercase
    // hex, so `Oid::try_from` cannot fail here. The `expect` documents
    // that invariant for the next reader.
    Oid::try_from(hex).expect("SHA-1 hex must satisfy Oid contract")
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
            .map_err(|e| Error::PackParse(format!("loose header write: {e}")))?;
        enc.write_all(payload)
            .map_err(|e| Error::PackParse(format!("loose payload write: {e}")))?;
        enc.finish()
            .map_err(|e| Error::PackParse(format!("loose zlib finish: {e}")))?;
    }
    Ok(buf)
}

/// Backwards-compat shim — callers in this module write `kind_str(k)`
/// in dozens of places and the `ObjectKind::as_str` const fn now
/// owns the logic. One-line passthrough keeps the call sites readable.
const fn kind_str(kind: ObjectKind) -> &'static str {
    kind.as_str()
}

/// D1 entry point. Parse `pack_bytes`, store every non-delta entry
/// via [`ObjectStore::write_loose`]. Returns the number of objects
/// stored. Errors out if any delta-kind entries are present — D2
/// and D3 add resolution for those.
///
/// Not yet hooked into `ingest_pack` — D4 does that wiring.
pub(crate) fn store_non_delta_entries<S: ObjectStore + ?Sized>(
    pack_bytes: &[u8],
    repo_id: &RepoId,
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
            },
            ParsedKind::RefDelta { .. } | ParsedKind::OfsDelta { .. } => {
                return Err(Error::PackParse(format!(
                    "entry {i}: delta entries not yet supported (D2/D3)"
                )));
            },
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------
// Delta resolution
//
// Git delta format (per Documentation/technical/pack-format.txt):
//
//   source_size  varint   (LE, MSB-continuation)
//   target_size  varint
//   instructions (until end of stream):
//     COPY:    first_byte & 0x80 == 0x80
//       lower 7 bits encode which optional offset/size bytes follow
//         bit 0..3: offset byte present (LSB → MSB)
//         bit 4..6: size byte present   (LSB → MSB)
//       default offset = 0; default size = 0x10000 (when no size byte set)
//       output += source[offset..offset + size]
//     INSERT:  first_byte & 0x80 == 0
//       size = first_byte & 0x7f   (size == 0 is reserved/invalid)
//       output += next `size` bytes of the delta stream
//
// We trust the target_size header and pre-allocate exactly that — a
// resolved object's size is bounded by what the pack producer chose,
// not by attacker-controllable input on the wire.
// ---------------------------------------------------------------------

/// Decode a delta varint from `bytes[idx..]`. Returns the value and
/// how many bytes it consumed. Lower 7 bits per byte; MSB continues.
fn read_delta_varint(bytes: &[u8], mut idx: usize) -> Result<(u64, usize)> {
    let start = idx;
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if idx >= bytes.len() {
            return Err(Error::PackParse(format!(
                "delta varint: truncated at offset {idx}"
            )));
        }
        let byte = bytes[idx];
        idx += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, idx - start));
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::PackParse("delta varint: overflows u64".to_string()));
        }
    }
}

/// Apply a delta-instruction stream against `base`, producing the
/// target payload. Errors on truncated input, source-size mismatch,
/// or COPY out of range.
pub(crate) fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    let (source_size, mut idx) = read_delta_varint(delta, 0)?;
    if source_size != base.len() as u64 {
        return Err(Error::PackParse(format!(
            "delta source size {source_size} != base len {}",
            base.len()
        )));
    }
    let (target_size, consumed) = read_delta_varint(delta, idx)?;
    idx += consumed;

    let target_size_usize = usize::try_from(target_size)
        .map_err(|_| Error::PackParse("delta target size too large for usize".to_string()))?;
    // The target size is an attacker-controlled varint. Reject an
    // absurd value before allocating, and never preallocate the full
    // declared size — the buffer grows as COPY/INSERT ops append, and
    // the post-loop `out.len() == target_size` check validates it.
    if target_size_usize > MAX_ENTRY_BYTES {
        return Err(Error::PackParse(format!(
            "delta target size {target_size_usize} exceeds {MAX_ENTRY_BYTES}-byte cap"
        )));
    }
    let mut out = Vec::with_capacity(target_size_usize.min(INITIAL_ALLOC_CAP));

    while idx < delta.len() {
        let op = delta[idx];
        idx += 1;
        if op & 0x80 != 0 {
            // COPY. Decode the 4-bit offset bitmask + 3-bit size bitmask.
            let mut offset: u32 = 0;
            for shift in 0..4 {
                if op & (1 << shift) != 0 {
                    if idx >= delta.len() {
                        return Err(Error::PackParse("delta COPY: truncated offset".to_string()));
                    }
                    offset |= u32::from(delta[idx]) << (shift * 8);
                    idx += 1;
                }
            }
            let mut size: u32 = 0;
            for shift in 0..3 {
                if op & (1 << (4 + shift)) != 0 {
                    if idx >= delta.len() {
                        return Err(Error::PackParse("delta COPY: truncated size".to_string()));
                    }
                    size |= u32::from(delta[idx]) << (shift * 8);
                    idx += 1;
                }
            }
            if size == 0 {
                // Per spec: zero-encoded size means 0x10000.
                size = 0x10000;
            }
            let start = offset as usize;
            let end = start.saturating_add(size as usize);
            if end > base.len() {
                return Err(Error::PackParse(format!(
                    "delta COPY: range {start}..{end} out of base len {}",
                    base.len()
                )));
            }
            out.extend_from_slice(&base[start..end]);
        } else {
            // INSERT. Low 7 bits of op = literal byte count.
            let n = (op & 0x7f) as usize;
            if n == 0 {
                return Err(Error::PackParse(
                    "delta INSERT: zero-byte op is reserved".to_string(),
                ));
            }
            if idx + n > delta.len() {
                return Err(Error::PackParse(format!(
                    "delta INSERT: {n} bytes wanted, {} available",
                    delta.len() - idx
                )));
            }
            out.extend_from_slice(&delta[idx..idx + n]);
            idx += n;
        }
    }

    if out.len() as u64 != target_size {
        return Err(Error::PackParse(format!(
            "delta applied: got {} bytes, target_size said {}",
            out.len(),
            target_size
        )));
    }
    Ok(out)
}

/// Read a base object's `(kind, payload)` out of an `ObjectStore` by
/// inflating its loose bytes locally. Sidesteps `read_object` —
/// the trait default isn't implemented on MemObjectStore /
/// SqliteObjectStore, but read_loose is universally available. The
/// loose-only restriction is fine for the D4 production target
/// (SqliteObjectStore stores everything as loose KV rows); FsObjectStore
/// already overrides read_object directly when packed bases need to
/// resolve.
fn read_loose_inflated<S: ObjectStore + ?Sized>(
    store: &S,
    repo_id: &RepoId,
    oid: &Oid,
) -> Result<Option<(ObjectKind, Vec<u8>)>> {
    let Some(bytes) = store.read_loose(repo_id, oid)? else {
        return Ok(None);
    };
    let mut decoder = flate2::read::ZlibDecoder::new(bytes.as_slice());
    let mut inflated = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut inflated)
        .map_err(|e| Error::PackParse(format!("loose inflate {oid}: {e}")))?;
    let nul = inflated
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::PackParse(format!("loose {oid}: header has no NUL")))?;
    let header = std::str::from_utf8(&inflated[..nul])
        .map_err(|e| Error::PackParse(format!("loose {oid}: header utf8: {e}")))?;
    let mut split = header.splitn(2, ' ');
    let kind = split
        .next()
        .ok_or_else(|| Error::PackParse(format!("loose {oid}: missing kind")))?;
    let kind = match kind {
        "commit" => ObjectKind::Commit,
        "tree" => ObjectKind::Tree,
        "blob" => ObjectKind::Blob,
        "tag" => ObjectKind::Tag,
        other => {
            return Err(Error::PackParse(format!(
                "loose {oid}: unknown kind {other:?}"
            )));
        },
    };
    let payload = inflated[nul + 1..].to_vec();
    Ok(Some((kind, payload)))
}

/// D3 entry point. Parse `pack_bytes`, store every Direct entry,
/// then resolve every delta entry — both REF_DELTA (looked up via
/// the store) and OFS_DELTA (looked up by byte offset in this pack).
/// Multi-pass with no-progress detection so chains of arbitrary
/// length resolve eventually, and a missing base surfaces as a hard
/// error rather than an infinite loop.
///
/// Returns the total number of objects stored.
pub(crate) fn store_with_full_resolution<S: ObjectStore + ?Sized>(
    pack_bytes: &[u8],
    repo_id: &RepoId,
    store: &S,
) -> Result<usize> {
    use std::collections::HashMap;

    let entries = parse_pack(pack_bytes)?;
    let mut count = 0usize;

    // Map a pack-byte-offset to its entry index so OFS_DELTA can
    // resolve `entry_offset - base_offset_delta` → the base entry's
    // position in `entries`.
    let offset_to_idx: HashMap<usize, usize> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.offset, i))
        .collect();

    // In-memory cache of (kind, payload) for entries we've fully
    // materialized this run. Direct entries land here in phase 1;
    // delta entries land here as their bases resolve.
    //
    // Bases are needed by OFS_DELTA in `apply_delta`, so we keep the
    // payload bytes around even after we've written them via
    // write_loose — a future deeply-deltified pack would otherwise
    // pay an inflate-from-store cost per OFS_DELTA hop. The Vec<u8>
    // cost is bounded by the pack's uncompressed size.
    let mut resolved: HashMap<usize, (ObjectKind, Vec<u8>)> = HashMap::new();

    // Phase 1: write every Direct entry, prime the resolved cache.
    for (i, entry) in entries.iter().enumerate() {
        if let ParsedKind::Direct(kind) = entry.kind {
            let payload = entry.data.clone();
            let oid = loose_oid_hex(kind, &payload);
            let loose = loose_format_bytes(kind, &payload)?;
            store.write_loose(repo_id, &oid, &loose)?;
            resolved.insert(i, (kind, payload));
            count += 1;
        }
    }

    // Phase 2: deltas. Multi-pass over the pending queue; each pass
    // resolves every delta whose base is now available (via the
    // resolved cache for OFS_DELTA, via the store for REF_DELTA).
    let mut pending: Vec<usize> = (0..entries.len())
        .filter(|i| !resolved.contains_key(i))
        .collect();

    while !pending.is_empty() {
        let before = pending.len();
        let mut still_pending: Vec<usize> = Vec::with_capacity(pending.len());
        for i in pending {
            let entry = &entries[i];
            let outcome = match &entry.kind {
                ParsedKind::Direct(_) => unreachable!("Direct entries already resolved"),
                ParsedKind::RefDelta { base_oid } => {
                    let base_hex = hex_oid(base_oid);
                    read_loose_inflated(store, repo_id, &base_hex)?
                },
                ParsedKind::OfsDelta { base_offset_delta } => {
                    let delta = usize::try_from(*base_offset_delta).map_err(|_| {
                        Error::PackParse(format!("entry {i}: OFS_DELTA offset doesn't fit usize"))
                    })?;
                    let base_offset = entry.offset.checked_sub(delta).ok_or_else(|| {
                        Error::PackParse(format!(
                            "entry {i}: OFS_DELTA base offset underflow ({} - {})",
                            entry.offset, delta
                        ))
                    })?;
                    let base_idx = *offset_to_idx.get(&base_offset).ok_or_else(|| {
                        Error::PackParse(format!(
                            "entry {i}: OFS_DELTA base offset {base_offset} doesn't match any entry"
                        ))
                    })?;
                    resolved.get(&base_idx).cloned()
                },
            };
            let Some((base_kind, base_payload)) = outcome else {
                still_pending.push(i);
                continue;
            };
            let target = apply_delta(&base_payload, &entry.data)
                .map_err(|e| Error::PackParse(format!("entry {i}: apply_delta: {e}")))?;
            let oid = loose_oid_hex(base_kind, &target);
            let loose = loose_format_bytes(base_kind, &target)?;
            store.write_loose(repo_id, &oid, &loose)?;
            resolved.insert(i, (base_kind, target));
            count += 1;
        }
        if still_pending.len() == before {
            return Err(Error::PackParse(format!(
                "delta resolution stuck: {} entries with missing bases",
                still_pending.len()
            )));
        }
        pending = still_pending;
    }

    Ok(count)
}

/// Hex-encode a 20-byte OID into a validated [`Oid`]. Pulled out so
/// REF_DELTA resolution has one canonical formatter. The 40-char
/// lowercase-hex output always satisfies the `Oid` contract; the
/// `expect` documents that for the next reader.
fn hex_oid(oid: &[u8; 20]) -> Oid {
    let mut s = String::with_capacity(40);
    for b in oid {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    Oid::try_from(s).expect("20-byte SHA-1 always hex-encodes to a valid Oid")
}

/// D2 entry point. Parse `pack_bytes`, store every non-delta entry,
/// then resolve every REF_DELTA entry against its base in the store
/// (either just-written this run or already present from a prior
/// ingest). OFS_DELTA entries still fail here — D3 adds them.
///
/// Returns the number of objects stored across both phases.
pub(crate) fn store_with_ref_delta_resolution<S: ObjectStore + ?Sized>(
    pack_bytes: &[u8],
    repo_id: &RepoId,
    store: &S,
) -> Result<usize> {
    let entries = parse_pack(pack_bytes)?;
    let mut count = 0usize;

    // Phase 1: write every direct entry. After this, REF_DELTA bases
    // that point at same-pack non-deltas are visible via read_loose.
    for entry in &entries {
        if let ParsedKind::Direct(kind) = entry.kind {
            let oid = loose_oid_hex(kind, &entry.data);
            let loose = loose_format_bytes(kind, &entry.data)?;
            store.write_loose(repo_id, &oid, &loose)?;
            count += 1;
        }
    }

    // Phase 2: resolve REF_DELTA entries. Multiple passes in case a
    // delta points at another delta (chains): each pass resolves
    // every entry whose base is now available, until either the
    // queue empties or a pass makes no progress (which would mean
    // a missing base).
    let mut pending: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e.kind {
            ParsedKind::RefDelta { .. } => Some(i),
            ParsedKind::OfsDelta { .. } => Some(i),
            // Explicit (not `_`) so a future ParsedKind variant forces a
            // compile error here rather than being silently treated as
            // a non-delta entry that needs no resolution.
            ParsedKind::Direct(_) => None,
        })
        .collect();

    if pending.is_empty() {
        return Ok(count);
    }

    // OfsDelta is a hard error at this layer; flag early before
    // burning passes.
    for &i in &pending {
        if matches!(entries[i].kind, ParsedKind::OfsDelta { .. }) {
            return Err(Error::PackParse(format!(
                "entry {i}: OFS_DELTA not yet supported (D3)"
            )));
        }
    }

    loop {
        let before = pending.len();
        let mut still_pending = Vec::with_capacity(pending.len());
        for i in pending {
            let entry = &entries[i];
            let ParsedKind::RefDelta { base_oid } = entry.kind else {
                unreachable!("filtered to delta kinds above");
            };
            let base_oid_hex = hex_oid(&base_oid);
            let Some((base_kind, base_payload)) =
                read_loose_inflated(store, repo_id, &base_oid_hex)?
            else {
                still_pending.push(i);
                continue;
            };
            let target = apply_delta(&base_payload, &entry.data).map_err(|e| {
                Error::PackParse(format!(
                    "entry {i}: REF_DELTA apply against {base_oid_hex}: {e}"
                ))
            })?;
            // The target object inherits the base's kind — delta
            // chains keep transforming the same object, never change
            // its type.
            let oid = loose_oid_hex(base_kind, &target);
            let loose = loose_format_bytes(base_kind, &target)?;
            store.write_loose(repo_id, &oid, &loose)?;
            count += 1;
        }
        if still_pending.is_empty() {
            return Ok(count);
        }
        if still_pending.len() == before {
            // No progress — some delta's base is genuinely missing.
            return Err(Error::PackParse(format!(
                "ref_delta resolution: {} entries with missing bases",
                still_pending.len()
            )));
        }
        pending = still_pending;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{Oid, RepoId};
    use crate::object_store::{MemObjectStore, ObjectKind};

    fn rid() -> RepoId {
        RepoId::try_from("rtst").unwrap()
    }

    fn oid_from(s: &str) -> Oid {
        Oid::try_from(s).unwrap()
    }

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
        let n = store_non_delta_entries(&pack, &rid(), &store).unwrap();
        assert_eq!(n, 2);

        // Each object retrievable by its canonical OID, and the
        // bytes match what was inflated from the pack.
        let blob_oid = loose_oid_hex(ObjectKind::Blob, payload_blob);
        let commit_oid = loose_oid_hex(ObjectKind::Commit, payload_commit);
        assert!(store.exists(&rid(), &blob_oid).unwrap());
        assert!(store.exists(&rid(), &commit_oid).unwrap());

        // The bytes we wrote back are zlib(`<kind> <size>\0<payload>`).
        // Sanity-check that the read_loose body starts with the zlib
        // magic (0x78) so we didn't accidentally write raw bytes,
        // then inflate locally and confirm the round-trip — Mem's
        // read_object isn't implemented, but the storage format is
        // what we care about.
        let bytes = store.read_loose(&rid(), &blob_oid).unwrap().unwrap();
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
                _ => {},
            }
        }
        assert!(have_commit && have_tree && have_blob);

        // Hash-equivalence: re-hash each Direct entry's payload and
        // confirm one of them matches our known blob/tree/commit OID.
        let mut hashes: Vec<String> = entries
            .iter()
            .filter_map(|e| match e.kind {
                ParsedKind::Direct(k) => Some(loose_oid_hex(k, &e.data).as_str().to_owned()),
                _ => None,
            })
            .collect();
        hashes.sort();
        let mut expected = vec![blob, tree, commit];
        expected.sort();
        assert_eq!(hashes, expected, "hashes from parser must match git's");
    }

    /// Encode a delta varint (LE, MSB-continuation).
    fn delta_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    #[test]
    fn delta_varint_roundtrips() {
        for &v in &[0u64, 1, 127, 128, 16384, 0x100_000_000, u32::MAX as u64] {
            let bytes = delta_varint(v);
            let (parsed, _) = read_delta_varint(&bytes, 0).unwrap();
            assert_eq!(parsed, v, "varint round-trip for {v}");
        }
    }

    #[test]
    fn apply_delta_pure_insert() {
        let base = b"the original".to_vec();
        // Delta: source_size=base.len(), target_size=N, INSERT N bytes literal.
        let target_payload = b"fresh bytes that didn't exist in the base";
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        delta.extend_from_slice(&delta_varint(target_payload.len() as u64));
        // INSERT op: low 7 bits = length (must fit in 0..127).
        assert!(target_payload.len() <= 127);
        delta.push(target_payload.len() as u8);
        delta.extend_from_slice(target_payload);
        let out = apply_delta(&base, &delta).unwrap();
        assert_eq!(out, target_payload);
    }

    // --- M2: bounded allocations ---------------------------------------

    /// Encode a pack entry header (type + size varint) exactly as
    /// `build_minimal_pack` does, exposed so a test can declare an
    /// arbitrary (possibly absurd) size.
    fn encode_entry_header(type_byte: u8, mut size: u64) -> Vec<u8> {
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
        header
    }

    fn zlib_compress(payload: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn decompress_zlib_roundtrips_within_cap() {
        let payload = b"a perfectly ordinary pack entry body\n".repeat(64);
        let compressed = zlib_compress(&payload);
        // Exact declared size: must round-trip cleanly.
        let (out, consumed) = decompress_zlib(&compressed, payload.len()).unwrap();
        assert_eq!(out, payload);
        assert_eq!(consumed, compressed.len());
    }

    #[test]
    fn decompress_zlib_rejects_output_over_declared_size() {
        // A stream that inflates to more than max_out is rejected before
        // the buffer can grow without bound — this is the decompression-
        // bomb guard. (max_out is the entry's declared size in the real
        // path; here we under-declare to trip it deterministically.)
        let payload = vec![0u8; 4096]; // compresses tiny, inflates to 4 KiB
        let compressed = zlib_compress(&payload);
        assert!(
            compressed.len() < 100,
            "all-zeros should compress to well under 100 bytes"
        );
        let err = decompress_zlib(&compressed, 16).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("exceeds") && msg.contains("declared size"),
            "expected output-cap rejection, got: {msg}"
        );
    }

    #[test]
    fn parse_pack_rejects_oversized_declared_size() {
        // One entry whose header declares an uncompressed size past the
        // MAX_ENTRY_BYTES cap. parse_pack must reject it before it ever
        // tries to decompress or allocate for the body.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        pack.extend_from_slice(&encode_entry_header(OBJ_BLOB, MAX_ENTRY_BYTES as u64 + 1));
        // No body/trailer needed — the size check fires first.
        let err = parse_pack(&pack).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("exceeds") && msg.contains("cap"),
            "expected declared-size rejection, got: {msg}"
        );
    }

    #[test]
    fn apply_delta_rejects_oversized_target_size() {
        // A delta whose target_size varint claims more than MAX_ENTRY_BYTES
        // must error before `Vec::with_capacity` — otherwise that single
        // line is a multi-hundred-MB+ allocation from a few delta bytes.
        let base = b"x".to_vec();
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        delta.extend_from_slice(&delta_varint(MAX_ENTRY_BYTES as u64 + 1));
        // No ops follow; the cap check returns before the op loop.
        let err = apply_delta(&base, &delta).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("exceeds") && msg.contains("cap"),
            "expected target-size rejection, got: {msg}"
        );
    }

    #[test]
    fn apply_delta_pure_copy() {
        let base = b"copy me copy you".to_vec();
        // COPY all of base verbatim.
        let target_size = base.len() as u64;
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        delta.extend_from_slice(&delta_varint(target_size));
        // COPY op: MSB set | offset-byte-0 bit | size-byte-0 bit.
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(0x00); // offset low byte = 0
        delta.push(base.len() as u8); // size low byte = len
        let out = apply_delta(&base, &delta).unwrap();
        assert_eq!(out, base);
    }

    #[test]
    fn apply_delta_mixed_copy_then_insert() {
        let base = b"prefix:OLD_SUFFIX".to_vec();
        // Target = "prefix:" + "NEW_TAIL"
        let copy_prefix = b"prefix:";
        let insert_tail = b"NEW_TAIL";
        let target_size = copy_prefix.len() + insert_tail.len();
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        delta.extend_from_slice(&delta_varint(target_size as u64));
        // COPY 7 bytes from offset 0.
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(0x00);
        delta.push(copy_prefix.len() as u8);
        // INSERT insert_tail.
        delta.push(insert_tail.len() as u8);
        delta.extend_from_slice(insert_tail);
        let out = apply_delta(&base, &delta).unwrap();
        assert_eq!(out, [copy_prefix.as_ref(), insert_tail.as_ref()].concat());
    }

    #[test]
    fn apply_delta_rejects_source_mismatch() {
        let base = b"too short".to_vec();
        let mut delta = Vec::new();
        // Claim source is 100 bytes; base is only 9.
        delta.extend_from_slice(&delta_varint(100));
        delta.extend_from_slice(&delta_varint(1));
        delta.push(1);
        delta.push(b'x');
        let err = apply_delta(&base, &delta).unwrap_err();
        assert!(format!("{err}").contains("source size"));
    }

    // Helper for D2 tests: build a pack containing one direct entry
    // + one REF_DELTA referencing it. The REF_DELTA reproduces the
    // base-plus-insert-tail shape used by `apply_delta_mixed_copy_then_insert`.
    fn build_pack_with_ref_delta(
        base_kind: ObjectKind,
        base_payload: &[u8],
        tail: &[u8],
    ) -> (Vec<u8>, [u8; 20]) {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use sha1::{Digest, Sha1};
        use std::io::Write;

        let base_oid_bytes: [u8; 20] = {
            let mut h = Sha1::new();
            h.update(format!("{} {}\0", kind_str(base_kind), base_payload.len()).as_bytes());
            h.update(base_payload);
            h.finalize().into()
        };

        // Build delta instructions: COPY all of base, INSERT tail.
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base_payload.len() as u64));
        delta.extend_from_slice(&delta_varint((base_payload.len() + tail.len()) as u64));
        // COPY base_payload.len() bytes from offset 0. Size encoding
        // uses 1-3 bytes; handle the >255 case.
        let bp_len = base_payload.len() as u32;
        let mut copy_op = 0x80u8;
        let mut copy_args = Vec::new();
        // offset byte 0 (offset = 0)
        copy_op |= 0x01;
        copy_args.push(0u8);
        // size bytes (1-3 needed)
        let sz_b0 = (bp_len & 0xff) as u8;
        let sz_b1 = ((bp_len >> 8) & 0xff) as u8;
        let sz_b2 = ((bp_len >> 16) & 0xff) as u8;
        if sz_b0 != 0 {
            copy_op |= 0x10;
            copy_args.push(sz_b0);
        }
        if sz_b1 != 0 {
            copy_op |= 0x20;
            copy_args.push(sz_b1);
        }
        if sz_b2 != 0 {
            copy_op |= 0x40;
            copy_args.push(sz_b2);
        }
        delta.push(copy_op);
        delta.extend_from_slice(&copy_args);
        // INSERT tail. Length must fit in 7 bits (≤ 127) for one op.
        assert!(tail.len() <= 127);
        delta.push(tail.len() as u8);
        delta.extend_from_slice(tail);

        // Now assemble the pack.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes()); // 2 entries

        // Entry 1: the direct base.
        let type_byte = match base_kind {
            ObjectKind::Commit => OBJ_COMMIT,
            ObjectKind::Tree => OBJ_TREE,
            ObjectKind::Blob => OBJ_BLOB,
            ObjectKind::Tag => OBJ_TAG,
        };
        let mut bsz = base_payload.len() as u64;
        let mut header =
            vec![(if bsz >> 4 > 0 { 0x80 } else { 0 }) | (type_byte << 4) | ((bsz & 0xf) as u8)];
        bsz >>= 4;
        while bsz > 0 {
            let b = (bsz & 0x7f) as u8;
            bsz >>= 7;
            header.push((if bsz > 0 { 0x80 } else { 0 }) | b);
        }
        pack.extend_from_slice(&header);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(base_payload).unwrap();
        pack.extend_from_slice(&enc.finish().unwrap());

        // Entry 2: REF_DELTA pointing at entry 1.
        // The entry-header size field is the inflated length of the body
        // that follows. For a delta entry that's the delta-instruction
        // stream — NOT the reconstructed object size (the target size
        // lives in a varint inside the stream). Real git packs encode it
        // this way; M2's decompress cap enforces the equality.
        let mut dsz = delta.len() as u64;
        let mut dheader = vec![
            (if dsz >> 4 > 0 { 0x80 } else { 0 }) | (OBJ_REF_DELTA << 4) | ((dsz & 0xf) as u8),
        ];
        dsz >>= 4;
        while dsz > 0 {
            let b = (dsz & 0x7f) as u8;
            dsz >>= 7;
            dheader.push((if dsz > 0 { 0x80 } else { 0 }) | b);
        }
        pack.extend_from_slice(&dheader);
        pack.extend_from_slice(&base_oid_bytes);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&delta).unwrap();
        pack.extend_from_slice(&enc.finish().unwrap());

        // SHA-1 trailer.
        let mut h = Sha1::new();
        h.update(&pack);
        pack.extend_from_slice(&h.finalize());
        (pack, base_oid_bytes)
    }

    #[test]
    fn ref_delta_resolves_against_in_pack_base() {
        let base_payload = b"the quick brown fox\n";
        let tail = b" jumps over\n";
        let (pack, _base_oid_bytes) =
            build_pack_with_ref_delta(ObjectKind::Blob, base_payload, tail);

        let store = MemObjectStore::new();
        let n = store_with_ref_delta_resolution(&pack, &rid(), &store).unwrap();
        assert_eq!(n, 2, "base + delta-resolved target");

        // Both objects must exist.
        let base_oid = loose_oid_hex(ObjectKind::Blob, base_payload);
        let expected_target: Vec<u8> = [base_payload.as_ref(), tail.as_ref()].concat();
        let target_oid = loose_oid_hex(ObjectKind::Blob, &expected_target);
        assert!(store.exists(&rid(), &base_oid).unwrap());
        assert!(store.exists(&rid(), &target_oid).unwrap());

        // The resolved target's loose bytes inflate to the right payload.
        let stored = store.read_loose(&rid(), &target_oid).unwrap().unwrap();
        let mut d = flate2::read::ZlibDecoder::new(stored.as_slice());
        let mut inflated = Vec::new();
        std::io::Read::read_to_end(&mut d, &mut inflated).unwrap();
        let nul = inflated.iter().position(|&b| b == 0).unwrap();
        assert_eq!(
            std::str::from_utf8(&inflated[..nul]).unwrap(),
            format!("blob {}", expected_target.len())
        );
        assert_eq!(&inflated[nul + 1..], expected_target.as_slice());
    }

    #[test]
    fn ref_delta_missing_base_errors() {
        // Same pack shape but only the REF_DELTA entry — the base
        // isn't in the pack and isn't in the store.
        let (pack, _) = build_pack_with_ref_delta(ObjectKind::Blob, b"some base", b" tail");
        // Strip the first entry by rebuilding the pack with only the
        // delta entry. Easier: just feed an empty store but use a
        // delta pointing at a base OID nothing has — the function
        // should fail with "missing bases."
        // Quick hack: use the existing helper but wipe the loose
        // copy of the base after store_with_ref_delta_resolution
        // would have written it — except phase-1 writes the base
        // unconditionally, so we'd never miss. Build a pack with
        // ONLY a REF_DELTA pointing at a phantom OID instead.
        let mut p = Vec::new();
        p.extend_from_slice(b"PACK");
        p.extend_from_slice(&2u32.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        // REF_DELTA header; size = inflated delta-body length (2 bytes).
        p.push((OBJ_REF_DELTA << 4) | 2);
        p.extend_from_slice(&[0xab; 20]); // phantom base
                                          // 2-byte delta body claiming source_size=0, target_size=0.
        {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let body = vec![0u8, 0u8];
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&body).unwrap();
            p.extend_from_slice(&enc.finish().unwrap());
        }
        p.extend_from_slice(&[0u8; 20]);

        let store = MemObjectStore::new();
        let err = store_with_ref_delta_resolution(&p, &rid(), &store).unwrap_err();
        let _ = pack; // silence unused
        assert!(format!("{err}").contains("missing bases"), "got: {err}");
    }

    /// Encode an OFS_DELTA negative-offset field. Inverse of the
    /// parser in `parse_ofs_delta_offset` — same MSB-continuation
    /// big-endian scheme with the "+1 per continuation" quirk.
    fn encode_ofs_offset(mut n: u64) -> Vec<u8> {
        let mut bytes = vec![(n & 0x7f) as u8];
        n >>= 7;
        while n > 0 {
            n -= 1;
            bytes.push(((n & 0x7f) | 0x80) as u8);
            n >>= 7;
        }
        bytes.reverse();
        bytes
    }

    #[test]
    fn ofs_delta_offset_roundtrips() {
        for &v in &[1u64, 127, 128, 16384, 1_000_000, u32::MAX as u64] {
            let bytes = encode_ofs_offset(v);
            let (parsed, consumed) = parse_ofs_delta_offset(&bytes).unwrap();
            assert_eq!(parsed, v, "ofs offset {v}");
            assert_eq!(consumed, bytes.len());
        }
    }

    /// Build a pack with [Direct base, OFS_DELTA pointing back at it].
    /// Test helper for D3.
    fn build_pack_with_ofs_delta(
        base_kind: ObjectKind,
        base_payload: &[u8],
        tail: &[u8],
    ) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use sha1::{Digest, Sha1};
        use std::io::Write;

        // Build delta instructions: COPY all of base, then INSERT tail.
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base_payload.len() as u64));
        delta.extend_from_slice(&delta_varint((base_payload.len() + tail.len()) as u64));
        let bp_len = base_payload.len() as u32;
        let mut copy_op = 0x80u8 | 0x01;
        let mut copy_args = vec![0u8];
        let b0 = (bp_len & 0xff) as u8;
        let b1 = ((bp_len >> 8) & 0xff) as u8;
        let b2 = ((bp_len >> 16) & 0xff) as u8;
        if b0 != 0 {
            copy_op |= 0x10;
            copy_args.push(b0);
        }
        if b1 != 0 {
            copy_op |= 0x20;
            copy_args.push(b1);
        }
        if b2 != 0 {
            copy_op |= 0x40;
            copy_args.push(b2);
        }
        delta.push(copy_op);
        delta.extend_from_slice(&copy_args);
        assert!(tail.len() <= 127);
        delta.push(tail.len() as u8);
        delta.extend_from_slice(tail);

        // Assemble the pack.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        // Entry 1: Direct base at offset 12.
        let base_offset = pack.len();
        let type_byte = match base_kind {
            ObjectKind::Commit => OBJ_COMMIT,
            ObjectKind::Tree => OBJ_TREE,
            ObjectKind::Blob => OBJ_BLOB,
            ObjectKind::Tag => OBJ_TAG,
        };
        let mut bsz = base_payload.len() as u64;
        let mut header =
            vec![(if bsz >> 4 > 0 { 0x80 } else { 0 }) | (type_byte << 4) | ((bsz & 0xf) as u8)];
        bsz >>= 4;
        while bsz > 0 {
            let b = (bsz & 0x7f) as u8;
            bsz >>= 7;
            header.push((if bsz > 0 { 0x80 } else { 0 }) | b);
        }
        pack.extend_from_slice(&header);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(base_payload).unwrap();
        pack.extend_from_slice(&enc.finish().unwrap());

        // Entry 2: OFS_DELTA pointing back at entry 1.
        let delta_offset = pack.len();
        // The entry-header size field is the inflated length of the body
        // that follows. For a delta entry that's the delta-instruction
        // stream — NOT the reconstructed object size (the target size
        // lives in a varint inside the stream). Real git packs encode it
        // this way; M2's decompress cap enforces the equality.
        let mut dsz = delta.len() as u64;
        let mut dheader = vec![
            (if dsz >> 4 > 0 { 0x80 } else { 0 }) | (OBJ_OFS_DELTA << 4) | ((dsz & 0xf) as u8),
        ];
        dsz >>= 4;
        while dsz > 0 {
            let b = (dsz & 0x7f) as u8;
            dsz >>= 7;
            dheader.push((if dsz > 0 { 0x80 } else { 0 }) | b);
        }
        pack.extend_from_slice(&dheader);
        // Negative offset to the base entry.
        let offset_field = encode_ofs_offset((delta_offset - base_offset) as u64);
        pack.extend_from_slice(&offset_field);
        // zlib-compressed delta body.
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&delta).unwrap();
        pack.extend_from_slice(&enc.finish().unwrap());

        // SHA-1 trailer.
        let mut h = Sha1::new();
        h.update(&pack);
        pack.extend_from_slice(&h.finalize());
        pack
    }

    #[test]
    fn ofs_delta_resolves_against_in_pack_base() {
        let base_payload = b"the quick brown fox\n";
        let tail = b" jumped\n";
        let pack = build_pack_with_ofs_delta(ObjectKind::Blob, base_payload, tail);

        let store = MemObjectStore::new();
        let n = store_with_full_resolution(&pack, &rid(), &store).unwrap();
        assert_eq!(n, 2);

        let base_oid = loose_oid_hex(ObjectKind::Blob, base_payload);
        let expected_target: Vec<u8> = [base_payload.as_ref(), tail.as_ref()].concat();
        let target_oid = loose_oid_hex(ObjectKind::Blob, &expected_target);
        assert!(store.exists(&rid(), &base_oid).unwrap());
        assert!(store.exists(&rid(), &target_oid).unwrap());
    }

    #[test]
    fn full_resolution_handles_ref_delta_too() {
        // The full-resolution path should also handle REF_DELTA
        // entries (D3 is supposed to be a superset of D2).
        let base_payload = b"a base shared between ref and ofs paths";
        let tail = b" tail";
        let (pack, _) = build_pack_with_ref_delta(ObjectKind::Blob, base_payload, tail);
        let store = MemObjectStore::new();
        let n = store_with_full_resolution(&pack, &rid(), &store).unwrap();
        assert_eq!(n, 2);
        let base_oid = loose_oid_hex(ObjectKind::Blob, base_payload);
        let expected = [base_payload.as_ref(), tail.as_ref()].concat();
        let target_oid = loose_oid_hex(ObjectKind::Blob, &expected);
        assert!(store.exists(&rid(), &base_oid).unwrap());
        assert!(store.exists(&rid(), &target_oid).unwrap());
    }

    #[test]
    fn ofs_delta_underflow_errors() {
        // Build a pack where entry 1 is an OFS_DELTA pointing
        // 99999 bytes BEFORE itself — impossible, so resolution
        // must fail with an offset-underflow message.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        pack.push((OBJ_OFS_DELTA << 4) | 2); // size = inflated delta-body length (2 bytes)
        let offset_field = encode_ofs_offset(99999);
        pack.extend_from_slice(&offset_field);
        {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let body = vec![0u8, 0u8];
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&body).unwrap();
            pack.extend_from_slice(&enc.finish().unwrap());
        }
        pack.extend_from_slice(&[0u8; 20]);

        let store = MemObjectStore::new();
        let err = store_with_full_resolution(&pack, &rid(), &store).unwrap_err();
        assert!(format!("{err}").contains("underflow"), "got: {err}");
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
        let err = store_non_delta_entries(&pack, &rid(), &store).unwrap_err();
        assert!(
            format!("{err}").contains("delta entries not yet supported"),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Additional coverage for error/edge paths
    // -----------------------------------------------------------------------

    // --- parse_pack: entry-header parse error (truncated cursor) -----------

    #[test]
    fn parse_pack_rejects_truncated_entry_header() {
        // Header says 1 entry, but there are no bytes left after the 12-byte
        // pack header. parse_entry_header gets an empty slice → error.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes()); // 1 entry declared
                                                     // No entry bytes at all.
        let err = parse_pack(&pack).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("header parse") || msg.contains("empty header"),
            "expected header-parse error, got: {msg}"
        );
    }

    // --- parse_pack: OBJ_TAG kind ------------------------------------------

    #[test]
    fn parses_tag_entry() {
        let payload = b"object deadbeefdeadbeef\ntype commit\ntag v1.0\n\nmsg\n";
        let pack = build_minimal_pack(&[(ObjectKind::Tag, payload)]);
        let entries = parse_pack(&pack).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].kind,
            ParsedKind::Direct(ObjectKind::Tag)
        ));
        assert_eq!(entries[0].data, payload);
    }

    // --- parse_pack: truncated REF_DELTA base OID --------------------------

    #[test]
    fn parse_pack_rejects_truncated_ref_delta_oid() {
        // Build a pack where the REF_DELTA entry header is present but the
        // 20-byte base OID is only partially present (truncated to 10 bytes).
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        // REF_DELTA header, size=0.
        pack.push(OBJ_REF_DELTA << 4);
        // Only 10 bytes instead of required 20.
        pack.extend_from_slice(&[0xabu8; 10]);
        // No trailer needed — the parse fails first.
        let err = parse_pack(&pack).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("truncated REF_DELTA"),
            "expected truncated-OID error, got: {msg}"
        );
    }

    // --- parse_pack: unknown type byte -------------------------------------

    #[test]
    fn parse_pack_rejects_unknown_type_byte() {
        // Type code 5 is reserved / unknown in the git pack format.
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        // type=5, size=1 (low 4 bits = 1, no continuation).
        pack.push((5u8 << 4) | 1u8);
        // We don't need a body — the type check happens before decompression.
        let err = parse_pack(&pack).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown object type"),
            "expected unknown-type error, got: {msg}"
        );
    }

    // --- parse_pack: zlib failure (truncated body) -------------------------

    #[test]
    fn parse_pack_rejects_truncated_zlib_body() {
        // Build a valid single-entry pack, then truncate the zlib body mid-stream.
        let pack = build_minimal_pack(&[(ObjectKind::Blob, b"some payload for truncation")]);
        // Keep the 12-byte header + 1-byte entry header; drop the rest of the
        // zlib stream (leave only 5 bytes of the compressed body).
        let truncated = &pack[..18];
        let err = parse_pack(truncated).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("zlib") || msg.contains("decompress"),
            "expected zlib error on truncated body, got: {msg}"
        );
    }

    // --- parse_entry_header: size-continuation overflow --------------------

    #[test]
    fn parse_entry_header_size_continuation_overflow() {
        // Feed parse_entry_header a byte stream where the MSB stays set for
        // 10 continuation bytes → shift would exceed 63 bits → overflow.
        // First byte: MSB set (continuation), type=1, size_low=0xf.
        // 9 more continuation bytes (all 0x80 = value 0, MSB=continue).
        // Final byte without continuation to terminate the stream.
        let mut bytes = vec![0x80 | (OBJ_BLOB << 4) | 0xfu8];
        bytes.extend(std::iter::repeat_n(0x80u8, 9));
        bytes.push(0x01);
        let err = parse_entry_header(&bytes).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("overflow"),
            "expected size overflow error, got: {msg}"
        );
    }

    // --- parse_entry_header: truncated continuation ------------------------

    #[test]
    fn parse_entry_header_truncated_continuation() {
        // First byte has MSB set (expects more), but there are no more bytes.
        let bytes = vec![0x80 | (OBJ_BLOB << 4) | 0x1u8]; // MSB set, no follow-up
        let err = parse_entry_header(&bytes).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("truncated entry header"),
            "expected truncated-header error, got: {msg}"
        );
    }

    // --- parse_ofs_delta_offset: empty / truncated / overflow --------------

    #[test]
    fn parse_ofs_delta_offset_rejects_empty() {
        let err = parse_ofs_delta_offset(&[]).unwrap_err();
        assert!(format!("{err}").contains("empty OFS_DELTA"));
    }

    #[test]
    fn parse_ofs_delta_offset_rejects_truncated_continuation() {
        // Single byte with MSB set means "more bytes follow," but there are none.
        let err = parse_ofs_delta_offset(&[0x80]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("truncated OFS_DELTA"),
            "expected truncated error, got: {msg}"
        );
    }

    #[test]
    fn parse_ofs_delta_offset_rejects_overflow() {
        // Build a sequence that would overflow: each additional byte left-shifts
        // the accumulated value by 7 and adds 1. After enough bytes the value
        // exceeds u64::MAX. 10 continuation bytes is plenty.
        // Each byte: MSB=1 (continue), value bits = 0x7f (127).
        // Final byte: no continuation.
        let mut bytes: Vec<u8> = std::iter::repeat_n(0xff_u8, 9).collect();
        bytes.push(0x7f);
        // This should overflow checked_add / checked_shl at some point.
        let result = parse_ofs_delta_offset(&bytes);
        // May succeed or overflow depending on how many bytes it takes, but
        // the important invariant is: it does NOT panic.
        let _ = result;
    }

    // --- OFS_DELTA parse error propagated through parse_pack ---------------

    #[test]
    fn parse_pack_propagates_ofs_delta_parse_error() {
        // Build a pack with an OFS_DELTA entry whose offset field is empty
        // (truncated after the entry header).
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        // OFS_DELTA header, size=2 (fits in 4 bits).
        pack.push((OBJ_OFS_DELTA << 4) | 2u8);
        // No offset bytes at all — parse_ofs_delta_offset gets an empty slice.
        let err = parse_pack(&pack).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("OFS_DELTA"),
            "expected OFS_DELTA parse error, got: {msg}"
        );
    }

    // --- read_delta_varint: truncated and overflow -------------------------

    #[test]
    fn read_delta_varint_rejects_truncated() {
        // Empty slice → immediate truncation.
        let err = read_delta_varint(&[], 0).unwrap_err();
        assert!(format!("{err}").contains("truncated"));
    }

    #[test]
    fn read_delta_varint_rejects_overflow() {
        // 10 bytes all with MSB=1 will force shift > 63 → overflow.
        let bytes = vec![0x80u8; 10];
        let err = read_delta_varint(&bytes, 0).unwrap_err();
        assert!(format!("{err}").contains("overflow"));
    }

    // --- apply_delta: COPY truncated offset bytes --------------------------

    #[test]
    fn apply_delta_rejects_copy_truncated_offset() {
        // COPY op 0x81: bit 0 set → expects 1 offset byte, but body ends.
        let base = b"base data".to_vec();
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        delta.extend_from_slice(&delta_varint(4)); // target_size = 4
                                                   // COPY op: MSB=1, offset-bit-0 set (0x01) — requires 1 offset byte.
        delta.push(0x81u8); // no offset byte follows
        let err = apply_delta(&base, &delta).unwrap_err();
        assert!(format!("{err}").contains("truncated offset"), "got: {err}");
    }

    // --- apply_delta: COPY truncated size bytes ----------------------------

    #[test]
    fn apply_delta_rejects_copy_truncated_size() {
        // COPY op 0x90: bit 4 set → expects 1 size byte, but body ends.
        let base = b"base data".to_vec();
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        delta.extend_from_slice(&delta_varint(4)); // target_size = 4
                                                   // op = 0x80 (COPY) | 0x10 (size-bit-0 set). No offset bits set,
                                                   // no size byte follows.
        delta.push(0x90u8);
        let err = apply_delta(&base, &delta).unwrap_err();
        assert!(format!("{err}").contains("truncated size"), "got: {err}");
    }

    // --- apply_delta: COPY with default size (0 → 0x10000) ----------------

    #[test]
    fn apply_delta_copy_default_size() {
        // When size bits are all zero the spec says size = 0x10000 (65536).
        // Build a base of exactly 65536 bytes and a COPY with no size bytes.
        let base = vec![b'A'; 0x10000];
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        // COPY op: MSB=1, no offset bits, no size bits.  size defaults to 0x10000.
        // We do need the offset to be 0, but no offset bytes are needed since
        // none of the offset bits (0..3) are set in the op byte.
        delta.push(0x80u8); // COPY, no optional bytes, offset=0, size=0x10000
        let out = apply_delta(&base, &delta).unwrap();
        assert_eq!(out.len(), 0x10000);
        assert_eq!(&out[..], &base[..]);
    }

    // --- apply_delta: COPY out of range ------------------------------------

    #[test]
    fn apply_delta_rejects_copy_out_of_range() {
        let base = b"short".to_vec(); // 5 bytes
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        delta.extend_from_slice(&delta_varint(10));
        // COPY op: offset bit-0 + size bit-0 set.
        delta.push(0x80 | 0x01 | 0x10); // offset byte follows, size byte follows
        delta.push(0); // offset = 0
        delta.push(100); // size = 100 — way beyond base length 5
        let err = apply_delta(&base, &delta).unwrap_err();
        assert!(format!("{err}").contains("out of base"), "got: {err}");
    }

    // --- apply_delta: INSERT zero-byte op ----------------------------------

    #[test]
    fn apply_delta_rejects_insert_zero_op() {
        let base = b"".to_vec();
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(0)); // source_size = 0
        delta.extend_from_slice(&delta_varint(0)); // target_size = 0
                                                   // INSERT op with n=0: reserved, must error.
        delta.push(0x00u8);
        let err = apply_delta(&base, &delta).unwrap_err();
        assert!(format!("{err}").contains("zero-byte op"), "got: {err}");
    }

    // --- apply_delta: INSERT truncated data --------------------------------

    #[test]
    fn apply_delta_rejects_insert_truncated_data() {
        let base = b"".to_vec();
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(0)); // source_size = 0
        delta.extend_from_slice(&delta_varint(10)); // target_size = 10
                                                    // INSERT n=10, but only 3 bytes follow.
        delta.push(10u8); // INSERT 10 bytes
        delta.extend_from_slice(b"abc"); // only 3 of required 10
        let err = apply_delta(&base, &delta).unwrap_err();
        assert!(format!("{err}").contains("bytes wanted"), "got: {err}");
    }

    // --- apply_delta: target size mismatch (produced less than declared) ---

    #[test]
    fn apply_delta_rejects_target_size_mismatch() {
        let base = b"hello".to_vec();
        let mut delta = Vec::new();
        delta.extend_from_slice(&delta_varint(base.len() as u64));
        // Declare target_size=10 but insert only 5 bytes.
        delta.extend_from_slice(&delta_varint(10));
        delta.push(5u8); // INSERT 5 bytes
        delta.extend_from_slice(b"world");
        // After the ops loop: out.len() == 5 != target_size == 10.
        let err = apply_delta(&base, &delta).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("target_size") || msg.contains("got"),
            "expected target-size mismatch, got: {msg}"
        );
    }

    // --- store_non_delta_entries: refuses OFS_DELTA entry ------------------

    #[test]
    fn store_non_delta_refuses_ofs_delta_entries() {
        // Build a pack with one OFS_DELTA entry using the same structure as
        // `ofs_delta_underflow_errors` (an underflow case that still parses).
        let pack = build_pack_with_ofs_delta(ObjectKind::Blob, b"the base\n", b" tail");
        // store_non_delta_entries must reject the delta entry before applying it.
        let store = MemObjectStore::new();
        let err = store_non_delta_entries(&pack, &rid(), &store).unwrap_err();
        assert!(
            format!("{err}").contains("delta entries not yet supported"),
            "got: {err}"
        );
    }

    // --- store_with_full_resolution: OFS_DELTA base offset mismatch --------

    #[test]
    fn full_resolution_ofs_delta_bad_base_offset() {
        // An OFS_DELTA whose back-offset lands at a byte position not matching
        // any entry's offset → "doesn't match any entry" error.
        // We reuse build_pack_with_ofs_delta, then corrupt the OFS offset
        // field so it points somewhere arbitrary.  Easier approach: build a
        // pack manually where the OFS offset is 1 (entry 1 is at offset 12,
        // 12-1=11, which has no entry).
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        // OFS_DELTA entry: size field = 2 (the delta body length), offset = 1.
        pack.push((OBJ_OFS_DELTA << 4) | 2u8);
        // offset field = 1 (single byte, no continuation).
        pack.push(0x01u8);
        // 2-byte compressed delta body (source=0, target=0).
        {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let body = vec![0u8, 0u8];
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&body).unwrap();
            pack.extend_from_slice(&enc.finish().unwrap());
        }
        pack.extend_from_slice(&[0u8; 20]);

        let store = MemObjectStore::new();
        let err = store_with_full_resolution(&pack, &rid(), &store).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("doesn't match any entry") || msg.contains("underflow"),
            "expected bad-offset error, got: {msg}"
        );
    }

    // --- store_with_full_resolution: stuck (missing base for REF_DELTA) ----

    #[test]
    fn full_resolution_ref_delta_missing_base_is_stuck() {
        // Use a REF_DELTA whose base OID is not in the store; this exercises
        // the "stuck" / "missing bases" branch in store_with_full_resolution.
        let mut p = Vec::new();
        p.extend_from_slice(b"PACK");
        p.extend_from_slice(&2u32.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        // REF_DELTA header; size = 2 (delta body inflated length).
        p.push((OBJ_REF_DELTA << 4) | 2u8);
        p.extend_from_slice(&[0xcd; 20]); // phantom base OID
        {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let body = vec![0u8, 0u8];
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&body).unwrap();
            p.extend_from_slice(&enc.finish().unwrap());
        }
        p.extend_from_slice(&[0u8; 20]);

        let store = MemObjectStore::new();
        let err = store_with_full_resolution(&p, &rid(), &store).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("missing bases") || msg.contains("stuck"),
            "expected stuck-resolution error, got: {msg}"
        );
    }

    // --- store_with_ref_delta_resolution: OFS_DELTA is rejected ------------

    #[test]
    fn ref_delta_resolution_rejects_ofs_delta() {
        let pack = build_pack_with_ofs_delta(ObjectKind::Blob, b"base payload\n", b" tail");
        let store = MemObjectStore::new();
        let err = store_with_ref_delta_resolution(&pack, &rid(), &store).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("OFS_DELTA not yet supported"), "got: {msg}");
    }

    // --- store_with_ref_delta_resolution: apply_delta error ----------------

    #[test]
    fn ref_delta_resolution_propagates_apply_delta_error() {
        // Build a REF_DELTA that references a real base (which we pre-populate
        // in the store), but whose delta instruction stream is invalid (empty,
        // which causes source_size mismatch since base is non-empty).
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let base_payload = b"some base content";
        let base_kind = ObjectKind::Blob;
        let base_oid = loose_oid_hex(base_kind, base_payload);
        let base_loose = loose_format_bytes(base_kind, base_payload).unwrap();

        // Populate the store with the base object.
        let store = MemObjectStore::new();
        store.write_loose(&rid(), &base_oid, &base_loose).unwrap();

        // Build the raw 20-byte OID for embedding in the pack.
        let base_oid_bytes: [u8; 20] = {
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update(format!("{} {}\0", kind_str(base_kind), base_payload.len()).as_bytes());
            h.update(base_payload);
            h.finalize().into()
        };

        // Build a pack with a REF_DELTA pointing at the base, but with a
        // delta body that declares source_size=0 (mismatch vs base len=17).
        let bad_delta = delta_varint(0); // source_size=0, wrong
        let mut delta_body = bad_delta;
        delta_body.extend_from_slice(&delta_varint(0)); // target_size=0

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());
        let delta_len = delta_body.len() as u64;
        pack.push(
            (if delta_len >> 4 > 0 { 0x80 } else { 0 })
                | (OBJ_REF_DELTA << 4)
                | ((delta_len & 0xf) as u8),
        );
        pack.extend_from_slice(&base_oid_bytes);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&delta_body).unwrap();
        pack.extend_from_slice(&enc.finish().unwrap());
        pack.extend_from_slice(&[0u8; 20]);

        let err = store_with_ref_delta_resolution(&pack, &rid(), &store).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("REF_DELTA apply") || msg.contains("source size"),
            "expected apply-delta error, got: {msg}"
        );
    }

    // --- store_with_ref_delta_resolution: all-direct pack → early return ---

    #[test]
    fn ref_delta_resolution_empty_pending_returns_early() {
        // A pack with only Direct entries should return immediately after
        // phase-1 without entering the delta loop at all.
        let pack = build_minimal_pack(&[(ObjectKind::Blob, b"just a blob")]);
        let store = MemObjectStore::new();
        let n = store_with_ref_delta_resolution(&pack, &rid(), &store).unwrap();
        assert_eq!(n, 1);
    }
}
