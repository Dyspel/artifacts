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
            .map_err(|e| Error::Other(anyhow::anyhow!("loose header write: {e}")))?;
        enc.write_all(payload)
            .map_err(|e| Error::Other(anyhow::anyhow!("loose payload write: {e}")))?;
        enc.finish()
            .map_err(|e| Error::Other(anyhow::anyhow!("loose zlib finish: {e}")))?;
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
            return Err(Error::Other(anyhow::anyhow!(
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
            return Err(Error::Other(anyhow::anyhow!("delta varint: overflows u64")));
        }
    }
}

/// Apply a delta-instruction stream against `base`, producing the
/// target payload. Errors on truncated input, source-size mismatch,
/// or COPY out of range.
pub(crate) fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    let (source_size, mut idx) = read_delta_varint(delta, 0)?;
    if source_size != base.len() as u64 {
        return Err(Error::Other(anyhow::anyhow!(
            "delta source size {source_size} != base len {}",
            base.len()
        )));
    }
    let (target_size, consumed) = read_delta_varint(delta, idx)?;
    idx += consumed;

    let target_size_usize = usize::try_from(target_size)
        .map_err(|_| Error::Other(anyhow::anyhow!("delta target size too large for usize")))?;
    let mut out = Vec::with_capacity(target_size_usize);

    while idx < delta.len() {
        let op = delta[idx];
        idx += 1;
        if op & 0x80 != 0 {
            // COPY. Decode the 4-bit offset bitmask + 3-bit size bitmask.
            let mut offset: u32 = 0;
            for shift in 0..4 {
                if op & (1 << shift) != 0 {
                    if idx >= delta.len() {
                        return Err(Error::Other(anyhow::anyhow!(
                            "delta COPY: truncated offset"
                        )));
                    }
                    offset |= u32::from(delta[idx]) << (shift * 8);
                    idx += 1;
                }
            }
            let mut size: u32 = 0;
            for shift in 0..3 {
                if op & (1 << (4 + shift)) != 0 {
                    if idx >= delta.len() {
                        return Err(Error::Other(anyhow::anyhow!("delta COPY: truncated size")));
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
                return Err(Error::Other(anyhow::anyhow!(
                    "delta COPY: range {start}..{end} out of base len {}",
                    base.len()
                )));
            }
            out.extend_from_slice(&base[start..end]);
        } else {
            // INSERT. Low 7 bits of op = literal byte count.
            let n = (op & 0x7f) as usize;
            if n == 0 {
                return Err(Error::Other(anyhow::anyhow!(
                    "delta INSERT: zero-byte op is reserved"
                )));
            }
            if idx + n > delta.len() {
                return Err(Error::Other(anyhow::anyhow!(
                    "delta INSERT: {n} bytes wanted, {} available",
                    delta.len() - idx
                )));
            }
            out.extend_from_slice(&delta[idx..idx + n]);
            idx += n;
        }
    }

    if out.len() as u64 != target_size {
        return Err(Error::Other(anyhow::anyhow!(
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
        .map_err(|e| Error::Other(anyhow::anyhow!("loose inflate {oid}: {e}")))?;
    let nul = inflated
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::Other(anyhow::anyhow!("loose {oid}: header has no NUL")))?;
    let header = std::str::from_utf8(&inflated[..nul])
        .map_err(|e| Error::Other(anyhow::anyhow!("loose {oid}: header utf8: {e}")))?;
    let mut split = header.splitn(2, ' ');
    let kind = split
        .next()
        .ok_or_else(|| Error::Other(anyhow::anyhow!("loose {oid}: missing kind")))?;
    let kind = match kind {
        "commit" => ObjectKind::Commit,
        "tree" => ObjectKind::Tree,
        "blob" => ObjectKind::Blob,
        "tag" => ObjectKind::Tag,
        other => {
            return Err(Error::Other(anyhow::anyhow!(
                "loose {oid}: unknown kind {other:?}"
            )));
        }
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
                }
                ParsedKind::OfsDelta { base_offset_delta } => {
                    let delta = usize::try_from(*base_offset_delta).map_err(|_| {
                        Error::Other(anyhow::anyhow!(
                            "entry {i}: OFS_DELTA offset doesn't fit usize"
                        ))
                    })?;
                    let base_offset = entry.offset.checked_sub(delta).ok_or_else(|| {
                        Error::Other(anyhow::anyhow!(
                            "entry {i}: OFS_DELTA base offset underflow ({} - {})",
                            entry.offset,
                            delta
                        ))
                    })?;
                    let base_idx = *offset_to_idx.get(&base_offset).ok_or_else(|| {
                        Error::Other(anyhow::anyhow!(
                            "entry {i}: OFS_DELTA base offset {base_offset} doesn't match any entry"
                        ))
                    })?;
                    resolved.get(&base_idx).cloned()
                }
            };
            let Some((base_kind, base_payload)) = outcome else {
                still_pending.push(i);
                continue;
            };
            let target = apply_delta(&base_payload, &entry.data)
                .map_err(|e| Error::Other(anyhow::anyhow!("entry {i}: apply_delta: {e}")))?;
            let oid = loose_oid_hex(base_kind, &target);
            let loose = loose_format_bytes(base_kind, &target)?;
            store.write_loose(repo_id, &oid, &loose)?;
            resolved.insert(i, (base_kind, target));
            count += 1;
        }
        if still_pending.len() == before {
            return Err(Error::Other(anyhow::anyhow!(
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
            _ => None,
        })
        .collect();

    if pending.is_empty() {
        return Ok(count);
    }

    // OfsDelta is a hard error at this layer; flag early before
    // burning passes.
    for &i in &pending {
        if matches!(entries[i].kind, ParsedKind::OfsDelta { .. }) {
            return Err(Error::Other(anyhow::anyhow!(
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
                Error::Other(anyhow::anyhow!(
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
            return Err(Error::Other(anyhow::anyhow!(
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
                _ => {}
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
        let target_size = (base_payload.len() + tail.len()) as u64;
        let mut dsz = target_size;
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
        // REF_DELTA header, target_size=0 (after applying).
        p.push(OBJ_REF_DELTA << 4);
        p.extend_from_slice(&[0xab; 20]); // phantom base
                                          // Empty delta body that claims source_size=0, target_size=0.
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
        let target_size = (base_payload.len() + tail.len()) as u64;
        let mut dsz = target_size;
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
        pack.push(OBJ_OFS_DELTA << 4); // size=0
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
}
