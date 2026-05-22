//! Git smart-HTTP v2 wire-protocol pieces.
//!
//! Grouped here so the wire concern lives in one directory rather
//! than as two siblings of `smart_http` at the crate root.
//!
//! - [`proto`]: pure byte→typed-shape parsers for `command=ls-refs`,
//!   `command=fetch`, and `git-receive-pack` bodies. No state, no
//!   I/O; fully unit-tested.
//! - [`v2`]: response builders for the `ls-refs` and `fetch`
//!   commands, plus the `pack-objects` subprocess fallback.
//!
//! `smart_http` (the dispatch + receive-pack handler) and `pkt_line`
//! (the framing primitive) still live at the crate root for now;
//! moving them here is a follow-up.

// `proto` is `pub` so the libFuzzer harness in `fuzz/` can call into
// the byte-shape parsers. `v2` stays `pub(crate)` — its response
// builders touch `RefStore` and don't compose well as a fuzz surface.
pub mod proto;
pub(crate) mod v2;
