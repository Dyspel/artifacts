#![no_main]
//! Fuzz target: arbitrary bytes → the three v2 / smart-HTTP body
//! parsers in `git_wire::proto`. None of these may panic; all should
//! return either `Some(parsed)` or `None` and leave the caller's
//! recovery path intact.
//!
//! Why one target for all three: they share the underlying `PktIter`
//! scanner, and giving libfuzzer one corpus that walks every entry
//! point lets coverage growth on one path bleed into the others.

use artifacts::git_wire::proto::{
    parse_ls_refs_only, parse_receive_pack_body, parse_v2_fetch,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_ls_refs_only(data);
    let _ = parse_v2_fetch(data);
    let _ = parse_receive_pack_body(data);
});
