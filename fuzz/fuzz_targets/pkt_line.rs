#![no_main]
//! Fuzz target: arbitrary bytes → `pkt_line::read`. The parser must
//! never panic and never read past `buf`. Network-facing on every
//! smart-HTTP POST, so the cost of a panic here is "one un-validated
//! client byte stream crashes the worker thread" — worth a fuzzer.
//!
//! Coverage notes:
//!   - We iterate `read` over the remaining slice until it returns an
//!     error or yields a flush/delim, mirroring how `PktIter` consumes
//!     a real wire body.
//!   - The 4-byte length-prefix parser is the most likely panic source
//!     (off-by-one in the slice-shrink). We feed it tiny inputs (≤ 3
//!     bytes) deliberately to keep that path hot.

use artifacts::pkt_line::{read, PktLine};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    // Bound the loop so an adversarial input with a billion 4-byte
    // pkt-lines doesn't burn the corpus budget on one slow case.
    for _ in 0..1024 {
        match read(rest) {
            Ok((PktLine::Flush | PktLine::Delim | PktLine::RespEnd, r))
            | Ok((PktLine::Data(_), r)) => {
                rest = r;
            }
            Err(_) => break,
        }
        if rest.is_empty() {
            break;
        }
    }
});
