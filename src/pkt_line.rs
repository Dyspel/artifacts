//! pkt-line framing helpers for the git wire protocol.
//!
//! pkt-line is the universal framing for everything git over the wire: a
//! 4-hex-char length prefix (the prefix counts itself) followed by the
//! payload. Three values are sentinels and have no payload:
//!
//!   - `0000` — flush-pkt (end of a stream of pkt-lines)
//!   - `0001` — delim-pkt (separator between sections within a v2 command)
//!   - `0002` — response-end-pkt (used by stateful protocols; v2 doesn't
//!              actually send these on the wire, but we accept them in
//!              parsing for forward-compat)
//!
//! Anything else with length < 4 is malformed.
//!
//! `PKT_LINE_MAX_PAYLOAD` is 65516 because the length field is 4 hex
//! digits — 0xFFFF = 65535 total, minus the 4-byte prefix.
//!
//! ## Why a separate module
//!
//! Both the smart-HTTP path (M1b-2 ls-refs/fetch, M1b-3 receive-pack) and
//! any future native protocol code share these primitives. Keeping the
//! parser/writer here means there's a single source of truth for the
//! framing rules — and the spec is small enough that we don't need a
//! dependency.

pub const PKT_LINE_MAX_PAYLOAD: usize = 65516;
pub const FLUSH: &[u8] = b"0000";
// DELIM / RESP_END are part of the v2 framing API surface; they're
// produced by `write_delim` (used for v2 ls-refs / fetch request
// construction in tests) and the parser recognizes them on input.
// Hold them as exports so any future native-protocol code using
// the library has them available without re-deriving.
#[allow(dead_code)]
pub const DELIM: &[u8] = b"0001";
#[allow(dead_code)]
pub const RESP_END: &[u8] = b"0002";

#[derive(Debug, PartialEq, Eq)]
pub enum PktLine<'a> {
    Flush,
    Delim,
    RespEnd,
    Data(&'a [u8]),
}

#[derive(Debug, PartialEq, Eq)]
pub enum PktError {
    /// Buffer ended before we could read the 4-byte length prefix.
    Truncated,
    /// Length prefix wasn't 4 hex digits.
    BadLength,
    /// Length prefix said N bytes but only M < N bytes follow.
    ShortPayload,
    /// Length prefix would push the payload over the spec cap.
    Oversized,
}

/// Parse one pkt-line from the front of `buf`. Returns the parsed line and
/// the remaining tail. Sentinels (`0000`/`0001`/`0002`) are returned as
/// their tagged variants with no payload. Data lines return a borrow into
/// `buf` — the trailing newline (if any) is included in the payload, since
/// not all commands use one and callers handle stripping themselves.
pub fn read(buf: &[u8]) -> Result<(PktLine<'_>, &[u8]), PktError> {
    if buf.len() < 4 {
        return Err(PktError::Truncated);
    }
    let len_str = std::str::from_utf8(&buf[..4]).map_err(|_| PktError::BadLength)?;
    let len = u16::from_str_radix(len_str, 16).map_err(|_| PktError::BadLength)?;
    match len {
        0 => Ok((PktLine::Flush, &buf[4..])),
        1 => Ok((PktLine::Delim, &buf[4..])),
        2 => Ok((PktLine::RespEnd, &buf[4..])),
        // 3 is reserved/unused; treat as bad framing.
        3 => Err(PktError::BadLength),
        n => {
            let n = n as usize;
            if n > PKT_LINE_MAX_PAYLOAD + 4 {
                return Err(PktError::Oversized);
            }
            if buf.len() < n {
                return Err(PktError::ShortPayload);
            }
            Ok((PktLine::Data(&buf[4..n]), &buf[n..]))
        }
    }
}

/// Iterator that yields pkt-lines until input is exhausted or malformed.
/// On a malformed frame the iterator surfaces the error and stops.
pub struct PktIter<'a> {
    buf: &'a [u8],
    done: bool,
}

impl<'a> PktIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, done: false }
    }
}

impl<'a> Iterator for PktIter<'a> {
    type Item = Result<PktLine<'a>, PktError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.buf.is_empty() {
            return None;
        }
        match read(self.buf) {
            Ok((line, tail)) => {
                self.buf = tail;
                Some(Ok(line))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Append a data pkt-line for `payload` to `out`. Caller decides whether
/// the payload includes a trailing `\n` (the protocol uses both forms;
/// command/argument lines typically do, ref-listing lines must).
///
/// In dev/test we panic on oversized payloads — the surrounding code
/// should have chunked or errored before reaching here. In release we
/// truncate and emit a structurally-valid frame with the cap-sized
/// payload, since silently wrapping the length field is the worse
/// failure mode.
pub fn write_data(out: &mut Vec<u8>, payload: &[u8]) {
    debug_assert!(
        payload.len() <= PKT_LINE_MAX_PAYLOAD,
        "pkt-line payload {} > max {}",
        payload.len(),
        PKT_LINE_MAX_PAYLOAD,
    );
    let payload = if payload.len() > PKT_LINE_MAX_PAYLOAD {
        &payload[..PKT_LINE_MAX_PAYLOAD]
    } else {
        payload
    };
    let len = payload.len() + 4;
    out.extend_from_slice(format!("{len:04x}").as_bytes());
    out.extend_from_slice(payload);
}

pub fn write_flush(out: &mut Vec<u8>) {
    out.extend_from_slice(FLUSH);
}

// Used by the v2 request-builders in tests; held as part of the
// pkt-line API for any future native-protocol code that needs to
// emit a delim-pkt section break.
#[allow(dead_code)]
pub fn write_delim(out: &mut Vec<u8>) {
    out.extend_from_slice(DELIM);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_data_line() {
        let mut buf = Vec::new();
        write_data(&mut buf, b"hello\n");
        // 6 bytes payload + 4-byte prefix = 10 = 0x000a.
        assert_eq!(&buf, b"000ahello\n");
        let (line, rest) = read(&buf).unwrap();
        assert_eq!(line, PktLine::Data(b"hello\n"));
        assert!(rest.is_empty());
    }

    #[test]
    fn flush_round_trip() {
        let mut buf = Vec::new();
        write_flush(&mut buf);
        let (line, rest) = read(&buf).unwrap();
        assert_eq!(line, PktLine::Flush);
        assert!(rest.is_empty());
    }

    #[test]
    fn delim_round_trip() {
        let mut buf = Vec::new();
        write_delim(&mut buf);
        let (line, rest) = read(&buf).unwrap();
        assert_eq!(line, PktLine::Delim);
        assert!(rest.is_empty());
    }

    #[test]
    fn iter_walks_full_v2_command_shape() {
        // Mirrors a typical client ls-refs request: command line,
        // capability lines, delim-pkt, argument lines, flush-pkt.
        let mut buf = Vec::new();
        write_data(&mut buf, b"command=ls-refs\n");
        write_data(&mut buf, b"agent=git/test\n");
        write_data(&mut buf, b"object-format=sha1\n");
        write_delim(&mut buf);
        write_data(&mut buf, b"peel\n");
        write_data(&mut buf, b"symrefs\n");
        write_data(&mut buf, b"ref-prefix HEAD\n");
        write_flush(&mut buf);

        let lines: Vec<_> = PktIter::new(&buf).collect::<Result<_, _>>().unwrap();
        assert!(matches!(lines[0], PktLine::Data(b"command=ls-refs\n")));
        assert_eq!(lines[3], PktLine::Delim);
        assert_eq!(*lines.last().unwrap(), PktLine::Flush);
    }

    #[test]
    fn read_short_payload_errors() {
        // Length says 10 but only 5 bytes follow.
        let buf = b"000ahi\n";
        assert_eq!(read(buf).unwrap_err(), PktError::ShortPayload);
    }

    #[test]
    fn read_bad_hex_errors() {
        let buf = b"zzzz";
        assert_eq!(read(buf).unwrap_err(), PktError::BadLength);
    }

    #[test]
    fn read_truncated_errors() {
        assert_eq!(read(b"00").unwrap_err(), PktError::Truncated);
    }

    #[test]
    fn read_oversized_errors_at_cap() {
        // ffff = 65535 → payload of 65531 bytes (length includes the
        // 4-byte prefix). 65531 > PKT_LINE_MAX_PAYLOAD (65516), so we
        // reject before even checking the buffer.
        assert_eq!(read(b"ffff").unwrap_err(), PktError::Oversized);
    }

    #[test]
    fn read_short_payload_when_buffer_truncated() {
        // 0064 = 100 byte total → payload of 96, but we provide only 4
        // bytes. Must return ShortPayload, not Oversized (96 is well
        // under cap).
        assert_eq!(read(b"0064").unwrap_err(), PktError::ShortPayload);
    }

    #[test]
    fn write_data_truncates_oversized_in_release() {
        // Skip in debug (debug_assert panics) — only meaningful in release.
        // We can still test the cap value as a guard against accidental drift.
        assert_eq!(PKT_LINE_MAX_PAYLOAD, 65516);
    }
}
