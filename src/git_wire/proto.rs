//! Wire-protocol parsers for the git smart-HTTP v2 commands we handle
//! natively (`ls-refs`, `fetch`) and the receive-pack push body.
//!
//! Pure byte-slice → typed-shape functions, no state and no I/O. Lives
//! in its own module so the surrounding handler code in `smart_http`
//! can stay focused on dispatch + response building, and so the
//! parsers can be exhaustively unit-tested without spinning up an
//! axum router or a `FsRefStore`.
//!
//! Conservative-by-design: every parser returns `None` on anything
//! unfamiliar (unknown capability, unknown argument, malformed
//! pkt-line). That lets `smart_http` fall through to the subprocess
//! path on inputs we haven't audited, instead of risking a
//! subtly-wrong response.

use crate::pkt_line::{PktIter, PktLine};

#[derive(Debug, PartialEq, Eq)]
pub struct LsRefsArgs {
    pub peel: bool,
    pub symrefs: bool,
    pub prefixes: Vec<String>,
}

/// Parsed shape of a v2 fetch request body. Mirrors the subset of args
/// `git` actually emits during clone + non-shallow fetch. Anything
/// unfamiliar trips `simple = false` and the caller falls back to
/// upload-pack rather than guess the right protocol response.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct V2FetchRequest {
    pub wants: Vec<String>,
    pub haves: Vec<String>,
    pub done: bool,
    /// Set when the client sent any arg we don't fully implement yet
    /// (shallow, deepen, filter, sideband-all, ...). Used to gate the
    /// native dispatch — we'd rather defer to `git upload-pack` than
    /// produce a subtly-wrong response.
    pub has_unsupported: bool,
    /// True if we saw `no-progress`; the caller suppresses sideband
    /// band-2 in that case. Currently the native path never emits
    /// progress, so this is informational.
    pub no_progress: bool,
}

impl V2FetchRequest {
    pub fn is_simple(&self) -> bool {
        // Native path only handles fetches the client has explicitly
        // closed with `done` (single-round negotiation, no acks needed)
        // and without any feature flag we haven't audited.
        self.done && !self.has_unsupported
    }
}

/// One ref-update command from a `git push`. Format on the wire:
///   `<old-oid> <new-oid> <refname>[\0<capabilities>]\n`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub name: String,
}

impl RefUpdate {
    /// `0000…000` is the canonical "ref doesn't exist" marker. A push
    /// where `old` is zero is a create; where `new` is zero is a delete.
    pub const ZERO: &'static str = "0000000000000000000000000000000000000000";

    pub fn is_create(&self) -> bool {
        self.old == Self::ZERO
    }
    pub fn is_delete(&self) -> bool {
        self.new == Self::ZERO
    }
}

/// Parsed shape of a smart-HTTP push body.
#[derive(Debug)]
pub struct ReceivePackRequest {
    pub updates: Vec<RefUpdate>,
    /// Capabilities advertised by the client on the first ref-update
    /// line (after a `\0`). We only need a few for the dispatch
    /// decision: whether to wrap the report in sideband-1, and whether
    /// the client expects a report at all.
    pub has_report_status: bool,
    pub has_sideband_64k: bool,
    /// True when the request shape includes anything we don't handle
    /// natively yet — e.g. an `atomic` push (all-or-nothing semantics
    /// across multiple refs requires its own implementation), or a
    /// `push-options` block we'd need to carry through to a hook.
    pub has_unsupported: bool,
    /// The pack bytes (everything after the ref-updates flush). May be
    /// empty: a push that only deletes refs sends no pack.
    pub pack: Vec<u8>,
}

impl ReceivePackRequest {
    pub fn is_simple(&self) -> bool {
        // A native receive-pack has to negotiate the report response
        // back to the client. Without `report-status` the client
        // doesn't expect any report. We only handle the "with-report"
        // case for now — without-report would mean returning empty,
        // which is a different code path and rarely seen.
        if !self.has_report_status {
            return false;
        }
        if self.has_unsupported {
            return false;
        }
        if self.updates.is_empty() {
            return false;
        }
        true
    }
}

/// Returns `Some(args)` iff `body` is a v2 ls-refs request and nothing
/// else. Conservative: any unfamiliar capability or argument returns
/// `None` so the subprocess path picks it up. That way new protocol
/// extensions don't silently get the wrong response.
pub fn parse_ls_refs_only(body: &[u8]) -> Option<LsRefsArgs> {
    let mut iter = PktIter::new(body);

    // 1. command line.
    let first = match iter.next()? {
        Ok(PktLine::Data(d)) => d,
        _ => return None,
    };
    let first = std::str::from_utf8(first).ok()?.trim_end_matches('\n');
    if first != "command=ls-refs" {
        return None;
    }

    // 2. capability lines until delim. Accept the small fixed set of
    //    capabilities `git` actually sends; reject anything unknown.
    let mut saw_delim = false;
    for item in iter.by_ref() {
        match item.ok()? {
            PktLine::Delim => {
                saw_delim = true;
                break;
            },
            PktLine::Flush => {
                // No args section at all — still a valid ls-refs.
                return Some(LsRefsArgs {
                    peel: false,
                    symrefs: false,
                    prefixes: Vec::new(),
                });
            },
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                if !is_known_capability(s) {
                    return None;
                }
            },
            PktLine::RespEnd => return None,
        }
    }
    if !saw_delim {
        return None;
    }

    // 3. argument lines until flush.
    let mut peel = false;
    let mut symrefs = false;
    let mut prefixes: Vec<String> = Vec::new();
    for item in iter.by_ref() {
        match item.ok()? {
            PktLine::Flush => {
                return Some(LsRefsArgs {
                    peel,
                    symrefs,
                    prefixes,
                });
            },
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                if s == "peel" {
                    peel = true;
                } else if s == "symrefs" {
                    symrefs = true;
                } else if let Some(p) = s.strip_prefix("ref-prefix ") {
                    prefixes.push(p.to_string());
                } else if s == "unborn" {
                    // Tolerate: `unborn` is a flag that says "include
                    // unborn HEAD in the response if applicable", which
                    // we already do unconditionally when symrefs is set.
                } else {
                    // Unknown argument — fall through to subprocess.
                    return None;
                }
            },
            PktLine::Delim | PktLine::RespEnd => return None,
        }
    }
    None
}

/// Capability lines we'll silently accept on a v2 command. Anything
/// else we don't understand → caller falls back to upload-pack so we
/// can't serve a wrong response for a feature we haven't audited.
fn is_known_capability(line: &str) -> bool {
    line.starts_with("agent=")
        || line.starts_with("object-format=")
        || line.starts_with("session-id=")
}

/// Returns `Some(req)` iff `body` is a v2 fetch command. Conservative:
/// accepts the well-known capabilities and arguments and tags any
/// unfamiliar one via `has_unsupported`. Multi-command bodies, malformed
/// pkt-lines, or non-fetch commands return `None`.
pub fn parse_v2_fetch(body: &[u8]) -> Option<V2FetchRequest> {
    let mut iter = PktIter::new(body);

    let first = match iter.next()? {
        Ok(PktLine::Data(d)) => d,
        _ => return None,
    };
    let first = std::str::from_utf8(first).ok()?.trim_end_matches('\n');
    if first != "command=fetch" {
        return None;
    }

    let mut saw_delim = false;
    for item in iter.by_ref() {
        match item.ok()? {
            PktLine::Delim => {
                saw_delim = true;
                break;
            },
            PktLine::Flush => {
                // No args at all is malformed for fetch — reject.
                return None;
            },
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                if !is_known_capability(s) {
                    return None;
                }
            },
            PktLine::RespEnd => return None,
        }
    }
    if !saw_delim {
        return None;
    }

    let mut req = V2FetchRequest::default();
    for item in iter.by_ref() {
        match item.ok()? {
            PktLine::Flush => return Some(req),
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                if let Some(oid) = s.strip_prefix("want ") {
                    if !is_hex40(oid) {
                        return None;
                    }
                    req.wants.push(oid.to_string());
                } else if let Some(oid) = s.strip_prefix("have ") {
                    if !is_hex40(oid) {
                        return None;
                    }
                    req.haves.push(oid.to_string());
                } else if s == "done" {
                    req.done = true;
                } else if s == "no-progress" {
                    req.no_progress = true;
                } else if matches!(s, "thin-pack" | "ofs-delta" | "include-tag") {
                    // Standard caps `git pack-objects --thin
                    // --delta-base-offset` already produces; nothing
                    // for us to do beyond knowing the client wants
                    // them.
                } else {
                    // Anything else (shallow, deepen, deepen-since,
                    // filter, sideband-all, packfile-uris, ...) needs
                    // protocol work we haven't done. Mark as
                    // unsupported and let the simple-check fall
                    // through to upload-pack.
                    req.has_unsupported = true;
                }
            },
            PktLine::Delim | PktLine::RespEnd => return None,
        }
    }
    None
}

pub const fn is_hex40(s: &str) -> bool {
    crate::object_store::is_hex40_bytes(s.as_bytes())
}

/// Parse the receive-pack body up to and including the flush-pkt that
/// terminates the ref-updates section. Everything past that flush is
/// treated as the pack payload (or no pack, if the push is delete-only).
///
/// Returns `None` for malformed or unfamiliar bodies — caller falls
/// through to `git receive-pack` which has every quirk covered.
pub fn parse_receive_pack_body(body: &[u8]) -> Option<ReceivePackRequest> {
    let mut req = ReceivePackRequest {
        updates: Vec::new(),
        has_report_status: false,
        has_sideband_64k: false,
        has_unsupported: false,
        pack: Vec::new(),
    };

    let mut buf = body;
    let mut first = true;
    loop {
        let (line, rest) = match crate::pkt_line::read(buf) {
            Ok((l, r)) => (l, r),
            Err(_) => return None,
        };
        match line {
            PktLine::Flush => {
                buf = rest;
                break;
            },
            PktLine::Data(d) => {
                let s = std::str::from_utf8(d).ok()?.trim_end_matches('\n');
                // First line carries capabilities after a NUL byte.
                let (head, caps) = match s.split_once('\0') {
                    Some((h, c)) => (h, Some(c)),
                    None => (s, None),
                };
                let parts: Vec<&str> = head.splitn(3, ' ').collect();
                if parts.len() != 3 {
                    return None;
                }
                let old = parts[0];
                let new = parts[1];
                let name = parts[2];
                if !is_hex40(old) || !is_hex40(new) {
                    return None;
                }
                req.updates.push(RefUpdate {
                    old: old.to_string(),
                    new: new.to_string(),
                    name: name.to_string(),
                });
                if first {
                    if let Some(caps) = caps {
                        for c in caps.split(' ') {
                            match c {
                                "" => {},
                                "report-status" | "report-status-v2" => {
                                    // We emit the v1 report shape
                                    // (`ok <ref>` / `ng <ref> <reason>`).
                                    // v2 adds optional `option ...` lines
                                    // which we never produce, so the v1
                                    // shape is also a valid v2 report.
                                    req.has_report_status = true;
                                },
                                "side-band-64k" => req.has_sideband_64k = true,
                                "ofs-delta" | "delete-refs" | "no-thin" | "quiet" => {},
                                "atomic" | "push-options" | "push-cert" => {
                                    req.has_unsupported = true;
                                },
                                other
                                    if other.starts_with("agent=")
                                        || other.starts_with("session-id=")
                                        || other.starts_with("object-format=") =>
                                {
                                    // Informational, ignore.
                                },
                                _ => {
                                    // Unknown caps trip the safety
                                    // net: better to fall through to
                                    // receive-pack than serve a
                                    // wrong response.
                                    req.has_unsupported = true;
                                },
                            }
                        }
                    } else {
                        // First update without caps — the client never
                        // advertised report-status, so we can't tell
                        // it the result. Defer to subprocess.
                        req.has_unsupported = true;
                    }
                    first = false;
                }
                buf = rest;
            },
            PktLine::Delim | PktLine::RespEnd => return None,
        }
    }

    req.pack = buf.to_vec();
    Some(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ls_refs_body(capabilities: &[&str], arguments: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        crate::pkt_line::write_data(&mut buf, b"command=ls-refs\n");
        for cap in capabilities {
            let mut line = (*cap).to_string();
            line.push('\n');
            crate::pkt_line::write_data(&mut buf, line.as_bytes());
        }
        crate::pkt_line::write_delim(&mut buf);
        for arg in arguments {
            let mut line = (*arg).to_string();
            line.push('\n');
            crate::pkt_line::write_data(&mut buf, line.as_bytes());
        }
        crate::pkt_line::write_flush(&mut buf);
        buf
    }

    #[test]
    fn parse_ls_refs_only_accepts_typical_clone_request() {
        // Default `git clone` with v2 sends:
        //   command=ls-refs / agent=... / object-format=sha1 / 0001
        //   peel / symrefs / ref-prefix HEAD / ref-prefix refs/heads/
        //   ref-prefix refs/tags/ / 0000
        let body = build_ls_refs_body(
            &["agent=git/2.43.0", "object-format=sha1"],
            &[
                "peel",
                "symrefs",
                "ref-prefix HEAD",
                "ref-prefix refs/heads/",
                "ref-prefix refs/tags/",
            ],
        );
        let args = parse_ls_refs_only(&body).expect("should parse");
        assert!(args.peel);
        assert!(args.symrefs);
        assert_eq!(
            args.prefixes,
            vec![
                "HEAD".to_string(),
                "refs/heads/".to_string(),
                "refs/tags/".to_string(),
            ]
        );
    }

    #[test]
    fn parse_ls_refs_only_rejects_fetch_command() {
        // A `command=fetch` body must not be parsed as ls-refs — would
        // cause a wrong response. Returning None falls through to
        // upload-pack subprocess which handles fetch correctly.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=fetch\n");
        crate::pkt_line::write_delim(&mut body);
        crate::pkt_line::write_data(&mut body, b"thin-pack\n");
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_only_rejects_unknown_argument() {
        // Unfamiliar args force fallthrough to subprocess so we never
        // serve a stale-spec response for a feature we haven't audited.
        let body = build_ls_refs_body(&["agent=git/2.43.0"], &["peel", "future-flag-we-dont-know"]);
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_only_accepts_zero_args() {
        // A bare `command=ls-refs\n0000` (no delim, no args) is a valid
        // v2 request meaning "list all refs, no extras". We accept it.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=ls-refs\n");
        crate::pkt_line::write_flush(&mut body);
        let args = parse_ls_refs_only(&body).expect("should parse");
        assert!(!args.peel);
        assert!(!args.symrefs);
        assert!(args.prefixes.is_empty());
    }

    fn build_receive_pack_body(updates: &[(&str, &str, &str)], caps: &str, pack: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (i, (old, new, name)) in updates.iter().enumerate() {
            let mut line = format!("{old} {new} {name}");
            if i == 0 {
                line.push('\0');
                line.push_str(caps);
            }
            line.push('\n');
            crate::pkt_line::write_data(&mut buf, line.as_bytes());
        }
        crate::pkt_line::write_flush(&mut buf);
        buf.extend_from_slice(pack);
        buf
    }

    #[test]
    fn parse_receive_pack_typical_single_update_create() {
        let pack = b"PACK_FAKE_BYTES";
        let body = build_receive_pack_body(
            &[(
                "0000000000000000000000000000000000000000",
                "0123456789abcdef0123456789abcdef01234567",
                "refs/heads/main",
            )],
            "report-status side-band-64k ofs-delta agent=git/2.43",
            pack,
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.is_simple());
        assert_eq!(req.updates.len(), 1);
        assert!(req.updates[0].is_create());
        assert!(req.has_report_status);
        assert!(req.has_sideband_64k);
        assert_eq!(req.pack, pack);
    }

    #[test]
    fn parse_receive_pack_marks_atomic_unsupported() {
        let body = build_receive_pack_body(
            &[(
                "0000000000000000000000000000000000000000",
                "0123456789abcdef0123456789abcdef01234567",
                "refs/heads/main",
            )],
            "report-status atomic agent=git/2.43",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.has_unsupported);
        assert!(!req.is_simple());
    }

    #[test]
    fn parse_receive_pack_marks_delete_only_simple_but_apply_rejects_native() {
        // A push that only deletes a ref sends no pack. The parser
        // accepts it, but apply_ref_update returns "native delete not
        // implemented" so the report says ng. We test the parser
        // here; the apply behavior is exercised by smoke.
        let body = build_receive_pack_body(
            &[(
                "0123456789abcdef0123456789abcdef01234567",
                "0000000000000000000000000000000000000000",
                "refs/heads/old",
            )],
            "report-status side-band-64k delete-refs agent=git/2.43",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.is_simple());
        assert!(req.updates[0].is_delete());
    }

    #[test]
    fn parse_receive_pack_rejects_no_caps() {
        // No capabilities means the client doesn't expect a report —
        // we don't natively handle that flow.
        let mut buf = Vec::new();
        crate::pkt_line::write_data(
            &mut buf,
            b"0000000000000000000000000000000000000000 0123456789abcdef0123456789abcdef01234567 refs/heads/main\n",
        );
        crate::pkt_line::write_flush(&mut buf);
        let req = parse_receive_pack_body(&buf).expect("should parse");
        assert!(!req.is_simple());
    }

    fn build_fetch_body(args: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        crate::pkt_line::write_data(&mut buf, b"command=fetch\n");
        crate::pkt_line::write_data(&mut buf, b"agent=git/test\n");
        crate::pkt_line::write_data(&mut buf, b"object-format=sha1\n");
        crate::pkt_line::write_delim(&mut buf);
        for a in args {
            let mut line = (*a).to_string();
            line.push('\n');
            crate::pkt_line::write_data(&mut buf, line.as_bytes());
        }
        crate::pkt_line::write_flush(&mut buf);
        buf
    }

    #[test]
    fn parse_v2_fetch_typical_clone() {
        // Clone of one ref: thin-pack + ofs-delta + one want + done.
        let body = build_fetch_body(&[
            "thin-pack",
            "ofs-delta",
            "no-progress",
            "want 0123456789abcdef0123456789abcdef01234567",
            "done",
        ]);
        let req = parse_v2_fetch(&body).expect("should parse");
        assert!(req.is_simple());
        assert_eq!(req.wants.len(), 1);
        assert!(req.haves.is_empty());
        assert!(req.done);
        assert!(req.no_progress);
        assert!(!req.has_unsupported);
    }

    #[test]
    fn parse_v2_fetch_with_haves_for_incremental_fetch() {
        let body = build_fetch_body(&[
            "thin-pack",
            "want 0123456789abcdef0123456789abcdef01234567",
            "have 89abcdef0123456789abcdef0123456789abcdef",
            "done",
        ]);
        let req = parse_v2_fetch(&body).expect("should parse");
        assert!(req.is_simple());
        assert_eq!(req.wants.len(), 1);
        assert_eq!(req.haves.len(), 1);
    }

    #[test]
    fn parse_v2_fetch_marks_shallow_unsupported() {
        // We don't natively handle shallow yet; the request must
        // fall through to upload-pack so the response is correct.
        let body = build_fetch_body(&[
            "thin-pack",
            "want 0123456789abcdef0123456789abcdef01234567",
            "shallow 89abcdef0123456789abcdef0123456789abcdef",
            "done",
        ]);
        let req = parse_v2_fetch(&body).expect("should parse");
        assert!(req.has_unsupported);
        assert!(!req.is_simple());
    }

    #[test]
    fn parse_v2_fetch_rejects_non_hex_want() {
        let body = build_fetch_body(&["want not-a-sha", "done"]);
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[test]
    fn parse_v2_fetch_rejects_ls_refs_command() {
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=ls-refs\n");
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_v2_fetch(&body).is_none());
    }

    // ── ls-refs edge branches ────────────────────────────────────────────────

    #[test]
    fn parse_ls_refs_empty_body_returns_none() {
        // An empty body has no first pkt-line at all → None.
        assert!(parse_ls_refs_only(b"").is_none());
    }

    #[test]
    fn parse_ls_refs_first_pkt_is_flush_returns_none() {
        // A leading flush-pkt is not a command line.
        let mut body = Vec::new();
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_first_pkt_is_delim_returns_none() {
        // A leading delim is not a command line.
        let mut body = Vec::new();
        crate::pkt_line::write_delim(&mut body);
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_resp_end_in_caps_returns_none() {
        // `0002` (response-end-pkt) anywhere in the capabilities section
        // must cause rejection.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=ls-refs\n");
        // Inject a raw 0002 byte sequence.
        body.extend_from_slice(b"0002");
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_no_delim_before_end_returns_none() {
        // If the iterator is exhausted after the caps loop without seeing a
        // delim, saw_delim stays false and we return None.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=ls-refs\n");
        crate::pkt_line::write_data(&mut body, b"agent=git/test\n");
        // No delim, no flush — buffer just ends. PktIter will return Truncated
        // or simply end, so saw_delim remains false.
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_unknown_capability_returns_none() {
        // A capability we don't recognise (not agent=, object-format=,
        // session-id=) must trip the fallback.
        let body = build_ls_refs_body(&["future-cap=yes"], &["peel"]);
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_session_id_capability_accepted() {
        // session-id= is a known-safe capability; must not reject.
        let body = build_ls_refs_body(
            &["agent=git/2.43.0", "session-id=abc123"],
            &["peel", "symrefs", "ref-prefix refs/heads/"],
        );
        let args = parse_ls_refs_only(&body).expect("session-id should be accepted");
        assert!(args.peel);
        assert!(args.symrefs);
    }

    #[test]
    fn parse_ls_refs_delim_in_args_returns_none() {
        // A delim-pkt inside the arguments section is malformed.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=ls-refs\n");
        crate::pkt_line::write_delim(&mut body); // end of caps
        crate::pkt_line::write_data(&mut body, b"peel\n");
        crate::pkt_line::write_delim(&mut body); // unexpected second delim
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_resp_end_in_args_returns_none() {
        // A response-end-pkt inside the arguments section is malformed.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=ls-refs\n");
        crate::pkt_line::write_delim(&mut body);
        crate::pkt_line::write_data(&mut body, b"peel\n");
        body.extend_from_slice(b"0002"); // RespEnd injected
        assert!(parse_ls_refs_only(&body).is_none());
    }

    #[test]
    fn parse_ls_refs_unborn_argument_tolerated() {
        // `unborn` is an accepted (no-op) argument; must not cause rejection.
        let body = build_ls_refs_body(
            &["agent=git/2.43.0"],
            &["peel", "symrefs", "unborn", "ref-prefix HEAD"],
        );
        let args = parse_ls_refs_only(&body).expect("unborn should be tolerated");
        assert!(args.peel);
        assert!(args.symrefs);
        assert_eq!(args.prefixes, vec!["HEAD".to_string()]);
    }

    #[test]
    fn parse_ls_refs_args_loop_exhausted_without_flush_returns_none() {
        // If the args loop runs out of input without a flush-pkt the outer
        // None is returned (the for-loop falls through without matching Flush).
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=ls-refs\n");
        crate::pkt_line::write_delim(&mut body);
        crate::pkt_line::write_data(&mut body, b"peel\n");
        // No flush — just end of buffer; iterator exhausts normally.
        assert!(parse_ls_refs_only(&body).is_none());
    }

    // ── v2 fetch edge branches ───────────────────────────────────────────────

    #[test]
    fn parse_v2_fetch_empty_body_returns_none() {
        assert!(parse_v2_fetch(b"").is_none());
    }

    #[test]
    fn parse_v2_fetch_first_pkt_is_flush_returns_none() {
        let mut body = Vec::new();
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[test]
    fn parse_v2_fetch_flush_during_cap_loop_returns_none() {
        // A flush immediately after the command line (before the delim) means
        // no args section — spec says that's malformed for fetch.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=fetch\n");
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[test]
    fn parse_v2_fetch_unknown_capability_returns_none() {
        // Unrecognised capability in the caps section forces None — we'd
        // rather subprocess than serve a wrong response.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=fetch\n");
        crate::pkt_line::write_data(&mut body, b"future-cap=yes\n");
        crate::pkt_line::write_delim(&mut body);
        crate::pkt_line::write_data(&mut body, b"done\n");
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[test]
    fn parse_v2_fetch_resp_end_in_caps_returns_none() {
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=fetch\n");
        body.extend_from_slice(b"0002");
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[test]
    fn parse_v2_fetch_no_delim_before_end_returns_none() {
        // Buffer ends after caps without a delim.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=fetch\n");
        crate::pkt_line::write_data(&mut body, b"agent=git/test\n");
        // No delim — saw_delim stays false.
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[test]
    fn parse_v2_fetch_ofs_delta_and_include_tag_accepted() {
        // ofs-delta and include-tag are standard caps; must not set
        // has_unsupported.
        let body = build_fetch_body(&[
            "ofs-delta",
            "include-tag",
            "want 0123456789abcdef0123456789abcdef01234567",
            "done",
        ]);
        let req = parse_v2_fetch(&body).expect("should parse");
        assert!(req.is_simple());
        assert!(!req.has_unsupported);
    }

    #[test]
    fn parse_v2_fetch_have_invalid_hex_returns_none() {
        let body = build_fetch_body(&[
            "want 0123456789abcdef0123456789abcdef01234567",
            "have not-a-sha",
            "done",
        ]);
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[test]
    fn parse_v2_fetch_delim_in_args_returns_none() {
        // A second delim in the args section is malformed.
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=fetch\n");
        crate::pkt_line::write_data(&mut body, b"agent=git/test\n");
        crate::pkt_line::write_delim(&mut body);
        crate::pkt_line::write_data(&mut body, b"done\n");
        crate::pkt_line::write_delim(&mut body); // unexpected
        crate::pkt_line::write_flush(&mut body);
        assert!(parse_v2_fetch(&body).is_none());
    }

    #[test]
    fn parse_v2_fetch_resp_end_in_args_returns_none() {
        let mut body = Vec::new();
        crate::pkt_line::write_data(&mut body, b"command=fetch\n");
        crate::pkt_line::write_delim(&mut body);
        crate::pkt_line::write_data(&mut body, b"done\n");
        body.extend_from_slice(b"0002");
        assert!(parse_v2_fetch(&body).is_none());
    }

    // ── receive-pack edge branches ───────────────────────────────────────────

    #[test]
    fn parse_receive_pack_malformed_pkt_returns_none() {
        // A body that starts with a truncated / bad-hex pkt-line must return
        // None rather than panic.
        assert!(parse_receive_pack_body(b"zzz").is_none());
    }

    #[test]
    fn parse_receive_pack_insufficient_parts_returns_none() {
        // A data line that doesn't have three space-separated parts is wrong.
        let mut buf = Vec::new();
        crate::pkt_line::write_data(&mut buf, b"onlyone\n");
        crate::pkt_line::write_flush(&mut buf);
        assert!(parse_receive_pack_body(&buf).is_none());
    }

    #[test]
    fn parse_receive_pack_bad_old_oid_returns_none() {
        let mut buf = Vec::new();
        crate::pkt_line::write_data(
            &mut buf,
            b"not-hex-40 0123456789abcdef0123456789abcdef01234567 refs/heads/x\n",
        );
        crate::pkt_line::write_flush(&mut buf);
        assert!(parse_receive_pack_body(&buf).is_none());
    }

    #[test]
    fn parse_receive_pack_bad_new_oid_returns_none() {
        let mut buf = Vec::new();
        crate::pkt_line::write_data(
            &mut buf,
            b"0123456789abcdef0123456789abcdef01234567 not-hex-40 refs/heads/x\n",
        );
        crate::pkt_line::write_flush(&mut buf);
        assert!(parse_receive_pack_body(&buf).is_none());
    }

    #[test]
    fn parse_receive_pack_report_status_v2_sets_flag() {
        // `report-status-v2` capability counts as has_report_status.
        let body = build_receive_pack_body(
            &[(
                "0000000000000000000000000000000000000000",
                "0123456789abcdef0123456789abcdef01234567",
                "refs/heads/main",
            )],
            "report-status-v2 side-band-64k",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.has_report_status);
        assert!(req.has_sideband_64k);
    }

    #[test]
    fn parse_receive_pack_push_options_marks_unsupported() {
        let body = build_receive_pack_body(
            &[(
                "0000000000000000000000000000000000000000",
                "0123456789abcdef0123456789abcdef01234567",
                "refs/heads/main",
            )],
            "report-status push-options",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.has_unsupported);
    }

    #[test]
    fn parse_receive_pack_push_cert_marks_unsupported() {
        let body = build_receive_pack_body(
            &[(
                "0000000000000000000000000000000000000000",
                "0123456789abcdef0123456789abcdef01234567",
                "refs/heads/main",
            )],
            "report-status push-cert",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.has_unsupported);
    }

    #[test]
    fn parse_receive_pack_unknown_cap_marks_unsupported() {
        // An unrecognised capability must set has_unsupported (safety net).
        let body = build_receive_pack_body(
            &[(
                "0000000000000000000000000000000000000000",
                "0123456789abcdef0123456789abcdef01234567",
                "refs/heads/main",
            )],
            "report-status future-unknown-capability",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(req.has_unsupported);
        assert!(!req.is_simple());
    }

    #[test]
    fn parse_receive_pack_agent_and_session_id_caps_ignored() {
        // agent= and session-id= are informational; must not set has_unsupported.
        let body = build_receive_pack_body(
            &[(
                "0000000000000000000000000000000000000000",
                "0123456789abcdef0123456789abcdef01234567",
                "refs/heads/main",
            )],
            "report-status side-band-64k agent=git/2.43.0 session-id=xyz object-format=sha1",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert!(!req.has_unsupported);
        assert!(req.has_report_status);
    }

    #[test]
    fn parse_receive_pack_delim_in_updates_returns_none() {
        // A delim-pkt inside the ref-updates section is malformed.
        let mut buf = Vec::new();
        crate::pkt_line::write_data(
            &mut buf,
            b"0000000000000000000000000000000000000000 0123456789abcdef0123456789abcdef01234567 refs/heads/main\0report-status\n",
        );
        crate::pkt_line::write_delim(&mut buf);
        crate::pkt_line::write_flush(&mut buf);
        assert!(parse_receive_pack_body(&buf).is_none());
    }

    #[test]
    fn parse_receive_pack_resp_end_in_updates_returns_none() {
        // A response-end-pkt inside the ref-updates section is malformed.
        let mut buf = Vec::new();
        crate::pkt_line::write_data(
            &mut buf,
            b"0000000000000000000000000000000000000000 0123456789abcdef0123456789abcdef01234567 refs/heads/main\0report-status\n",
        );
        buf.extend_from_slice(b"0002");
        assert!(parse_receive_pack_body(&buf).is_none());
    }

    #[test]
    fn parse_receive_pack_multiple_updates_second_no_caps() {
        // Only the first update line has capabilities. Subsequent lines have
        // no NUL; their (head, caps) split returns None for caps, which is
        // ignored after `first` flips to false.
        let body = build_receive_pack_body(
            &[
                (
                    "0000000000000000000000000000000000000000",
                    "0123456789abcdef0123456789abcdef01234567",
                    "refs/heads/main",
                ),
                (
                    "0000000000000000000000000000000000000000",
                    "89abcdef0123456789abcdef0123456789abcdef",
                    "refs/heads/dev",
                ),
            ],
            "report-status side-band-64k",
            b"",
        );
        let req = parse_receive_pack_body(&body).expect("should parse");
        assert_eq!(req.updates.len(), 2);
        assert!(req.has_report_status);
        assert!(!req.has_unsupported);
    }

    #[test]
    fn ref_update_is_create_and_is_delete() {
        let zero = RefUpdate::ZERO;
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let create = RefUpdate {
            old: zero.to_string(),
            new: sha.to_string(),
            name: "refs/heads/x".to_string(),
        };
        assert!(create.is_create());
        assert!(!create.is_delete());

        let delete = RefUpdate {
            old: sha.to_string(),
            new: zero.to_string(),
            name: "refs/heads/x".to_string(),
        };
        assert!(!delete.is_create());
        assert!(delete.is_delete());
    }

    #[test]
    fn v2_fetch_request_is_simple_checks() {
        let mut req = V2FetchRequest::default();
        // Neither done nor simple.
        assert!(!req.is_simple());
        req.done = true;
        assert!(req.is_simple());
        req.has_unsupported = true;
        assert!(!req.is_simple());
    }
}
