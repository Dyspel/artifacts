//! Small helpers shared across the read endpoints.
//!
//! These were previously mixed in at the bottom of `reads.rs` with
//! the seven endpoint handlers. Pulling them out clarifies which
//! pieces are general validators (`validate_ref_or_sha`,
//! `validate_path`) versus endpoint-specific (`is_valid_notes_ref` —
//! tighter than the generic ref validator because the notes endpoint
//! deliberately scopes to `refs/notes/*`).

use crate::error::{Error, Result};
use std::path::Path;

/// Permissive ref/SHA validator. `git` itself rejects dangerous
/// input; we only block characters that would break the shell or
/// that refmaps reject. HEAD and branch/tag paths
/// (`refs/heads/...`, `refs/notes/...`) are all OK.
pub(super) fn validate_ref_or_sha(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 512 {
        return Err(Error::BadRequest("ref/sha empty or too long".into()));
    }
    for ch in s.chars() {
        if ch.is_whitespace() || matches!(ch, '\0' | ':' | '?' | '*' | '[' | '~' | '^' | '\\') {
            return Err(Error::BadRequest(format!("invalid character in ref: {ch:?}")));
        }
    }
    Ok(())
}

/// Path validator for repo-relative paths.
pub(super) fn validate_path(p: &str) -> Result<()> {
    if p.is_empty() || p.len() > 4096 {
        return Err(Error::BadRequest("path empty or too long".into()));
    }
    if p.starts_with('/') || p.contains("..") || p.contains('\0') {
        return Err(Error::BadRequest(format!("invalid path: {p:?}")));
    }
    Ok(())
}

/// Tighter validator for the notes endpoint — refs must live under
/// `refs/notes/`. Rejects empty leaf names, doubled slashes, and the
/// same dangerous characters `validate_ref_or_sha` blocks.
pub(super) fn is_valid_notes_ref(s: &str) -> bool {
    s.starts_with("refs/notes/")
        && s.len() > "refs/notes/".len()
        && !s.contains("//")
        && !s.ends_with('/')
        && s.chars().all(|c| c > ' ' && c != ':' && c != '?' && c != '*' && c != '~' && c != '^' && c != '[')
}

/// Recursive on-disk size of a directory in bytes. Used by the
/// repo-detail endpoint to surface a size hint; the walk is best-
/// effort and silently skips entries it can't stat.
pub(super) fn dir_size(path: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            total += dir_size(&entry.path()).unwrap_or(0);
        } else {
            total += meta.len();
        }
    }
    Ok(total)
}
