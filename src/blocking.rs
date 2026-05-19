//! Helper for funnelling sync work onto `tokio::task::spawn_blocking`.
//!
//! Most of our blocking work is git / gix calls that don't have async
//! equivalents, plus a few subprocess wrappers and SQLite calls. The
//! call-site shape used to be four lines verbatim:
//!
//! ```ignore
//! tokio::task::spawn_blocking(move || ...)
//!     .await
//!     .map_err(|e| Error::Other(anyhow::anyhow!("foo join: {e}")))??
//! ```
//!
//! Repeated twice in the same handler, twelve times across the crate,
//! with slightly different `anyhow!` wording at each site (sometimes
//! `"foo join: {e}"`, sometimes `"{e}"`, sometimes plain `anyhow!(e)`).
//! That inconsistency makes JoinError debugging unnecessarily painful.
//!
//! [`run_blocking`] collapses all of it: one line at the call site,
//! one canonical JoinError → `Error::Other` mapping, one label string
//! that the call site supplies so tracing keeps the context.

use crate::error::{Error, Result};

/// Run `f` on a `spawn_blocking` worker and await its result. The
/// `label` is folded into the JoinError → Error::Other message so a
/// panicked or cancelled worker still surfaces with a useful name.
///
/// The closure returns `Result<T>` — the outer JoinError handling +
/// inner Result unwrap collapse into one `?` for the caller.
pub async fn run_blocking<T, F>(label: &'static str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("{label} join: {e}")))?
}
