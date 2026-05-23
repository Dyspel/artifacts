//! Artifacts — versioned filesystem that speaks Git (prototype).
//!
//! Library crate. The `artifacts` binary (`src/main.rs`) is the
//! single entry point that wires CLI parsing + tracing init and
//! delegates everything else to [`app::serve`]. The split exists so
//!
//! - integration tests can spawn the binary via
//!   `CARGO_BIN_EXE_artifacts` (the only consumer today, see
//!   `tests/integration_smoke.rs`) **and**
//! - future tooling can link the library and exercise internals
//!   without a process boundary (`cargo test --lib` works against
//!   the lib alone).
//!
//! Every module that used to be declared in `main.rs` lives here as
//! `pub mod ...`, with the same `crate::xxx::yyy` paths internally
//! that the pre-split code already had.

#![deny(unused)]

pub mod alternates_cache;
pub mod app;
pub mod audit;
pub mod auth;
pub mod blocking;
pub mod commits;
pub mod config;
pub mod db_migrate;
pub mod error;
pub mod events;
pub mod gc;
pub mod git_cmd;
pub mod git_wire;
pub mod ids;
pub mod ip_rate_limit;
pub mod jwt;
pub mod merge;
pub mod metrics;
pub mod native_pack;
pub mod object_store;
pub mod ownership;
pub mod pkt_line;
pub mod rate_limit;
pub mod reads;
pub mod refs;
pub mod request_id;
pub mod rest;
pub mod secrets;
pub mod smart_http;
pub mod storage;
#[cfg(test)]
pub mod test_support;
pub mod tokens;
pub mod webhooks;

/// Re-export so `crate::random_admin_token()` keeps resolving inside
/// the lib (used by `rest/admin.rs` for the rotate endpoint). Bin
/// crate doesn't need this re-export — only one caller and it lives
/// here.
pub(crate) use app::random_admin_token;
