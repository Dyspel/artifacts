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
//!
//! ## Concurrency invariants
//!
//! H3 (production-hardening) swept the codebase for the three common
//! tokio + sync-primitive bug patterns. Results (mostly negative — the
//! prior refactors already covered them):
//!
//! 1. **`std::sync::Mutex` / `RwLock` held across `.await`** — searched
//!    every `.lock()` / `.read()` / `.write()` call in an `async fn`
//!    body. Zero production sites. The async traits (`RefStore`,
//!    `OwnershipStore`, `TokenStore`, `AuditStore`) all dispatch into
//!    sync SQL via `r2d2::PooledConnection`; the guard lifetime is
//!    bounded by the SQL block and dropped before any await point.
//!    `MemRefStore` is `#[cfg(test)]` and also drops its guard before
//!    returning. The `Config` RwLock sites (jwt_secret / admin_token)
//!    are sync getters that clone-out before returning, so no guard
//!    leaks into async code.
//!
//! 2. **`tokio::sync::Mutex` where `RwLock` would help** — zero live
//!    sites. The `Arc<tokio::sync::Mutex<Connection>>` shape was
//!    removed in A5 in favor of the r2d2 pool; references in module
//!    docstrings refer to the previous design, not current code. The
//!    pool gives N-reader / 1-writer parallelism under SQLite WAL,
//!    which is the same shape an RwLock would give plus connection
//!    multiplexing — strictly better.
//!
//! 3. **`Arc<dyn Trait>.clone()` in hot paths** — `RestState` carries
//!    seven `Arc<dyn ...>` fields (storage / ownership / refs /
//!    objects / tokens / audit / webhooks); cloning per request is
//!    seven atomic-RMW operations, roughly 70ns. F4's measurement
//:    pinned the bench p99 noise floor at ±40ms — three orders of
//!    magnitude larger. Keeping `Arc<dyn>` for the trait-object
//!    dispatch flexibility; static dispatch via generics would
//!    propagate concrete types through every signature in the REST
//!    handler tree.
//!
//! One open concern documented (not fixed): `r2d2::Pool::get()` is
//! synchronous and can block a tokio worker thread when the pool is
//! exhausted. With the default pool sizing (10 connections) and
//! typical control-plane load it's a non-issue; under a future
//! receive-pack burst that funnels through the audit store, this
//! could starve worker threads. The fix is either (a) sizing the
//! pool against expected request concurrency or (b) wrapping every
//! SQL call in `spawn_blocking`. (b) has its own cost (task spawn
//! overhead vs. the ~microseconds a typical query takes), so the
//! call is "leave the design as-is and revisit with a real
//! measurement if pool-exhausted spikes show up in the
//! `artifacts_sqlite_lock_wait_seconds` histogram".

// Lint policy (unused/unsafe discipline + curated `clippy::pedantic`)
// lives in the `[lints]` table in Cargo.toml, so it applies uniformly
// to the library, both binaries, tests, and benches from one place.

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
