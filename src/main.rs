mod alternates_cache;
mod audit;
mod auth;
mod commits;
mod config;
mod error;
mod events;
mod gc;
mod jwt;
mod merge;
mod metrics;
mod native_pack;
mod object_store;
mod ownership;
mod pkt_line;
mod rate_limit;
mod reads;
mod refs;
mod request_id;
mod rest;
mod secrets;
mod smart_http;
mod storage;
mod tokens;
mod webhooks;

use crate::{
    config::Config,
    ownership::{OwnershipStore, SqliteOwnershipStore},
    rate_limit::RateLimiter,
    refs::{FsRefStore, RefStore},
    rest::RestState,
    smart_http::GitState,
    storage::{FsStorage, Storage},
    tokens::{SqliteTokenStore, TokenStore},
};
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc, time::Duration};

#[derive(Parser)]
#[command(name = "artifacts", version, about = "Versioned filesystem that speaks Git")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the server.
    Serve {
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,

        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,

        /// Public base URL used to generate clone URLs. Should match how
        /// clients reach this server from outside.
        #[arg(long, default_value = "http://127.0.0.1:8787")]
        public_base_url: String,

        /// Admin token required for REST endpoints. If omitted, a fresh
        /// token is generated and printed to stderr on startup.
        #[arg(long, env = "ARTIFACTS_ADMIN_TOKEN")]
        admin_token: Option<String>,

        /// Shared HS256 secret for verifying JWTs on REST endpoints.
        /// When set, any `Authorization: Bearer <jwt>` that verifies
        /// against this secret resolves to `Principal::User { subject }`
        /// from the JWT's `userId` (Dyspel convention) or `sub` claim.
        /// When unset, only the admin token authorizes REST calls.
        #[arg(long, env = "ARTIFACTS_JWT_SECRET")]
        jwt_secret: Option<String>,

        /// Path to the SQLite file that stores minted tokens. Defaults to
        /// `<data-dir>/tokens.db` so the token table lives next to the
        /// repos it authorizes.
        #[arg(long)]
        token_db: Option<PathBuf>,

        /// Maximum number of repos a single non-admin user may own.
        /// Prevents an agent retry loop or runaway client from creating
        /// unbounded repos. Admin callers bypass the limit. Set high
        /// enough that a legitimate heavy user doesn't hit it; low
        /// enough that a misbehaving one can't fill the disk before
        /// someone notices.
        #[arg(long, env = "ARTIFACTS_MAX_REPOS_PER_USER", default_value_t = 100)]
        max_repos_per_user: u64,

        /// Maximum size in bytes of any single file in a REST-side
        /// commit. Default 8 MB. Applies to both `content` (UTF-8) and
        /// `contentBase64` after decoding. Files larger than this
        /// should go through `git push` (the smart-HTTP endpoints
        /// stream; this one doesn't) or, eventually, LFS.
        #[arg(long, env = "ARTIFACTS_MAX_COMMIT_BLOB_BYTES", default_value_t = 8 * 1024 * 1024)]
        max_commit_blob_bytes: usize,

        /// PEM-encoded TLS certificate. Pair with `--tls-key`. When
        /// both are set the server listens HTTPS via rustls and the
        /// bind-safety check no longer requires loopback. When either
        /// is missing the server falls back to plaintext HTTP (for
        /// dev — production should put a terminator in front, or set
        /// these flags).
        #[arg(long, env = "ARTIFACTS_TLS_CERT")]
        tls_cert: Option<PathBuf>,

        /// PEM-encoded TLS private key. Paired with `--tls-cert`.
        #[arg(long, env = "ARTIFACTS_TLS_KEY")]
        tls_key: Option<PathBuf>,

        /// Graceful-shutdown drain timeout, in seconds. On SIGTERM /
        /// SIGINT (Ctrl-C), the server stops accepting new connections
        /// and waits up to this long for in-flight requests to
        /// complete before exiting. Default 30s — covers a slow git
        /// push (which buffers on the server side) without blocking a
        /// deployment for a stuck client. Set to 0 to skip the drain
        /// (immediate shutdown — dev only).
        #[arg(long, env = "ARTIFACTS_SHUTDOWN_TIMEOUT_SECS", default_value_t = 30)]
        shutdown_timeout_secs: u64,

        /// Audit log retention, in days. Rows older than this are
        /// pruned hourly. `0` disables pruning (audit log grows
        /// indefinitely — useful for compliance scenarios where an
        /// external archiver moves rows out before they age out).
        /// Default 90 days.
        #[arg(long, env = "ARTIFACTS_AUDIT_RETENTION_DAYS", default_value_t = 90)]
        audit_retention_days: u64,

        /// Opt-in to binding a non-loopback address with `http://`.
        /// Without this flag we refuse to start in that combination,
        /// because it broadcasts tokens in the clear to anyone who can
        /// reach the listener. The correct shape for a non-loopback
        /// deployment is an HTTPS terminator (nginx / caddy / cloudflared)
        /// in front of the server, with `--public-base-url` set to the
        /// `https://` URL of that terminator. This flag exists for
        /// people who know what they're doing (ephemeral test rigs,
        /// internal networks with out-of-band authentication, etc.).
        #[arg(long)]
        allow_insecure: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "artifacts=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve {
            data_dir,
            bind,
            public_base_url,
            admin_token,
            jwt_secret,
            token_db,
            max_repos_per_user,
            max_commit_blob_bytes,
            tls_cert,
            tls_key,
            shutdown_timeout_secs,
            audit_retention_days,
            allow_insecure,
        } => {
            // Refuse to start in the "non-loopback bind + plaintext HTTP"
            // combination. Tokens travel in URLs and Basic auth — both
            // plaintext unless TLS is terminating somewhere. The #1
            // reason prototypes leak credentials in real deploys is
            // forgetting to put a terminator in front.
            // TLS is enabled iff both cert + key are set. Mismatched
            // (only one set) is a misconfig — fail fast rather than
            // silently downgrade to plaintext.
            let tls_enabled = match (tls_cert.as_ref(), tls_key.as_ref()) {
                (Some(_), Some(_)) => true,
                (None, None) => false,
                _ => anyhow::bail!(
                    "--tls-cert and --tls-key must be set together (one without the other is a config error)"
                ),
            };
            check_bind_safety(&bind, &public_base_url, allow_insecure, tls_enabled)?;
            let admin_token = admin_token.unwrap_or_else(|| {
                let t = random_admin_token();
                eprintln!("[artifacts] generated admin token: {t}");
                eprintln!("[artifacts] export ARTIFACTS_ADMIN_TOKEN={t} to persist across restarts");
                t
            });
            if jwt_secret.is_some() {
                tracing::info!("jwt auth enabled (HS256)");
            } else {
                tracing::info!("jwt auth disabled — only admin token accepted");
            }
            let cfg = Arc::new(Config::new(
                data_dir.clone(),
                public_base_url,
                admin_token,
                jwt_secret,
                max_repos_per_user,
                max_commit_blob_bytes,
            ));
            tracing::info!(
                max_repos_per_user,
                max_commit_blob_bytes,
                "non-admin quotas"
            );

            // Install the prometheus recorder *before* any metrics call
            // site runs (startup-time gauges, middleware). Fallible
            // because registration can fail (duplicate name, bad
            // matcher) — surface a clean error instead of a panic.
            let prom_handle = metrics::init()
                .map_err(|e| anyhow::anyhow!("metrics init failed: {e:#}"))?;
            std::fs::create_dir_all(&data_dir)?;
            let storage: Arc<dyn Storage> = Arc::new(FsStorage::new(cfg.repos_dir())?);
            // Object-store seam: gc reads/writes/lists/deletes loose
            // objects through this. The FS impl wraps the same
            // `<repos_dir>` the storage layer uses; a future chunked-KV
            // impl swaps in here without changing handler code.
            let objects: Arc<dyn object_store::ObjectStore> =
                Arc::new(object_store::FsObjectStore::new(cfg.repos_dir()));
            let token_db_path = token_db.unwrap_or_else(|| data_dir.join("tokens.db"));
            tracing::info!(path = %token_db_path.display(), "opening metadata db");
            let sqlite_tokens = Arc::new(SqliteTokenStore::open(&token_db_path)?);
            // Periodic prune of revoked + expired rows. Without this the
            // tokens table grows monotonically: at 10k tokens/day, a year
            // of operation = 3.6M rows of dead weight. Runs hourly, with
            // a 24h grace window after expiry so admins can still audit
            // recently-expired tokens before they're gone.
            tokens::spawn_prune_task(
                sqlite_tokens.clone(),
                Duration::from_secs(3600),
                Duration::from_secs(86400),
            );
            // Populate the active-token gauge before any handler can
            // observe it as zero, then spawn a 60-second refresher so
            // the gauge tracks real mint/revoke activity within a
            // minute rather than waiting for the hourly prune.
            tokens::refresh_active_token_gauge(&*sqlite_tokens).await;
            let tokens: Arc<dyn TokenStore> = sqlite_tokens;
            tokens::spawn_active_gauge_refresher(tokens.clone(), Duration::from_secs(60));
            // Reuses the same SQLite file for a separate `repos` table.
            // Separate table and separate connection keeps the concerns
            // cleanly split; WAL-mode lets them coexist without lock
            // contention on the hot path.
            let ownership: Arc<dyn OwnershipStore> =
                Arc::new(SqliteOwnershipStore::open(&token_db_path)?);
            // Audit log lives in its own DB so it can be archived /
            // rotated independently of the token store. Same WAL-mode
            // SQLite shape; the writer is best-effort (a SQLite
            // hiccup logs but doesn't fail the underlying mutation).
            let audit_db_path = data_dir.join("audit.db");
            tracing::info!(path = %audit_db_path.display(), "opening audit db");
            let audit: Arc<dyn audit::AuditStore> =
                Arc::new(audit::SqliteAuditStore::open(&audit_db_path)?);
            // Hourly retention sweep — same cadence as the token-prune
            // task. `0` days from the CLI flag disables pruning, which
            // `spawn_prune_task` honors by not spawning at all.
            audit::spawn_prune_task(
                audit.clone(),
                Duration::from_secs(3600),
                Duration::from_secs(audit_retention_days * 86400),
            );
            // Emit a startup audit event so a compliance reviewer can
            // see "when did this server boot, with what
            // security-relevant configuration." Captures the flags
            // that affect the threat model (TLS, allow_insecure) plus
            // the retention/quota knobs that bound auditability and
            // capacity. Live `tracing::info!` mirrors the same fields
            // for live log subscribers — same shape as the rest of
            // the audit-event call sites.
            tracing::info!(
                target: "audit",
                event = "server.start",
                actor = "admin",
                bind = %bind,
                public_base_url = %cfg.public_base_url,
                tls_enabled,
                allow_insecure,
                max_repos_per_user,
                audit_retention_days,
                shutdown_timeout_secs,
            );
            crate::audit::record_silent(
                &*audit,
                "server.start",
                "admin",
                None,
                serde_json::json!({
                    "bind": bind,
                    "public_base_url": cfg.public_base_url,
                    "tls_enabled": tls_enabled,
                    "allow_insecure": allow_insecure,
                    "max_repos_per_user": max_repos_per_user,
                    "audit_retention_days": audit_retention_days,
                    "shutdown_timeout_secs": shutdown_timeout_secs,
                    "version": env!("CARGO_PKG_VERSION"),
                }),
                None,
            )
            .await;
            let refs: Arc<dyn RefStore> = Arc::new(FsRefStore::new(cfg.repos_dir()));
            let rate_limit = Arc::new(RateLimiter::with_defaults());
            // Prune stale per-subject buckets every 5 min; buckets not
            // touched for an hour get dropped. Keeps the map from
            // growing unbounded if a lot of short-lived JWT subjects
            // come and go.
            rate_limit::spawn_cleanup(
                rate_limit.clone(),
                Duration::from_secs(300),
                Duration::from_secs(3600),
            );

            let event_bus = events::EventBus::new();
            // Webhook subscription store: SQLite-backed if
            // ARTIFACTS_WEBHOOK_DB is set (or implicitly when a
            // webhooks.db file already exists in data_dir), in-memory
            // otherwise. Both impls satisfy the same trait, so the
            // dispatcher and REST endpoints don't care which is in
            // play. Picking SQLite by default once the data_dir
            // contains the file means an admin can flip persistence
            // on by creating an empty webhooks.db; nice for
            // upgrade-in-place without env-var ceremony.
            let webhook_db_path = std::env::var("ARTIFACTS_WEBHOOK_DB")
                .ok()
                .map(PathBuf::from)
                .or_else(|| {
                    let p = data_dir.join("webhooks.db");
                    p.exists().then_some(p)
                });
            // The on-disk key path is plumbed into RestState so
            // `admin_rotate_webhook_key` can rewrite it post-rotation.
            // None for env-var-only / in-memory deployments.
            let mut webhook_key_path: Option<std::path::PathBuf> = None;
            let webhook_registry: Arc<dyn webhooks::WebhookRegistry> =
                match webhook_db_path {
                    Some(p) => {
                        // Load the AES-256 master key that seals webhook
                        // HMAC secrets at rest. Resolution order is
                        // env-first, then `<data-dir>/webhook-key.bin`,
                        // then auto-generate (with a warning) so a
                        // first-run dev server doesn't fail to start.
                        let key_path = data_dir.join("webhook-key.bin");
                        let master_key = Arc::new(
                            secrets::MasterKey::load_or_generate(&key_path)?,
                        );
                        // Only plumb the key path through state if the
                        // env var isn't set — when env is the source of
                        // truth, rewriting the file would silently
                        // disagree with the env on next restart.
                        if std::env::var_os("ARTIFACTS_WEBHOOK_KEY").is_none() {
                            webhook_key_path = Some(key_path);
                        }
                        tracing::info!(path = %p.display(), "webhooks: SQLite-backed registry (encrypted secrets)");
                        Arc::new(webhooks::SqliteWebhookRegistry::open(&p, master_key)?)
                    }
                    None => {
                        tracing::info!("webhooks: in-memory registry (subscriptions lost on restart)");
                        Arc::new(webhooks::MemRegistry::new())
                    }
                };
            // Spawn the webhook dispatcher *before* any handler can
            // publish, so the broadcast subscriber registers before
            // events start flying. Otherwise the first commit/fork on
            // boot wouldn't reach any subscribers.
            webhooks::spawn_dispatcher(webhook_registry.clone(), event_bus.clone());
            // Active-subscription gauge: synchronous startup populate +
            // 60s refresher. Mirrors the active-token gauge shape.
            webhooks::refresh_active_webhook_gauge(&*webhook_registry);
            webhooks::spawn_active_gauge_refresher(
                webhook_registry.clone(),
                Duration::from_secs(60),
            );

            let rest_state = RestState {
                cfg: cfg.clone(),
                storage,
                tokens: tokens.clone(),
                ownership,
                refs: refs.clone(),
                rate_limit,
                events: event_bus,
                alternates_cache: Arc::new(alternates_cache::AlternatesCache::new()),
                webhooks: webhook_registry,
                audit,
                webhook_key_path,
                objects,
            };
            // Bench A/B kill-switch. Production never sets this; the
            // bench scripts toggle it to compare native vs subprocess
            // on the same release binary. Any non-empty value enables
            // the legacy paths (chosen so `=0` and `=1` are both
            // explicit).
            let disable_native = std::env::var("ARTIFACTS_DISABLE_NATIVE")
                .map(|v| !v.is_empty() && v != "0")
                .unwrap_or(false);
            if disable_native {
                tracing::warn!(
                    "ARTIFACTS_DISABLE_NATIVE set: native protocol paths disabled \
                     (bench / parity mode)",
                );
            }
            let git_state = GitState {
                cfg: cfg.clone(),
                tokens,
                refs,
                disable_native,
            };

            let rest_router = Router::new()
                .route("/v1/health", get(rest::health))
                .route("/v1/health/ready", get(rest::health_ready))
                .route("/v1/repos", post(rest::create_repo).get(rest::list_repos))
                .route("/v1/repos/:id", delete(rest::delete_repo).get(reads::get_repo))
                .route("/v1/repos/:id/forks", post(rest::fork_repo))
                .route(
                    "/v1/repos/:id/tokens",
                    post(rest::mint_token).get(rest::list_tokens),
                )
                .route("/v1/repos/:id/tokens/rotate", post(rest::rotate_tokens))
                .route(
                    "/v1/repos/:id/webhooks",
                    post(rest::create_webhook).get(rest::list_webhooks),
                )
                .route(
                    "/v1/repos/:id/webhooks/:hook_id",
                    delete(rest::delete_webhook),
                )
                .route("/v1/repos/:id/commits", post(commits::create_commit).get(reads::list_commits))
                .route("/v1/repos/:id/merge", post(merge::merge_branches))
                .route("/v1/repos/:id/refs", get(reads::list_refs))
                .route("/v1/repos/:id/tree", get(reads::get_tree))
                .route("/v1/repos/:id/blob", get(reads::get_blob))
                .route("/v1/repos/:id/diff", get(reads::get_diff))
                .route("/v1/repos/:id/notes", get(reads::get_note))
                .route("/v1/events", get(events::sse_stream))
                .route("/v1/tokens/revoke", post(rest::revoke_token))
                .route("/v1/admin/token/rotate", post(rest::admin_rotate_token))
                .route("/v1/admin/webhook-key/rotate", post(rest::admin_rotate_webhook_key))
                .route("/v1/admin/audit", get(rest::admin_list_audit))
                .route("/v1/admin/audit/stats", get(rest::admin_audit_stats))
                .route("/v1/admin/repos", get(rest::admin_list_repos))
                .route("/v1/admin/repos/:id", get(rest::admin_get_repo))
                .route(
                    "/v1/admin/repos/:id/gc-preview",
                    get(rest::admin_gc_preview),
                )
                .route(
                    "/v1/admin/repos/:id/gc",
                    post(rest::admin_gc_run),
                )
                .with_state(rest_state)
                // Metrics middleware only wraps the REST surface (not
                // /git, which streams large bodies where per-request
                // timing is a poor signal) and not /metrics itself
                // (self-scraping would be noise).
                .layer(axum_middleware::from_fn(metrics::track_metrics));

            // /metrics is outside the REST router so the track_metrics
            // middleware doesn't observe its own scrape.
            let metrics_route = {
                let handle = prom_handle.clone();
                Router::new()
                    .route("/metrics", get(move || async move { metrics::render(&handle) }))
            };

            let app = rest_router
                .merge(metrics_route)
                // Git smart-HTTP. A single catch-all route under /git/:id.git/
                // dispatches to the backend based on the method + path.
                .nest(
                    "/git",
                    Router::new()
                        .route("/:id/*rest", get(smart_http::git_handler).post(smart_http::git_handler))
                        .with_state(git_state),
                )
                // Request-ID middleware wraps *everything* (including
                // /metrics and /git) so every served request gets an
                // id and a one-line structured log. Runs outermost so
                // the span covers the full request lifecycle.
                .layer(axum_middleware::from_fn(request_id::instrument));

            let shutdown_timeout = Duration::from_secs(shutdown_timeout_secs);
            if tls_enabled {
                // rustls 0.23 dropped the implicit default crypto
                // provider — install ring once before any RustlsConfig
                // touches the global default. Idempotent (harmless to
                // call once; second call returns Err which we swallow).
                let _ = rustls::crypto::ring::default_provider().install_default();
                // Both flags are Some by the tls_enabled gate above.
                let cert = tls_cert.expect("tls_cert checked above");
                let key = tls_key.expect("tls_key checked above");
                let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                    .await
                    .map_err(|e| anyhow::anyhow!(
                        "loading TLS material from {cert:?} + {key:?}: {e}"
                    ))?;
                let addr: std::net::SocketAddr = bind
                    .parse()
                    .map_err(|e| anyhow::anyhow!("parsing --bind={bind}: {e}"))?;
                tracing::info!(
                    %bind,
                    data_dir = %data_dir.display(),
                    cert = %cert.display(),
                    shutdown_timeout_secs,
                    "artifacts listening (TLS)"
                );
                // axum-server exposes graceful shutdown via Handle:
                // hand the shared handle to a signal-listener task that
                // calls `graceful_shutdown(timeout)` when SIGTERM /
                // SIGINT fires. The serve() call then returns once the
                // drain completes (or hits the timeout).
                let handle = axum_server::Handle::new();
                spawn_shutdown_listener(handle.clone(), shutdown_timeout);
                axum_server::bind_rustls(addr, config)
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await?;
            } else {
                let listener = tokio::net::TcpListener::bind(&bind).await?;
                tracing::info!(
                    %bind,
                    data_dir = %data_dir.display(),
                    shutdown_timeout_secs,
                    "artifacts listening"
                );
                // axum::serve takes a future that resolves when shutdown
                // should begin; once it does, axum stops accepting new
                // connections and lets in-flight requests finish (up to
                // a tower-managed deadline). The outer timeout ensures
                // we exit even if a request is genuinely stuck.
                let serve = axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown_signal());
                if shutdown_timeout.is_zero() {
                    serve.await?;
                } else {
                    // Bound the total drain time. If the drain doesn't
                    // finish in `shutdown_timeout`, we abandon it and
                    // let the process exit — better than blocking a
                    // rolling deploy on a stuck client.
                    match tokio::time::timeout(shutdown_timeout, serve).await {
                        Ok(r) => r?,
                        Err(_) => tracing::warn!(
                            timeout_secs = shutdown_timeout_secs,
                            "graceful shutdown timed out — exiting with in-flight requests"
                        ),
                    }
                }
            }
        }
    }
    Ok(())
}

/// Refuse to start in the configuration most likely to leak credentials:
/// a non-loopback bind serving a plaintext-HTTP public URL.
///
/// Rationale: every client (git, the REST API) authenticates with a
/// bearer token or Basic credentials. Both are plaintext. A non-loopback
/// bind + `http://` public base URL means those plaintext credentials
/// travel over whatever network reaches the listener. In development
/// this is someone's laptop over Wi-Fi; in a cloud deployment it's
/// usually someone who forgot to put a TLS terminator in front and
/// silently leaked every token to passive observers.
///
/// `allow_insecure` is the explicit opt-out. `--bind 127.0.0.1:...` and
/// loopback IPv6 (`::1`) are permitted unconditionally (nothing but the
/// local host reaches them).
fn check_bind_safety(
    bind: &str,
    public_base_url: &str,
    allow_insecure: bool,
    tls_enabled: bool,
) -> anyhow::Result<()> {
    if allow_insecure {
        tracing::warn!("--allow-insecure is set; bind-safety check skipped");
        return Ok(());
    }
    if tls_enabled {
        // TLS terminates in-process — bytes on the wire are encrypted.
        // The terminator-in-front shape (loopback bind + https public
        // URL) was the previous "safe non-loopback" route; this is
        // the second one.
        return Ok(());
    }
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
    // Strip IPv6 brackets if present: `[::1]:8787` → `::1`.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "0:0:0:0:0:0:0:1");
    if is_loopback {
        return Ok(());
    }
    if public_base_url.starts_with("https://") {
        // Non-loopback + HTTPS public URL is the terminator-in-front
        // shape — a separate process is rewriting https:// → http://
        // on the loopback leg.
        return Ok(());
    }
    anyhow::bail!(
        "refusing to start: bind={bind} is not loopback, --tls-cert/--tls-key are not set, and public-base-url={public_base_url} is not https://.\n\
         Tokens travel in plaintext — this is almost always a deployment mistake.\n\
         Fix one of:\n\
           - pass --tls-cert / --tls-key to terminate TLS in-process\n\
           - bind 127.0.0.1:... and put a TLS terminator in front\n\
           - set --public-base-url to an https:// URL (terminator handles TLS for you)\n\
           - pass --allow-insecure if you really mean it (an ephemeral test rig, say)"
    );
}

/// Resolves on the first SIGTERM (Linux/Mac systemd / k8s graceful
/// stop) or SIGINT (Ctrl-C in a dev shell). Both signal sources
/// are wired up on Unix; on non-Unix platforms only Ctrl-C is
/// available and SIGTERM-style requests have to come through the
/// stdlib's ctrl-c handler (which Windows maps appropriately).
async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install ctrl-c handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received SIGINT, beginning graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("received SIGTERM, beginning graceful shutdown");
        }
    }
}

/// Kick off the axum-server graceful-shutdown handshake when the
/// signal-listener fires. `timeout == 0` means "skip the drain and
/// hard-exit" (dev-only use case); axum-server's `graceful_shutdown`
/// takes `Option<Duration>` where `Some(ZERO)` means "drop active
/// connections immediately" — close enough for our purposes that we
/// just pass the timeout through.
fn spawn_shutdown_listener(handle: axum_server::Handle, timeout: Duration) {
    tokio::spawn(async move {
        shutdown_signal().await;
        handle.graceful_shutdown(Some(timeout));
    });
}

pub(crate) fn random_admin_token() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::Rng;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod bind_safety_tests {
    use super::*;

    #[test]
    fn allow_insecure_skips_all_checks() {
        // Even the worst-case combo (non-loopback + plaintext + no TLS)
        // is permitted with --allow-insecure. The flag is the explicit
        // "I know what I'm doing" override.
        assert!(check_bind_safety("0.0.0.0:8787", "http://0.0.0.0:8787", true, false).is_ok());
    }

    #[test]
    fn tls_enabled_permits_non_loopback() {
        // Bytes on the wire are encrypted — non-loopback is fine.
        assert!(check_bind_safety("0.0.0.0:8787", "http://example.com", false, true).is_ok());
    }

    #[test]
    fn loopback_passes_without_tls() {
        for host in ["127.0.0.1:8787", "[::1]:8787", "localhost:8787"] {
            assert!(
                check_bind_safety(host, "http://localhost:8787", false, false).is_ok(),
                "expected loopback bind {host} to pass"
            );
        }
    }

    #[test]
    fn non_loopback_with_https_public_url_passes() {
        // Terminator-in-front shape — separate process is rewriting
        // https:// → http:// on the loopback leg (not exercised here,
        // but the safety check trusts the operator's https:// assertion).
        assert!(
            check_bind_safety("0.0.0.0:8787", "https://artifacts.example.com", false, false)
                .is_ok()
        );
    }

    #[test]
    fn non_loopback_plaintext_no_tls_is_rejected() {
        let r = check_bind_safety("0.0.0.0:8787", "http://0.0.0.0:8787", false, false);
        assert!(r.is_err(), "expected refusal, got {r:?}");
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("--tls-cert"), "error should mention TLS path: {msg}");
    }

    #[test]
    fn ipv6_loopback_brackets_stripped() {
        // [::1] in bind syntax must be recognized as loopback once
        // the brackets are trimmed. Regression: an earlier version
        // matched on the bracketed string and treated [::1] as
        // non-loopback.
        assert!(check_bind_safety("[::1]:8787", "http://[::1]:8787", false, false).is_ok());
    }
}
