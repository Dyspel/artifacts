//! Server-mode entrypoint. The CLI parse + tracing init live in
//! `main.rs`; everything else (state construction, listener wiring,
//! shutdown handling) is here.
//!
//! `serve(ServeArgs)` is the one entry point. Called from `main` after
//! the `Serve` subcommand is parsed; returns when the listener has
//! drained (clean shutdown) or panics if the bind path errors out.
//!
//! The serve body is intentionally one big wiring function. Each line
//! is a piece of plumbing whose ordering matters (gauges populate
//! before listener starts; webhook dispatcher subscribes before any
//! handler can publish; the drain flag exists before the shutdown
//! listener spawns). Chopping it into smaller pieces would just hide
//! those ordering constraints behind helper signatures.

#![allow(clippy::too_many_lines)]

use crate::{
    alternates_cache, audit, commits,
    config::Config,
    events, ip_rate_limit, merge, metrics, object_store,
    ownership::{self, OwnershipStore, SqliteOwnershipStore},
    rate_limit::{self, RateLimiter},
    reads,
    refs::{FsRefStore, RefStore},
    request_id, rest,
    rest::RestState,
    secrets, smart_http,
    smart_http::GitState,
    storage::{FsStorage, Storage},
    tokens::{self, SqliteTokenStore, TokenStore},
    webhooks,
};
use axum::{
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use clap::Args;
use std::{path::PathBuf, sync::Arc, time::Duration};

/// Cadence the active-* gauges (tokens, repos, webhooks, audit) refresh
/// at. 60s is the smallest interval that keeps dashboards "live to the
/// minute" without making `SELECT COUNT(*)` against indexed tables a
/// noticeable load. Used everywhere we spawn a gauge refresher.
const GAUGE_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Cadence the periodic-prune tasks run at. Tokens (revoked + expired
/// rows), audit log (rows older than retention). Hourly is the
/// standard "doesn't paper over a bug, doesn't pile up unboundedly"
/// trade-off.
const PRUNE_INTERVAL: Duration = Duration::from_secs(3600);

/// Token-prune grace window after expiry. Keeps recently-expired rows
/// around for 24h so an admin investigating a stale token failure can
/// still see when/why it died before the row vanishes.
const TOKEN_PRUNE_GRACE: Duration = Duration::from_secs(86400);

/// Per-request body size cap for the REST surface (`/v1/*`). 1 MiB
/// is well above realistic JSON payloads (the largest is a
/// `create_commit` with inline file contents; even a few dozen
/// source files easily fit) and well below where an unauthenticated
/// client could DoS the server by streaming megabytes into the
/// JSON deserializer. Git smart-HTTP (`/git/*`) has its own much
/// larger cap inside `smart_http.rs` because clone / push bodies
/// are legitimately huge.
const REST_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Parsed arguments for the `serve` subcommand. Carried as one struct
/// so the `match` arm in `main` is a one-liner and the `serve` function
/// has a single argument; adds 14 individual fields wouldn't.
#[derive(Args, Debug)]
pub struct ServeArgs {
    #[arg(long, default_value = "./data")]
    pub data_dir: PathBuf,

    #[arg(long, default_value = "127.0.0.1:8787")]
    pub bind: String,

    /// Public base URL used to generate clone URLs. Should match how
    /// clients reach this server from outside.
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    pub public_base_url: String,

    /// Admin token required for REST endpoints. If omitted, a fresh
    /// token is generated and printed to stderr on startup.
    #[arg(long, env = "ARTIFACTS_ADMIN_TOKEN")]
    pub admin_token: Option<String>,

    /// Shared HS256 secret for verifying JWTs on REST endpoints.
    /// When set, any `Authorization: Bearer <jwt>` that verifies
    /// against this secret resolves to `Principal::User { subject }`
    /// from the JWT's `userId` (Dyspel convention) or `sub` claim.
    /// When unset, only the admin token authorizes REST calls.
    #[arg(long, env = "ARTIFACTS_JWT_SECRET")]
    pub jwt_secret: Option<String>,

    /// Path to the SQLite file that stores minted tokens. Defaults to
    /// `<data-dir>/tokens.db` so the token table lives next to the
    /// repos it authorizes.
    #[arg(long)]
    pub token_db: Option<PathBuf>,

    /// Maximum number of repos a single non-admin user may own.
    /// Prevents an agent retry loop or runaway client from creating
    /// unbounded repos. Admin callers bypass the limit.
    #[arg(long, env = "ARTIFACTS_MAX_REPOS_PER_USER", default_value_t = 100)]
    pub max_repos_per_user: u64,

    /// Maximum size in bytes of any single file in a REST-side
    /// commit. Default 8 MB.
    #[arg(long, env = "ARTIFACTS_MAX_COMMIT_BLOB_BYTES", default_value_t = 8 * 1024 * 1024)]
    pub max_commit_blob_bytes: usize,

    /// PEM-encoded TLS certificate. Pair with `--tls-key`.
    #[arg(long, env = "ARTIFACTS_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS private key. Paired with `--tls-cert`.
    #[arg(long, env = "ARTIFACTS_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    /// Graceful-shutdown drain timeout, in seconds.
    #[arg(long, env = "ARTIFACTS_SHUTDOWN_TIMEOUT_SECS", default_value_t = 30)]
    pub shutdown_timeout_secs: u64,

    /// Drain delay between SIGTERM and the start of axum's graceful
    /// drain, in seconds.
    #[arg(long, env = "ARTIFACTS_SHUTDOWN_DRAIN_DELAY_SECS", default_value_t = 5)]
    pub shutdown_drain_delay_secs: u64,

    /// Audit log retention, in days. Rows older than this are pruned
    /// hourly. `0` disables pruning.
    #[arg(long, env = "ARTIFACTS_AUDIT_RETENTION_DAYS", default_value_t = 90)]
    pub audit_retention_days: u64,

    /// Opt-in to binding a non-loopback address with `http://`.
    #[arg(long)]
    pub allow_insecure: bool,

    /// OTLP/gRPC endpoint for distributed tracing. When set, per-request
    /// spans (the same ones rendered to stderr) are also batched out to
    /// this collector — Jaeger, Tempo, Honeycomb, or any OTLP-speaking
    /// receiver. Default off; setting it is the only configuration
    /// required.
    ///
    /// Example: `--otlp-endpoint http://otel-collector:4317`.
    #[arg(long, env = "ARTIFACTS_OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,
}

/// Build the full server state graph and run the listener until
/// graceful shutdown completes. Every store open, gauge bootstrap,
/// prune task spawn, refresher spawn, and audit emission lives here
/// — the ordering between them matters and is documented inline.
pub async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let ServeArgs {
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
        shutdown_drain_delay_secs,
        audit_retention_days,
        allow_insecure,
        otlp_endpoint,
    } = args;

    // Install the tracing subscriber. The fmt layer is always present
    // (per-request structured stderr logs); the OTLP layer is
    // conditional on --otlp-endpoint being set. Both feed off the
    // same EnvFilter so RUST_LOG controls both surfaces identically.
    init_tracing(otlp_endpoint.as_deref())?;

    // Refuse to start in the "non-loopback bind + plaintext HTTP"
    // combination. Tokens travel in URLs and Basic auth — both
    // plaintext unless TLS is terminating somewhere. The #1 reason
    // prototypes leak credentials in real deploys is forgetting to
    // put a terminator in front. TLS is enabled iff both cert + key
    // are set. Mismatched (only one set) is a misconfig — fail fast
    // rather than silently downgrade to plaintext.
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
    // JWT secret resolution: env (already captured in `jwt_secret`)
    // wins. If unset, fall back to `<data-dir>/jwt-key.bin`. If neither
    // is present, JWT auth stays disabled until an admin rotates the
    // key in via `POST /v1/admin/jwt-key/rotate`. The path is also the
    // persistence target for that rotation; pinning via env means we
    // skip the file rewrite (admin pre-committed the secret in the
    // env, so the file isn't the source of truth).
    let env_pinned_jwt = jwt_secret.is_some();
    let jwt_key_path: Option<std::path::PathBuf> = if env_pinned_jwt {
        None
    } else {
        Some(data_dir.join("jwt-key.bin"))
    };
    let jwt_secret = match jwt_secret {
        Some(s) => Some(s),
        None => jwt_key_path
            .as_deref()
            .filter(|p| p.exists())
            .and_then(|p| {
                std::fs::read_to_string(p)
                    .map(|s| s.trim().to_string())
                    .ok()
                    .filter(|s| !s.is_empty())
            }),
    };
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

    // Install the prometheus recorder *before* any metrics call site
    // runs (startup-time gauges, middleware). Fallible because
    // registration can fail (duplicate name, bad matcher) — surface a
    // clean error instead of a panic.
    let prom_handle = metrics::init().map_err(|e| anyhow::anyhow!("metrics init failed: {e:#}"))?;
    std::fs::create_dir_all(&data_dir)?;
    let storage: Arc<dyn Storage> = Arc::new(FsStorage::new(cfg.repos_dir())?);
    // Object-store seam: gc reads/writes/lists/deletes loose objects
    // through this. The FS impl wraps the same `<repos_dir>` the
    // storage layer uses; a future chunked-KV impl swaps in here
    // without changing handler code.
    let objects: Arc<dyn object_store::ObjectStore> =
        Arc::new(object_store::FsObjectStore::new(cfg.repos_dir()));
    let token_db_path = token_db.unwrap_or_else(|| data_dir.join("tokens.db"));
    tracing::info!(path = %token_db_path.display(), "opening metadata db");
    // Collect each store's pool handle as we open them, so the
    // pool-gauge refresher spawned below can publish
    // `artifacts_sqlite_pool_size{store}` /
    // `artifacts_sqlite_pool_in_use{store}` without having to
    // re-thread the concrete types through the rest of the function.
    let mut sqlite_pools: Vec<(&'static str, crate::db_migrate::DbPool)> = Vec::new();
    let sqlite_tokens = Arc::new(SqliteTokenStore::open(&token_db_path)?);
    sqlite_pools.push(("tokens", sqlite_tokens.pool().clone()));
    // Periodic prune of revoked + expired rows. Without this the
    // tokens table grows monotonically: at 10k tokens/day, a year of
    // operation = 3.6M rows of dead weight. Runs hourly, with a 24h
    // grace window after expiry so admins can still audit
    // recently-expired tokens before they're gone.
    tokens::spawn_prune_task(sqlite_tokens.clone(), PRUNE_INTERVAL, TOKEN_PRUNE_GRACE);
    // Populate the active-token gauge before any handler can observe
    // it as zero, then spawn a 60-second refresher so the gauge
    // tracks real mint/revoke activity within a minute rather than
    // waiting for the hourly prune.
    tokens::refresh_active_token_gauge(&*sqlite_tokens).await;
    let tokens: Arc<dyn TokenStore> = sqlite_tokens;
    tokens::spawn_active_gauge_refresher(tokens.clone(), GAUGE_REFRESH_INTERVAL);
    // Reuses the same SQLite file for a separate `repos` table.
    // Separate table and separate connection keeps the concerns
    // cleanly split; WAL-mode lets them coexist without lock
    // contention on the hot path.
    let sqlite_ownership = SqliteOwnershipStore::open(&token_db_path)?;
    sqlite_pools.push(("ownership", sqlite_ownership.pool().clone()));
    let ownership: Arc<dyn OwnershipStore> = Arc::new(sqlite_ownership);
    // Populate the repos-total gauge before the listener starts (so
    // the first scrape isn't 0), then spawn a 60s refresher to track
    // create/delete activity. Same cadence and rationale as the
    // active-token / active-webhook gauges spawned above.
    ownership::refresh_repos_gauge(&*ownership).await;
    ownership::spawn_repos_gauge_refresher(ownership.clone(), GAUGE_REFRESH_INTERVAL);
    // Audit log lives in its own DB so it can be archived / rotated
    // independently of the token store. Same WAL-mode SQLite shape;
    // the writer is best-effort (a SQLite hiccup logs but doesn't
    // fail the underlying mutation).
    let audit_db_path = data_dir.join("audit.db");
    tracing::info!(path = %audit_db_path.display(), "opening audit db");
    let sqlite_audit = audit::SqliteAuditStore::open(&audit_db_path)?;
    sqlite_pools.push(("audit", sqlite_audit.pool().clone()));
    let audit: Arc<dyn audit::AuditStore> = Arc::new(sqlite_audit);
    // Hourly retention sweep — same cadence as the token-prune task.
    // `0` days from the CLI flag disables pruning, which
    // `spawn_prune_task` honors by not spawning at all.
    audit::spawn_prune_task(
        audit.clone(),
        PRUNE_INTERVAL,
        Duration::from_secs(audit_retention_days * 86400),
    );
    // Stored-events gauge — populate before the listener starts so
    // the first scrape isn't 0, then a 60s refresher keeps it fresh
    // between hourly prune sweeps (the prune task itself also
    // refreshes after each delete batch). Mirrors the token /
    // webhook / repo gauges spawned above.
    audit::refresh_events_stored_gauge(&*audit).await;
    audit::spawn_events_stored_gauge_refresher(audit.clone(), GAUGE_REFRESH_INTERVAL);
    // Emit a startup audit event so a compliance reviewer can see
    // "when did this server boot, with what security-relevant
    // configuration." Captures the flags that affect the threat
    // model (TLS, allow_insecure) plus the retention/quota knobs
    // that bound auditability and capacity. Live `tracing::info!`
    // mirrors the same fields for live log subscribers — same shape
    // as the rest of the audit-event call sites.
    crate::audit::record(
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
            "shutdown_drain_delay_secs": shutdown_drain_delay_secs,
            "version": env!("CARGO_PKG_VERSION"),
        }),
        None,
    )
    .await;
    let refs: Arc<dyn RefStore> = Arc::new(FsRefStore::new(cfg.repos_dir()));
    let rate_limit = Arc::new(RateLimiter::with_defaults());
    // Prune stale per-subject buckets every 5 min; buckets not
    // touched for an hour get dropped. Keeps the map from growing
    // unbounded if a lot of short-lived JWT subjects come and go.
    rate_limit::spawn_cleanup(
        rate_limit.clone(),
        Duration::from_secs(300),
        Duration::from_secs(3600),
    );

    // Per-IP rate limiter for the two unauth health endpoints. Same
    // shape as `RateLimiter` but keyed on peer IP instead of subject;
    // lives behind a middleware layer attached to `/v1/health*` so
    // authenticated traffic is unaffected.
    let ip_rate_limit = Arc::new(ip_rate_limit::IpRateLimiter::with_defaults());
    ip_rate_limit::spawn_cleanup(
        ip_rate_limit.clone(),
        Duration::from_secs(300),
        Duration::from_secs(3600),
    );

    let event_bus = events::EventBus::new();
    // Webhook subscription store: SQLite-backed if
    // ARTIFACTS_WEBHOOK_DB is set (or implicitly when a webhooks.db
    // file already exists in data_dir), in-memory otherwise.
    let webhook_db_path = std::env::var("ARTIFACTS_WEBHOOK_DB")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            let p = data_dir.join("webhooks.db");
            p.exists().then_some(p)
        });
    let mut webhook_key_path: Option<std::path::PathBuf> = None;
    let webhook_registry: Arc<dyn webhooks::WebhookRegistry> = match webhook_db_path {
        Some(p) => {
            let key_path = data_dir.join("webhook-key.bin");
            let master_key = Arc::new(secrets::MasterKey::load_or_generate(&key_path)?);
            if std::env::var_os("ARTIFACTS_WEBHOOK_KEY").is_none() {
                webhook_key_path = Some(key_path);
            }
            tracing::info!(path = %p.display(), "webhooks: SQLite-backed registry (encrypted secrets)");
            let sqlite_wh = webhooks::SqliteWebhookRegistry::open(&p, master_key)?;
            sqlite_pools.push(("webhooks", sqlite_wh.pool().clone()));
            Arc::new(sqlite_wh)
        }
        None => {
            tracing::info!("webhooks: in-memory registry (subscriptions lost on restart)");
            Arc::new(webhooks::MemRegistry::new())
        }
    };
    // Spawn the webhook dispatcher *before* any handler can publish,
    // so the broadcast subscriber registers before events start
    // flying. Otherwise the first commit/fork on boot wouldn't reach
    // any subscribers.
    webhooks::spawn_dispatcher(webhook_registry.clone(), event_bus.clone());
    webhooks::refresh_active_webhook_gauge(&*webhook_registry);
    webhooks::spawn_active_gauge_refresher(webhook_registry.clone(), GAUGE_REFRESH_INTERVAL);

    // One task that refreshes every store's pool gauges. Populated by
    // each `SqliteXxxStore::open` call above; an empty `sqlite_pools`
    // (e.g. webhook_registry is the in-memory variant) just becomes
    // a no-op tick.
    crate::metrics::spawn_pool_gauge_refresher(sqlite_pools, GAUGE_REFRESH_INTERVAL);

    // Shared drain flag. Flipped from `false` → `true` by the
    // shutdown listener task on first SIGTERM/SIGINT, before
    // axum-server begins refusing connections. The readiness probe
    // checks this and starts returning 503 immediately so an
    // orchestrator can pull the process out of rotation before
    // in-flight drain begins.
    let draining = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Hold a clone of the audit store outside `rest_state` so we can
    // emit a `server.shutdown` audit event after the listener returns
    // — paired with the `server.start` event emitted at boot, this
    // gives a compliance reviewer a bracket-record per process
    // instance.
    let audit_for_shutdown = audit.clone();
    let server_started_at = std::time::Instant::now();
    let drain_started: Arc<std::sync::Mutex<Option<std::time::Instant>>> =
        Arc::new(std::sync::Mutex::new(None));

    let rest_state = RestState {
        cfg: cfg.clone(),
        data: crate::rest::DataState {
            storage,
            ownership,
            refs: refs.clone(),
            objects: objects.clone(),
            alternates_cache: Arc::new(alternates_cache::AlternatesCache::new()),
        },
        authn: crate::rest::AuthnState {
            tokens: tokens.clone(),
            rate_limit,
        },
        observ: crate::rest::ObservState {
            audit,
            events: event_bus,
            webhooks: webhook_registry,
            webhook_key_path,
            jwt_key_path: jwt_key_path.clone(),
        },
        runtime: crate::rest::RuntimeState {
            draining: draining.clone(),
        },
    };
    // Bench A/B kill-switch. Production never sets this; the bench
    // scripts toggle it to compare native vs subprocess on the same
    // release binary. Any non-empty value enables the legacy paths
    // (chosen so `=0` and `=1` are both explicit).
    let disable_native = std::env::var("ARTIFACTS_DISABLE_NATIVE")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    if disable_native {
        tracing::warn!(
            "ARTIFACTS_DISABLE_NATIVE set: native protocol paths disabled (bench / parity mode)",
        );
    }
    let git_state = GitState {
        cfg: cfg.clone(),
        tokens,
        refs,
        objects,
        disable_native,
    };

    // Health routes carry their own per-IP rate-limit layer so an
    // unauthenticated scanner can't pound /v1/health* — the
    // principal-keyed limiter can't see them because auth doesn't
    // run. State is dedicated (the limiter Arc); the main router's
    // `RestState` is unaffected.
    let health_router = Router::new()
        .route("/v1/health", get(rest::health))
        .route("/v1/health/ready", get(rest::health_ready))
        .layer(axum_middleware::from_fn_with_state(
            ip_rate_limit.clone(),
            ip_rate_limit_middleware,
        ));

    let rest_router = Router::new()
        .merge(health_router)
        .route("/v1/repos", post(rest::create_repo).get(rest::list_repos))
        .route(
            "/v1/repos/:id",
            delete(rest::delete_repo).get(reads::get_repo),
        )
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
        .route(
            "/v1/repos/:id/commits",
            post(commits::create_commit).get(reads::list_commits),
        )
        .route("/v1/repos/:id/merge", post(merge::merge_branches))
        .route("/v1/repos/:id/refs", get(reads::list_refs))
        .route("/v1/repos/:id/tree", get(reads::get_tree))
        .route("/v1/repos/:id/blob", get(reads::get_blob))
        .route("/v1/repos/:id/diff", get(reads::get_diff))
        .route("/v1/repos/:id/notes", get(reads::get_note))
        .route("/v1/events", get(events::sse_stream))
        .route("/v1/tokens/revoke", post(rest::revoke_token))
        .route("/v1/admin/token/rotate", post(rest::admin_rotate_token))
        .route(
            "/v1/admin/webhook-key/rotate",
            post(rest::admin_rotate_webhook_key),
        )
        .route("/v1/admin/jwt-key/rotate", post(rest::admin_rotate_jwt_key))
        .route("/v1/admin/audit", get(rest::admin_list_audit))
        .route("/v1/admin/audit/stats", get(rest::admin_audit_stats))
        .route(
            "/v1/admin/audit/verify-chain",
            get(rest::admin_verify_audit_chain),
        )
        .route("/v1/admin/repos", get(rest::admin_list_repos))
        .route("/v1/admin/repos/:id", get(rest::admin_get_repo))
        .route(
            "/v1/admin/repos/:id/gc-preview",
            get(rest::admin_gc_preview),
        )
        .route("/v1/admin/repos/:id/gc", post(rest::admin_gc_run))
        .with_state(rest_state)
        .layer(axum_middleware::from_fn(metrics::track_metrics))
        .layer(DefaultBodyLimit::max(REST_BODY_LIMIT_BYTES));

    let metrics_route = {
        let handle = prom_handle.clone();
        Router::new().route(
            "/metrics",
            get(move || async move { metrics::render(&handle) }),
        )
    };

    let app = rest_router
        .merge(metrics_route)
        .nest(
            "/git",
            Router::new()
                .route(
                    "/:id/*rest",
                    get(smart_http::git_handler).post(smart_http::git_handler),
                )
                .with_state(git_state),
        )
        .layer(axum_middleware::from_fn(request_id::instrument));

    let shutdown_timeout = Duration::from_secs(shutdown_timeout_secs);
    let shutdown_drain_delay = Duration::from_secs(shutdown_drain_delay_secs);
    if tls_enabled {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = tls_cert.expect("tls_cert checked above");
        let key = tls_key.expect("tls_key checked above");
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
            .await
            .map_err(|e| anyhow::anyhow!("loading TLS material from {cert:?} + {key:?}: {e}"))?;
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
        let handle = axum_server::Handle::new();
        spawn_shutdown_listener(
            handle.clone(),
            shutdown_timeout,
            draining.clone(),
            shutdown_drain_delay,
            drain_started.clone(),
        );
        axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
        emit_server_shutdown(
            &*audit_for_shutdown,
            server_started_at,
            shutdown_timeout,
            drain_started.clone(),
        )
        .await;
    } else {
        let listener = tokio::net::TcpListener::bind(&bind).await?;
        tracing::info!(
            %bind,
            data_dir = %data_dir.display(),
            shutdown_timeout_secs,
            "artifacts listening"
        );
        let serve = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal(
            draining.clone(),
            shutdown_drain_delay,
            drain_started.clone(),
        ));
        if shutdown_timeout.is_zero() {
            serve.await?;
        } else {
            match tokio::time::timeout(shutdown_timeout, serve).await {
                Ok(r) => r?,
                Err(_) => tracing::warn!(
                    timeout_secs = shutdown_timeout_secs,
                    "graceful shutdown timed out — exiting with in-flight requests"
                ),
            }
        }
        emit_server_shutdown(
            &*audit_for_shutdown,
            server_started_at,
            shutdown_timeout,
            drain_started.clone(),
        )
        .await;
    }
    Ok(())
}

/// Refuse to start in the configuration most likely to leak
/// credentials: a non-loopback bind serving a plaintext-HTTP public
/// URL. `allow_insecure` is the explicit opt-out.
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
        return Ok(());
    }
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "0:0:0:0:0:0:0:1");
    if is_loopback {
        return Ok(());
    }
    if public_base_url.starts_with("https://") {
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
/// stop) or SIGINT (Ctrl-C in a dev shell), then performs the
/// pre-drain hand-off: flip the draining flag, sleep `drain_delay`,
/// then resolve.
async fn shutdown_signal(
    draining: Arc<std::sync::atomic::AtomicBool>,
    drain_delay: Duration,
    drain_started: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
) {
    use std::sync::atomic::Ordering;
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
    draining.store(true, Ordering::Relaxed);
    if !drain_delay.is_zero() {
        tracing::info!(
            drain_delay_secs = drain_delay.as_secs(),
            "marked draining; sleeping so orchestrator can pull from rotation",
        );
        tokio::time::sleep(drain_delay).await;
    }
    *drain_started.lock().expect("drain_started mutex poisoned") = Some(std::time::Instant::now());
}

/// Classify the drain outcome for the `server.shutdown` audit event.
/// Path-independent: same logic for HTTP and TLS deployments.
fn classify_shutdown_kind(
    drain_started: Option<std::time::Instant>,
    shutdown_timeout: Duration,
) -> &'static str {
    if shutdown_timeout.is_zero() {
        return "graceful";
    }
    let Some(start) = drain_started else {
        return "graceful";
    };
    let epsilon = Duration::from_millis(100);
    if start.elapsed() >= shutdown_timeout + epsilon {
        "timed_out"
    } else {
        "graceful"
    }
}

/// Emit a `server.shutdown` audit event after the listener returns.
/// Paired with `server.start` at boot — together they bracket a
/// process instance in the audit log.
async fn emit_server_shutdown(
    audit: &dyn audit::AuditStore,
    started_at: std::time::Instant,
    shutdown_timeout: Duration,
    drain_started: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
) {
    let kind = classify_shutdown_kind(
        *drain_started.lock().expect("drain_started mutex poisoned"),
        shutdown_timeout,
    );
    let uptime_secs = started_at.elapsed().as_secs();
    audit::record(
        audit,
        "server.shutdown",
        "admin",
        None,
        serde_json::json!({
            "kind": kind,
            "uptime_secs": uptime_secs,
            "shutdown_timeout_secs": shutdown_timeout.as_secs(),
            "version": env!("CARGO_PKG_VERSION"),
        }),
        None,
    )
    .await;
}

/// Kick off the axum-server graceful-shutdown handshake when the
/// signal-listener fires.
fn spawn_shutdown_listener(
    handle: axum_server::Handle,
    timeout: Duration,
    draining: Arc<std::sync::atomic::AtomicBool>,
    drain_delay: Duration,
    drain_started: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
) {
    tokio::spawn(async move {
        shutdown_signal(draining, drain_delay, drain_started).await;
        handle.graceful_shutdown(Some(timeout));
    });
}

/// Axum middleware: charge one token from the per-IP bucket before
/// running the wrapped handler; return 429 if the bucket is empty.
async fn ip_rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<Arc<ip_rate_limit::IpRateLimiter>>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(axum::extract::ConnectInfo(addr)) = connect_info {
        if let Err(e) = limiter.check(addr.ip()) {
            return e.into_response();
        }
    }
    next.run(req).await
}

pub(crate) fn random_admin_token() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::Rng;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Initialize tracing. `fmt` layer always; `tracing-opentelemetry` +
/// OTLP/gRPC batched exporter when `otlp_endpoint` is `Some`. Both
/// layers share the same `EnvFilter` so `RUST_LOG` controls them
/// uniformly — no surprise where stderr shows a span but the
/// collector doesn't.
///
/// On exporter failure (collector unreachable, bad endpoint, etc.)
/// the batch processor logs to stderr and drops spans; the server
/// keeps running. We don't want a remote-tracing misconfig to take
/// the production data plane down.
fn init_tracing(otlp_endpoint: Option<&str>) -> anyhow::Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "artifacts=info,tower_http=info".into());
    let fmt_layer = tracing_subscriber::fmt::layer();

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    match otlp_endpoint {
        None => registry.init(),
        Some(endpoint) => {
            use opentelemetry::trace::TracerProvider;
            use opentelemetry_otlp::WithExportConfig;
            let resource = opentelemetry_sdk::Resource::new(vec![
                opentelemetry::KeyValue::new("service.name", "artifacts"),
                opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            ]);
            let provider = opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(
                    opentelemetry_otlp::new_exporter()
                        .tonic()
                        .with_endpoint(endpoint.to_string()),
                )
                .with_trace_config(
                    opentelemetry_sdk::trace::Config::default().with_resource(resource),
                )
                .install_batch(opentelemetry_sdk::runtime::Tokio)
                .map_err(|e| anyhow::anyhow!("install OTLP exporter ({endpoint}): {e}"))?;
            // Make the tracer the global provider so any opentelemetry
            // code path (none in production today, but spawning libs
            // may use it) sees the same exporter.
            let _ = opentelemetry::global::set_tracer_provider(provider.clone());
            let tracer = provider.tracer("artifacts");
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            registry.with(otel_layer).init();
            tracing::info!(endpoint = %endpoint, "OTLP tracing enabled");
        }
    }
    Ok(())
}

#[cfg(test)]
mod bind_safety_tests {
    use super::*;

    #[test]
    fn allow_insecure_skips_all_checks() {
        assert!(check_bind_safety("0.0.0.0:8787", "http://0.0.0.0:8787", true, false).is_ok());
    }

    #[test]
    fn tls_enabled_permits_non_loopback() {
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
        assert!(check_bind_safety(
            "0.0.0.0:8787",
            "https://artifacts.example.com",
            false,
            false
        )
        .is_ok());
    }

    #[test]
    fn non_loopback_plaintext_no_tls_is_rejected() {
        let r = check_bind_safety("0.0.0.0:8787", "http://0.0.0.0:8787", false, false);
        assert!(r.is_err(), "expected refusal, got {r:?}");
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("--tls-cert"),
            "error should mention TLS path: {msg}"
        );
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

#[cfg(test)]
mod shutdown_classification_tests {
    use super::*;

    #[test]
    fn no_drain_started_is_graceful() {
        assert_eq!(
            classify_shutdown_kind(None, Duration::from_secs(30)),
            "graceful"
        );
    }

    #[test]
    fn zero_timeout_is_always_graceful() {
        assert_eq!(
            classify_shutdown_kind(Some(std::time::Instant::now()), Duration::from_secs(0)),
            "graceful",
        );
    }

    #[test]
    fn fast_drain_is_graceful() {
        let just_now = std::time::Instant::now();
        assert_eq!(
            classify_shutdown_kind(Some(just_now), Duration::from_secs(30)),
            "graceful",
        );
    }

    #[test]
    fn elapsed_past_budget_is_timed_out() {
        let long_ago = std::time::Instant::now() - Duration::from_secs(60);
        assert_eq!(
            classify_shutdown_kind(Some(long_ago), Duration::from_secs(30)),
            "timed_out",
        );
    }

    #[test]
    fn within_epsilon_of_budget_still_graceful() {
        let near_deadline = std::time::Instant::now() - Duration::from_millis(29_950);
        assert_eq!(
            classify_shutdown_kind(Some(near_deadline), Duration::from_secs(30)),
            "graceful",
        );
    }
}
