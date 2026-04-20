mod auth;
mod commits;
mod config;
mod error;
mod jwt;
mod ownership;
mod refs;
mod rest;
mod smart_http;
mod storage;
mod tokens;

use crate::{
    config::Config,
    ownership::{OwnershipStore, SqliteOwnershipStore},
    refs::{FsRefStore, RefStore},
    rest::RestState,
    smart_http::GitState,
    storage::{FsStorage, Storage},
    tokens::{SqliteTokenStore, TokenStore},
};
use axum::{
    routing::{delete, get, post},
    Router,
};
use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc};
use tower_http::trace::TraceLayer;

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
            allow_insecure,
        } => {
            // Refuse to start in the "non-loopback bind + plaintext HTTP"
            // combination. Tokens travel in URLs and Basic auth — both
            // plaintext unless TLS is terminating somewhere. The #1
            // reason prototypes leak credentials in real deploys is
            // forgetting to put a terminator in front.
            check_bind_safety(&bind, &public_base_url, allow_insecure)?;
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
            let cfg = Arc::new(Config {
                data_dir: data_dir.clone(),
                public_base_url,
                admin_token,
                jwt_secret,
            });
            std::fs::create_dir_all(&data_dir)?;
            let storage: Arc<dyn Storage> = Arc::new(FsStorage::new(cfg.repos_dir())?);
            let token_db_path = token_db.unwrap_or_else(|| data_dir.join("tokens.db"));
            tracing::info!(path = %token_db_path.display(), "opening metadata db");
            let tokens: Arc<dyn TokenStore> = Arc::new(SqliteTokenStore::open(&token_db_path)?);
            // Reuses the same SQLite file for a separate `repos` table.
            // Separate table and separate connection keeps the concerns
            // cleanly split; WAL-mode lets them coexist without lock
            // contention on the hot path.
            let ownership: Arc<dyn OwnershipStore> =
                Arc::new(SqliteOwnershipStore::open(&token_db_path)?);
            let refs: Arc<dyn RefStore> = Arc::new(FsRefStore::new(cfg.repos_dir()));

            let rest_state = RestState {
                cfg: cfg.clone(),
                storage,
                tokens: tokens.clone(),
                ownership,
                refs,
            };
            let git_state = GitState { cfg: cfg.clone(), tokens };

            let app = Router::new()
                // REST
                .route("/v1/health", get(rest::health))
                .route("/v1/repos", post(rest::create_repo))
                .route("/v1/repos/:id", delete(rest::delete_repo))
                .route("/v1/repos/:id/forks", post(rest::fork_repo))
                .route("/v1/repos/:id/tokens", post(rest::mint_token))
                .route("/v1/repos/:id/commits", post(commits::create_commit))
                .route("/v1/tokens/revoke", post(rest::revoke_token))
                .with_state(rest_state)
                // Git smart-HTTP. A single catch-all route under /git/:id.git/
                // dispatches to the backend based on the method + path.
                .nest(
                    "/git",
                    Router::new()
                        .route("/:id/*rest", get(smart_http::git_handler).post(smart_http::git_handler))
                        .with_state(git_state),
                )
                .layer(TraceLayer::new_for_http());

            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!(%bind, data_dir = %data_dir.display(), "artifacts listening");
            axum::serve(listener, app).await?;
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
fn check_bind_safety(bind: &str, public_base_url: &str, allow_insecure: bool) -> anyhow::Result<()> {
    if allow_insecure {
        tracing::warn!("--allow-insecure is set; bind-safety check skipped");
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
        // Non-loopback + HTTPS is the intended shape — a terminator is
        // presumably rewriting https:// → http:// on the loopback leg.
        return Ok(());
    }
    anyhow::bail!(
        "refusing to start: bind={bind} is not loopback and public-base-url={public_base_url} is not https://.\n\
         Tokens travel in plaintext — this is almost always a deployment mistake.\n\
         Fix one of:\n\
           - bind 127.0.0.1:... and put a TLS terminator in front (recommended)\n\
           - set --public-base-url to an https:// URL (terminator handles TLS for you)\n\
           - pass --allow-insecure if you really mean it (an ephemeral test rig, say)"
    );
}

fn random_admin_token() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::Rng;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
