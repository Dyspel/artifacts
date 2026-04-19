mod auth;
mod commits;
mod config;
mod error;
mod refs;
mod rest;
mod smart_http;
mod storage;
mod tokens;

use crate::{
    config::Config,
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

        /// Path to the SQLite file that stores minted tokens. Defaults to
        /// `<data-dir>/tokens.db` so the token table lives next to the
        /// repos it authorizes.
        #[arg(long)]
        token_db: Option<PathBuf>,
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
            token_db,
        } => {
            let admin_token = admin_token.unwrap_or_else(|| {
                let t = random_admin_token();
                eprintln!("[artifacts] generated admin token: {t}");
                eprintln!("[artifacts] export ARTIFACTS_ADMIN_TOKEN={t} to persist across restarts");
                t
            });
            let cfg = Arc::new(Config {
                data_dir: data_dir.clone(),
                public_base_url,
                admin_token,
            });
            std::fs::create_dir_all(&data_dir)?;
            let storage: Arc<dyn Storage> = Arc::new(FsStorage::new(cfg.repos_dir())?);
            let token_db_path = token_db.unwrap_or_else(|| data_dir.join("tokens.db"));
            tracing::info!(path = %token_db_path.display(), "opening token db");
            let tokens: Arc<dyn TokenStore> = Arc::new(SqliteTokenStore::open(&token_db_path)?);
            let refs: Arc<dyn RefStore> = Arc::new(FsRefStore::new(cfg.repos_dir()));

            let rest_state = RestState {
                cfg: cfg.clone(),
                storage,
                tokens: tokens.clone(),
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

fn random_admin_token() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::Rng;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
