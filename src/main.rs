#![deny(unused)]

mod alternates_cache;
mod app;
mod audit;
mod auth;
mod blocking;
mod commits;
mod config;
mod db_migrate;
mod error;
mod events;
mod gc;
mod git_cmd;
mod git_wire;
mod ip_rate_limit;
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
#[cfg(test)]
mod test_support;
mod tokens;
mod webhooks;

use clap::{Parser, Subcommand};

/// CLI entry point. Parses arguments, initializes tracing, and
/// dispatches to the requested subcommand. All real server logic
/// lives in [`app::serve`]; this file is intentionally tiny so
/// `main.rs` stays a stable launching pad for whatever subcommands
/// land next.
#[derive(Parser)]
#[command(
    name = "artifacts",
    version,
    about = "Versioned filesystem that speaks Git"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the server.
    Serve(app::ServeArgs),
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
        Cmd::Serve(args) => app::serve(args).await?,
    }
    Ok(())
}

pub(crate) use app::random_admin_token;
