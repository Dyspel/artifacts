//! `artifacts` binary entry point. Parses CLI args, initializes
//! tracing, and dispatches to [`artifacts::app::serve`]. Everything
//! else lives in the library crate (`src/lib.rs` and friends) so
//! `cargo test --lib` can exercise internals without going through
//! the binary.

use clap::{Parser, Subcommand};

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
    Serve(artifacts::app::ServeArgs),
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
        Cmd::Serve(args) => artifacts::app::serve(args).await?,
    }
    Ok(())
}
