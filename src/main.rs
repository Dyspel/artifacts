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
    // Tracing init moved into `app::serve` so it can read the
    // `--otlp-endpoint` flag off the parsed args and install the
    // OTLP layer alongside the fmt layer when present. Errors from
    // clap parsing land on stderr via clap's own formatter, which
    // happens before any of our spans would have fired anyway.
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve(args) => artifacts::app::serve(args).await?,
    }
    Ok(())
}
