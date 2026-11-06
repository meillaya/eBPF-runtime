// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-relay` entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use relay::{run, RelayConfig};

#[derive(Debug, Parser)]
#[command(name = "ebpf-relay", version, about = "Projection relay")]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Run one pass and exit.
    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .try_init();
    let cli = Cli::parse();
    let config = match cli.config {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<RelayConfig>(&text) {
                Ok(config) => config,
                Err(error) => return fail(error),
            },
            Err(error) => return fail(error),
        },
        None => RelayConfig::default(),
    };
    let mut config = config;
    if let Ok(url) = std::env::var("DATABASE_URL") {
        config.database_url = url;
    }
    run(config, cli.once)
        .await
        .map_or_else(fail, |_| ExitCode::SUCCESS)
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("ebpf-relay: {error}");
    ExitCode::FAILURE
}
