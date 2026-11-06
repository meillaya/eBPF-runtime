// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-control-plane` entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use control_plane::{migrate, serve, ControlConfig};

#[derive(Debug, Parser)]
#[command(
    name = "ebpf-control-plane",
    version,
    about = "eBPF fleet control plane"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the control plane.
    Serve {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        dev: bool,
    },
    /// Run database migrations.
    Migrate {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { config, dev } => {
            let mut config = match ControlConfig::load(config.as_deref()) {
                Ok(config) => config,
                Err(error) => return fail(error),
            };
            if dev {
                config.dev = true;
                config.database_url =
                    std::env::var("DATABASE_URL").unwrap_or_else(|_| config.database_url.clone());
                if let Err(error) = config.validate() {
                    return fail(error);
                }
            }
            init_logging();
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime
                .block_on(serve(config))
                .map_or_else(fail, |_| ExitCode::SUCCESS)
        }
        Command::Migrate { config } => {
            let config = match ControlConfig::load(config.as_deref()) {
                Ok(config) => config,
                Err(error) => return fail(error),
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime
                .block_on(migrate(&config))
                .map_or_else(fail, |_| ExitCode::SUCCESS)
        }
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .try_init();
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("ebpf-control-plane: {error}");
    ExitCode::FAILURE
}
