// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-agent` entry point.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use agent::{init_logging, run, AgentConfig};
use clap::{Parser, Subcommand};
use storage_local::{LocalStorage, StorageKey};
use tokio::sync::watch;

#[derive(Debug, Parser)]
#[command(name = "ebpf-agent", version, about = "eBPF node agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a 32-byte SQLCipher key.
    Keygen {
        /// Output path.
        #[arg(long, default_value = "/etc/ebpf-agent/storage.key")]
        out: PathBuf,
    },
    /// Create the local database and key.
    Init {
        /// Configuration file.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Use a test key and a temporary database.
        #[arg(long)]
        dev: bool,
    },
    /// Run the agent.
    Run {
        /// Configuration file.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Use a test key and a temporary database.
        #[arg(long)]
        dev: bool,
    },
    /// Print local storage status.
    Status {
        /// Configuration file.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Checkpoint local storage.
    Flush {
        /// Configuration file.
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { out } => match StorageKey::generate().save(&out) {
            Ok(()) => {
                println!("wrote {}", out.display());
                ExitCode::SUCCESS
            }
            Err(error) => fail(error),
        },
        Command::Init { config, dev } => match init(config, dev) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(error),
        },
        Command::Run { config, dev } => {
            init_logging();
            let config = match load(config, dev) {
                Ok(config) => config,
                Err(error) => return fail(error),
            };
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime
                .block_on(async move {
                    let (shutdown_tx, shutdown_rx) = watch::channel(false);
                    tokio::spawn(async move {
                        let mut sigterm = tokio::signal::unix::signal(
                            tokio::signal::unix::SignalKind::terminate(),
                        )
                        .expect("SIGTERM");
                        let mut sigint = tokio::signal::unix::signal(
                            tokio::signal::unix::SignalKind::interrupt(),
                        )
                        .expect("SIGINT");
                        tokio::select! {
                            _ = sigterm.recv() => {},
                            _ = sigint.recv() => {},
                        }
                        let _ = shutdown_tx.send(true);
                    });
                    run(config, shutdown_rx).await
                })
                .map_or_else(fail, |_| ExitCode::SUCCESS)
        }
        Command::Status { config } => match status(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(error),
        },
        Command::Flush { config } => match flush(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(error),
        },
    }
}

fn load(path: Option<PathBuf>, dev: bool) -> Result<AgentConfig, String> {
    let mut config = AgentConfig::load(path.as_deref()).map_err(|error| error.to_string())?;
    if dev {
        config.dev = true;
        if config.db_path == Path::new("/var/lib/ebpf-agent/outbox.db") {
            config.db_path = std::env::temp_dir().join("ebpf-agent-dev/outbox.db");
        }
        if config.key_path == Path::new("/etc/ebpf-agent/storage.key") {
            config.key_path = std::env::temp_dir().join("ebpf-agent-dev/storage.key");
        }
    }
    Ok(config)
}

fn init(path: Option<PathBuf>, dev: bool) -> Result<(), String> {
    let config = load(path, dev)?;
    if !config.key_path.exists() {
        StorageKey::generate()
            .save(&config.key_path)
            .map_err(|error| error.to_string())?;
        println!("generated {}", config.key_path.display());
    }
    let key = StorageKey::load(&config.key_path).map_err(|error| error.to_string())?;
    let storage = LocalStorage::open(&config.db_path, &key).map_err(|error| error.to_string())?;
    storage
        .run_migrations()
        .map_err(|error| error.to_string())?;
    println!("initialized {}", config.db_path.display());
    Ok(())
}

fn open(config: Option<PathBuf>) -> Result<(AgentConfig, Arc<LocalStorage>), String> {
    let config = load(config, false)?;
    let key = StorageKey::load(&config.key_path).map_err(|error| error.to_string())?;
    let storage = LocalStorage::open(&config.db_path, &key).map_err(|error| error.to_string())?;
    Ok((config, Arc::new(storage)))
}

fn status(path: Option<PathBuf>) -> Result<(), String> {
    let (config, storage) = open(path)?;
    let events = storage
        .query_events(1, None)
        .map_err(|error| error.to_string())?;
    let depth = storage.outbox_depth().map_err(|error| error.to_string())?;
    println!(
        "{} agent={} cluster={} outbox={} newest_event={}",
        config.db_path.display(),
        if config.agent_id.is_empty() {
            "generated"
        } else {
            &config.agent_id
        },
        config.cluster,
        depth,
        events
            .first()
            .map_or("none", |event| event.event_id.as_str())
    );
    Ok(())
}

fn flush(path: Option<PathBuf>) -> Result<(), String> {
    let (_config, storage) = open(path)?;
    storage.checkpoint().map_err(|error| error.to_string())?;
    println!("checkpointed");
    Ok(())
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("ebpf-agent: {error}");
    ExitCode::FAILURE
}
