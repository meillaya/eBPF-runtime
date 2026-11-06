// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpfctl` entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use cli::{load_config, save_token, Client};

#[derive(Debug, Parser)]
#[command(name = "ebpfctl", version, about = "eBPF fleet CLI")]
struct Cli {
    /// Configuration file.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Save a bearer token for later requests.
    Login {
        /// Token value. Prefer EBPF_TOKEN for scripts.
        token: String,
    },
    /// List agents.
    Agents,
    /// List recent events.
    Events {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// List policy versions.
    Policies,
    /// Stage a policy YAML file.
    Stage {
        /// YAML file.
        file: PathBuf,
        /// Policy version.
        #[arg(long)]
        version: i64,
        /// Policy name.
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Commit a policy version.
    Commit {
        /// Policy version.
        version: i64,
    },
    /// Show policy acknowledgements.
    Acks {
        /// Policy version.
        version: i64,
    },
    /// List audit rows.
    Audit,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = match load_config(cli.config.as_deref()) {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    if let Command::Login { token } = &cli.command {
        return match save_token(&config.token_path, token) {
            Ok(()) => {
                println!("saved {}", config.token_path.display());
                ExitCode::SUCCESS
            }
            Err(error) => fail(error),
        };
    }
    let client = match Client::from_config(&config) {
        Ok(client) => client,
        Err(error) => return fail(error),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(run(cli.command, client))
}

async fn run(command: Command, client: Client) -> ExitCode {
    let result = match command {
        Command::Login { .. } => unreachable!(),
        Command::Agents => client.get("/agents").await,
        Command::Events { limit } => {
            client
                .get(&format!("/events?limit={}", limit.clamp(1, 1000)))
                .await
        }
        Command::Policies => client.get("/policies").await,
        Command::Stage {
            file,
            version,
            name,
        } => {
            let content = match std::fs::read_to_string(&file) {
                Ok(content) => content,
                Err(error) => return fail(error),
            };
            client
                .post(
                    "/policies/stage",
                    serde_json::json!({"version": version, "content": content, "name": name}),
                )
                .await
        }
        Command::Commit { version } => {
            client
                .post("/policies/commit", serde_json::json!({"version": version}))
                .await
        }
        Command::Acks { version } => client.get(&format!("/policies/{version}/acks")).await,
        Command::Audit => client.get("/audit").await,
    };
    match result {
        Ok(value) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("ebpfctl: {error}");
    ExitCode::FAILURE
}
