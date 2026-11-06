// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-bench` entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use bench::{run, BenchConfig};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "ebpf-bench", version, about = "Fleet ingest benchmark gate")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:9443")]
    endpoint: String,
    #[arg(long)]
    insecure: bool,
    #[arg(long, default_value = "control-plane")]
    domain_name: String,
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    #[arg(long, default_value = "bench")]
    cluster: String,
    #[arg(long, default_value = "bench-node")]
    node_name: String,
    #[arg(long)]
    agent_id: Option<String>,
    #[arg(long, default_value_t = 10_000)]
    events: usize,
    #[arg(long, default_value_t = 500)]
    batch_size: usize,
    #[arg(long, default_value_t = 2)]
    warmup: usize,
    #[arg(long, default_value_t = 250.0)]
    max_p99_ms: f64,
    #[arg(long, default_value_t = 5000.0)]
    min_events_per_sec: f64,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = BenchConfig {
        endpoint: cli.endpoint,
        insecure: cli.insecure,
        domain_name: cli.domain_name,
        ca_path: cli
            .ca
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        cert_path: cli
            .cert
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        key_path: cli
            .key
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        cluster: cli.cluster,
        node_name: cli.node_name,
        agent_id: cli
            .agent_id
            .unwrap_or_else(|| format!("bench-{}", uuid::Uuid::new_v4())),
        events: cli.events,
        batch_size: cli.batch_size,
        warmup: cli.warmup,
        max_p99_ms: cli.max_p99_ms,
        min_events_per_sec: cli.min_events_per_sec,
    };
    match run(&config).await {
        Ok(result) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ebpf-bench: {error}");
            ExitCode::FAILURE
        }
    }
}
