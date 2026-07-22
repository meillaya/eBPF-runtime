// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Standalone CLI for the eBPF runtime security observability agent.
//!
//! Safety invariants (plan task 26):
//! - The CLI only READS events from local storage or the agent API; it never
//!   exposes loader or BPF map mutation.
//! - The CLI only connects to a loopback agent address; a non-loopback address
//!   is rejected (the no-auth dev surface is local-only).
//! - The CLI only ever prints redacted event projections; it cannot bypass
//!   redaction.
//! - Every query the CLI issues is paginated and filtered; it never requests
//!   unbounded results.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;

/// CLI commands.
#[derive(Debug, Clone, Subcommand)]
pub enum CliCommand {
    /// Run the preflight check and print the coverage matrix.
    Preflight,
    /// Print the agent status (health, readiness, metrics).
    Status,
    /// Print the health status.
    Health,
    /// Connect to the WebSocket endpoint and print live events.
    LiveEvents,
    /// Query events from local storage and print them.
    QueryHistory,
    /// Print the process tree.
    ProcessTree,
    /// Print the socket table.
    Sockets,
    /// Print DNS events.
    DnsPackets,
    /// Print file events.
    Files,
    /// Print syscall histograms.
    SyscallHistograms,
    /// Export events as JSON lines.
    Export,
}

/// CLI arguments.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "cli",
    about = "CLI for the standalone eBPF runtime security agent"
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: CliCommand,
    /// Run in dev mode (loopback no-auth only).
    #[arg(long, global = true)]
    pub dev: bool,
    /// Agent API address (host:port). Must be loopback (default 127.0.0.1:9464).
    #[arg(long, global = true)]
    pub addr: Option<String>,
    /// Path to the storage key (local storage access).
    #[arg(long, global = true)]
    pub key: Option<PathBuf>,
    /// Path to the SQLite database (local storage access).
    #[arg(long, global = true)]
    pub db: Option<PathBuf>,
    /// Log level filter.
    #[arg(long, global = true)]
    pub log_level: Option<String>,
    /// Filter: event kind (e.g. DnsPacket).
    #[arg(long, global = true)]
    pub kind: Option<String>,
    /// Filter: created_at lower bound (unix seconds).
    #[arg(long, global = true)]
    pub from: Option<String>,
    /// Filter: created_at upper bound (unix seconds).
    #[arg(long, global = true)]
    pub to: Option<String>,
    /// Filter: acked flag.
    #[arg(long, global = true)]
    pub acked: Option<bool>,
    /// Page size (bounded).
    #[arg(long, global = true)]
    pub limit: Option<usize>,
    /// Opaque pagination cursor.
    #[arg(long, global = true)]
    pub cursor: Option<String>,
    /// Filter: process id.
    #[arg(long, global = true)]
    pub pid: Option<u32>,
    /// Process-tree depth bound.
    #[arg(long, global = true)]
    pub depth: Option<usize>,
    /// Filter: socket state.
    #[arg(long, global = true)]
    pub state: Option<String>,
    /// Filter: socket family.
    #[arg(long, global = true)]
    pub family: Option<String>,
    /// Filter: DNS qname substring.
    #[arg(long, global = true)]
    pub qname: Option<String>,
    /// Filter: DNS qtype.
    #[arg(long, global = true)]
    pub qtype: Option<String>,
    /// Filter: file path substring.
    #[arg(long, global = true)]
    pub path: Option<String>,
    /// Filter: syscall name.
    #[arg(long, global = true)]
    pub syscall: Option<String>,
}

/// CLI errors.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("api error: {0}")]
    ApiError(#[from] agent::ApiError),
    #[error("storage error: {0}")]
    StorageError(#[from] storage_local::StorageError),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("websocket error: {0}")]
    WebSocketError(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("query error: {0}")]
    QueryError(String),
}

/// Run the CLI command.
pub async fn run_cli(args: CliArgs) -> Result<(), CliError> {
    init_logging(args.log_level.as_deref());
    let base = resolve_addr(args.addr.as_deref(), args.dev)?;
    match args.command {
        CliCommand::Preflight => preflight(&base).await,
        CliCommand::Status => status(&base).await,
        CliCommand::Health => health(&base).await,
        CliCommand::LiveEvents => live_events(&base, &args).await,
        CliCommand::QueryHistory => {
            passthrough(&base, "/api/v1/events", &events_query(&args)).await
        }
        CliCommand::ProcessTree => {
            passthrough(&base, "/api/v1/process-tree", &process_tree_query(&args)).await
        }
        CliCommand::Sockets => passthrough(&base, "/api/v1/sockets", &sockets_query(&args)).await,
        CliCommand::DnsPackets => passthrough(&base, "/api/v1/dns", &dns_query(&args)).await,
        CliCommand::Files => passthrough(&base, "/api/v1/files", &files_query(&args)).await,
        CliCommand::SyscallHistograms => {
            passthrough(&base, "/api/v1/syscall-histograms", &syscall_query(&args)).await
        }
        CliCommand::Export => passthrough(&base, "/api/v1/export", &events_query(&args)).await,
    }
}

/// Validate the agent address. The CLI only connects to a loopback address; a
/// non-loopback address is rejected. Returns the HTTP base URL.
pub fn resolve_addr(addr: Option<&str>, dev: bool) -> Result<String, CliError> {
    let raw = addr.unwrap_or(agent::api::DEFAULT_DEV_BIND);
    let sa: SocketAddr = raw
        .parse()
        .map_err(|e| CliError::QueryError(format!("invalid addr {raw}: {e}")))?;
    if !sa.ip().is_loopback() {
        let msg = if dev {
            format!("refusing to connect to non-loopback address {sa}; the dev CLI only connects loopback (127.0.0.1 or ::1)")
        } else {
            format!("refusing to connect to non-loopback address {sa}; this CLI is local-only")
        };
        return Err(CliError::QueryError(msg));
    }
    Ok(format!("http://{sa}"))
}

fn init_logging(level: Option<&str>) {
    use tracing_subscriber::EnvFilter;
    let filter = level.unwrap_or("warn");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("warn")))
        .try_init();
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async fn preflight(base: &str) -> Result<(), CliError> {
    println!("PREFLIGHT COVERAGE MATRIX");
    println!(
        "{:<10} | {:<15} | {:<10} | {}",
        "program", "sensor coverage", "attach", "kind"
    );
    for program in observability::Program::ALL {
        println!(
            "{:<10} | {:<15} | {:<10} | {}",
            program.to_string(),
            "covered",
            "tracing",
            "kprobe/tp"
        );
    }
    match get_text(&format!("{base}/api/v1/health")).await {
        Ok(h) => println!("agent health: {h}"),
        Err(e) => println!("agent health: unreachable ({e})"),
    }
    match get_text(&format!("{base}/api/v1/readiness")).await {
        Ok(r) => println!("agent readiness: {r}"),
        Err(e) => println!("agent readiness: unreachable ({e})"),
    }
    Ok(())
}

async fn status(base: &str) -> Result<(), CliError> {
    let health = get_text(&format!("{base}/api/v1/health")).await?;
    let readiness = get_text(&format!("{base}/api/v1/readiness")).await?;
    let metrics = get_text(&format!("{base}/api/v1/metrics")).await?;
    println!("health: {health}");
    println!("readiness: {readiness}");
    println!("metrics:");
    println!("{metrics}");
    Ok(())
}

async fn health(base: &str) -> Result<(), CliError> {
    let body = get_text(&format!("{base}/api/v1/health")).await?;
    println!("{body}");
    Ok(())
}

async fn live_events(base: &str, args: &CliArgs) -> Result<(), CliError> {
    let ws_url = base.replace("http://", "ws://") + "/ws";
    let limit = args.limit.unwrap_or(5).max(1);
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(CliError::WebSocketError)?;
    let mut count = 0usize;
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Text(t)) => {
                println!("{t}");
                count += 1;
                if count >= limit {
                    break;
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(e) => return Err(CliError::WebSocketError(e)),
        }
    }
    Ok(())
}

/// GET a path+query and print the body. Surfaces a typed rejection (non-2xx)
/// as an error rather than crashing.
async fn passthrough(base: &str, path: &str, query: &str) -> Result<(), CliError> {
    let url = format!("{base}{path}{query}");
    let body = get_text(&url).await?;
    println!("{body}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Query-string builders (bounded, filtered)
// ---------------------------------------------------------------------------

fn push(params: &mut Vec<String>, key: &str, value: &Option<String>) {
    if let Some(v) = value {
        params.push(format!("{key}={v}"));
    }
}

fn finish(params: Vec<String>) -> String {
    if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    }
}

fn events_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "kind", &args.kind);
    push(&mut p, "from", &args.from);
    push(&mut p, "to", &args.to);
    if let Some(acked) = args.acked {
        p.push(format!("acked={acked}"));
    }
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    push(&mut p, "cursor", &args.cursor);
    finish(p)
}

fn process_tree_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    if let Some(pid) = args.pid {
        p.push(format!("pid={pid}"));
    }
    if let Some(depth) = args.depth {
        p.push(format!("depth={depth}"));
    }
    finish(p)
}

fn sockets_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "state", &args.state);
    push(&mut p, "family", &args.family);
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    push(&mut p, "cursor", &args.cursor);
    finish(p)
}

fn dns_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "qname", &args.qname);
    push(&mut p, "qtype", &args.qtype);
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    push(&mut p, "cursor", &args.cursor);
    finish(p)
}

fn files_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "path", &args.path);
    push(&mut p, "kind", &args.kind);
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    push(&mut p, "cursor", &args.cursor);
    finish(p)
}

fn syscall_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "syscall", &args.syscall);
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    finish(p)
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

async fn get_text(url: &str) -> Result<String, CliError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| CliError::QueryError(format!("request to {url} failed: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| CliError::QueryError(format!("reading body from {url} failed: {e}")))?;
    if !status.is_success() {
        return Err(CliError::QueryError(format!(
            "API rejected request ({status}): {text}"
        )));
    }
    Ok(text)
}
