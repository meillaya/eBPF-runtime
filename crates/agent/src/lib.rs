// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Standalone node service for the eBPF runtime security observability
//! platform (plan task 26).
//!
//! The agent reads events from the ring buffer (simulated in this task),
//! applies the mandatory privacy redaction stage, inserts the redacted events
//! into encrypted local storage, and exports them through the versioned local
//! REST/WebSocket API ([`api`]).
//!
//! Safety invariants (plan task 26):
//! - The agent NEVER exposes loader or BPF map mutation; it only reads events
//!   and exports redacted projections.
//! - The agent NEVER binds the no-auth surface to a non-loopback address; the
//!   dev surface only binds `127.0.0.1` / `::1`. A non-loopback bind is
//!   rejected by a strict check.
//! - The agent NEVER bypasses redaction; every event passes through
//!   [`privacy::apply_redaction`] before persistence or export.
//! - The agent NEVER returns unbounded results; every query is paginated and
//!   filtered (see [`api`]).

pub mod api;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_core::{
    normalize_bytes, synthetic_record, EventId, Kind, MonotonicNs, NormalizedEvent, PidTgid,
    RawEvent, Sequence,
};
use observability::MetricsRegistry;
use privacy::{apply_redaction, DecodedDns, DecodedRecord, RedactionPolicy};
use storage_local::{load_key_from_file, test_key, LocalStorage, StorageKey, DEFAULT_KEY_PATH};
use tokio::sync::broadcast;

pub use api::{ApiError, ApiErrorKind, ApiServer};

/// Default drain/flush timeout in milliseconds (mirrors
/// `bench/schemas/storage.v1.json#default_drain_timeout_ms`).
pub const DEFAULT_DRAIN_TIMEOUT_MS: u64 = 10000;
/// Number of simulated events seeded at startup (bounded).
pub const SIMULATED_EVENT_COUNT: usize = 64;
/// Environment override for the drain timeout (used by tests).
pub const DRAIN_TIMEOUT_ENV: &str = "EBPF_AGENT_DRAIN_TIMEOUT_MS";
/// Environment override that simulates a slow drain (used by tests).
pub const SLOW_DRAIN_ENV: &str = "EBPF_AGENT_SLOW_DRAIN_MS";

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

/// Command-line arguments for the standalone agent.
#[derive(Debug, Clone, clap::Parser)]
#[command(
    name = "agent",
    about = "Standalone eBPF runtime security node service (local REST/WebSocket API)"
)]
pub struct AgentArgs {
    /// Run in dev mode. The no-auth surface only ever binds a loopback address.
    #[arg(long)]
    pub dev: bool,
    /// Listen address (host:port). Must be loopback (default 127.0.0.1:9464).
    #[arg(long)]
    pub listen: Option<String>,
    /// Path to the 32-byte SQLCipher storage key file.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Path to the SQLite database file.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// Log level filter (e.g. "info", "debug", "trace").
    #[arg(long)]
    pub log_level: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the agent loop.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("storage error: {0}")]
    StorageError(#[from] storage_local::StorageError),
    #[error("observability error: {0}")]
    ObservabilityError(#[from] observability::ObservabilityError),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("signal error: {0}")]
    SignalError(std::io::Error),
    #[error("drain/flush exceeded the configured timeout")]
    TimeoutError,
}

// ---------------------------------------------------------------------------
// Shutdown coordination
// ---------------------------------------------------------------------------

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_NOTIFY: std::sync::LazyLock<tokio::sync::Notify> =
    std::sync::LazyLock::new(tokio::sync::Notify::new);

/// Request a graceful shutdown. This is the same coordination channel that
/// SIGTERM/SIGINT feed, exposed so tests and embeds can trigger a drain
/// deterministically.
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    SHUTDOWN_NOTIFY.notify_waiters();
}

/// Clear the shutdown latch (used at the start of each `run_agent` invocation
/// so a stale request from a previous run does not short-circuit a fresh one).
pub fn reset_shutdown() {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
}

fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Agent loop
// ---------------------------------------------------------------------------

/// Run the standalone agent: validate the bind address, open encrypted local
/// storage, start the local REST/WebSocket API, ingest a bounded stream of
/// simulated redacted events, and on SIGTERM/SIGINT drain the ring buffer and
/// flush local storage within the configured timeout.
pub async fn run_agent(args: AgentArgs) -> Result<(), AgentError> {
    init_logging(args.log_level.as_deref());
    reset_shutdown();

    // Strict loopback check BEFORE any bind.
    let addr = validate_listen(args.listen.as_deref(), args.dev)?;

    let key = load_storage_key(args.key.as_deref(), args.dev)?;
    let db_path = args.db.clone().unwrap_or_else(|| default_db_path(args.dev));
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let storage = Arc::new(LocalStorage::open(&db_path, &key)?);
    storage.run_migrations()?;

    let registry = Arc::new(MetricsRegistry::new());
    registry.set_storage_available(true);

    let server = Arc::new(ApiServer::new(storage.clone(), registry.clone(), addr));
    let broadcaster = server.broadcaster();

    let policy = RedactionPolicy::with_default_secrets();
    // Seed BEFORE serving so the API never reports healthy on an empty store.
    seed_simulated_events(&storage, &broadcaster, &policy)?;

    let server_task = server.clone();
    let server_handle = tokio::spawn(async move { server_task.serve().await });

    // Background bounded drip so live WebSocket consumers receive events.
    let drip_handle = {
        let storage = storage.clone();
        let broadcaster = broadcaster.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            let base = match normalize_bytes(&synthetic_record(0)) {
                Ok(b) => b,
                Err(_) => return,
            };
            let mut i = 100_000usize;
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let ev = make_event(&base, i);
                i += 1;
                let redacted = apply_redaction(&ev, &policy);
                if storage.insert_event(&redacted).is_ok() {
                    let _ = broadcaster
                        .send(serde_json::to_string(&redacted.to_json()).unwrap_or_default());
                }
            }
        })
    };

    // Wait for SIGTERM / SIGINT / request_shutdown().
    wait_for_shutdown().await;

    // Drain + flush within the configured timeout.
    let timeout = drain_timeout();
    let drain_storage = storage.clone();
    let drain_result =
        tokio::time::timeout(timeout, async move { drain_and_flush(&drain_storage).await }).await;

    drip_handle.abort();
    server_handle.abort();

    match drain_result {
        Ok(Ok(())) => {
            tracing::info!("agent shut down cleanly");
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => {
            tracing::error!(timeout_ms = timeout.as_millis() as u64, "drain/flush timed out");
            Err(AgentError::TimeoutError)
        }
    }
}

/// Validate the listen address. The standalone service is local-only: it only
/// ever binds a loopback address. A non-loopback bind (e.g. `0.0.0.0:8080`) is
/// rejected by a strict check.
pub fn validate_listen(listen: Option<&str>, dev: bool) -> Result<std::net::SocketAddr, AgentError> {
    let raw = listen.unwrap_or(api::DEFAULT_DEV_BIND);
    let addr: std::net::SocketAddr = raw.parse().map_err(|e| {
        AgentError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid listen address {raw}: {e}"),
        ))
    })?;
    if !addr.ip().is_loopback() {
        let kind = std::io::ErrorKind::PermissionDenied;
        let msg = if dev {
            format!(
                "refusing no-auth dev bind to non-loopback address {addr}; the dev surface only binds loopback (127.0.0.1 or ::1)"
            )
        } else {
            format!("refusing to bind non-loopback address {addr}; this service is local-only")
        };
        return Err(AgentError::IoError(std::io::Error::new(kind, msg)));
    }
    Ok(addr)
}

/// Load the storage key. The key is NEVER stored in the DB, config, or log.
/// In dev mode, when no key file is present, an injected dev key is used so the
/// standalone service can run unprivileged.
pub fn load_storage_key(key_path: Option<&Path>, dev: bool) -> Result<StorageKey, AgentError> {
    if let Some(p) = key_path {
        return Ok(load_key_from_file(p)?);
    }
    let default = PathBuf::from(DEFAULT_KEY_PATH);
    if default.exists() {
        return Ok(load_key_from_file(&default)?);
    }
    if dev {
        tracing::warn!("no storage key at {DEFAULT_KEY_PATH}; using injected dev key (dev mode)");
        return Ok(test_key());
    }
    Err(storage_local::StorageError::KeyFileMissing.into())
}

fn default_db_path(dev: bool) -> PathBuf {
    if dev {
        std::env::temp_dir()
            .join("ebpf-agent-dev")
            .join("outbox.db")
    } else {
        PathBuf::from("/var/lib/ebpf-agent/outbox.db")
    }
}

/// Initialize tracing logging once. Idempotent across repeated calls (tests).
pub fn init_logging(level: Option<&str>) {
    use tracing_subscriber::EnvFilter;
    let filter = level.unwrap_or("info");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}

/// Wait for SIGTERM, SIGINT, or a programmatic shutdown request.
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    loop {
        if shutdown_requested() {
            tracing::info!("shutdown request observed; draining");
            return;
        }
        tokio::select! {
            _ = sigterm.recv() => { tracing::info!("SIGTERM received; draining"); return; }
            _ = sigint.recv() => { tracing::info!("SIGINT received; draining"); return; }
            _ = SHUTDOWN_NOTIFY.notified() => { tracing::info!("shutdown notified; draining"); return; }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

/// Drain the ring buffer and flush local storage. In this simulated design
/// events are inserted synchronously, so draining means ensuring no in-flight
/// inserts remain and then checkpointing (truncating) the WAL.
async fn drain_and_flush(storage: &LocalStorage) -> Result<(), AgentError> {
    // Test hook: simulate a slow drain to exercise the timeout path.
    if let Ok(ms) = std::env::var(SLOW_DRAIN_ENV) {
        if let Ok(ms) = ms.parse::<u64>() {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
    }
    storage.checkpoint()?;
    tracing::info!("drained ring buffer and flushed (checkpointed) local storage");
    Ok(())
}

/// The configured drain/flush timeout (schema default 10000ms, env-overridable
/// for tests).
pub fn drain_timeout() -> Duration {
    let ms = std::env::var(DRAIN_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_DRAIN_TIMEOUT_MS);
    Duration::from_millis(ms)
}

// ---------------------------------------------------------------------------
// Simulated event source (this task only — the ring buffer is simulated)
// ---------------------------------------------------------------------------

/// Seed a bounded burst of simulated, redacted events into storage and publish
/// each to the live-event broadcaster.
pub fn seed_simulated_events(
    storage: &LocalStorage,
    broadcaster: &broadcast::Sender<String>,
    policy: &RedactionPolicy,
) -> Result<(), AgentError> {
    let base = normalize_bytes(&synthetic_record(0)).map_err(|e| {
        AgentError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("synthetic record failed to decode: {e}"),
        ))
    })?;
    for i in 0..SIMULATED_EVENT_COUNT {
        let ev = make_event(&base, i);
        let redacted = apply_redaction(&ev, policy);
        storage.insert_event(&redacted)?;
        let _ = broadcaster.send(serde_json::to_string(&redacted.to_json()).unwrap_or_default());
    }
    Ok(())
}

/// Build `count` simulated normalized events from a decoded base record.
pub fn simulated_events(base: &NormalizedEvent, count: usize) -> Vec<NormalizedEvent> {
    (0..count).map(|i| make_event(base, i)).collect()
}

/// Build a single simulated normalized event for index `i`, cycling through
/// event kinds and encoding a bounded [`DecodedRecord`] as the raw payload (the
/// shape [`privacy::decode_record`] consumes).
pub fn make_event(base: &NormalizedEvent, i: usize) -> NormalizedEvent {
    const KINDS: [Kind; 11] = [
        Kind::ProcessFork,
        Kind::ProcessExecResult,
        Kind::ProcessExit,
        Kind::FileOpen,
        Kind::FileCreate,
        Kind::FileUnlink,
        Kind::NetworkConnect,
        Kind::NetworkAccept,
        Kind::DnsPacket,
        Kind::SyscallEnter,
        Kind::SyscallExit,
    ];
    let mut e = base.clone();
    let kind = KINDS[i % KINDS.len()];
    e.kind = kind;
    e.sequence = Sequence(i as u64);
    e.monotonic_ns = MonotonicNs((i as u64).saturating_mul(1_000_000));
    // Unique kernel event id per simulated event (the cloned base record would
    // otherwise reuse a single event id for every event). Offset by one so no
    // event carries the degenerate all-zero id.
    let idx = (i as u64) + 1;
    let mut id_bytes = [0u8; 16];
    id_bytes[..8].copy_from_slice(&idx.to_le_bytes());
    id_bytes[8..].copy_from_slice(&(idx.wrapping_mul(0x9E37_79B1_85EB_CA87)).to_le_bytes());
    e.event_id = EventId(id_bytes);
    let pid = 1000 + (i as u64 % 8);
    e.namespaces.pid = Some(pid);
    e.pid_tgid = PidTgid((pid << 32) | pid);
    let record = decoded_for(kind, i);
    let payload = serde_json::to_vec(&record).unwrap_or_default();
    e.raw = RawEvent {
        payload: payload.into_boxed_slice(),
    };
    e
}

fn decoded_for(kind: Kind, i: usize) -> DecodedRecord {
    const SYSCALLS: [&str; 5] = ["read", "write", "openat", "close", "execve"];
    let mut r = DecodedRecord::default();
    match kind {
        Kind::ProcessFork | Kind::ProcessExecResult | Kind::ProcessExit => {
            let path = format!("/usr/bin/proc{}", i % 4);
            r.argv = vec![path.clone(), format!("--arg={i}")];
            r.path = path;
        }
        Kind::FileOpen
        | Kind::FileCreate
        | Kind::FileUnlink
        | Kind::FileRename
        | Kind::FileTruncate => {
            let path = format!("/var/data/file{}.txt", i % 5);
            r.arguments = vec![path.clone()];
            r.path = path;
        }
        Kind::NetworkConnect | Kind::NetworkAccept | Kind::NetworkState => {
            r.path = format!("10.0.0.{}:{}", (i % 5) + 1, 4000 + (i % 100));
            r.arguments = vec!["inet".to_string(), "established".to_string()];
        }
        Kind::DnsPacket => {
            r.dns = Some(DecodedDns {
                qname: format!("host{}.example.com", i % 3),
                qtype: 1,
                qclass: 1,
                an_count: 1,
                rdata: vec![format!("10.0.0.{}", (i % 5) + 1)],
            });
        }
        Kind::SyscallEnter | Kind::SyscallExit => {
            r.arguments = vec![SYSCALLS[i % SYSCALLS.len()].to_string()];
        }
        _ => {}
    }
    r.message = format!("simulated {kind:?} event {i}");
    r
}
