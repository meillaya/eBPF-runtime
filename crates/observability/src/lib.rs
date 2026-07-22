// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Structured health, compatibility, loss, and low-cardinality Prometheus
//! metrics for the eBPF runtime security agent.
//!
//! All metric labels use bounded enums. Process/container/pod/path IDs belong
//! in events, not metric labels. The registry never logs secrets or raw
//! records. Readiness never declares ready before required sensors and storage
//! attach.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod logging;
pub mod server;

use std::collections::BTreeMap;
use std::fmt;

use parking_lot::Mutex;
use prometheus::{
    Encoder, Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry, TextEncoder,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Bounded label enums — the cardinality guarantee
// ---------------------------------------------------------------------------

/// Bounded enum for event sources. Exactly six values; no unbounded strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Source {
    Process,
    File,
    Network,
    Dns,
    Syscall,
    Identity,
}

impl Source {
    /// All variants in canonical order.
    pub const ALL: [Source; 6] = [
        Source::Process,
        Source::File,
        Source::Network,
        Source::Dns,
        Source::Syscall,
        Source::Identity,
    ];
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Source::Process => "process",
            Source::File => "file",
            Source::Network => "network",
            Source::Dns => "dns",
            Source::Syscall => "syscall",
            Source::Identity => "identity",
        })
    }
}

/// Bounded enum for drop reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DropReason {
    RingFull,
    ChannelFull,
    DecodeError,
    PolicyDrop,
    EnrichmentError,
}

impl DropReason {
    pub const ALL: [DropReason; 5] = [
        DropReason::RingFull,
        DropReason::ChannelFull,
        DropReason::DecodeError,
        DropReason::PolicyDrop,
        DropReason::EnrichmentError,
    ];
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DropReason::RingFull => "ring_full",
            DropReason::ChannelFull => "channel_full",
            DropReason::DecodeError => "decode_error",
            DropReason::PolicyDrop => "policy_drop",
            DropReason::EnrichmentError => "enrichment_error",
        })
    }
}

/// Bounded enum for internal channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Channel {
    Data,
    Control,
}

impl Channel {
    pub const ALL: [Channel; 2] = [Channel::Data, Channel::Control];
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Channel::Data => "data",
            Channel::Control => "control",
        })
    }
}

/// Bounded enum for caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cache {
    ProcessGraph,
    SocketTable,
    Enrichment,
}

impl Cache {
    pub const ALL: [Cache; 3] = [Cache::ProcessGraph, Cache::SocketTable, Cache::Enrichment];
}

impl fmt::Display for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Cache::ProcessGraph => "process_graph",
            Cache::SocketTable => "socket_table",
            Cache::Enrichment => "enrichment",
        })
    }
}

/// Bounded enum for BPF programs (one per sensor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Program {
    Process,
    File,
    Network,
    Dns,
    Syscall,
    Identity,
}

impl Program {
    pub const ALL: [Program; 6] = [
        Program::Process,
        Program::File,
        Program::Network,
        Program::Dns,
        Program::Syscall,
        Program::Identity,
    ];
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Program::Process => "process",
            Program::File => "file",
            Program::Network => "network",
            Program::Dns => "dns",
            Program::Syscall => "syscall",
            Program::Identity => "identity",
        })
    }
}

/// Bounded enum for enrichment providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Provider {
    Containerd,
    Crio,
    Docker,
    Kubernetes,
}

impl Provider {
    pub const ALL: [Provider; 4] = [
        Provider::Containerd,
        Provider::Crio,
        Provider::Docker,
        Provider::Kubernetes,
    ];
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Provider::Containerd => "containerd",
            Provider::Crio => "crio",
            Provider::Docker => "docker",
            Provider::Kubernetes => "kubernetes",
        })
    }
}

/// Bounded enum for syscall names tracked in the latency histogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Syscall {
    Read,
    Write,
    Open,
    Openat,
    Close,
    Execve,
    Fork,
    Clone,
    Kill,
    Socket,
    Connect,
    Accept,
    Bind,
    Listen,
    Sendto,
    Recvfrom,
    Unlink,
    Rename,
    Mkdir,
    Rmdir,
}

impl Syscall {
    pub const ALL: [Syscall; 20] = [
        Syscall::Read,
        Syscall::Write,
        Syscall::Open,
        Syscall::Openat,
        Syscall::Close,
        Syscall::Execve,
        Syscall::Fork,
        Syscall::Clone,
        Syscall::Kill,
        Syscall::Socket,
        Syscall::Connect,
        Syscall::Accept,
        Syscall::Bind,
        Syscall::Listen,
        Syscall::Sendto,
        Syscall::Recvfrom,
        Syscall::Unlink,
        Syscall::Rename,
        Syscall::Mkdir,
        Syscall::Rmdir,
    ];
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Syscall::Read => "read",
            Syscall::Write => "write",
            Syscall::Open => "open",
            Syscall::Openat => "openat",
            Syscall::Close => "close",
            Syscall::Execve => "execve",
            Syscall::Fork => "fork",
            Syscall::Clone => "clone",
            Syscall::Kill => "kill",
            Syscall::Socket => "socket",
            Syscall::Connect => "connect",
            Syscall::Accept => "accept",
            Syscall::Bind => "bind",
            Syscall::Listen => "listen",
            Syscall::Sendto => "sendto",
            Syscall::Recvfrom => "recvfrom",
            Syscall::Unlink => "unlink",
            Syscall::Rename => "rename",
            Syscall::Mkdir => "mkdir",
            Syscall::Rmdir => "rmdir",
        })
    }
}

/// Bounded enum for BPF program attach state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttachState {
    Attached,
    Detached,
    Degraded,
}

impl AttachState {
    /// Numeric encoding for the Prometheus gauge: 2=attached, 1=degraded, 0=detached.
    pub fn as_metric_value(self) -> i64 {
        match self {
            AttachState::Attached => 2,
            AttachState::Degraded => 1,
            AttachState::Detached => 0,
        }
    }
}

impl fmt::Display for AttachState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AttachState::Attached => "attached",
            AttachState::Detached => "detached",
            AttachState::Degraded => "degraded",
        })
    }
}

/// Bounded enum for enrichment provider status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnrichmentState {
    Available,
    Unavailable,
    Degraded,
}

impl EnrichmentState {
    /// Numeric encoding: 2=available, 1=degraded, 0=unavailable.
    pub fn as_metric_value(self) -> i64 {
        match self {
            EnrichmentState::Available => 2,
            EnrichmentState::Degraded => 1,
            EnrichmentState::Unavailable => 0,
        }
    }
}

impl fmt::Display for EnrichmentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EnrichmentState::Available => "available",
            EnrichmentState::Unavailable => "unavailable",
            EnrichmentState::Degraded => "degraded",
        })
    }
}

/// Bounded enum for policy enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyMode {
    Audit,
    Enforce,
}

impl PolicyMode {
    /// Numeric encoding: 0=audit, 1=enforce.
    pub fn as_metric_value(self) -> i64 {
        match self {
            PolicyMode::Audit => 0,
            PolicyMode::Enforce => 1,
        }
    }
}

impl fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PolicyMode::Audit => "audit",
            PolicyMode::Enforce => "enforce",
        })
    }
}

// ---------------------------------------------------------------------------
// Health and readiness types
// ---------------------------------------------------------------------------

/// Overall health state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

impl fmt::Display for HealthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HealthState::Healthy => "healthy",
            HealthState::Degraded => "degraded",
            HealthState::Unhealthy => "unhealthy",
        })
    }
}

/// Health status with reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: HealthState,
    pub reasons: Vec<String>,
}

/// Readiness state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadinessState {
    Ready,
    NotReady,
}

impl fmt::Display for ReadinessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReadinessState::Ready => "ready",
            ReadinessState::NotReady => "not_ready",
        })
    }
}

/// Readiness status with reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessStatus {
    pub status: ReadinessState,
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error kind for the observability subsystem.
#[derive(Debug)]
pub enum ObservabilityErrorKind {
    BindError(std::io::Error),
    ServeError(hyper::Error),
    MetricsError(prometheus::Error),
    LoggingError(String),
}

impl fmt::Display for ObservabilityErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObservabilityErrorKind::BindError(e) => write!(f, "bind error: {e}"),
            ObservabilityErrorKind::ServeError(e) => write!(f, "serve error: {e}"),
            ObservabilityErrorKind::MetricsError(e) => write!(f, "metrics error: {e}"),
            ObservabilityErrorKind::LoggingError(e) => write!(f, "logging error: {e}"),
        }
    }
}

/// Observability error wrapping a kind.
#[derive(Debug)]
pub struct ObservabilityError {
    pub kind: ObservabilityErrorKind,
}

impl fmt::Display for ObservabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}

impl std::error::Error for ObservabilityError {}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Mutable internal state tracked for health/readiness computation.
struct RegistryState {
    /// Attach state per BPF program.
    program_states: BTreeMap<Program, AttachState>,
    /// Whether storage (SQLite) is available.
    storage_available: bool,
}

impl RegistryState {
    fn new() -> Self {
        let mut program_states = BTreeMap::new();
        for program in Program::ALL {
            program_states.insert(program, AttachState::Detached);
        }
        Self {
            program_states,
            storage_available: false,
        }
    }
}

// ---------------------------------------------------------------------------
// MetricsRegistry
// ---------------------------------------------------------------------------

/// The canonical metrics registry. Wraps a `prometheus::Registry` and exposes
/// bounded-cardinality metrics for the eBPF runtime security agent.
///
/// All metric labels use bounded enums. Process/container/pod/path IDs belong
/// in events, not metric labels. The registry never logs secrets or raw
/// records.
pub struct MetricsRegistry {
    registry: Registry,
    state: Mutex<RegistryState>,

    // Program attach state
    program_attach_state: IntGaugeVec,

    // Source metrics
    source_attempts_total: IntCounterVec,
    source_drops_total: IntCounterVec,
    source_gaps_total: IntCounterVec,

    // Channel metrics
    channel_occupancy: IntGaugeVec,
    channel_shedding_total: IntCounterVec,

    // Cache metrics
    cache_size: IntGaugeVec,
    cache_evictions_total: IntCounterVec,

    // SQLite metrics
    sqlite_size_bytes: IntGauge,
    sqlite_wal_size_bytes: IntGauge,
    sqlite_checkpoint_total: IntCounter,
    outbox_age_seconds: Gauge,

    // Enrichment metrics
    enrichment_status: IntGaugeVec,

    // Policy metrics
    policy_version: IntGauge,
    policy_mode: IntGauge,

    // Lag metrics
    grpc_lag_seconds: Gauge,
    kafka_lag_seconds: Gauge,
    clickhouse_lag_seconds: Gauge,

    // Syscall histogram
    syscall_latency_seconds: HistogramVec,
}

impl MetricsRegistry {
    /// Creates a new metrics registry with all standard metrics registered.
    /// All sensors start as detached and storage as unavailable — the safe
    /// default that never declares ready prematurely.
    pub fn new() -> Self {
        let registry = Registry::new();

        let program_attach_state = IntGaugeVec::new(
            Opts::new(
                "ebpf_agent_program_attach_state",
                "Attach state of each BPF program (2=attached, 1=degraded, 0=detached)",
            ),
            &["program"],
        )
        .expect("metric registration");

        let source_attempts_total = IntCounterVec::new(
            Opts::new(
                "ebpf_agent_source_attempts_total",
                "Total number of attempts per source",
            ),
            &["source"],
        )
        .expect("metric registration");

        let source_drops_total = IntCounterVec::new(
            Opts::new(
                "ebpf_agent_source_drops_total",
                "Total number of drops per source and reason",
            ),
            &["source", "reason"],
        )
        .expect("metric registration");

        let source_gaps_total = IntCounterVec::new(
            Opts::new(
                "ebpf_agent_source_gaps_total",
                "Total number of sequence gaps per source",
            ),
            &["source"],
        )
        .expect("metric registration");

        let channel_occupancy = IntGaugeVec::new(
            Opts::new(
                "ebpf_agent_channel_occupancy",
                "Current occupancy of each bounded channel",
            ),
            &["channel"],
        )
        .expect("metric registration");

        let channel_shedding_total = IntCounterVec::new(
            Opts::new(
                "ebpf_agent_channel_shedding_total",
                "Total number of shedding events per channel",
            ),
            &["channel"],
        )
        .expect("metric registration");

        let cache_size = IntGaugeVec::new(
            Opts::new("ebpf_agent_cache_size", "Current size of each cache"),
            &["cache"],
        )
        .expect("metric registration");

        let cache_evictions_total = IntCounterVec::new(
            Opts::new(
                "ebpf_agent_cache_evictions_total",
                "Total number of evictions per cache",
            ),
            &["cache"],
        )
        .expect("metric registration");

        let sqlite_size_bytes = IntGauge::new(
            "ebpf_agent_sqlite_size_bytes",
            "Current size of the SQLite database in bytes",
        )
        .expect("metric registration");

        let sqlite_wal_size_bytes = IntGauge::new(
            "ebpf_agent_sqlite_wal_size_bytes",
            "Current size of the SQLite WAL in bytes",
        )
        .expect("metric registration");

        let sqlite_checkpoint_total = IntCounter::new(
            "ebpf_agent_sqlite_checkpoint_total",
            "Total number of checkpoints",
        )
        .expect("metric registration");

        let outbox_age_seconds = Gauge::new(
            "ebpf_agent_outbox_age_seconds",
            "Age of the oldest unacked event in the outbox in seconds",
        )
        .expect("metric registration");

        let enrichment_status = IntGaugeVec::new(
            Opts::new(
                "ebpf_agent_enrichment_status",
                "Status of each enrichment provider (2=available, 1=degraded, 0=unavailable)",
            ),
            &["provider"],
        )
        .expect("metric registration");

        let policy_version = IntGauge::new("ebpf_agent_policy_version", "Current policy version")
            .expect("metric registration");

        let policy_mode = IntGauge::new(
            "ebpf_agent_policy_mode",
            "Current policy mode (0=audit, 1=enforce)",
        )
        .expect("metric registration");

        let grpc_lag_seconds = Gauge::new(
            "ebpf_agent_grpc_lag_seconds",
            "Lag of the gRPC stream in seconds",
        )
        .expect("metric registration");

        let kafka_lag_seconds = Gauge::new(
            "ebpf_agent_kafka_lag_seconds",
            "Lag of the Kafka stream in seconds",
        )
        .expect("metric registration");

        let clickhouse_lag_seconds = Gauge::new(
            "ebpf_agent_clickhouse_lag_seconds",
            "Lag of the ClickHouse stream in seconds",
        )
        .expect("metric registration");

        let syscall_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "ebpf_agent_syscall_latency_seconds",
                "Syscall latency histogram per syscall",
            ),
            &["syscall"],
        )
        .expect("metric registration");

        // Register all metrics.
        registry
            .register(Box::new(program_attach_state.clone()))
            .expect("register program_attach_state");
        registry
            .register(Box::new(source_attempts_total.clone()))
            .expect("register source_attempts_total");
        registry
            .register(Box::new(source_drops_total.clone()))
            .expect("register source_drops_total");
        registry
            .register(Box::new(source_gaps_total.clone()))
            .expect("register source_gaps_total");
        registry
            .register(Box::new(channel_occupancy.clone()))
            .expect("register channel_occupancy");
        registry
            .register(Box::new(channel_shedding_total.clone()))
            .expect("register channel_shedding_total");
        registry
            .register(Box::new(cache_size.clone()))
            .expect("register cache_size");
        registry
            .register(Box::new(cache_evictions_total.clone()))
            .expect("register cache_evictions_total");
        registry
            .register(Box::new(sqlite_size_bytes.clone()))
            .expect("register sqlite_size_bytes");
        registry
            .register(Box::new(sqlite_wal_size_bytes.clone()))
            .expect("register sqlite_wal_size_bytes");
        registry
            .register(Box::new(sqlite_checkpoint_total.clone()))
            .expect("register sqlite_checkpoint_total");
        registry
            .register(Box::new(outbox_age_seconds.clone()))
            .expect("register outbox_age_seconds");
        registry
            .register(Box::new(enrichment_status.clone()))
            .expect("register enrichment_status");
        registry
            .register(Box::new(policy_version.clone()))
            .expect("register policy_version");
        registry
            .register(Box::new(policy_mode.clone()))
            .expect("register policy_mode");
        registry
            .register(Box::new(grpc_lag_seconds.clone()))
            .expect("register grpc_lag_seconds");
        registry
            .register(Box::new(kafka_lag_seconds.clone()))
            .expect("register kafka_lag_seconds");
        registry
            .register(Box::new(clickhouse_lag_seconds.clone()))
            .expect("register clickhouse_lag_seconds");
        registry
            .register(Box::new(syscall_latency_seconds.clone()))
            .expect("register syscall_latency_seconds");

        // Pre-initialize all bounded label combinations so every metric family
        // appears in the exposition output from the start (Prometheus Vec
        // metrics are invisible until at least one label set is touched).
        for program in Program::ALL {
            program_attach_state
                .with_label_values(&[&program.to_string()])
                .set(AttachState::Detached.as_metric_value());
        }
        for source in Source::ALL {
            source_attempts_total.with_label_values(&[&source.to_string()]);
            source_gaps_total.with_label_values(&[&source.to_string()]);
            for reason in DropReason::ALL {
                source_drops_total.with_label_values(&[&source.to_string(), &reason.to_string()]);
            }
        }
        for channel in Channel::ALL {
            channel_occupancy.with_label_values(&[&channel.to_string()]);
            channel_shedding_total.with_label_values(&[&channel.to_string()]);
        }
        for cache in Cache::ALL {
            cache_size.with_label_values(&[&cache.to_string()]);
            cache_evictions_total.with_label_values(&[&cache.to_string()]);
        }
        for provider in Provider::ALL {
            enrichment_status.with_label_values(&[&provider.to_string()]);
        }
        for syscall in Syscall::ALL {
            syscall_latency_seconds.with_label_values(&[&syscall.to_string()]);
        }

        Self {
            registry,
            state: Mutex::new(RegistryState::new()),
            program_attach_state,
            source_attempts_total,
            source_drops_total,
            source_gaps_total,
            channel_occupancy,
            channel_shedding_total,
            cache_size,
            cache_evictions_total,
            sqlite_size_bytes,
            sqlite_wal_size_bytes,
            sqlite_checkpoint_total,
            outbox_age_seconds,
            enrichment_status,
            policy_version,
            policy_mode,
            grpc_lag_seconds,
            kafka_lag_seconds,
            clickhouse_lag_seconds,
            syscall_latency_seconds,
        }
    }

    /// Returns the current health status.
    ///
    /// - `Unhealthy` if storage is unavailable.
    /// - `Degraded` if any sensor is detached or degraded.
    /// - `Healthy` otherwise.
    pub fn health(&self) -> HealthStatus {
        let state = self.state.lock();
        let mut reasons = Vec::new();

        if !state.storage_available {
            reasons.push("storage unavailable".to_string());
        }

        for (program, attach_state) in &state.program_states {
            match attach_state {
                AttachState::Detached => {
                    reasons.push(format!("sensor {program} detached"));
                }
                AttachState::Degraded => {
                    reasons.push(format!("sensor {program} degraded"));
                }
                AttachState::Attached => {}
            }
        }

        let status = if !state.storage_available {
            HealthState::Unhealthy
        } else if reasons.is_empty() {
            HealthState::Healthy
        } else {
            HealthState::Degraded
        };

        HealthStatus { status, reasons }
    }

    /// Returns the current readiness status.
    ///
    /// Never declares ready before all required sensors are attached and
    /// storage is available.
    pub fn readiness(&self) -> ReadinessStatus {
        let state = self.state.lock();
        let mut reasons = Vec::new();

        if !state.storage_available {
            reasons.push("storage unavailable".to_string());
        }

        for (program, attach_state) in &state.program_states {
            if *attach_state != AttachState::Attached {
                reasons.push(format!("sensor {program} not attached"));
            }
        }

        let status = if reasons.is_empty() {
            ReadinessState::Ready
        } else {
            ReadinessState::NotReady
        };

        ReadinessStatus { status, reasons }
    }

    /// Returns the Prometheus metrics as a string in the Prometheus text
    /// exposition format.
    pub fn metrics(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .expect("encode metrics");
        String::from_utf8(buffer).expect("metrics are valid UTF-8")
    }

    // -----------------------------------------------------------------------
    // State mutation methods
    // -----------------------------------------------------------------------

    /// Set the attach state of a BPF program. Updates both the internal state
    /// (for health/readiness) and the Prometheus gauge.
    pub fn set_program_state(&self, program: Program, state: AttachState) {
        self.program_attach_state
            .with_label_values(&[&program.to_string()])
            .set(state.as_metric_value());
        let mut internal = self.state.lock();
        internal.program_states.insert(program, state);
        tracing::debug!(program = %program, state = %state, "program attach state updated");
    }

    /// Set whether storage (SQLite) is available.
    pub fn set_storage_available(&self, available: bool) {
        let mut internal = self.state.lock();
        internal.storage_available = available;
        tracing::debug!(available, "storage availability updated");
    }

    /// Increment the attempt counter for a source.
    pub fn increment_source_attempts(&self, source: Source) {
        self.source_attempts_total
            .with_label_values(&[&source.to_string()])
            .inc();
    }

    /// Increment the drop counter for a source and reason.
    pub fn increment_source_drops(&self, source: Source, reason: DropReason) {
        self.source_drops_total
            .with_label_values(&[&source.to_string(), &reason.to_string()])
            .inc();
    }

    /// Increment the sequence gap counter for a source.
    pub fn increment_source_gaps(&self, source: Source) {
        self.source_gaps_total
            .with_label_values(&[&source.to_string()])
            .inc();
    }

    /// Set the current occupancy of a channel.
    pub fn set_channel_occupancy(&self, channel: Channel, value: i64) {
        self.channel_occupancy
            .with_label_values(&[&channel.to_string()])
            .set(value);
    }

    /// Increment the shedding counter for a channel.
    pub fn increment_channel_shedding(&self, channel: Channel) {
        self.channel_shedding_total
            .with_label_values(&[&channel.to_string()])
            .inc();
    }

    /// Set the current size of a cache.
    pub fn set_cache_size(&self, cache: Cache, value: i64) {
        self.cache_size
            .with_label_values(&[&cache.to_string()])
            .set(value);
    }

    /// Increment the eviction counter for a cache.
    pub fn increment_cache_evictions(&self, cache: Cache) {
        self.cache_evictions_total
            .with_label_values(&[&cache.to_string()])
            .inc();
    }

    /// Set the SQLite database size in bytes.
    pub fn set_sqlite_size(&self, bytes: i64) {
        self.sqlite_size_bytes.set(bytes);
    }

    /// Set the SQLite WAL size in bytes.
    pub fn set_sqlite_wal_size(&self, bytes: i64) {
        self.sqlite_wal_size_bytes.set(bytes);
    }

    /// Increment the checkpoint counter.
    pub fn increment_sqlite_checkpoint(&self) {
        self.sqlite_checkpoint_total.inc();
    }

    /// Set the outbox age in seconds.
    pub fn set_outbox_age(&self, seconds: f64) {
        self.outbox_age_seconds.set(seconds);
    }

    /// Set the enrichment provider status.
    pub fn set_enrichment_status(&self, provider: Provider, status: EnrichmentState) {
        self.enrichment_status
            .with_label_values(&[&provider.to_string()])
            .set(status.as_metric_value());
        tracing::debug!(provider = %provider, status = %status, "enrichment status updated");
    }

    /// Set the policy version.
    pub fn set_policy_version(&self, version: i64) {
        self.policy_version.set(version);
    }

    /// Set the policy mode.
    pub fn set_policy_mode(&self, mode: PolicyMode) {
        self.policy_mode.set(mode.as_metric_value());
    }

    /// Set the gRPC lag in seconds.
    pub fn set_grpc_lag(&self, seconds: f64) {
        self.grpc_lag_seconds.set(seconds);
    }

    /// Set the Kafka lag in seconds.
    pub fn set_kafka_lag(&self, seconds: f64) {
        self.kafka_lag_seconds.set(seconds);
    }

    /// Set the ClickHouse lag in seconds.
    pub fn set_clickhouse_lag(&self, seconds: f64) {
        self.clickhouse_lag_seconds.set(seconds);
    }

    /// Observe a syscall latency measurement.
    pub fn observe_syscall_latency(&self, syscall: Syscall, seconds: f64) {
        self.syscall_latency_seconds
            .with_label_values(&[&syscall.to_string()])
            .observe(seconds);
    }

    /// Count the number of unique metric series currently registered.
    /// Used for the cardinality audit.
    pub fn series_count(&self) -> usize {
        self.registry
            .gather()
            .iter()
            .map(|mf| mf.get_metric().len())
            .sum::<usize>()
        // Histogram metrics expand to multiple series (buckets + sum + count)
        // but prometheus::gather() already counts them as individual metrics
        // in the MetricFamily. We count the raw metric entries.
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}
