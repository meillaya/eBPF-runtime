// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Metrics registry: struct definition and internal state.

mod init;
mod methods;

use std::collections::BTreeMap;

use parking_lot::Mutex;
use prometheus::{Gauge, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Registry};

use crate::labels::Program;
use crate::labels_ext::AttachState;

/// Mutable internal state tracked for health/readiness computation.
pub(crate) struct RegistryState {
    /// Attach state per BPF program.
    pub(crate) program_states: BTreeMap<Program, AttachState>,
    /// Whether storage (SQLite) is available.
    pub(crate) storage_available: bool,
}

impl RegistryState {
    pub(crate) fn new() -> Self {
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

/// The canonical metrics registry. Wraps a `prometheus::Registry` and exposes
/// bounded-cardinality metrics for the eBPF runtime security agent.
///
/// All metric labels use bounded enums. Process/container/pod/path IDs belong
/// in events, not metric labels. The registry never logs secrets or raw
/// records.
pub struct MetricsRegistry {
    pub(crate) registry: Registry,
    pub(crate) state: Mutex<RegistryState>,

    // Program attach state
    pub(crate) program_attach_state: IntGaugeVec,

    // Source metrics
    pub(crate) source_attempts_total: IntCounterVec,
    pub(crate) source_drops_total: IntCounterVec,
    pub(crate) source_gaps_total: IntCounterVec,

    // Channel metrics
    pub(crate) channel_occupancy: IntGaugeVec,
    pub(crate) channel_shedding_total: IntCounterVec,

    // Cache metrics
    pub(crate) cache_size: IntGaugeVec,
    pub(crate) cache_evictions_total: IntCounterVec,

    // SQLite metrics
    pub(crate) sqlite_size_bytes: IntGauge,
    pub(crate) sqlite_wal_size_bytes: IntGauge,
    pub(crate) sqlite_checkpoint_total: IntCounter,
    pub(crate) outbox_age_seconds: Gauge,

    // Enrichment metrics
    pub(crate) enrichment_status: IntGaugeVec,

    // Policy metrics
    pub(crate) policy_version: IntGauge,
    pub(crate) policy_mode: IntGauge,

    // Lag metrics
    pub(crate) grpc_lag_seconds: Gauge,
    pub(crate) kafka_lag_seconds: Gauge,
    pub(crate) clickhouse_lag_seconds: Gauge,

    // Syscall histogram
    pub(crate) syscall_latency_seconds: HistogramVec,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}
