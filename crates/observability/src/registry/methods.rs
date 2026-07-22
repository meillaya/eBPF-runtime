// SPDX-License-Identifier: Apache-2.0 OR MIT
//! MetricsRegistry query and mutation methods.

use prometheus::{Encoder, TextEncoder};

use super::MetricsRegistry;
use crate::health::{HealthState, HealthStatus, ReadinessState, ReadinessStatus};
use crate::labels::*;
use crate::labels_ext::*;

impl MetricsRegistry {
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
    }
}
