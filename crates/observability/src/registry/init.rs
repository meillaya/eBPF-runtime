// SPDX-License-Identifier: Apache-2.0 OR MIT
//! MetricsRegistry constructor.

use prometheus::{
    Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry,
};

use super::{MetricsRegistry, RegistryState};
use crate::labels::*;
use crate::labels_ext::*;
use parking_lot::Mutex;

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
}
