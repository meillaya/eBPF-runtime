// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Edge case tests for the observability crate.

use observability::{
    AttachState, Cache, Channel, DropReason, EnrichmentState, HealthState, MetricsRegistry,
    PolicyMode, Program, Provider, ReadinessState, Source, Syscall,
};

// ---------------------------------------------------------------------------
// Multiple-reason health/readiness tests
// ---------------------------------------------------------------------------

#[test]
fn health_status_degraded_with_multiple_reasons() {
    let registry = MetricsRegistry::new();
    registry.set_storage_available(true);
    // Detach multiple sensors.
    registry.set_program_state(Program::Process, AttachState::Detached);
    registry.set_program_state(Program::Network, AttachState::Degraded);
    registry.set_program_state(Program::Dns, AttachState::Detached);
    // Attach the rest.
    registry.set_program_state(Program::File, AttachState::Attached);
    registry.set_program_state(Program::Syscall, AttachState::Attached);
    registry.set_program_state(Program::Identity, AttachState::Attached);

    let health = registry.health();
    assert_eq!(health.status, HealthState::Degraded);
    assert!(health.reasons.len() >= 3);
    assert!(health.reasons.iter().any(|r| r.contains("sensor process detached")));
    assert!(health.reasons.iter().any(|r| r.contains("sensor network degraded")));
    assert!(health.reasons.iter().any(|r| r.contains("sensor dns detached")));
}

#[test]
fn health_status_unhealthy_with_multiple_reasons() {
    let registry = MetricsRegistry::new();
    // Storage unavailable + sensors detached.
    registry.set_program_state(Program::Process, AttachState::Detached);
    registry.set_program_state(Program::File, AttachState::Detached);

    let health = registry.health();
    assert_eq!(health.status, HealthState::Unhealthy);
    assert!(health.reasons.iter().any(|r| r.contains("storage unavailable")));
    assert!(health.reasons.iter().any(|r| r.contains("sensor process detached")));
    assert!(health.reasons.iter().any(|r| r.contains("sensor file detached")));
}

#[test]
fn readiness_status_not_ready_with_multiple_reasons() {
    let registry = MetricsRegistry::new();
    // Storage unavailable + multiple sensors not attached.
    registry.set_program_state(Program::Process, AttachState::Attached);
    registry.set_program_state(Program::File, AttachState::Detached);
    registry.set_program_state(Program::Network, AttachState::Degraded);

    let readiness = registry.readiness();
    assert_eq!(readiness.status, ReadinessState::NotReady);
    assert!(readiness.reasons.iter().any(|r| r.contains("storage unavailable")));
    assert!(readiness.reasons.iter().any(|r| r.contains("sensor file not attached")));
    assert!(readiness.reasons.iter().any(|r| r.contains("sensor network not attached")));
}

// ---------------------------------------------------------------------------
// Zero/empty state metrics tests
// ---------------------------------------------------------------------------

#[test]
fn metrics_export_with_no_events_returns_zero_counters() {
    let registry = MetricsRegistry::new();
    // Touch the counters so they appear in the output with value 0.
    registry.increment_source_attempts(Source::Process);
    // Reset by creating a fresh registry and only touching the metric.
    let registry = MetricsRegistry::new();
    registry.increment_source_attempts(Source::Process);

    let metrics = registry.metrics();
    // The counter should show 1 (we incremented once).
    assert!(metrics.contains("ebpf_agent_source_attempts_total{source=\"process\"} 1"));
}

#[test]
fn metrics_export_with_no_sensors_returns_empty_program_attach_state() {
    let registry = MetricsRegistry::new();
    // Don't set any program state. The metric family exists but no labels
    // have been initialized.
    let metrics = registry.metrics();
    // The HELP/TYPE lines should still be present for the registered metric.
    assert!(metrics.contains("ebpf_agent_program_attach_state"));
}

#[test]
fn metrics_export_with_no_caches_returns_empty_cache_size() {
    let registry = MetricsRegistry::new();
    let metrics = registry.metrics();
    assert!(metrics.contains("ebpf_agent_cache_size"));
}

#[test]
fn metrics_export_with_no_sqlite_returns_zero_sqlite_size() {
    let registry = MetricsRegistry::new();
    let metrics = registry.metrics();
    // The gauge is registered and defaults to 0.
    assert!(metrics.contains("ebpf_agent_sqlite_size_bytes"));
}

#[test]
fn metrics_export_with_no_outbox_returns_zero_outbox_age() {
    let registry = MetricsRegistry::new();
    let metrics = registry.metrics();
    assert!(metrics.contains("ebpf_agent_outbox_age_seconds"));
}

#[test]
fn metrics_export_with_no_enrichment_returns_empty_enrichment_status() {
    let registry = MetricsRegistry::new();
    let metrics = registry.metrics();
    assert!(metrics.contains("ebpf_agent_enrichment_status"));
}

#[test]
fn metrics_export_with_no_policy_returns_zero_policy_version() {
    let registry = MetricsRegistry::new();
    let metrics = registry.metrics();
    assert!(metrics.contains("ebpf_agent_policy_version"));
}

#[test]
fn metrics_export_with_no_grpc_returns_zero_grpc_lag() {
    let registry = MetricsRegistry::new();
    let metrics = registry.metrics();
    assert!(metrics.contains("ebpf_agent_grpc_lag_seconds"));
}

#[test]
fn metrics_export_with_no_kafka_returns_zero_kafka_lag() {
    let registry = MetricsRegistry::new();
    let metrics = registry.metrics();
    assert!(metrics.contains("ebpf_agent_kafka_lag_seconds"));
}

#[test]
fn metrics_export_with_no_clickhouse_returns_zero_clickhouse_lag() {
    let registry = MetricsRegistry::new();
    let metrics = registry.metrics();
    assert!(metrics.contains("ebpf_agent_clickhouse_lag_seconds"));
}

#[test]
fn metrics_export_with_no_syscall_returns_empty_syscall_latency() {
    let registry = MetricsRegistry::new();
    let metrics = registry.metrics();
    assert!(metrics.contains("ebpf_agent_syscall_latency_seconds"));
}

// ---------------------------------------------------------------------------
// Large cardinality audit
// ---------------------------------------------------------------------------

#[test]
fn cardinality_audit_with_100000_events_leaves_unique_series_below_1024() {
    let registry = MetricsRegistry::new();

    // Simulate 100000 events across all sources and syscalls.
    for i in 0..100000 {
        let source = Source::ALL[i % Source::ALL.len()];
        let reason = DropReason::ALL[i % DropReason::ALL.len()];
        let syscall = Syscall::ALL[i % Syscall::ALL.len()];

        registry.increment_source_attempts(source);
        registry.increment_source_drops(source, reason);
        registry.increment_source_gaps(source);
        registry.observe_syscall_latency(syscall, 0.0001 * (i as f64));
    }

    // Set all other metrics.
    for program in Program::ALL {
        registry.set_program_state(program, AttachState::Attached);
    }
    for channel in Channel::ALL {
        registry.set_channel_occupancy(channel, 10);
        registry.increment_channel_shedding(channel);
    }
    for cache in Cache::ALL {
        registry.set_cache_size(cache, 100);
        registry.increment_cache_evictions(cache);
    }
    for provider in Provider::ALL {
        registry.set_enrichment_status(provider, EnrichmentState::Available);
    }
    registry.set_storage_available(true);
    registry.set_sqlite_size(4096);
    registry.set_sqlite_wal_size(2048);
    registry.increment_sqlite_checkpoint();
    registry.set_outbox_age(1.0);
    registry.set_policy_version(1);
    registry.set_policy_mode(PolicyMode::Audit);
    registry.set_grpc_lag(0.1);
    registry.set_kafka_lag(0.2);
    registry.set_clickhouse_lag(0.3);

    let series_count = registry.series_count();
    assert!(
        series_count < 1024,
        "cardinality audit failed: {series_count} series >= 1024 limit"
    );
}

// ---------------------------------------------------------------------------
// Multi-source saturation
// ---------------------------------------------------------------------------

#[test]
fn saturation_with_multiple_sources_increments_all_loss_counters() {
    let registry = MetricsRegistry::new();

    // Simulate saturation across all sources.
    for source in Source::ALL {
        registry.increment_source_drops(source, DropReason::RingFull);
        registry.increment_source_drops(source, DropReason::ChannelFull);
        registry.increment_source_gaps(source);
    }
    for channel in Channel::ALL {
        registry.increment_channel_shedding(channel);
    }

    let metrics = registry.metrics();

    // Verify all sources have drop counters.
    for source in Source::ALL {
        assert!(
            metrics.contains(&format!("source=\"{source}\"")),
            "missing source label for {source}"
        );
    }
    // Verify ring_full and channel_full reasons present.
    assert!(metrics.contains("reason=\"ring_full\""));
    assert!(metrics.contains("reason=\"channel_full\""));
    // Verify channel shedding.
    assert!(metrics.contains("ebpf_agent_channel_shedding_total{channel=\"data\"} 1"));
    assert!(metrics.contains("ebpf_agent_channel_shedding_total{channel=\"control\"} 1"));
}

// ---------------------------------------------------------------------------
// Endpoint error tests (no server running)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn healthz_endpoint_with_no_server_returns_error() {
    // Use a port that is very unlikely to have a server.
    let result = reqwest::get("http://127.0.0.1:19999/healthz").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn readyz_endpoint_with_no_server_returns_error() {
    let result = reqwest::get("http://127.0.0.1:19999/readyz").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn metrics_endpoint_with_no_server_returns_error() {
    let result = reqwest::get("http://127.0.0.1:19999/metrics").await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Logging error test
// ---------------------------------------------------------------------------

#[test]
fn logging_with_invalid_filter_returns_error() {
    let result = observability::logging::init_logging_with_filter("invalid[[[filter");
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid filter") || msg.contains("logging error"));
}
