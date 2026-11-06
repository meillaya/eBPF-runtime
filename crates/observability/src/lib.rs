// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Prometheus metrics with a stable prefix.

#![forbid(unsafe_code)]

use prometheus::{Encoder, IntCounter, IntGauge, Opts, Registry, TextEncoder};
use thiserror::Error;

/// Metrics shared by the agent and the control plane.
pub struct Metrics {
    registry: Registry,
    /// Events decoded and stored.
    pub events_total: IntCounter,
    /// Decode failures.
    pub decode_errors_total: IntCounter,
    /// Rule matches.
    pub alerts_total: IntCounter,
    /// Local storage failures.
    pub storage_errors_total: IntCounter,
    /// Transport retries.
    pub transport_retries_total: IntCounter,
    /// Batches accepted by the control plane.
    pub batches_total: IntCounter,
    /// Events accepted by the control plane.
    pub ingested_events_total: IntCounter,
    /// Batches delivered by this agent.
    pub delivered_batches_total: IntCounter,
    /// Events delivered by this agent.
    pub delivered_events_total: IntCounter,
    /// Unacknowledged local batches.
    pub outbox_depth: IntGauge,
    /// Local database size.
    pub storage_bytes: IntGauge,
    /// Ring buffer drops reported by the loader.
    pub ring_drops_total: IntCounter,
}

/// Metrics construction errors.
#[derive(Debug, Error)]
pub enum MetricsError {
    /// A metric name or help string is invalid.
    #[error("metric registration failed: {0}")]
    Register(String),
}

impl Metrics {
    /// Build the registry and all counters.
    pub fn new() -> Result<Self, MetricsError> {
        let registry = Registry::new();
        let events_total = counter("ebpf_runtime_events_total", "Events stored")?;
        let decode_errors_total = counter("ebpf_runtime_decode_errors_total", "Decode failures")?;
        let alerts_total = counter("ebpf_runtime_alerts_total", "Rule matches")?;
        let storage_errors_total =
            counter("ebpf_runtime_storage_errors_total", "Storage failures")?;
        let transport_retries_total = counter(
            "ebpf_runtime_transport_retries_total",
            "Transport delivery retries",
        )?;
        let batches_total = counter(
            "ebpf_runtime_batches_total",
            "Batches accepted by the control plane",
        )?;
        let ingested_events_total = counter(
            "ebpf_runtime_ingested_events_total",
            "Events accepted by the control plane",
        )?;
        let delivered_batches_total = counter(
            "ebpf_runtime_delivered_batches_total",
            "Batches delivered by this agent",
        )?;
        let delivered_events_total = counter(
            "ebpf_runtime_delivered_events_total",
            "Events delivered by this agent",
        )?;
        let ring_drops_total = counter("ebpf_runtime_ring_drops_total", "Ring buffer drops")?;
        let outbox_depth = gauge("ebpf_runtime_outbox_depth", "Unacknowledged local batches")?;
        let storage_bytes = gauge("ebpf_runtime_storage_bytes", "Local database size")?;

        registry
            .register(Box::new(events_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(decode_errors_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(alerts_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(storage_errors_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(transport_retries_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(batches_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(ingested_events_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(delivered_batches_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(delivered_events_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(ring_drops_total.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(outbox_depth.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;
        registry
            .register(Box::new(storage_bytes.clone()))
            .map_err(|error| MetricsError::Register(error.to_string()))?;

        Ok(Self {
            registry,
            events_total,
            decode_errors_total,
            alerts_total,
            storage_errors_total,
            transport_retries_total,
            batches_total,
            ingested_events_total,
            delivered_batches_total,
            delivered_events_total,
            outbox_depth,
            storage_bytes,
            ring_drops_total,
        })
    }

    /// Render the Prometheus text format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        let mut buffer = Vec::new();
        if encoder.encode(&families, &mut buffer).is_err() {
            return String::new();
        }
        String::from_utf8(buffer).unwrap_or_default()
    }
}

fn counter(name: &str, help: &str) -> Result<IntCounter, MetricsError> {
    IntCounter::with_opts(Opts::new(name, help))
        .map_err(|error| MetricsError::Register(error.to_string()))
}

fn gauge(name: &str, help: &str) -> Result<IntGauge, MetricsError> {
    IntGauge::with_opts(Opts::new(name, help))
        .map_err(|error| MetricsError::Register(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters() {
        let metrics = Metrics::new().unwrap();
        metrics.events_total.inc_by(2);
        metrics.alerts_total.inc();
        let text = metrics.render();
        assert!(text.contains("ebpf_runtime_events_total 2"));
        assert!(text.contains("ebpf_runtime_alerts_total 1"));
    }
}
