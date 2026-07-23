// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Health and expiry metrics for the SPIFFE identity client.
//!
//! Metrics follow the observability crate's pattern: bounded
//! labels, Prometheus text exposition, no secrets in labels.
//!
//! # Metrics
//!
//! - `spiffe_svid_expiry_seconds`: gauge — seconds until the
//!   primary SVID expires (negative = expired).
//! - `spiffe_svid_rotations_total`: counter — total number of
//!   complete-set rotations.
//! - `spiffe_stream_health`: gauge — stream state (0=disconnected,
//!   1=connecting, 2=streaming, 3=reconnecting).
//! - `spiffe_stream_reconnects_total`: counter — total
//!   reconnection attempts.
//! - `spiffe_authorization_decisions_total`: counter vec —
//!   authorization decisions by outcome (allowed/denied).

#![forbid(unsafe_code)]

use prometheus::{Gauge, IntCounter, IntCounterVec, IntGauge, Opts, Registry};

use crate::workload::StreamHealth;

/// SPIFFE identity metrics reporter.
///
/// Clone-safe: all inner metrics are Arc-wrapped by prometheus.
#[derive(Clone)]
pub struct SpiffeMetrics {
    registry: Registry,
    svid_expiry_seconds: Gauge,
    svid_rotations_total: IntCounter,
    stream_health: IntGauge,
    stream_reconnects_total: IntCounter,
    authorization_decisions_total: IntCounterVec,
    last_rotation_timestamp: Gauge,
}

impl SpiffeMetrics {
    /// Create a new metrics reporter with all SPIFFE metrics
    /// registered.
    pub fn new() -> Self {
        let registry = Registry::new();

        let svid_expiry_seconds = Gauge::new(
            "spiffe_svid_expiry_seconds",
            "Seconds until the primary SVID expires (negative = expired)",
        )
        .expect("metric registration");

        let svid_rotations_total = IntCounter::new(
            "spiffe_svid_rotations_total",
            "Total number of complete-set SVID rotations",
        )
        .expect("metric registration");

        let stream_health = IntGauge::new(
            "spiffe_stream_health",
            "Stream health state (0=disconnected, 1=connecting, 2=streaming, 3=reconnecting)",
        )
        .expect("metric registration");

        let stream_reconnects_total = IntCounter::new(
            "spiffe_stream_reconnects_total",
            "Total number of stream reconnection attempts",
        )
        .expect("metric registration");

        let authorization_decisions_total = IntCounterVec::new(
            Opts::new(
                "spiffe_authorization_decisions_total",
                "Total authorization decisions by outcome",
            ),
            &["outcome"],
        )
        .expect("metric registration");

        let last_rotation_timestamp = Gauge::new(
            "spiffe_last_rotation_timestamp_seconds",
            "Unix timestamp of the last SVID rotation",
        )
        .expect("metric registration");

        // Register all metrics.
        registry
            .register(Box::new(svid_expiry_seconds.clone()))
            .expect("register svid_expiry_seconds");
        registry
            .register(Box::new(svid_rotations_total.clone()))
            .expect("register svid_rotations_total");
        registry
            .register(Box::new(stream_health.clone()))
            .expect("register stream_health");
        registry
            .register(Box::new(stream_reconnects_total.clone()))
            .expect("register stream_reconnects_total");
        registry
            .register(Box::new(authorization_decisions_total.clone()))
            .expect("register authorization_decisions_total");
        registry
            .register(Box::new(last_rotation_timestamp.clone()))
            .expect("register last_rotation_timestamp");

        // Pre-initialize bounded label combinations.
        authorization_decisions_total.with_label_values(&["allowed"]);
        authorization_decisions_total.with_label_values(&["denied"]);

        // Initialize stream health to disconnected.
        stream_health.set(StreamHealth::Disconnected.as_metric_value());

        Self {
            registry,
            svid_expiry_seconds,
            svid_rotations_total,
            stream_health,
            stream_reconnects_total,
            authorization_decisions_total,
            last_rotation_timestamp,
        }
    }

    /// Set the seconds until SVID expiry.
    pub fn set_svid_expiry_seconds(&self, seconds: i64) {
        self.svid_expiry_seconds.set(seconds as f64);
    }

    /// Increment the rotation counter.
    pub fn increment_rotations(&self) {
        self.svid_rotations_total.inc();
    }

    /// Set the stream health state.
    pub fn set_stream_health(&self, health: StreamHealth) {
        self.stream_health.set(health.as_metric_value());
    }

    /// Increment the reconnection counter.
    pub fn increment_reconnects(&self) {
        self.stream_reconnects_total.inc();
    }

    /// Record an authorization decision.
    pub fn record_authorization(&self, allowed: bool) {
        let outcome = if allowed { "allowed" } else { "denied" };
        self.authorization_decisions_total
            .with_label_values(&[outcome])
            .inc();
    }

    /// Set the last rotation timestamp (unix seconds).
    pub fn set_last_rotation(&self, timestamp_unix: i64) {
        self.last_rotation_timestamp.set(timestamp_unix as f64);
    }

    /// Render metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .expect("encode metrics");
        String::from_utf8(buffer).expect("metrics are valid UTF-8")
    }

    /// Get the current rotation count.
    pub fn rotation_count(&self) -> u64 {
        self.svid_rotations_total.get()
    }

    /// Get the current reconnect count.
    pub fn reconnect_count(&self) -> u64 {
        self.stream_reconnects_total.get()
    }

    /// Get the current stream health value.
    pub fn stream_health_value(&self) -> i64 {
        self.stream_health.get()
    }
}

impl Default for SpiffeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_contains_all_families() {
        let m = SpiffeMetrics::new();
        m.set_svid_expiry_seconds(3600);
        m.increment_rotations();
        m.set_stream_health(StreamHealth::Streaming);
        m.increment_reconnects();
        m.record_authorization(true);
        m.record_authorization(false);
        m.set_last_rotation(1700000000);

        let text = m.render();
        assert!(text.contains("spiffe_svid_expiry_seconds"));
        assert!(text.contains("spiffe_svid_rotations_total"));
        assert!(text.contains("spiffe_stream_health"));
        assert!(text.contains("spiffe_stream_reconnects_total"));
        assert!(text.contains("spiffe_authorization_decisions_total"));
        assert!(text.contains("spiffe_last_rotation_timestamp_seconds"));
    }

    #[test]
    fn rotation_counter_increments() {
        let m = SpiffeMetrics::new();
        assert_eq!(m.rotation_count(), 0);
        m.increment_rotations();
        m.increment_rotations();
        assert_eq!(m.rotation_count(), 2);
    }

    #[test]
    fn stream_health_tracks_state() {
        let m = SpiffeMetrics::new();
        assert_eq!(m.stream_health_value(), 0); // Disconnected

        m.set_stream_health(StreamHealth::Connecting);
        assert_eq!(m.stream_health_value(), 1);

        m.set_stream_health(StreamHealth::Streaming);
        assert_eq!(m.stream_health_value(), 2);

        m.set_stream_health(StreamHealth::Reconnecting);
        assert_eq!(m.stream_health_value(), 3);
    }

    #[test]
    fn authorization_decisions_tracked() {
        let m = SpiffeMetrics::new();
        m.record_authorization(true);
        m.record_authorization(true);
        m.record_authorization(false);

        let text = m.render();
        // Both labels should appear.
        assert!(text.contains("allowed"));
        assert!(text.contains("denied"));
    }

    #[test]
    fn clone_shares_state() {
        let m = SpiffeMetrics::new();
        let m2 = m.clone();
        m.increment_rotations();
        assert_eq!(m2.rotation_count(), 1);
    }
}
