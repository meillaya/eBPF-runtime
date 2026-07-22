// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Transport configuration.
//!
//! All numeric defaults are anchored in
//! `bench/schemas/protocol.v1.json` (message bounds, deadlines)
//! and `bench/schemas/enforcement.v1.json` (kill-switch latency).
//! The transport config composes those schema-anchored values
//! with transport-specific queue/backoff/keepalive settings.

#![forbid(unsafe_code)]

use protocol::bounds::MessageBounds;
use protocol::deadline::DEFAULT_DEADLINE_MS;

/// Default event queue capacity (bounded memory).
pub const DEFAULT_EVENT_QUEUE_CAPACITY: usize = 4_096;

/// Default control queue capacity (small: low-volume,
/// high-priority; must never be blocked by events).
pub const DEFAULT_CONTROL_QUEUE_CAPACITY: usize = 64;

/// Default keepalive interval in milliseconds (gRPC keepalive
/// ping period).
pub const DEFAULT_KEEPALIVE_INTERVAL_MS: u64 = 30_000;

/// Default keepalive timeout in milliseconds (max time to wait
/// for a keepalive ping ACK before considering the connection
/// dead).
pub const DEFAULT_KEEPALIVE_TIMEOUT_MS: u64 = 10_000;

/// Default maximum connection age in milliseconds (force
/// reconnect after this duration to pick up SVID rotation and
/// rebalance).
pub const DEFAULT_MAX_CONNECTION_AGE_MS: u64 = 3_600_000; // 1 hour

/// Default backoff base delay in milliseconds.
pub const DEFAULT_BACKOFF_BASE_MS: u64 = 100;

/// Default backoff maximum delay in milliseconds.
pub const DEFAULT_BACKOFF_MAX_MS: u64 = 30_000;

/// Default backoff multiplier.
pub const DEFAULT_BACKOFF_MULTIPLIER: f64 = 2.0;

/// Default maximum reconnect attempts before circuit-breaking.
pub const DEFAULT_MAX_RECONNECT_ATTEMPTS: u32 = 20;

/// Default ACK deadline in milliseconds (time to wait for a
/// batch ACK after durable Kafka acceptance).
pub const DEFAULT_ACK_DEADLINE_MS: u64 = 60_000;

/// Transport configuration for the agent/control-plane
/// connection.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Event queue capacity (bounded).
    pub event_queue_capacity: usize,
    /// Control queue capacity (bounded, small).
    pub control_queue_capacity: usize,
    /// Message bounds (compression, batch limits) from the
    /// protocol crate.
    pub message_bounds: MessageBounds,
    /// Default RPC deadline in milliseconds.
    pub deadline_ms: u64,
    /// Keepalive ping interval in milliseconds.
    pub keepalive_interval_ms: u64,
    /// Keepalive ping ACK timeout in milliseconds.
    pub keepalive_timeout_ms: u64,
    /// Maximum connection age in milliseconds (force reconnect).
    pub max_connection_age_ms: u64,
    /// Backoff base delay in milliseconds.
    pub backoff_base_ms: u64,
    /// Backoff maximum delay in milliseconds.
    pub backoff_max_ms: u64,
    /// Backoff multiplier.
    pub backoff_multiplier: f64,
    /// Maximum reconnect attempts before circuit-breaking.
    pub max_reconnect_attempts: u32,
    /// ACK deadline in milliseconds.
    pub ack_deadline_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            event_queue_capacity: DEFAULT_EVENT_QUEUE_CAPACITY,
            control_queue_capacity: DEFAULT_CONTROL_QUEUE_CAPACITY,
            message_bounds: MessageBounds::default(),
            deadline_ms: DEFAULT_DEADLINE_MS,
            keepalive_interval_ms: DEFAULT_KEEPALIVE_INTERVAL_MS,
            keepalive_timeout_ms: DEFAULT_KEEPALIVE_TIMEOUT_MS,
            max_connection_age_ms: DEFAULT_MAX_CONNECTION_AGE_MS,
            backoff_base_ms: DEFAULT_BACKOFF_BASE_MS,
            backoff_max_ms: DEFAULT_BACKOFF_MAX_MS,
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
            max_reconnect_attempts: DEFAULT_MAX_RECONNECT_ATTEMPTS,
            ack_deadline_ms: DEFAULT_ACK_DEADLINE_MS,
        }
    }
}

impl TransportConfig {
    /// Validate the configuration. Returns a list of validation
    /// errors (empty = valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.event_queue_capacity == 0 {
            errors.push("event_queue_capacity must be > 0".into());
        }
        if self.control_queue_capacity == 0 {
            errors.push("control_queue_capacity must be > 0".into());
        }
        if self.deadline_ms == 0 {
            errors.push("deadline_ms must be > 0".into());
        }
        if self.keepalive_interval_ms == 0 {
            errors.push("keepalive_interval_ms must be > 0".into());
        }
        if self.keepalive_timeout_ms == 0 {
            errors.push("keepalive_timeout_ms must be > 0".into());
        }
        if self.max_connection_age_ms == 0 {
            errors.push("max_connection_age_ms must be > 0".into());
        }
        if self.backoff_base_ms == 0 {
            errors.push("backoff_base_ms must be > 0".into());
        }
        if self.backoff_max_ms < self.backoff_base_ms {
            errors.push("backoff_max_ms must be >= backoff_base_ms".into());
        }
        if self.backoff_multiplier < 1.0 {
            errors.push("backoff_multiplier must be >= 1.0".into());
        }
        if self.max_reconnect_attempts == 0 {
            errors.push("max_reconnect_attempts must be > 0".into());
        }
        if self.ack_deadline_ms == 0 {
            errors.push("ack_deadline_ms must be > 0".into());
        }
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = TransportConfig::default();
        assert!(config.validate().is_empty());
    }

    #[test]
    fn default_queue_capacities() {
        let config = TransportConfig::default();
        assert_eq!(config.event_queue_capacity, 4096);
        assert_eq!(config.control_queue_capacity, 64);
    }

    #[test]
    fn default_deadline_matches_protocol_schema() {
        let config = TransportConfig::default();
        assert_eq!(config.deadline_ms, 30_000);
    }

    #[test]
    fn default_message_bounds_match_protocol() {
        let config = TransportConfig::default();
        assert_eq!(config.message_bounds.max_message_size_bytes, 1_048_576);
        assert_eq!(config.message_bounds.max_batch_messages, 1_000);
    }

    #[test]
    fn zero_event_queue_rejected() {
        let config = TransportConfig {
            event_queue_capacity: 0,
            ..Default::default()
        };
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("event_queue_capacity")));
    }

    #[test]
    fn zero_control_queue_rejected() {
        let config = TransportConfig {
            control_queue_capacity: 0,
            ..Default::default()
        };
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("control_queue_capacity")));
    }

    #[test]
    fn backoff_max_less_than_base_rejected() {
        let config = TransportConfig {
            backoff_max_ms: 50,
            backoff_base_ms: 100,
            ..Default::default()
        };
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("backoff_max_ms")));
    }

    #[test]
    fn backoff_multiplier_less_than_one_rejected() {
        let config = TransportConfig {
            backoff_multiplier: 0.5,
            ..Default::default()
        };
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("backoff_multiplier")));
    }

    #[test]
    fn keepalive_defaults() {
        let config = TransportConfig::default();
        assert_eq!(config.keepalive_interval_ms, 30_000);
        assert_eq!(config.keepalive_timeout_ms, 10_000);
    }

    #[test]
    fn max_connection_age_default_one_hour() {
        let config = TransportConfig::default();
        assert_eq!(config.max_connection_age_ms, 3_600_000);
    }
}
