// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Idempotent Kafka producer configuration.
//!
//! All constants are anchored in `bench/schemas/kafka.v1.json`.
//! The defaults here match the schema; the bench harness reads
//! the schema, NOT these constants.
//!
//! # Idempotent producer invariants
//!
//! - `acks = all`: every produce request waits for all in-sync
//!   replicas to acknowledge before the batch is considered
//!   durable.
//! - `enable.idempotence = true`: the producer assigns a
//!   producer ID and sequence numbers to each partition,
//!   enabling the broker to deduplicate retried batches.
//! - `max.in.flight.requests.per.connection <= 5`: required by
//!   the idempotent producer to guarantee ordering. We default
//!   to 5 (the Kafka maximum for idempotent producers).
//! - `retries > 0`: the producer retries transient failures
//!   (leader election, network blips) up to the configured
//!   maximum.

#![forbid(unsafe_code)]

/// Default topic for event batches.
pub const DEFAULT_TOPIC: &str = "events.v1";

/// Default DLQ topic for schema-rejected batches.
pub const DEFAULT_DLQ_TOPIC: &str = "events.dlq.v1";

/// Default broker count for the KRaft fixture cluster.
pub const DEFAULT_BROKER_COUNT: u32 = 3;

/// Default number of partitions for the events topic.
pub const DEFAULT_PARTITION_COUNT: u32 = 12;

/// Default maximum in-flight requests per connection.
/// Kafka's idempotent producer requires this to be <= 5.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 5;

/// Default maximum retries for transient produce failures.
pub const DEFAULT_MAX_RETRIES: u32 = 2_147_483_647; // i32::MAX (Kafka default)

/// Default produce timeout in milliseconds.
pub const DEFAULT_PRODUCE_TIMEOUT_MS: u64 = 30_000;

/// Default maximum local queue depth (bounded backpressure).
pub const DEFAULT_MAX_QUEUE_DEPTH: usize = 10_000;

/// Idempotent Kafka producer configuration.
///
/// Anchored by `bench/schemas/kafka.v1.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerConfig {
    /// The Kafka topic for event batches.
    pub topic: String,
    /// The DLQ topic for schema-rejected batches.
    pub dlq_topic: String,
    /// Number of brokers in the cluster.
    pub broker_count: u32,
    /// Number of partitions for the events topic.
    pub partition_count: u32,
    /// Acks setting: "all" for idempotent producer.
    pub acks: String,
    /// Whether idempotence is enabled.
    pub enable_idempotence: bool,
    /// Maximum in-flight requests per connection (<= 5 for
    /// idempotent producer).
    pub max_in_flight: usize,
    /// Maximum retries for transient produce failures.
    pub max_retries: u32,
    /// Produce timeout in milliseconds.
    pub produce_timeout_ms: u64,
    /// Maximum local queue depth before backpressure.
    pub max_queue_depth: usize,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            topic: DEFAULT_TOPIC.to_string(),
            dlq_topic: DEFAULT_DLQ_TOPIC.to_string(),
            broker_count: DEFAULT_BROKER_COUNT,
            partition_count: DEFAULT_PARTITION_COUNT,
            acks: "all".to_string(),
            enable_idempotence: true,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            max_retries: DEFAULT_MAX_RETRIES,
            produce_timeout_ms: DEFAULT_PRODUCE_TIMEOUT_MS,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
        }
    }
}

impl ProducerConfig {
    /// Validate the configuration for idempotent producer
    /// invariants.
    ///
    /// Returns an error string if any invariant is violated.
    pub fn validate(&self) -> Result<(), String> {
        if self.acks != "all" {
            return Err(format!(
                "acks must be 'all' for idempotent producer, got '{}'",
                self.acks
            ));
        }
        if !self.enable_idempotence {
            return Err("enable.idempotence must be true for idempotent producer".to_string());
        }
        if self.max_in_flight > 5 {
            return Err(format!(
                "max.in.flight must be <= 5 for idempotent producer, got {}",
                self.max_in_flight
            ));
        }
        if self.max_in_flight == 0 {
            return Err("max.in.flight must be > 0".to_string());
        }
        if self.broker_count == 0 {
            return Err("broker_count must be > 0".to_string());
        }
        if self.partition_count == 0 {
            return Err("partition_count must be > 0".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_schema_constants() {
        let cfg = ProducerConfig::default();
        assert_eq!(cfg.topic, "events.v1");
        assert_eq!(cfg.dlq_topic, "events.dlq.v1");
        assert_eq!(cfg.broker_count, 3);
        assert_eq!(cfg.partition_count, 12);
        assert_eq!(cfg.acks, "all");
        assert!(cfg.enable_idempotence);
        assert_eq!(cfg.max_in_flight, 5);
        assert_eq!(cfg.max_retries, 2_147_483_647);
        assert_eq!(cfg.produce_timeout_ms, 30_000);
        assert_eq!(cfg.max_queue_depth, 10_000);
    }

    #[test]
    fn default_config_validates() {
        let cfg = ProducerConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn acks_not_all_rejected() {
        let cfg = ProducerConfig {
            acks: "1".to_string(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("acks must be 'all'"));
    }

    #[test]
    fn idempotence_disabled_rejected() {
        let cfg = ProducerConfig {
            enable_idempotence: false,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("enable.idempotence must be true"));
    }

    #[test]
    fn max_in_flight_over_5_rejected() {
        let cfg = ProducerConfig {
            max_in_flight: 6,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max.in.flight must be <= 5"));
    }

    #[test]
    fn max_in_flight_zero_rejected() {
        let cfg = ProducerConfig {
            max_in_flight: 0,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max.in.flight must be > 0"));
    }

    #[test]
    fn zero_brokers_rejected() {
        let cfg = ProducerConfig {
            broker_count: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_partitions_rejected() {
        let cfg = ProducerConfig {
            partition_count: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
