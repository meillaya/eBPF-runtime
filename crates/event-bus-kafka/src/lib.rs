// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Control-plane Kafka event publisher.
//!
//! Publishes idempotent event batches to Kafka topic
//! `events.v1` with per-agent partition ordering, protobuf
//! schema/version headers, durable-delivery callback for gRPC
//! ACK, and `events.dlq.v1` dead-letter path for
//! schema-rejected batches.
//!
//! # Semantics
//!
//! - **At-least-once** with declared duplicates only. No
//!   cross-session exactly-once claim.
//! - **No ACK before durability**: the gRPC ACK to the agent
//!   fires ONLY after the broker confirms `acks=all`
//!   acceptance.
//! - **No hidden loss**: every submitted batch is accounted
//!   for (accepted, duplicate, DLQ, timeout, queue-full, or
//!   unrecoverable).
//! - **No agent credentials beyond control plane**: agents
//!   never see Kafka. This publisher runs exclusively in the
//!   control plane.
//!
//! # BLOCKER
//!
//! This host does not have a running Kafka broker. All logic
//! is validated via `MockKafkaProducer`. Live Kafka integration
//! re-opens on the declared self-hosted runner with a KRaft
//! cluster deployed.
//!
//! # Modules
//!
//! - [`config`]: Idempotent producer configuration
//!   (`acks=all`, `enable.idempotence=true`, bounded in-flight)
//! - [`partition`]: Deterministic partition key derivation from
//!   cluster/agent identity
//! - [`headers`]: Protobuf schema/version headers
//! - [`producer`]: Mock Kafka producer with idempotent
//!   semantics
//! - [`publisher`]: The main publisher (control-plane entry
//!   point)
//! - [`dlq`]: Dead-letter queue routing for schema-rejected
//!   batches
//! - [`metrics`]: Timeout/backpressure metrics
//! - [`error`]: Typed publisher errors

#![forbid(unsafe_code)]

pub mod config;
pub mod dlq;
pub mod error;
pub mod headers;
pub mod metrics;
pub mod partition;
pub mod producer;
pub mod publisher;

/// The primary event topic.
pub const TOPIC_EVENTS_V1: &str = "events.v1";

/// The dead-letter queue topic for schema-rejected batches.
pub const TOPIC_DLQ_V1: &str = "events.dlq.v1";

/// Re-export the publisher as the crate's primary interface.
pub use publisher::KafkaPublisher;

/// Re-export the producer config.
pub use config::ProducerConfig;

/// Re-export the durable acceptance confirmation.
pub use producer::DurableAcceptance;

/// Re-export the error type.
pub use error::{KafkaError, KafkaResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_constants_match_config_defaults() {
        let cfg = ProducerConfig::default();
        assert_eq!(cfg.topic, TOPIC_EVENTS_V1);
        assert_eq!(cfg.dlq_topic, TOPIC_DLQ_V1);
    }

    #[test]
    fn topic_constants_are_versioned() {
        assert!(TOPIC_EVENTS_V1.ends_with(".v1"));
        assert!(TOPIC_DLQ_V1.ends_with(".v1"));
    }
}
