// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kafka producer for the batch relay.
//!
//! Postgres remains the source of truth. The relay publishes one message per
//! batch, keyed by batch id, so consumers can deduplicate retries.

#![forbid(unsafe_code)]

use std::time::Duration;

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use thiserror::Error;

/// Kafka producer errors.
#[derive(Debug, Error)]
pub enum KafkaError {
    /// Client configuration failure.
    #[error("kafka: {0}")]
    Client(String),
    /// Send failure.
    #[error("kafka send: {0}")]
    Send(String),
}

/// A future-based Kafka producer.
pub struct KafkaSink {
    producer: FutureProducer,
    topic: String,
}

impl KafkaSink {
    /// Connect to the broker list.
    pub fn connect(brokers: &[String], topic: impl Into<String>) -> Result<Self, KafkaError> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers.join(","))
            .set("message.timeout.ms", "10000")
            .set("enable.idempotence", "true")
            .create()
            .map_err(|error| KafkaError::Client(error.to_string()))?;
        Ok(Self {
            producer,
            topic: topic.into(),
        })
    }

    /// Publish one batch keyed by batch id.
    pub async fn publish(&self, key: &str, payload: &[u8]) -> Result<(), KafkaError> {
        self.producer
            .send(
                FutureRecord::to(&self.topic).key(key).payload(payload),
                Duration::from_secs(10),
            )
            .await
            .map_err(|(error, _)| KafkaError::Send(error.to_string()))?;
        Ok(())
    }
}
