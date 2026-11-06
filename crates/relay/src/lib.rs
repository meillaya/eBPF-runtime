// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Projection relay.
//!
//! The control plane commits batches to PostgreSQL before ACK. This relay
//! copies those batches to Kafka and ClickHouse and marks `relayed_at` only
//! after both succeed.

#![forbid(unsafe_code)]

use std::time::Duration;

use analytics_clickhouse::ClickHouse;
use event_bus_kafka::KafkaSink;
use event_model::Batch;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Relay configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// PostgreSQL URL.
    pub database_url: String,
    /// Kafka brokers. Empty disables Kafka.
    #[serde(default)]
    pub kafka_brokers: Vec<String>,
    /// Kafka topic.
    #[serde(default = "default_topic")]
    pub kafka_topic: String,
    /// ClickHouse HTTP endpoint.
    pub clickhouse_url: String,
    /// ClickHouse database.
    #[serde(default = "default_database")]
    pub clickhouse_database: String,
    /// Poll interval.
    #[serde(default = "default_poll_ms")]
    pub poll_ms: u64,
    /// Batches per pass.
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_topic() -> String {
    "ebpf.batches".to_string()
}

fn default_database() -> String {
    "ebpf".to_string()
}

fn default_poll_ms() -> u64 {
    1000
}

fn default_limit() -> usize {
    100
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            database_url: "postgres://postgres@127.0.0.1:5432/control".to_string(),
            kafka_brokers: Vec::new(),
            kafka_topic: default_topic(),
            clickhouse_url: "http://127.0.0.1:8123".to_string(),
            clickhouse_database: default_database(),
            poll_ms: default_poll_ms(),
            limit: default_limit(),
        }
    }
}

/// Relay errors.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Database failure.
    #[error("database: {0}")]
    Database(#[from] control_db::DbError),
    /// Kafka failure.
    #[error("kafka: {0}")]
    Kafka(#[from] event_bus_kafka::KafkaError),
    /// ClickHouse failure.
    #[error("clickhouse: {0}")]
    ClickHouse(#[from] analytics_clickhouse::ClickHouseError),
    /// Serialization failure.
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Run the relay forever, or once when `once` is true.
pub async fn run(config: RelayConfig, once: bool) -> Result<(), RelayError> {
    let pool = control_db::connect(&config.database_url, 5).await?;
    control_db::migrate(&pool).await?;
    let clickhouse = ClickHouse::new(&config.clickhouse_url);
    clickhouse
        .ensure_schema(&config.clickhouse_database)
        .await?;
    let kafka = if config.kafka_brokers.is_empty() {
        None
    } else {
        Some(KafkaSink::connect(
            &config.kafka_brokers,
            &config.kafka_topic,
        )?)
    };

    loop {
        let pending = control_db::pending_projections(&pool, config.limit).await?;
        for row in &pending {
            let batch: Batch = serde_json::from_slice(&row.payload)?;
            if let Some(kafka) = &kafka {
                kafka.publish(&batch.batch_id, &row.payload).await?;
            }
            clickhouse
                .insert_batch(&config.clickhouse_database, &batch)
                .await?;
            control_db::mark_relayed(&pool, &batch.batch_id).await?;
            tracing::info!(batch_id = %batch.batch_id, events = row.event_count, "projected batch");
        }
        if once {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(config.poll_ms.max(100))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let config = RelayConfig::default();
        assert_eq!(config.kafka_topic, "ebpf.batches");
        assert_eq!(config.clickhouse_database, "ebpf");
        assert!(config.limit > 0);
    }
}
