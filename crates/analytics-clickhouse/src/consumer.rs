// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Consumer-lag metric types and bounded settings.
//!
//! Mirrors the consumer lag views in
//! `deploy/clickhouse/0004_consumer_lag_metrics.sql`.
//!
//! The bounded lag threshold (10,000 messages/partition) is the
//! alerting boundary: if consumer lag exceeds this, the ingestion
//! pipeline is considered degraded.

use serde::{Deserialize, Serialize};

use crate::error::{AnalyticsError, AnalyticsResult};
use crate::MAX_CONSUMER_LAG_PER_PARTITION;

/// Per-partition consumer lag metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionLag {
    /// Kafka topic.
    pub topic: String,
    /// Kafka partition.
    pub partition: i32,
    /// Last consumed offset.
    pub consumed_offset: u64,
    /// Latest available offset (from Kafka broker).
    pub latest_offset: u64,
    /// Total rows ingested for this partition.
    pub total_rows: u64,
}

impl PartitionLag {
    /// The current lag (latest - consumed).
    pub fn lag(&self) -> u64 {
        self.latest_offset.saturating_sub(self.consumed_offset)
    }

    /// Whether the lag is within the bounded threshold.
    pub fn is_within_bounds(&self) -> bool {
        self.lag() <= MAX_CONSUMER_LAG_PER_PARTITION
    }

    /// Validate the lag against the bounded threshold.
    pub fn validate(&self) -> AnalyticsResult<()> {
        if !self.is_within_bounds() {
            return Err(AnalyticsError::ConsumerLagExceeded {
                partition: self.partition,
                lag: self.lag(),
                threshold: MAX_CONSUMER_LAG_PER_PARTITION,
            });
        }
        Ok(())
    }
}

/// Aggregate consumer lag metrics across all partitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerLagMetrics {
    /// Per-partition lag.
    pub partitions: Vec<PartitionLag>,
}

impl ConsumerLagMetrics {
    /// Create from per-partition data.
    pub fn new(partitions: Vec<PartitionLag>) -> Self {
        Self { partitions }
    }

    /// Total lag across all partitions.
    pub fn total_lag(&self) -> u64 {
        self.partitions.iter().map(|p| p.lag()).sum()
    }

    /// Maximum lag across all partitions.
    pub fn max_lag(&self) -> u64 {
        self.partitions.iter().map(|p| p.lag()).max().unwrap_or(0)
    }

    /// Whether all partitions are within bounds.
    pub fn is_within_bounds(&self) -> bool {
        self.partitions.iter().all(|p| p.is_within_bounds())
    }

    /// Validate all partitions against the bounded threshold.
    pub fn validate(&self) -> AnalyticsResult<()> {
        for partition in &self.partitions {
            partition.validate()?;
        }
        Ok(())
    }

    /// Number of partitions being tracked.
    pub fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    /// Partitions that exceed the lag threshold.
    pub fn lagging_partitions(&self) -> Vec<&PartitionLag> {
        self.partitions
            .iter()
            .filter(|p| !p.is_within_bounds())
            .collect()
    }
}

/// Kafka consumer configuration (bounded settings).
/// Mirrors the Kafka engine SETTINGS in 0002_kafka_consumer.sql.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerConfig {
    /// Kafka broker list.
    pub broker_list: String,
    /// Topic to consume.
    pub topic: String,
    /// Consumer group name.
    pub group_name: String,
    /// Number of consumers (1 per partition is the upper bound).
    pub num_consumers: u32,
    /// Maximum block size for polling.
    pub max_block_size: u32,
    /// Skip broken messages count (0 = strict, >0 = tolerant).
    pub skip_broken_messages: u32,
    /// Commit every batch (1 = commit after each poll).
    pub commit_every_batch: u32,
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            broker_list: "localhost:9092".to_string(),
            topic: "events.v1".to_string(),
            group_name: "clickhouse-events-v1".to_string(),
            num_consumers: 1,
            max_block_size: 65536,
            skip_broken_messages: 0,
            commit_every_batch: 1,
        }
    }
}

impl ConsumerConfig {
    /// Validate the consumer configuration.
    pub fn validate(&self) -> AnalyticsResult<()> {
        if self.broker_list.is_empty() {
            return Err(AnalyticsError::MalformedMessage {
                reason: "broker_list must not be empty".to_string(),
            });
        }
        if self.topic.is_empty() {
            return Err(AnalyticsError::MalformedMessage {
                reason: "topic must not be empty".to_string(),
            });
        }
        if self.group_name.is_empty() {
            return Err(AnalyticsError::MalformedMessage {
                reason: "group_name must not be empty".to_string(),
            });
        }
        if self.num_consumers == 0 {
            return Err(AnalyticsError::MalformedMessage {
                reason: "num_consumers must be >= 1".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_partition_lag(partition: i32, consumed: u64, latest: u64) -> PartitionLag {
        PartitionLag {
            topic: "events.v1".to_string(),
            partition,
            consumed_offset: consumed,
            latest_offset: latest,
            total_rows: consumed,
        }
    }

    #[test]
    fn zero_lag_within_bounds() {
        let lag = make_partition_lag(0, 100, 100);
        assert_eq!(lag.lag(), 0);
        assert!(lag.is_within_bounds());
        assert!(lag.validate().is_ok());
    }

    #[test]
    fn small_lag_within_bounds() {
        let lag = make_partition_lag(0, 100, 5000);
        assert_eq!(lag.lag(), 4900);
        assert!(lag.is_within_bounds());
    }

    #[test]
    fn threshold_lag_within_bounds() {
        let lag = make_partition_lag(0, 0, MAX_CONSUMER_LAG_PER_PARTITION);
        assert_eq!(lag.lag(), MAX_CONSUMER_LAG_PER_PARTITION);
        assert!(lag.is_within_bounds());
    }

    #[test]
    fn exceeded_lag_rejected() {
        let lag = make_partition_lag(0, 0, MAX_CONSUMER_LAG_PER_PARTITION + 1);
        assert!(!lag.is_within_bounds());
        assert!(matches!(
            lag.validate().unwrap_err(),
            AnalyticsError::ConsumerLagExceeded { .. }
        ));
    }

    #[test]
    fn aggregate_metrics_all_within_bounds() {
        let metrics = ConsumerLagMetrics::new(vec![
            make_partition_lag(0, 100, 200),
            make_partition_lag(1, 500, 600),
            make_partition_lag(2, 1000, 1000),
        ]);
        assert!(metrics.is_within_bounds());
        assert_eq!(metrics.total_lag(), 200);
        assert_eq!(metrics.max_lag(), 100);
        assert_eq!(metrics.partition_count(), 3);
    }

    #[test]
    fn aggregate_metrics_one_exceeds() {
        let metrics = ConsumerLagMetrics::new(vec![
            make_partition_lag(0, 100, 200),
            make_partition_lag(1, 0, MAX_CONSUMER_LAG_PER_PARTITION + 500),
        ]);
        assert!(!metrics.is_within_bounds());
        assert_eq!(metrics.lagging_partitions().len(), 1);
        assert_eq!(metrics.lagging_partitions()[0].partition, 1);
    }

    #[test]
    fn aggregate_validate_fails_on_exceeded() {
        let metrics = ConsumerLagMetrics::new(vec![make_partition_lag(
            0,
            0,
            MAX_CONSUMER_LAG_PER_PARTITION + 1,
        )]);
        assert!(metrics.validate().is_err());
    }

    #[test]
    fn empty_metrics_within_bounds() {
        let metrics = ConsumerLagMetrics::new(vec![]);
        assert!(metrics.is_within_bounds());
        assert_eq!(metrics.total_lag(), 0);
        assert_eq!(metrics.max_lag(), 0);
    }

    #[test]
    fn default_consumer_config_valid() {
        let config = ConsumerConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.topic, "events.v1");
        assert_eq!(config.group_name, "clickhouse-events-v1");
    }

    #[test]
    fn empty_broker_list_rejected() {
        let config = ConsumerConfig {
            broker_list: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_consumers_rejected() {
        let config = ConsumerConfig {
            num_consumers: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn saturating_sub_prevents_underflow() {
        // consumed > latest (shouldn't happen, but be safe)
        let lag = make_partition_lag(0, 200, 100);
        assert_eq!(lag.lag(), 0);
    }
}
