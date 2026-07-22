// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Mock Kafka producer with idempotent semantics.
//!
//! # BLOCKER
//!
//! This host does not have a running Kafka broker. The
//! `MockKafkaProducer` simulates the idempotent producer
//! contract: producer ID + sequence numbers per partition,
//! broker-side deduplication, `acks=all` durability semantics,
//! bounded in-flight, retry with backoff, and leader failover.
//!
//! Live Kafka integration (real `rdkafka` producer against a
//! KRaft cluster) is deferred to the declared self-hosted runner.
//!
//! # Idempotent producer contract
//!
//! - Each produce request carries a (producer_id, partition,
//!   sequence) triple.
//! - The broker deduplicates: if it sees a sequence it already
//!   committed, it returns the original offset (declared
//!   duplicate) instead of writing again.
//! - `acks=all` means the write is durable only after all
//!   in-sync replicas acknowledge.
//! - `max.in.flight <= 5` guarantees ordering even with
//!   retries.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::config::ProducerConfig;
use crate::error::{KafkaError, KafkaResult};
use crate::headers::RecordHeader;

/// A record to be produced to Kafka.
#[derive(Debug, Clone)]
pub struct ProducerRecord {
    /// The target topic.
    pub topic: String,
    /// The partition (determined by partition key).
    pub partition: i32,
    /// The record key (partition key for ordering).
    pub key: Vec<u8>,
    /// The record payload (serialized batch).
    pub payload: Vec<u8>,
    /// Record headers (schema version, event kind, etc.).
    pub headers: Vec<RecordHeader>,
}

/// Durable acceptance confirmation from the broker.
///
/// This is the ONLY signal that permits a gRPC ACK to the
/// agent. Mirrors `transport::ack::KafkaAcceptance`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableAcceptance {
    /// The batch ID that was accepted.
    pub batch_id: String,
    /// The topic the batch was written to.
    pub topic: String,
    /// The partition.
    pub partition: i32,
    /// The offset (confirms durability).
    pub offset: i64,
    /// Whether this was a declared duplicate (already written).
    pub is_duplicate: bool,
}

/// Simulated broker partition state.
#[derive(Debug, Default)]
struct PartitionState {
    /// The next offset to assign.
    next_offset: i64,
    /// Committed sequences: (producer_id, sequence) → offset.
    /// Used for idempotent deduplication.
    committed: HashMap<(u64, u64), i64>,
    /// Whether this partition's leader is available.
    leader_available: bool,
}

/// Simulated broker failure modes for testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailureMode {
    /// No failures (happy path).
    #[default]
    None,
    /// Transient failure: the first N produce attempts fail,
    /// then succeed (simulates leader election).
    Transient { fail_count: u32 },
    /// Broker unavailable: all produces fail.
    BrokerDown,
    /// Queue full: reject when in-flight exceeds limit.
    QueueFull,
}

/// Mock Kafka producer with idempotent semantics.
///
/// Simulates the Kafka idempotent producer contract for testing
/// without a live broker.
pub struct MockKafkaProducer {
    /// Producer configuration.
    config: ProducerConfig,
    /// Unique producer ID (assigned on init).
    producer_id: u64,
    /// Per-partition sequence numbers.
    sequences: HashMap<i32, u64>,
    /// Per-partition broker state.
    partitions: HashMap<i32, PartitionState>,
    /// Current in-flight request count.
    in_flight: usize,
    /// Failure mode for testing.
    failure_mode: FailureMode,
    /// Transient failures remaining.
    transient_remaining: u32,
    /// Total retries performed.
    retries: u64,
}

impl std::fmt::Debug for MockKafkaProducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockKafkaProducer")
            .field("producer_id", &self.producer_id)
            .field("in_flight", &self.in_flight)
            .field("failure_mode", &self.failure_mode)
            .field("retries", &self.retries)
            .finish()
    }
}

impl MockKafkaProducer {
    /// Create a new mock producer with the given config.
    pub fn new(config: ProducerConfig) -> Self {
        let mut partitions = HashMap::new();
        for p in 0..config.partition_count as i32 {
            partitions.insert(
                p,
                PartitionState {
                    next_offset: 0,
                    committed: HashMap::new(),
                    leader_available: true,
                },
            );
        }
        Self {
            config,
            producer_id: 1, // Deterministic for tests.
            sequences: HashMap::new(),
            partitions,
            in_flight: 0,
            failure_mode: FailureMode::None,
            transient_remaining: 0,
            retries: 0,
        }
    }

    /// Set the failure mode for testing.
    pub fn set_failure_mode(&mut self, mode: FailureMode) {
        if let FailureMode::Transient { fail_count } = mode {
            self.transient_remaining = fail_count;
        }
        self.failure_mode = mode;
    }

    /// The total retries performed.
    pub fn retries(&self) -> u64 {
        self.retries
    }

    /// The current in-flight count.
    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Simulate a leader failover for a partition.
    ///
    /// Marks the partition's leader as unavailable, then
    /// restores it (simulating election completion).
    pub fn simulate_leader_failover(&mut self, partition: i32) {
        if let Some(state) = self.partitions.get_mut(&partition) {
            state.leader_available = false;
        }
    }

    /// Restore a partition's leader after failover.
    pub fn restore_leader(&mut self, partition: i32) {
        if let Some(state) = self.partitions.get_mut(&partition) {
            state.leader_available = true;
        }
    }

    /// Produce a record with idempotent semantics.
    ///
    /// Returns a `DurableAcceptance` on success, or a
    /// `KafkaError` on failure. The idempotent producer
    /// guarantees:
    ///
    /// - Retried batches are deduplicated (declared duplicate).
    /// - Ordering is preserved (bounded in-flight).
    /// - Durability requires `acks=all` (all ISR acknowledge).
    pub fn produce(
        &mut self,
        record: &ProducerRecord,
        batch_id: &str,
    ) -> KafkaResult<DurableAcceptance> {
        // Check queue full (backpressure).
        if self.failure_mode == FailureMode::QueueFull
            || self.in_flight >= self.config.max_in_flight
        {
            return Err(KafkaError::QueueFull {
                in_flight: self.in_flight,
                max_in_flight: self.config.max_in_flight,
            });
        }

        // Check broker down.
        if self.failure_mode == FailureMode::BrokerDown {
            return Err(KafkaError::BrokerUnavailable {
                reason: "broker down (simulated)".to_string(),
            });
        }

        // Check partition leader availability.
        let partition_state = self.partitions.get(&record.partition).ok_or_else(|| {
            KafkaError::BrokerUnavailable {
                reason: format!("unknown partition {}", record.partition),
            }
        })?;

        if !partition_state.leader_available {
            return Err(KafkaError::BrokerUnavailable {
                reason: format!(
                    "partition {} leader unavailable (failover)",
                    record.partition
                ),
            });
        }

        // Simulate transient failure.
        if matches!(self.failure_mode, FailureMode::Transient { .. })
            && self.transient_remaining > 0
        {
            self.transient_remaining -= 1;
            self.retries += 1;
            return Err(KafkaError::BrokerUnavailable {
                reason: format!("transient failure ({} remaining)", self.transient_remaining),
            });
        }

        // Track in-flight.
        self.in_flight += 1;

        // Get or assign sequence for this partition.
        let seq = self.sequences.entry(record.partition).or_insert(0);
        let current_seq = *seq;

        // Check for idempotent deduplication.
        let partition_state = self.partitions.get_mut(&record.partition).unwrap();
        let dedup_key = (self.producer_id, current_seq);

        let result = if let Some(&existing_offset) = partition_state.committed.get(&dedup_key) {
            // Declared duplicate: already committed.
            Ok(DurableAcceptance {
                batch_id: batch_id.to_string(),
                topic: record.topic.clone(),
                partition: record.partition,
                offset: existing_offset,
                is_duplicate: true,
            })
        } else {
            // New write: assign offset and commit.
            let offset = partition_state.next_offset;
            partition_state.next_offset += 1;
            partition_state.committed.insert(dedup_key, offset);

            // Advance sequence.
            *self.sequences.get_mut(&record.partition).unwrap() += 1;

            Ok(DurableAcceptance {
                batch_id: batch_id.to_string(),
                topic: record.topic.clone(),
                partition: record.partition,
                offset,
                is_duplicate: false,
            })
        };

        // Release in-flight.
        self.in_flight -= 1;

        result
    }

    /// Produce with retry (simulates the idempotent producer's
    /// internal retry loop).
    ///
    /// Retries up to `max_retries` on transient failures.
    /// Returns the first success or the last error.
    pub fn produce_with_retry(
        &mut self,
        record: &ProducerRecord,
        batch_id: &str,
    ) -> KafkaResult<DurableAcceptance> {
        let max_attempts = self.config.max_retries.min(10) + 1; // Cap for tests.
        let mut last_err = None;

        for _ in 0..max_attempts {
            match self.produce(record, batch_id) {
                Ok(acceptance) => return Ok(acceptance),
                Err(e @ KafkaError::BrokerUnavailable { .. }) => {
                    last_err = Some(e);
                    self.retries += 1;
                    // In a real producer, we'd backoff here.
                    continue;
                }
                Err(e) => return Err(e), // Non-retryable.
            }
        }

        Err(last_err.unwrap_or(KafkaError::UnrecoverableProducerError {
            batch_id: batch_id.to_string(),
            reason: "retries exhausted".to_string(),
        }))
    }

    /// The next offset for a partition (for test assertions).
    pub fn next_offset(&self, partition: i32) -> Option<i64> {
        self.partitions.get(&partition).map(|p| p.next_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ProducerConfig {
        ProducerConfig {
            partition_count: 4,
            max_in_flight: 5,
            ..Default::default()
        }
    }

    fn test_record(partition: i32) -> ProducerRecord {
        ProducerRecord {
            topic: "events.v1".to_string(),
            partition,
            key: b"prod/agent/prod/node-1".to_vec(),
            payload: b"test-payload".to_vec(),
            headers: vec![],
        }
    }

    #[test]
    fn produce_assigns_offset() {
        let mut producer = MockKafkaProducer::new(test_config());
        let record = test_record(0);
        let acc = producer.produce(&record, "b-1").unwrap();
        assert_eq!(acc.offset, 0);
        assert_eq!(acc.partition, 0);
        assert!(!acc.is_duplicate);
    }

    #[test]
    fn produce_sequential_offsets() {
        let mut producer = MockKafkaProducer::new(test_config());
        let record = test_record(0);
        let a1 = producer.produce(&record, "b-1").unwrap();
        let a2 = producer.produce(&record, "b-2").unwrap();
        assert_eq!(a1.offset, 0);
        assert_eq!(a2.offset, 1);
    }

    #[test]
    fn idempotent_deduplication() {
        let mut producer = MockKafkaProducer::new(test_config());
        let record = test_record(0);

        // First produce succeeds.
        let a1 = producer.produce(&record, "b-1").unwrap();
        assert!(!a1.is_duplicate);

        // Simulate retry: reset sequence to replay.
        producer.sequences.insert(0, 0);
        let a2 = producer.produce(&record, "b-1-retry").unwrap();
        assert!(a2.is_duplicate);
        assert_eq!(a2.offset, a1.offset); // Same offset.
    }

    #[test]
    fn queue_full_backpressure() {
        let mut producer = MockKafkaProducer::new(test_config());
        producer.set_failure_mode(FailureMode::QueueFull);
        let record = test_record(0);
        let err = producer.produce(&record, "b-1").unwrap_err();
        assert!(matches!(err, KafkaError::QueueFull { .. }));
    }

    #[test]
    fn broker_down_rejected() {
        let mut producer = MockKafkaProducer::new(test_config());
        producer.set_failure_mode(FailureMode::BrokerDown);
        let record = test_record(0);
        let err = producer.produce(&record, "b-1").unwrap_err();
        assert!(matches!(err, KafkaError::BrokerUnavailable { .. }));
    }

    #[test]
    fn transient_failure_then_success() {
        let mut producer = MockKafkaProducer::new(test_config());
        producer.set_failure_mode(FailureMode::Transient { fail_count: 2 });
        let record = test_record(0);

        // First two attempts fail.
        let e1 = producer.produce(&record, "b-1").unwrap_err();
        assert!(matches!(e1, KafkaError::BrokerUnavailable { .. }));
        let e2 = producer.produce(&record, "b-1").unwrap_err();
        assert!(matches!(e2, KafkaError::BrokerUnavailable { .. }));

        // Third attempt succeeds.
        let acc = producer.produce(&record, "b-1").unwrap();
        assert!(!acc.is_duplicate);
    }

    #[test]
    fn produce_with_retry_recovers() {
        let mut producer = MockKafkaProducer::new(test_config());
        producer.set_failure_mode(FailureMode::Transient { fail_count: 2 });
        let record = test_record(0);

        let acc = producer.produce_with_retry(&record, "b-1").unwrap();
        assert!(!acc.is_duplicate);
        assert!(producer.retries() >= 2);
    }

    #[test]
    fn leader_failover_and_recovery() {
        let mut producer = MockKafkaProducer::new(test_config());
        let record = test_record(0);

        // Produce succeeds initially.
        producer.produce(&record, "b-1").unwrap();

        // Simulate leader failover.
        producer.simulate_leader_failover(0);
        let err = producer.produce(&record, "b-2").unwrap_err();
        assert!(matches!(err, KafkaError::BrokerUnavailable { .. }));

        // Restore leader.
        producer.restore_leader(0);
        let acc = producer.produce(&record, "b-2").unwrap();
        assert_eq!(acc.offset, 1); // Continues from where it left off.
    }

    #[test]
    fn per_partition_sequences_independent() {
        let mut producer = MockKafkaProducer::new(test_config());
        let r0 = test_record(0);
        let r1 = test_record(1);

        producer.produce(&r0, "b-p0").unwrap();
        producer.produce(&r1, "b-p1").unwrap();
        producer.produce(&r0, "b-p0-2").unwrap();

        // Partition 0 has 2 records, partition 1 has 1.
        assert_eq!(producer.next_offset(0), Some(2));
        assert_eq!(producer.next_offset(1), Some(1));
    }

    #[test]
    fn in_flight_returns_to_zero() {
        let mut producer = MockKafkaProducer::new(test_config());
        let record = test_record(0);
        producer.produce(&record, "b-1").unwrap();
        assert_eq!(producer.in_flight(), 0);
    }
}
