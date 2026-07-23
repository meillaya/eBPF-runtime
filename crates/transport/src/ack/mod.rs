// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Deterministic batch ACK after durable Kafka acceptance.
//!
//! # Central invariant
//!
//! A batch is ACKed (and its outbox row deleted) ONLY after the
//! control plane confirms **durable Kafka acceptance** — never
//! on receipt alone. The `AckTracker` enforces this by requiring
//! an explicit `KafkaAcceptance` confirmation before
//! transitioning a batch to `Acked`.
//!
//! # Outbox deletion
//!
//! After a matching ACK, the outbox row is deleted (not merely
//! marked). This is the "SQLite outbox deletion after matching
//! ACK" requirement. The `OutboxDeleter` trait abstracts the
//! storage backend so tests can use an in-memory mock.

#![forbid(unsafe_code)]

mod tracker;

pub use tracker::{AckTracker, MockOutboxDeleter, OutboxDeleter};

/// The ACK state of a batch in the transport layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckState {
    /// Batch sent to the control plane, awaiting durable
    /// Kafka acceptance.
    AwaitingKafkaAcceptance,
    /// Kafka has durably accepted the batch; the ACK can be
    /// sent back to the agent.
    KafkaAccepted,
    /// The ACK has been sent and the outbox row deleted.
    AckedAndDeleted,
}

/// Confirmation that Kafka has durably accepted a batch.
///
/// This is the ONLY signal that permits an ACK. Receipt-only
/// confirmation is structurally absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaAcceptance {
    /// The batch ID that was accepted.
    pub batch_id: String,
    /// The Kafka topic the batch was written to.
    pub topic: String,
    /// The Kafka partition.
    pub partition: i32,
    /// The Kafka offset (confirms durability).
    pub offset: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransportError;

    fn acceptance(batch_id: &str) -> KafkaAcceptance {
        KafkaAcceptance {
            batch_id: batch_id.to_string(),
            topic: "events".to_string(),
            partition: 0,
            offset: 42,
        }
    }

    #[test]
    fn register_sent_creates_awaiting_state() {
        let mut tracker = AckTracker::new();
        tracker.register_sent("b-1");
        assert_eq!(
            tracker.state("b-1"),
            Some(AckState::AwaitingKafkaAcceptance)
        );
        assert_eq!(tracker.awaiting_count(), 1);
    }

    #[test]
    fn kafka_acceptance_transitions_state() {
        let mut tracker = AckTracker::new();
        tracker.register_sent("b-1");
        tracker.record_kafka_acceptance(acceptance("b-1")).unwrap();
        assert_eq!(tracker.state("b-1"), Some(AckState::KafkaAccepted));
        assert_eq!(tracker.awaiting_count(), 0);
    }

    #[test]
    fn kafka_acceptance_idempotent() {
        let mut tracker = AckTracker::new();
        tracker.register_sent("b-1");
        tracker.record_kafka_acceptance(acceptance("b-1")).unwrap();
        // Second acceptance is a no-op.
        tracker.record_kafka_acceptance(acceptance("b-1")).unwrap();
        assert_eq!(tracker.state("b-1"), Some(AckState::KafkaAccepted));
    }

    #[test]
    fn kafka_acceptance_unknown_batch_rejected() {
        let mut tracker = AckTracker::new();
        let err = tracker
            .record_kafka_acceptance(acceptance("unknown"))
            .unwrap_err();
        assert!(matches!(err, TransportError::OutboxError { .. }));
    }

    #[test]
    fn receipt_only_ack_always_rejected() {
        let mut tracker = AckTracker::new();
        tracker.register_sent("b-1");
        let err = tracker.try_receipt_only_ack("b-1").unwrap_err();
        assert!(matches!(err, TransportError::ReceiptOnlyAck { .. }));
    }

    #[test]
    fn complete_ack_before_kafka_acceptance_rejected() {
        let mut tracker = AckTracker::new();
        tracker.register_sent("b-1");
        // Try to ACK without Kafka acceptance.
        let err = tracker.complete_ack("b-1").unwrap_err();
        assert!(matches!(err, TransportError::ReceiptOnlyAck { .. }));
    }

    #[test]
    fn complete_ack_after_kafka_acceptance_succeeds() {
        let mut tracker = AckTracker::new();
        tracker.register_sent("b-1");
        tracker.record_kafka_acceptance(acceptance("b-1")).unwrap();
        tracker.complete_ack("b-1").unwrap();
        assert_eq!(tracker.state("b-1"), Some(AckState::AckedAndDeleted));
        assert_eq!(tracker.acked_count(), 1);
    }

    #[test]
    fn complete_ack_idempotent() {
        let mut tracker = AckTracker::new();
        tracker.register_sent("b-1");
        tracker.record_kafka_acceptance(acceptance("b-1")).unwrap();
        tracker.complete_ack("b-1").unwrap();
        // Second complete is a no-op.
        tracker.complete_ack("b-1").unwrap();
        assert_eq!(tracker.state("b-1"), Some(AckState::AckedAndDeleted));
    }

    #[test]
    fn outbox_deletion_after_matching_ack() {
        let deleter = MockOutboxDeleter::new(vec!["b-1".into(), "b-2".into()]);
        let mut tracker = AckTracker::with_outbox_deleter(Box::new(deleter));

        tracker.register_sent("b-1");
        tracker.register_sent("b-2");

        // ACK b-1 only.
        tracker.record_kafka_acceptance(acceptance("b-1")).unwrap();
        tracker.complete_ack("b-1").unwrap();

        // b-1 deleted, b-2 still in outbox.
        assert_eq!(tracker.state("b-1"), Some(AckState::AckedAndDeleted));
        assert_eq!(
            tracker.state("b-2"),
            Some(AckState::AwaitingKafkaAcceptance)
        );
    }

    #[test]
    fn mock_outbox_deleter_deletes_rows() {
        let deleter = MockOutboxDeleter::new(vec!["b-1".into(), "b-2".into()]);
        assert!(deleter.delete_outbox_row("b-1").unwrap());
        assert!(!deleter.delete_outbox_row("b-1").unwrap()); // Already deleted.
        assert_eq!(deleter.rows(), vec!["b-2".to_string()]);
    }

    #[test]
    fn batches_in_state_filters_correctly() {
        let mut tracker = AckTracker::new();
        tracker.register_sent("b-1");
        tracker.register_sent("b-2");
        tracker.register_sent("b-3");
        tracker.record_kafka_acceptance(acceptance("b-1")).unwrap();
        tracker.complete_ack("b-1").unwrap();

        let awaiting = tracker.batches_in_state(AckState::AwaitingKafkaAcceptance);
        assert_eq!(awaiting.len(), 2);
        assert!(awaiting.contains(&"b-2".to_string()));
        assert!(awaiting.contains(&"b-3".to_string()));

        let acked = tracker.batches_in_state(AckState::AckedAndDeleted);
        assert_eq!(acked, vec!["b-1".to_string()]);
    }

    #[test]
    fn acceptance_stored_with_offset() {
        let mut tracker = AckTracker::new();
        tracker.register_sent("b-1");
        tracker.record_kafka_acceptance(acceptance("b-1")).unwrap();
        let acc = tracker.acceptance("b-1").unwrap();
        assert_eq!(acc.topic, "events");
        assert_eq!(acc.offset, 42);
    }
}
