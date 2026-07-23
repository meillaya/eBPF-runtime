// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed Kafka publisher errors.
//!
//! Every failure path maps to a variant here so callers can
//! match on the exact rejection reason without string-parsing.
//! Mirrors the protocol/transport crate error discipline: the
//! publisher NEVER panics on invalid input; it returns
//! `Err(KafkaError::...)`.

#![forbid(unsafe_code)]

use std::fmt;

/// Typed errors for the Kafka event publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KafkaError {
    /// The local producer queue is full; the caller must
    /// backpressure. The batch is NOT lost — it remains in the
    /// outbox for retry after backpressure relief.
    QueueFull {
        /// Current in-flight request count.
        in_flight: usize,
        /// Maximum in-flight requests (bounded by config).
        max_in_flight: usize,
    },

    /// The produce request timed out before durable acceptance.
    /// The batch remains in the outbox; no ACK is sent.
    Timeout {
        /// The batch ID that timed out.
        batch_id: String,
        /// The timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// The downstream consumer rejected the batch schema.
    /// The batch is routed to the DLQ topic (events.dlq.v1).
    SchemaRejected {
        /// The batch ID that was rejected.
        batch_id: String,
        /// The schema major version in the batch headers.
        schema_major: u32,
        /// The schema minor version in the batch headers.
        schema_minor: u32,
        /// Human-readable rejection reason.
        reason: String,
    },

    /// The Kafka broker is unavailable; the batch cannot be
    /// durably accepted. The batch MUST NOT be ACKed.
    BrokerUnavailable {
        /// Human-readable reason.
        reason: String,
    },

    /// A duplicate batch was detected by the idempotent
    /// producer. This is a DECLARED duplicate (at-least-once
    /// semantics): the batch was already durably accepted.
    /// The caller may safely ACK.
    DuplicateBatch {
        /// The batch ID that was a duplicate.
        batch_id: String,
        /// The partition the original was written to.
        partition: i32,
        /// The offset of the original write.
        offset: i64,
    },

    /// The batch payload failed serialization.
    SerializationFailed {
        /// The batch ID.
        batch_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// An unrecoverable producer error occurred. The batch
    /// remains in the outbox. The caller MUST NOT
    /// application-resend without reconciliation (the idempotent
    /// producer may have already delivered the batch).
    UnrecoverableProducerError {
        /// The batch ID.
        batch_id: String,
        /// Human-readable reason.
        reason: String,
    },
}

impl fmt::Display for KafkaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull {
                in_flight,
                max_in_flight,
            } => {
                write!(
                    f,
                    "producer queue full: {in_flight}/{max_in_flight} in-flight"
                )
            }
            Self::Timeout {
                batch_id,
                timeout_ms,
            } => {
                write!(f, "produce timeout: batch {batch_id} after {timeout_ms}ms")
            }
            Self::SchemaRejected {
                batch_id,
                schema_major,
                schema_minor,
                reason,
            } => {
                write!(
                    f,
                    "schema rejected: batch {batch_id} v{schema_major}.{schema_minor}: {reason}"
                )
            }
            Self::BrokerUnavailable { reason } => {
                write!(f, "broker unavailable: {reason}")
            }
            Self::DuplicateBatch {
                batch_id,
                partition,
                offset,
            } => {
                write!(
                    f,
                    "declared duplicate: batch {batch_id} already at partition {partition} offset {offset}"
                )
            }
            Self::SerializationFailed { batch_id, reason } => {
                write!(f, "serialization failed: batch {batch_id}: {reason}")
            }
            Self::UnrecoverableProducerError { batch_id, reason } => {
                write!(
                    f,
                    "unrecoverable producer error: batch {batch_id}: {reason} (do NOT application-resend without reconciliation)"
                )
            }
        }
    }
}

impl std::error::Error for KafkaError {}

/// Typed result alias for Kafka publisher operations.
pub type KafkaResult<T> = Result<T, KafkaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_displayable() {
        let variants = [
            KafkaError::QueueFull {
                in_flight: 5,
                max_in_flight: 5,
            },
            KafkaError::Timeout {
                batch_id: "b-1".into(),
                timeout_ms: 30000,
            },
            KafkaError::SchemaRejected {
                batch_id: "b-2".into(),
                schema_major: 0,
                schema_minor: 1,
                reason: "stale major".into(),
            },
            KafkaError::BrokerUnavailable {
                reason: "leader election".into(),
            },
            KafkaError::DuplicateBatch {
                batch_id: "b-3".into(),
                partition: 2,
                offset: 100,
            },
            KafkaError::SerializationFailed {
                batch_id: "b-4".into(),
                reason: "invalid utf8".into(),
            },
            KafkaError::UnrecoverableProducerError {
                batch_id: "b-5".into(),
                reason: "fenced".into(),
            },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn duplicate_batch_message_includes_offset() {
        let err = KafkaError::DuplicateBatch {
            batch_id: "b-42".into(),
            partition: 1,
            offset: 999,
        };
        let msg = err.to_string();
        assert!(msg.contains("declared duplicate"));
        assert!(msg.contains("999"));
    }

    #[test]
    fn unrecoverable_error_warns_no_resend() {
        let err = KafkaError::UnrecoverableProducerError {
            batch_id: "b-7".into(),
            reason: "fenced by newer producer".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("do NOT application-resend"));
    }
}
