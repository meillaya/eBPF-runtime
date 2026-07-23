// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed transport errors.
//!
//! Every failure path in the transport layer maps to a variant
//! here so callers can match on the exact rejection reason
//! without string-parsing. Mirrors the protocol crate's
//! `ProtocolError` discipline: the transport NEVER panics on
//! invalid input; it returns `Err(TransportError::...)`.

#![forbid(unsafe_code)]

use std::fmt;

/// Typed status/error codes for the agent/control-plane
/// transport layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The bounded queue is full; the caller must backpressure.
    /// Control and event queues are independent — a full event
    /// queue does NOT block control delivery.
    QueueFull {
        /// Which queue rejected the enqueue.
        queue: &'static str,
        /// Current capacity.
        capacity: usize,
    },

    /// The operation's deadline expired before completion.
    /// Wraps the protocol crate's deadline propagation.
    DeadlineExpired {
        /// The deadline that expired (epoch millis).
        deadline_epoch_ms: u64,
        /// The current time when expiry was detected.
        now_epoch_ms: u64,
    },

    /// The peer's SPIFFE ID failed authorization. The transport
    /// is fail-closed: no valid SPIFFE mTLS → no connection.
    PeerUnauthorized {
        /// The peer SPIFFE ID (or "<none>" if absent).
        peer_spiffe_id: String,
        /// Human-readable rejection reason.
        reason: String,
    },

    /// A sequence gap was detected between the agent's last
    /// acknowledged sequence and the next expected sequence.
    SequenceGap {
        /// The last sequence the control plane acknowledged.
        last_acked_seq: u64,
        /// The next sequence the agent attempted to send.
        next_seq: u64,
        /// The agent generation at gap detection.
        agent_generation: String,
    },

    /// The batch ACK did not arrive within the deadline.
    /// The batch remains in the outbox for retry.
    AckTimeout {
        /// The batch ID that timed out.
        batch_id: String,
        /// The deadline that expired (epoch millis).
        deadline_epoch_ms: u64,
    },

    /// Reconnection attempts exhausted (circuit breaker open).
    ReconnectExhausted {
        /// Number of attempts made.
        attempts: u32,
        /// The maximum attempts before circuit-breaking.
        max_attempts: u32,
    },

    /// The SQLite outbox operation failed.
    OutboxError {
        /// Human-readable reason.
        reason: String,
    },

    /// The Kafka broker is unavailable; batch acceptance cannot
    /// be confirmed. The batch MUST NOT be ACKed.
    KafkaUnavailable {
        /// Human-readable reason.
        reason: String,
    },

    /// The peer attempted a receipt-only ACK (ACK before
    /// durable Kafka acceptance). This is a protocol violation.
    ReceiptOnlyAck {
        /// The batch ID that was receipt-only ACKed.
        batch_id: String,
    },

    /// The SVID has expired or been redacted; the transport
    /// cannot establish mTLS. Fail-closed.
    CredentialsUnavailable {
        /// Human-readable reason.
        reason: String,
    },

    /// The channel is closed (peer disconnected or shut down).
    ChannelClosed {
        /// Which channel closed.
        channel: &'static str,
    },
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull { queue, capacity } => {
                write!(f, "queue full: {queue} at capacity {capacity}")
            }
            Self::DeadlineExpired {
                deadline_epoch_ms,
                now_epoch_ms,
            } => {
                write!(
                    f,
                    "deadline expired: deadline {deadline_epoch_ms} < now {now_epoch_ms}"
                )
            }
            Self::PeerUnauthorized {
                peer_spiffe_id,
                reason,
            } => {
                write!(f, "peer unauthorized: {peer_spiffe_id}: {reason}")
            }
            Self::SequenceGap {
                last_acked_seq,
                next_seq,
                agent_generation,
            } => {
                write!(
                    f,
                    "sequence gap: last_acked={last_acked_seq} next={next_seq} gen={agent_generation}"
                )
            }
            Self::AckTimeout {
                batch_id,
                deadline_epoch_ms,
            } => {
                write!(
                    f,
                    "ack timeout: batch {batch_id} deadline {deadline_epoch_ms}"
                )
            }
            Self::ReconnectExhausted {
                attempts,
                max_attempts,
            } => {
                write!(f, "reconnect exhausted: {attempts}/{max_attempts} attempts")
            }
            Self::OutboxError { reason } => {
                write!(f, "outbox error: {reason}")
            }
            Self::KafkaUnavailable { reason } => {
                write!(f, "kafka unavailable: {reason}")
            }
            Self::ReceiptOnlyAck { batch_id } => {
                write!(
                    f,
                    "receipt-only ACK rejected: batch {batch_id} (must wait for durable Kafka acceptance)"
                )
            }
            Self::CredentialsUnavailable { reason } => {
                write!(f, "credentials unavailable: {reason}")
            }
            Self::ChannelClosed { channel } => {
                write!(f, "channel closed: {channel}")
            }
        }
    }
}

impl std::error::Error for TransportError {}

/// Typed result alias for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_displayable() {
        let variants = [
            TransportError::QueueFull {
                queue: "event",
                capacity: 1024,
            },
            TransportError::DeadlineExpired {
                deadline_epoch_ms: 100,
                now_epoch_ms: 200,
            },
            TransportError::PeerUnauthorized {
                peer_spiffe_id: "spiffe://evil/agent/x/y".into(),
                reason: "trust domain mismatch".into(),
            },
            TransportError::SequenceGap {
                last_acked_seq: 5,
                next_seq: 10,
                agent_generation: "gen-1".into(),
            },
            TransportError::AckTimeout {
                batch_id: "batch-1".into(),
                deadline_epoch_ms: 1000,
            },
            TransportError::ReconnectExhausted {
                attempts: 10,
                max_attempts: 10,
            },
            TransportError::OutboxError {
                reason: "disk full".into(),
            },
            TransportError::KafkaUnavailable {
                reason: "broker down".into(),
            },
            TransportError::ReceiptOnlyAck {
                batch_id: "batch-2".into(),
            },
            TransportError::CredentialsUnavailable {
                reason: "SVID expired".into(),
            },
            TransportError::ChannelClosed { channel: "control" },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn queue_full_includes_queue_name() {
        let err = TransportError::QueueFull {
            queue: "event",
            capacity: 512,
        };
        let msg = err.to_string();
        assert!(msg.contains("event"));
        assert!(msg.contains("512"));
    }

    #[test]
    fn receipt_only_ack_rejected_message() {
        let err = TransportError::ReceiptOnlyAck {
            batch_id: "b-42".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("receipt-only"));
        assert!(msg.contains("durable Kafka acceptance"));
    }
}
