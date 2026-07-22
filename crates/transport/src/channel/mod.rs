// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Separate deadline-bound control and event channels.
//!
//! # Architecture
//!
//! The transport uses TWO independent channels:
//!
//! 1. **Control channel**: low-volume, high-priority. Carries
//!    kill-switch commands, policy updates, registration
//!    responses. NEVER blocked by event backpressure.
//!
//! 2. **Event channel**: high-volume. Carries event batches.
//!    Backpressures independently via a bounded queue.
//!
//! # Deadlock prevention
//!
//! Each channel has separate read and write halves that run in
//! independent tokio tasks. The write task drains the outbound
//! queue; the read task processes inbound messages. Neither task
//! holds a lock while awaiting the other. Communication between
//! tasks is via `tokio::sync::mpsc` (async, non-blocking) and
//! `tokio::sync::Notify` (for shutdown signaling).
//!
//! # Deadline propagation
//!
//! Every outbound message carries a `protocol::Deadline`. The
//! write task checks the deadline before sending; expired
//! messages are dropped with a metric. The read task checks
//! deadlines on inbound responses.

#![forbid(unsafe_code)]

mod control;
mod event;
mod loops;

pub use control::ControlChannel;
pub use event::EventChannel;
pub use loops::{run_control_write_loop, run_event_ack_read_loop, run_event_write_loop};

use protocol::deadline::Deadline;

/// A control message (low-volume, high-priority).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// Kill-switch engage/disengage.
    KillSwitch {
        /// Whether deny is disabled (true = audit-only).
        deny_disabled: bool,
        /// Monotonic toggle sequence.
        toggle_seq: u64,
    },
    /// Policy stage command.
    PolicyStage {
        /// Policy version.
        version: u64,
        /// Content digest (hex).
        digest_hex: String,
    },
    /// Policy commit command.
    PolicyCommit {
        /// Policy version to commit.
        version: u64,
    },
    /// Agent registration response.
    RegisterResponse {
        /// The assigned agent ID.
        agent_id: String,
        /// Policy version.
        policy_version: String,
    },
    /// Health check ping.
    HealthPing {
        /// Timestamp (epoch ms).
        timestamp_ms: u64,
    },
    /// Health check pong.
    HealthPong {
        /// Timestamp (epoch ms).
        timestamp_ms: u64,
    },
}

/// An event batch message (high-volume).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventBatchMessage {
    /// The batch ID (UUID).
    pub batch_id: String,
    /// Monotonic sequence number.
    pub seq: u64,
    /// Agent generation.
    pub agent_generation: String,
    /// Boot ID (hex).
    pub boot_id_hex: String,
    /// Number of events in the batch.
    pub event_count: usize,
    /// Serialized batch size in bytes.
    pub size_bytes: usize,
    /// The deadline for this batch's ACK.
    pub deadline: Deadline,
}

/// An ACK message from the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckMessage {
    /// The batch ID being ACKed.
    pub batch_id: String,
    /// The sequence number being ACKed.
    pub seq: u64,
    /// Whether this is a durable ACK (Kafka accepted) or
    /// receipt-only. Receipt-only is a protocol violation.
    pub durable: bool,
}

/// Metrics for a channel.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChannelMetrics {
    /// Messages sent.
    pub sent_total: u64,
    /// Messages received.
    pub received_total: u64,
    /// Messages dropped (deadline expired).
    pub dropped_expired: u64,
    /// Messages rejected (queue full).
    pub rejected_full: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportConfig;

    fn test_config() -> TransportConfig {
        TransportConfig {
            control_queue_capacity: 8,
            event_queue_capacity: 16,
            ..Default::default()
        }
    }

    #[test]
    fn event_channel_queue_full_does_not_block_control() {
        let config = test_config();
        let event_ch = EventChannel::from_config(&config);
        let control_ch = ControlChannel::from_config(&config);

        // Fill the event queue.
        for i in 0..config.event_queue_capacity {
            let batch = EventBatchMessage {
                batch_id: format!("b-{i}"),
                seq: i as u64,
                agent_generation: "gen-1".into(),
                boot_id_hex: "00".repeat(16),
                event_count: 1,
                size_bytes: 100,
                deadline: Deadline::at(u64::MAX),
            };
            assert!(event_ch.send(batch).is_ok());
        }

        // Event queue is now full.
        let overflow_batch = EventBatchMessage {
            batch_id: "overflow".into(),
            seq: 999,
            agent_generation: "gen-1".into(),
            boot_id_hex: "00".repeat(16),
            event_count: 1,
            size_bytes: 100,
            deadline: Deadline::at(u64::MAX),
        };
        assert!(event_ch.send(overflow_batch).is_err());

        // Control channel is still responsive.
        let deadline = Deadline::at(u64::MAX);
        assert!(control_ch
            .send(
                ControlMessage::KillSwitch {
                    deny_disabled: true,
                    toggle_seq: 1,
                },
                deadline,
            )
            .is_ok());
    }
}
