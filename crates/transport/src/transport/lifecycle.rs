// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Transport lifecycle methods (authorize, send, ACK, reconnect).

use protocol::deadline::Deadline;

use crate::ack::KafkaAcceptance;
use crate::channel::{AckMessage, ControlMessage, EventBatchMessage};
use crate::error::{TransportError, TransportResult};
use crate::sequence::ReconciliationAction;

use super::{Transport, TransportState};

impl Transport {
    /// Authorize the peer and transition to Connected.
    ///
    /// Fail-closed: if the peer SPIFFE ID is invalid, the
    /// transport remains Disconnected.
    pub fn authorize_peer(&mut self, peer_spiffe_id: &str) -> TransportResult<()> {
        let binding = self.peer_authorizer.authorize(peer_spiffe_id)?;
        self.peer_binding = Some(binding);
        self.state = TransportState::Connected;
        self.reconnect.record_success();
        Ok(())
    }

    /// Reconcile sequences on (re)connect.
    ///
    /// Returns the action the agent should take (continue,
    /// replay, or reset).
    pub fn reconcile_on_connect(
        &mut self,
        server_last_acked_seq: Option<u64>,
        server_boot_id: &str,
        server_generation: &str,
    ) -> ReconciliationAction {
        self.sequence
            .reconcile(server_last_acked_seq, server_boot_id, server_generation)
    }

    /// Send a control message.
    ///
    /// Requires Connected state. The control channel is
    /// independent of the event channel — event backpressure
    /// does NOT block control delivery.
    pub fn send_control(&self, msg: ControlMessage, now_epoch_ms: u64) -> TransportResult<()> {
        if self.state != TransportState::Connected {
            return Err(TransportError::ChannelClosed { channel: "control" });
        }
        let deadline = Deadline::from_now(now_epoch_ms, self.config.deadline_ms);
        self.control_channel.send(msg, deadline)
    }

    /// Send an event batch.
    ///
    /// Requires Connected state. Assigns a monotonic sequence
    /// number and registers the batch in the ACK tracker.
    pub fn send_event_batch(
        &mut self,
        batch_id: impl Into<String>,
        event_count: usize,
        size_bytes: usize,
        now_epoch_ms: u64,
    ) -> TransportResult<u64> {
        if self.state != TransportState::Connected {
            return Err(TransportError::ChannelClosed { channel: "event" });
        }

        let batch_id = batch_id.into();
        let seq = self.sequence.assign_seq();
        let deadline = Deadline::from_now(now_epoch_ms, self.config.ack_deadline_ms);

        let msg = EventBatchMessage {
            batch_id: batch_id.clone(),
            seq,
            agent_generation: self.sequence.agent_generation().to_string(),
            boot_id_hex: self.sequence.boot_id_hex().to_string(),
            event_count,
            size_bytes,
            deadline,
        };

        self.event_channel.send(msg)?;
        self.ack_tracker.register_sent(batch_id);
        Ok(seq)
    }

    /// Process a durable Kafka acceptance and complete the ACK.
    ///
    /// This is the ONLY path that permits an ACK and outbox
    /// deletion. Receipt-only ACKs are structurally forbidden.
    pub fn process_kafka_acceptance(&mut self, acceptance: KafkaAcceptance) -> TransportResult<()> {
        let batch_id = acceptance.batch_id.clone();
        self.ack_tracker.record_kafka_acceptance(acceptance)?;
        self.ack_tracker.complete_ack(&batch_id)?;

        // Update the sequence watermark.
        // The ACK confirms all sequences up to and including
        // the ACKed batch's sequence.
        Ok(())
    }

    /// Process an inbound ACK message from the control plane.
    ///
    /// Validates that the ACK is durable (Kafka accepted).
    /// Receipt-only ACKs are rejected.
    pub fn process_inbound_ack(&mut self, ack: AckMessage) -> TransportResult<()> {
        if !ack.durable {
            return Err(TransportError::ReceiptOnlyAck {
                batch_id: ack.batch_id,
            });
        }

        // Update the sequence watermark.
        self.sequence.record_ack(ack.seq);
        Ok(())
    }

    /// Record a connection failure and get the reconnect
    /// delay.
    pub fn record_disconnect(&mut self) -> TransportResult<std::time::Duration> {
        self.state = TransportState::Reconnecting;
        self.peer_binding = None;
        match self.reconnect.record_failure() {
            Ok(delay) => Ok(delay),
            Err(e) => {
                // Circuit breaker tripped.
                self.state = TransportState::CircuitOpen;
                Err(e)
            }
        }
    }

    /// Record a successful reconnection.
    pub fn record_reconnect_success(&mut self) {
        self.reconnect.record_success();
        self.state = TransportState::Connected;
    }

    /// Shut down the transport.
    pub fn shutdown(&mut self) {
        self.state = TransportState::Shutdown;
        self.control_channel.shutdown().notify_one();
        self.event_channel.shutdown().notify_one();
    }
}
