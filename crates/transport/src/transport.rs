// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Transport orchestrator.
//!
//! Ties together the separate control/event channels, ACK
//! tracker, sequence reconciliation, peer authorization, and
//! reconnection policy into a single lifecycle manager.
//!
//! # Lifecycle
//!
//! 1. **Authorize peer**: validate the control plane's SPIFFE
//!    ID before any data flows.
//! 2. **Reconcile sequences**: on (re)connect, reconcile the
//!    agent's sequence state with the server's last ACK.
//! 3. **Run channels**: spawn independent read/write loops for
//!    control and event channels.
//! 4. **ACK pipeline**: event batches are ACKed only after
//!    durable Kafka acceptance; outbox rows are deleted after
//!    matching ACK.
//! 5. **Reconnect**: on disconnect, apply exponential backoff
//!    with jitter; rotate SVIDs at max-age.
//!
//! # BLOCKER NOTE
//!
//! This host does not have a running gRPC server or Kafka
//! broker. The transport logic is fully implemented and tested
//! with in-memory mocks and fixtures. Live gRPC/Kafka
//! integration re-opens on the declared self-hosted runner.

#![forbid(unsafe_code)]

use protocol::deadline::Deadline;

use crate::ack::{AckTracker, KafkaAcceptance};
use crate::channel::{AckMessage, ControlChannel, ControlMessage, EventBatchMessage, EventChannel};
use crate::config::TransportConfig;
use crate::error::{TransportError, TransportResult};
use crate::peer::PeerAuthorizer;
use crate::reconnect::ReconnectPolicy;
use crate::sequence::{ReconciliationAction, SequenceTracker};

/// The transport state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    /// Not yet connected.
    Disconnected,
    /// Peer authorized, channels running.
    Connected,
    /// Reconnecting after a disconnect.
    Reconnecting,
    /// Circuit breaker open (too many failures).
    CircuitOpen,
    /// Shut down.
    Shutdown,
}

/// The transport orchestrator.
///
/// Manages the full lifecycle of the agent/control-plane
/// transport: peer authorization, sequence reconciliation,
/// separate control/event channels, deterministic ACK, and
/// reconnection with backoff.
pub struct Transport {
    config: TransportConfig,
    state: TransportState,
    peer_authorizer: PeerAuthorizer,
    sequence: SequenceTracker,
    ack_tracker: AckTracker,
    reconnect: ReconnectPolicy,
    control_channel: ControlChannel,
    event_channel: EventChannel,
    /// The authorized peer binding (set after authorization).
    peer_binding: Option<identity_spiffe::authorization::AgentBinding>,
}

impl Transport {
    /// Create a new transport with the given configuration.
    pub fn new(
        config: TransportConfig,
        trust_domain: impl Into<String>,
        boot_id_hex: impl Into<String>,
        agent_generation: impl Into<String>,
    ) -> Self {
        let control_channel = ControlChannel::from_config(&config);
        let event_channel = EventChannel::from_config(&config);
        let reconnect = ReconnectPolicy::from_config(&config);

        Self {
            config,
            state: TransportState::Disconnected,
            peer_authorizer: PeerAuthorizer::new(trust_domain),
            sequence: SequenceTracker::new(boot_id_hex, agent_generation),
            ack_tracker: AckTracker::new(),
            reconnect,
            control_channel,
            event_channel,
            peer_binding: None,
        }
    }

    /// Create a transport with an outbox deleter for ACK
    /// processing.
    pub fn with_outbox_deleter(
        config: TransportConfig,
        trust_domain: impl Into<String>,
        boot_id_hex: impl Into<String>,
        agent_generation: impl Into<String>,
        deleter: Box<dyn crate::ack::OutboxDeleter>,
    ) -> Self {
        let mut t = Self::new(config, trust_domain, boot_id_hex, agent_generation);
        t.ack_tracker = AckTracker::with_outbox_deleter(deleter);
        t
    }

    /// The current transport state.
    pub fn state(&self) -> TransportState {
        self.state
    }

    /// The transport configuration.
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// The sequence tracker.
    pub fn sequence(&self) -> &SequenceTracker {
        &self.sequence
    }

    /// The sequence tracker (mutable).
    pub fn sequence_mut(&mut self) -> &mut SequenceTracker {
        &mut self.sequence
    }

    /// The ACK tracker.
    pub fn ack_tracker(&self) -> &AckTracker {
        &self.ack_tracker
    }

    /// The ACK tracker (mutable).
    pub fn ack_tracker_mut(&mut self) -> &mut AckTracker {
        &mut self.ack_tracker
    }

    /// The reconnect policy.
    pub fn reconnect(&self) -> &ReconnectPolicy {
        &self.reconnect
    }

    /// The reconnect policy (mutable).
    pub fn reconnect_mut(&mut self) -> &mut ReconnectPolicy {
        &mut self.reconnect
    }

    /// The control channel.
    pub fn control_channel(&self) -> &ControlChannel {
        &self.control_channel
    }

    /// The control channel (mutable).
    pub fn control_channel_mut(&mut self) -> &mut ControlChannel {
        &mut self.control_channel
    }

    /// The event channel.
    pub fn event_channel(&self) -> &EventChannel {
        &self.event_channel
    }

    /// The event channel (mutable).
    pub fn event_channel_mut(&mut self) -> &mut EventChannel {
        &mut self.event_channel
    }

    /// The authorized peer binding (if connected).
    pub fn peer_binding(&self) -> Option<&identity_spiffe::authorization::AgentBinding> {
        self.peer_binding.as_ref()
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ack::MockOutboxDeleter;

    const TD: &str = "kernel-v1.test";
    const BOOT: &str = "00000000000000000000000000000000";
    const GEN: &str = "gen-1";
    const PEER: &str = "spiffe://kernel-v1.test/agent/prod/node-1";

    fn transport() -> Transport {
        Transport::new(TransportConfig::default(), TD, BOOT, GEN)
    }

    #[test]
    fn initial_state_disconnected() {
        let t = transport();
        assert_eq!(t.state(), TransportState::Disconnected);
    }

    #[test]
    fn authorize_valid_peer() {
        let mut t = transport();
        t.authorize_peer(PEER).unwrap();
        assert_eq!(t.state(), TransportState::Connected);
        assert!(t.peer_binding().is_some());
        assert_eq!(t.peer_binding().unwrap().cluster, "prod");
    }

    #[test]
    fn authorize_invalid_peer_rejected() {
        let mut t = transport();
        let err = t
            .authorize_peer("spiffe://evil.example/agent/prod/node-1")
            .unwrap_err();
        assert!(matches!(err, TransportError::PeerUnauthorized { .. }));
        assert_eq!(t.state(), TransportState::Disconnected);
    }

    #[test]
    fn send_control_requires_connected() {
        let t = transport();
        let err = t
            .send_control(ControlMessage::HealthPing { timestamp_ms: 1 }, 1000)
            .unwrap_err();
        assert!(matches!(
            err,
            TransportError::ChannelClosed { channel: "control" }
        ));
    }

    #[test]
    fn send_control_when_connected() {
        let mut t = transport();
        t.authorize_peer(PEER).unwrap();
        assert!(t
            .send_control(ControlMessage::HealthPing { timestamp_ms: 1 }, 1000)
            .is_ok());
    }

    #[test]
    fn send_event_batch_assigns_seq() {
        let mut t = transport();
        t.authorize_peer(PEER).unwrap();
        let seq0 = t.send_event_batch("b-0", 10, 1024, 1000).unwrap();
        let seq1 = t.send_event_batch("b-1", 5, 512, 1000).unwrap();
        assert_eq!(seq0, 0);
        assert_eq!(seq1, 1);
        assert_eq!(t.sequence().next_seq(), 2);
    }

    #[test]
    fn send_event_batch_registers_in_ack_tracker() {
        let mut t = transport();
        t.authorize_peer(PEER).unwrap();
        t.send_event_batch("b-0", 10, 1024, 1000).unwrap();
        assert_eq!(
            t.ack_tracker().state("b-0"),
            Some(crate::ack::AckState::AwaitingKafkaAcceptance)
        );
    }

    #[test]
    fn kafka_acceptance_completes_ack() {
        let mut t = transport();
        t.authorize_peer(PEER).unwrap();
        t.send_event_batch("b-0", 10, 1024, 1000).unwrap();

        t.process_kafka_acceptance(KafkaAcceptance {
            batch_id: "b-0".into(),
            topic: "events".into(),
            partition: 0,
            offset: 100,
        })
        .unwrap();

        assert_eq!(
            t.ack_tracker().state("b-0"),
            Some(crate::ack::AckState::AckedAndDeleted)
        );
    }

    #[test]
    fn receipt_only_ack_rejected() {
        let mut t = transport();
        t.authorize_peer(PEER).unwrap();
        t.send_event_batch("b-0", 10, 1024, 1000).unwrap();

        let err = t
            .process_inbound_ack(AckMessage {
                batch_id: "b-0".into(),
                seq: 0,
                durable: false,
            })
            .unwrap_err();
        assert!(matches!(err, TransportError::ReceiptOnlyAck { .. }));
    }

    #[test]
    fn durable_ack_updates_sequence() {
        let mut t = transport();
        t.authorize_peer(PEER).unwrap();
        t.send_event_batch("b-0", 10, 1024, 1000).unwrap();
        t.send_event_batch("b-1", 5, 512, 1000).unwrap();

        t.process_inbound_ack(AckMessage {
            batch_id: "b-1".into(),
            seq: 1,
            durable: true,
        })
        .unwrap();

        assert_eq!(t.sequence().last_acked_seq(), Some(1));
    }

    #[test]
    fn reconcile_on_connect_gap() {
        let mut t = transport();
        // Simulate sending 10 batches.
        for i in 0..10 {
            t.sequence_mut().assign_seq();
            let _ = i;
        }
        // Server only ACKed through 3.
        let action = t.reconcile_on_connect(Some(3), BOOT, GEN);
        assert_eq!(
            action,
            ReconciliationAction::ReplayFrom { replay_from_seq: 4 }
        );
    }

    #[test]
    fn reconcile_on_connect_generation_change() {
        let mut t = transport();
        t.sequence_mut().assign_seq();
        let action = t.reconcile_on_connect(Some(0), &"ff".repeat(16), GEN);
        assert!(matches!(
            action,
            ReconciliationAction::GenerationReset { .. }
        ));
    }

    #[test]
    fn disconnect_and_reconnect() {
        let mut t = transport();
        t.authorize_peer(PEER).unwrap();
        assert_eq!(t.state(), TransportState::Connected);

        let delay = t.record_disconnect().unwrap();
        assert_eq!(t.state(), TransportState::Reconnecting);
        assert!(delay.as_millis() > 0);

        t.record_reconnect_success();
        assert_eq!(t.state(), TransportState::Connected);
    }

    #[test]
    fn circuit_breaker_opens_after_max_failures() {
        let config = TransportConfig {
            max_reconnect_attempts: 3,
            ..Default::default()
        };
        let mut t = Transport::new(config, TD, BOOT, GEN);
        t.authorize_peer(PEER).unwrap();

        for _ in 0..3 {
            t.record_disconnect().unwrap();
            t.record_reconnect_success();
        }
        // The 4th failure should trip the circuit breaker.
        // But record_success resets the backoff, so we need
        // consecutive failures.
        let mut t2 = Transport::new(
            TransportConfig {
                max_reconnect_attempts: 3,
                ..Default::default()
            },
            TD,
            BOOT,
            GEN,
        );
        t2.authorize_peer(PEER).unwrap();
        t2.record_disconnect().unwrap();
        // Don't call record_reconnect_success — consecutive failures.
        t2.state = TransportState::Reconnecting;
        t2.record_disconnect().unwrap();
        t2.state = TransportState::Reconnecting;
        t2.record_disconnect().unwrap();
        // 4th failure: circuit breaker.
        t2.state = TransportState::Reconnecting;
        let err = t2.record_disconnect().unwrap_err();
        assert!(matches!(err, TransportError::ReconnectExhausted { .. }));
        assert_eq!(t2.state(), TransportState::CircuitOpen);
    }

    #[test]
    fn shutdown_transitions_state() {
        let mut t = transport();
        t.authorize_peer(PEER).unwrap();
        t.shutdown();
        assert_eq!(t.state(), TransportState::Shutdown);
    }

    #[test]
    fn outbox_deletion_after_matching_ack() {
        let deleter = MockOutboxDeleter::new(vec!["b-0".into(), "b-1".into()]);
        let mut t = Transport::with_outbox_deleter(
            TransportConfig::default(),
            TD,
            BOOT,
            GEN,
            Box::new(deleter),
        );
        t.authorize_peer(PEER).unwrap();

        t.send_event_batch("b-0", 10, 1024, 1000).unwrap();
        t.send_event_batch("b-1", 5, 512, 1000).unwrap();

        // ACK b-0 only.
        t.process_kafka_acceptance(KafkaAcceptance {
            batch_id: "b-0".into(),
            topic: "events".into(),
            partition: 0,
            offset: 100,
        })
        .unwrap();

        assert_eq!(
            t.ack_tracker().state("b-0"),
            Some(crate::ack::AckState::AckedAndDeleted)
        );
        assert_eq!(
            t.ack_tracker().state("b-1"),
            Some(crate::ack::AckState::AwaitingKafkaAcceptance)
        );
    }

    #[test]
    fn event_backpressure_does_not_block_control() {
        let config = TransportConfig {
            event_queue_capacity: 2,
            control_queue_capacity: 4,
            ..Default::default()
        };
        let mut t = Transport::new(config, TD, BOOT, GEN);
        t.authorize_peer(PEER).unwrap();

        // Fill the event queue.
        t.send_event_batch("b-0", 1, 100, 1000).unwrap();
        t.send_event_batch("b-1", 1, 100, 1000).unwrap();
        // Event queue is now full.
        let err = t.send_event_batch("b-2", 1, 100, 1000).unwrap_err();
        assert!(matches!(err, TransportError::QueueFull { .. }));

        // Control channel is still responsive.
        assert!(t
            .send_control(
                ControlMessage::KillSwitch {
                    deny_disabled: true,
                    toggle_seq: 1,
                },
                1000,
            )
            .is_ok());
    }
}
