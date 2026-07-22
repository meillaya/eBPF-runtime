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

mod lifecycle;

use crate::ack::AckTracker;
use crate::channel::{ControlChannel, EventChannel};
use crate::config::TransportConfig;
use crate::peer::PeerAuthorizer;
use crate::reconnect::ReconnectPolicy;
use crate::sequence::SequenceTracker;

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
    pub(crate) config: TransportConfig,
    pub(crate) state: TransportState,
    pub(crate) peer_authorizer: PeerAuthorizer,
    pub(crate) sequence: SequenceTracker,
    pub(crate) ack_tracker: AckTracker,
    pub(crate) reconnect: ReconnectPolicy,
    pub(crate) control_channel: ControlChannel,
    pub(crate) event_channel: EventChannel,
    /// The authorized peer binding (set after authorization).
    pub(crate) peer_binding: Option<identity_spiffe::authorization::AgentBinding>,
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
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
