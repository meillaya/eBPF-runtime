// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Control channel: low-volume, high-priority.

use std::sync::Arc;

use parking_lot::Mutex;
use protocol::deadline::Deadline;
use tokio::sync::{mpsc, Notify};

use crate::config::TransportConfig;
use crate::error::TransportResult;
use crate::queue::BoundedQueue;

use super::{ChannelMetrics, ControlMessage};

/// The control channel: low-volume, high-priority.
///
/// Carries kill-switch, policy, and registration messages.
/// NEVER blocked by event backpressure.
pub struct ControlChannel {
    /// Outbound queue (agent → control plane).
    outbound: BoundedQueue<(ControlMessage, Deadline)>,
    /// Inbound receiver (control plane → agent).
    inbound_rx: Option<mpsc::Receiver<ControlMessage>>,
    /// Inbound sender (for the read task).
    inbound_tx: mpsc::Sender<ControlMessage>,
    /// Shutdown signal.
    shutdown: Arc<Notify>,
    /// Channel metrics.
    pub(crate) metrics: Arc<Mutex<ChannelMetrics>>,
}

impl ControlChannel {
    /// Create a control channel with the given queue capacity.
    pub fn new(capacity: usize) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(capacity);
        Self {
            outbound: BoundedQueue::new(capacity, "control-out"),
            inbound_rx: Some(inbound_rx),
            inbound_tx,
            shutdown: Arc::new(Notify::new()),
            metrics: Arc::new(Mutex::new(ChannelMetrics::default())),
        }
    }

    /// Create from transport config.
    pub fn from_config(config: &TransportConfig) -> Self {
        Self::new(config.control_queue_capacity)
    }

    /// Enqueue a control message for sending.
    ///
    /// Non-blocking: returns `Err(QueueFull)` if the control
    /// queue is full (should be rare given the small capacity).
    pub fn send(&self, msg: ControlMessage, deadline: Deadline) -> TransportResult<()> {
        self.outbound.try_enqueue((msg, deadline)).inspect_err(|_| {
            self.metrics.lock().rejected_full += 1;
        })
    }

    /// Take the outbound receiver (for the write task).
    pub fn take_outbound_rx(&mut self) -> Option<mpsc::Receiver<(ControlMessage, Deadline)>> {
        self.outbound.take_receiver()
    }

    /// Take the inbound receiver (for the read task).
    pub fn take_inbound_rx(&mut self) -> Option<mpsc::Receiver<ControlMessage>> {
        self.inbound_rx.take()
    }

    /// The inbound sender (for feeding responses in tests).
    pub fn inbound_sender(&self) -> mpsc::Sender<ControlMessage> {
        self.inbound_tx.clone()
    }

    /// The shutdown signal.
    pub fn shutdown(&self) -> Arc<Notify> {
        self.shutdown.clone()
    }

    /// The channel metrics.
    pub fn metrics(&self) -> ChannelMetrics {
        *self.metrics.lock()
    }

    /// Record a sent message.
    pub fn record_sent(&self) {
        self.metrics.lock().sent_total += 1;
    }

    /// Record a received message.
    pub fn record_received(&self) {
        self.metrics.lock().received_total += 1;
    }

    /// Record a dropped (expired) message.
    pub fn record_dropped_expired(&self) {
        self.metrics.lock().dropped_expired += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransportError;

    #[test]
    fn control_channel_send_within_capacity() {
        let ch = ControlChannel::new(4);
        let deadline = Deadline::at(u64::MAX);
        assert!(ch
            .send(ControlMessage::HealthPing { timestamp_ms: 100 }, deadline,)
            .is_ok());
    }

    #[test]
    fn control_channel_queue_full() {
        let ch = ControlChannel::new(2);
        let deadline = Deadline::at(u64::MAX);
        assert!(ch
            .send(ControlMessage::HealthPing { timestamp_ms: 1 }, deadline)
            .is_ok());
        assert!(ch
            .send(ControlMessage::HealthPing { timestamp_ms: 2 }, deadline)
            .is_ok());
        let err = ch
            .send(ControlMessage::HealthPing { timestamp_ms: 3 }, deadline)
            .unwrap_err();
        assert!(matches!(
            err,
            TransportError::QueueFull {
                queue: "control-out",
                ..
            }
        ));
    }

    #[test]
    fn control_metrics_tracked() {
        let ch = ControlChannel::new(4);
        let deadline = Deadline::at(u64::MAX);
        ch.send(ControlMessage::HealthPing { timestamp_ms: 1 }, deadline)
            .unwrap();
        ch.record_sent();
        ch.record_received();
        let m = ch.metrics();
        assert_eq!(m.sent_total, 1);
        assert_eq!(m.received_total, 1);
    }
}
