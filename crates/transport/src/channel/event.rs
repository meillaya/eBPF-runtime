// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Event channel: high-volume, independently backpressured.

use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{mpsc, Notify};

use crate::config::TransportConfig;
use crate::error::TransportResult;
use crate::queue::BoundedQueue;

use super::{AckMessage, ChannelMetrics, EventBatchMessage};

/// The event channel: high-volume, independently
/// backpressured.
///
/// Carries event batches. Backpressure does NOT affect the
/// control channel.
pub struct EventChannel {
    /// Outbound queue (agent → control plane).
    outbound: BoundedQueue<EventBatchMessage>,
    /// Inbound ACK receiver (control plane → agent).
    ack_rx: Option<mpsc::Receiver<AckMessage>>,
    /// Inbound ACK sender (for the read task).
    ack_tx: mpsc::Sender<AckMessage>,
    /// Shutdown signal.
    shutdown: Arc<Notify>,
    /// Channel metrics.
    pub(crate) metrics: Arc<Mutex<ChannelMetrics>>,
}

impl EventChannel {
    /// Create an event channel with the given queue capacity.
    pub fn new(capacity: usize) -> Self {
        let (ack_tx, ack_rx) = mpsc::channel(capacity);
        Self {
            outbound: BoundedQueue::new(capacity, "event-out"),
            ack_rx: Some(ack_rx),
            ack_tx,
            shutdown: Arc::new(Notify::new()),
            metrics: Arc::new(Mutex::new(ChannelMetrics::default())),
        }
    }

    /// Create from transport config.
    pub fn from_config(config: &TransportConfig) -> Self {
        Self::new(config.event_queue_capacity)
    }

    /// Enqueue an event batch for sending.
    ///
    /// Non-blocking: returns `Err(QueueFull)` when the event
    /// queue is at capacity. This is the backpressure signal.
    /// The control channel is NOT affected.
    pub fn send(&self, batch: EventBatchMessage) -> TransportResult<()> {
        self.outbound.try_enqueue(batch).inspect_err(|_| {
            self.metrics.lock().rejected_full += 1;
        })
    }

    /// Take the outbound receiver (for the write task).
    pub fn take_outbound_rx(&mut self) -> Option<mpsc::Receiver<EventBatchMessage>> {
        self.outbound.take_receiver()
    }

    /// Take the ACK receiver (for the read task).
    pub fn take_ack_rx(&mut self) -> Option<mpsc::Receiver<AckMessage>> {
        self.ack_rx.take()
    }

    /// The ACK sender (for feeding ACKs in tests).
    pub fn ack_sender(&self) -> mpsc::Sender<AckMessage> {
        self.ack_tx.clone()
    }

    /// The shutdown signal.
    pub fn shutdown(&self) -> Arc<Notify> {
        self.shutdown.clone()
    }

    /// The channel metrics.
    pub fn metrics(&self) -> ChannelMetrics {
        *self.metrics.lock()
    }

    /// Record a sent batch.
    pub fn record_sent(&self) {
        self.metrics.lock().sent_total += 1;
    }

    /// Record a received ACK.
    pub fn record_received(&self) {
        self.metrics.lock().received_total += 1;
    }

    /// Record a dropped (expired) batch.
    pub fn record_dropped_expired(&self) {
        self.metrics.lock().dropped_expired += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::deadline::Deadline;

    #[test]
    fn event_channel_send_within_capacity() {
        let ch = EventChannel::new(4);
        let batch = EventBatchMessage {
            batch_id: "b-1".into(),
            seq: 0,
            agent_generation: "gen-1".into(),
            boot_id_hex: "00".repeat(16),
            event_count: 10,
            size_bytes: 1024,
            deadline: Deadline::at(u64::MAX),
        };
        assert!(ch.send(batch).is_ok());
    }

    #[test]
    fn event_metrics_tracked() {
        let ch = EventChannel::new(4);
        ch.record_sent();
        ch.record_sent();
        ch.record_dropped_expired();
        let m = ch.metrics();
        assert_eq!(m.sent_total, 2);
        assert_eq!(m.dropped_expired, 1);
    }
}
