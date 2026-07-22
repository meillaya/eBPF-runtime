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

use std::sync::Arc;

use parking_lot::Mutex;
use protocol::deadline::Deadline;
use tokio::sync::{mpsc, Notify};

use crate::config::TransportConfig;
use crate::error::TransportResult;
use crate::queue::BoundedQueue;

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
    metrics: Arc<Mutex<ChannelMetrics>>,
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
    metrics: Arc<Mutex<ChannelMetrics>>,
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

/// Run the control channel write loop.
///
/// Drains the outbound queue and "sends" each message (in a
/// real implementation, this would write to a gRPC stream).
/// Checks deadlines before sending; expired messages are
/// dropped.
///
/// This function runs until the shutdown signal is received or
/// the outbound queue is closed. It NEVER blocks on the read
/// loop, preventing deadlock.
pub async fn run_control_write_loop(
    mut rx: mpsc::Receiver<(ControlMessage, Deadline)>,
    shutdown: Arc<Notify>,
    metrics: Arc<Mutex<ChannelMetrics>>,
    now_ms: impl Fn() -> u64,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("control write loop: shutdown");
                break;
            }
            item = rx.recv() => {
                match item {
                    None => {
                        tracing::info!("control write loop: outbound closed");
                        break;
                    }
                    Some((msg, deadline)) => {
                        let now = now_ms();
                        if deadline.is_expired(now) {
                            metrics.lock().dropped_expired += 1;
                            tracing::warn!(
                                deadline_ms = deadline.deadline_epoch_ms,
                                now_ms = now,
                                "control write loop: dropping expired message"
                            );
                            continue;
                        }
                        // In a real implementation: write to gRPC stream.
                        metrics.lock().sent_total += 1;
                        tracing::debug!(?msg, "control write loop: sent");
                    }
                }
            }
        }
    }
}

/// Run the event channel write loop.
///
/// Drains the outbound event queue and "sends" each batch.
/// Checks deadlines before sending. Independent of the control
/// channel — event backpressure does NOT block control.
pub async fn run_event_write_loop(
    mut rx: mpsc::Receiver<EventBatchMessage>,
    shutdown: Arc<Notify>,
    metrics: Arc<Mutex<ChannelMetrics>>,
    now_ms: impl Fn() -> u64,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("event write loop: shutdown");
                break;
            }
            item = rx.recv() => {
                match item {
                    None => {
                        tracing::info!("event write loop: outbound closed");
                        break;
                    }
                    Some(batch) => {
                        let now = now_ms();
                        if batch.deadline.is_expired(now) {
                            metrics.lock().dropped_expired += 1;
                            tracing::warn!(
                                batch_id = %batch.batch_id,
                                "event write loop: dropping expired batch"
                            );
                            continue;
                        }
                        // In a real implementation: write to gRPC stream.
                        metrics.lock().sent_total += 1;
                        tracing::debug!(
                            batch_id = %batch.batch_id,
                            seq = batch.seq,
                            "event write loop: sent batch"
                        );
                    }
                }
            }
        }
    }
}

/// Run the event channel ACK read loop.
///
/// Processes inbound ACKs. Validates that each ACK is durable
/// (Kafka accepted); receipt-only ACKs are rejected.
/// Independent of the write loop — cannot deadlock.
pub async fn run_event_ack_read_loop(
    mut rx: mpsc::Receiver<AckMessage>,
    shutdown: Arc<Notify>,
    metrics: Arc<Mutex<ChannelMetrics>>,
    mut on_ack: impl FnMut(AckMessage) -> TransportResult<()>,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("event ACK read loop: shutdown");
                break;
            }
            item = rx.recv() => {
                match item {
                    None => {
                        tracing::info!("event ACK read loop: inbound closed");
                        break;
                    }
                    Some(ack) => {
                        // Reject receipt-only ACKs.
                        if !ack.durable {
                            tracing::warn!(
                                batch_id = %ack.batch_id,
                                "event ACK read loop: rejecting receipt-only ACK"
                            );
                            continue;
                        }
                        metrics.lock().received_total += 1;
                        if let Err(e) = on_ack(ack) {
                            tracing::error!(
                                error = %e,
                                "event ACK read loop: ACK processing failed"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransportError;
    use std::time::Duration;

    fn test_config() -> TransportConfig {
        TransportConfig {
            control_queue_capacity: 8,
            event_queue_capacity: 16,
            ..Default::default()
        }
    }

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

    #[tokio::test]
    async fn control_write_loop_drops_expired_messages() {
        let mut ch = ControlChannel::new(4);
        let metrics = ch.metrics.clone();
        let shutdown = ch.shutdown();
        let rx = ch.take_outbound_rx().unwrap();

        // Send an already-expired message.
        let expired_deadline = Deadline::at(100);
        ch.send(
            ControlMessage::HealthPing { timestamp_ms: 1 },
            expired_deadline,
        )
        .unwrap();

        // Send a valid message.
        let valid_deadline = Deadline::at(u64::MAX);
        ch.send(
            ControlMessage::HealthPing { timestamp_ms: 2 },
            valid_deadline,
        )
        .unwrap();

        // Run the write loop with a fixed "now" of 200ms.
        let handle = tokio::spawn(run_control_write_loop(
            rx,
            shutdown.clone(),
            metrics,
            || 200,
        ));

        // Give the loop time to process.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.notify_one();
        handle.await.unwrap();

        let m = ch.metrics();
        assert_eq!(m.sent_total, 1); // Only the valid message.
        assert_eq!(m.dropped_expired, 1); // The expired one.
    }

    #[tokio::test]
    async fn event_ack_read_loop_rejects_receipt_only() {
        let mut ch = EventChannel::new(4);
        let metrics = ch.metrics.clone();
        let shutdown = ch.shutdown();
        let rx = ch.take_ack_rx().unwrap();
        let ack_tx = ch.ack_sender();

        let acked = Arc::new(Mutex::new(Vec::new()));
        let acked_clone = acked.clone();

        let handle = tokio::spawn(run_event_ack_read_loop(
            rx,
            shutdown.clone(),
            metrics,
            move |ack| {
                acked_clone.lock().push(ack.batch_id);
                Ok(())
            },
        ));

        // Send a durable ACK (should be processed).
        ack_tx
            .send(AckMessage {
                batch_id: "b-1".into(),
                seq: 0,
                durable: true,
            })
            .await
            .unwrap();

        // Send a receipt-only ACK (should be rejected).
        ack_tx
            .send(AckMessage {
                batch_id: "b-2".into(),
                seq: 1,
                durable: false,
            })
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.notify_one();
        handle.await.unwrap();

        let processed = acked.lock();
        assert_eq!(*processed, vec!["b-1".to_string()]);
        assert_eq!(ch.metrics().received_total, 1);
    }

    #[tokio::test]
    async fn separate_channels_independent_shutdown() {
        let config = test_config();
        let mut event_ch = EventChannel::from_config(&config);
        let mut control_ch = ControlChannel::from_config(&config);

        let event_shutdown = event_ch.shutdown();
        let control_shutdown = control_ch.shutdown();

        let event_rx = event_ch.take_outbound_rx().unwrap();
        let control_rx = control_ch.take_outbound_rx().unwrap();

        let event_metrics = event_ch.metrics.clone();
        let control_metrics = control_ch.metrics.clone();

        let event_handle = tokio::spawn(run_event_write_loop(
            event_rx,
            event_shutdown.clone(),
            event_metrics,
            || 0,
        ));

        let control_handle = tokio::spawn(run_control_write_loop(
            control_rx,
            control_shutdown.clone(),
            control_metrics,
            || 0,
        ));

        // Shut down event channel only.
        event_shutdown.notify_one();
        event_handle.await.unwrap();

        // Control channel is still running (not shut down).
        // Send a control message to prove it's alive.
        let deadline = Deadline::at(u64::MAX);
        control_ch
            .send(ControlMessage::HealthPing { timestamp_ms: 42 }, deadline)
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        control_shutdown.notify_one();
        control_handle.await.unwrap();

        assert_eq!(control_ch.metrics().sent_total, 1);
    }
}
