// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Channel read/write loops (deadlock-free, deadline-aware).

use std::sync::Arc;

use parking_lot::Mutex;
use protocol::deadline::Deadline;
use tokio::sync::{mpsc, Notify};

use crate::error::TransportResult;

use super::{AckMessage, ChannelMetrics, ControlMessage, EventBatchMessage};

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
    use crate::channel::{ControlChannel, EventChannel};
    use std::time::Duration;

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
        use crate::config::TransportConfig;

        let config = TransportConfig {
            control_queue_capacity: 8,
            event_queue_capacity: 16,
            ..Default::default()
        };
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
