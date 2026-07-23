// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded independent queues for control and event streams.
//!
//! The control queue and event queue are completely independent:
//! a full event queue does NOT block control delivery (kill
//! switch, policy updates). Each queue is a bounded
//! `tokio::sync::mpsc` channel with `try_send` for non-blocking
//! backpressure.
//!
//! # Deadlock prevention
//!
//! The read and write loops for each channel run in separate
//! tokio tasks. The write loop drains the outbound queue; the
//! read loop processes inbound ACKs/responses. Neither loop
//! holds a lock while waiting on the other, so they cannot
//! deadlock.

#![forbid(unsafe_code)]

use tokio::sync::mpsc;

use crate::error::{TransportError, TransportResult};

/// A bounded queue with non-blocking backpressure.
///
/// Wraps a `tokio::sync::mpsc` channel. `try_enqueue` returns
/// `Err(QueueFull)` immediately when the queue is at capacity
/// instead of blocking, enabling the caller to apply
/// backpressure without risking deadlock.
#[derive(Debug)]
pub struct BoundedQueue<T> {
    tx: mpsc::Sender<T>,
    rx: Option<mpsc::Receiver<T>>,
    capacity: usize,
    name: &'static str,
}

impl<T> BoundedQueue<T> {
    /// Create a new bounded queue with the given capacity.
    ///
    /// The receiver is extracted once via `take_receiver()`.
    pub fn new(capacity: usize, name: &'static str) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            tx,
            rx: Some(rx),
            capacity,
            name,
        }
    }

    /// The queue's name (for error messages and metrics).
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The queue's capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Try to enqueue an item without blocking.
    ///
    /// Returns `Err(QueueFull)` if the queue is at capacity.
    /// This is the backpressure signal: the caller should drop
    /// or buffer the item, NOT block.
    pub fn try_enqueue(&self, item: T) -> TransportResult<()> {
        self.tx.try_send(item).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => TransportError::QueueFull {
                queue: self.name,
                capacity: self.capacity,
            },
            mpsc::error::TrySendError::Closed(_) => {
                TransportError::ChannelClosed { channel: self.name }
            }
        })
    }

    /// Take the receiver (can only be called once).
    ///
    /// The receiver is used by the read/write loop task. After
    /// this call, the queue is send-only.
    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<T>> {
        self.rx.take()
    }

    /// Clone the sender for multi-producer use.
    pub fn sender(&self) -> mpsc::Sender<T> {
        self.tx.clone()
    }

    /// Whether the receiver has been taken.
    pub fn receiver_taken(&self) -> bool {
        self.rx.is_none()
    }

    /// Whether the channel is closed (receiver dropped).
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// Pressure metrics for a bounded queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueuePressure {
    /// Total items enqueued successfully.
    pub enqueued_total: u64,
    /// Total items rejected (queue full).
    pub rejected_total: u64,
    /// Current queue depth (approximate).
    pub current_depth: usize,
}

impl QueuePressure {
    /// Whether the queue is under pressure (has rejections).
    pub fn is_under_pressure(&self) -> bool {
        self.rejected_total > 0
    }

    /// The rejection rate as a fraction [0.0, 1.0].
    pub fn rejection_rate(&self) -> f64 {
        let total = self.enqueued_total + self.rejected_total;
        if total == 0 {
            return 0.0;
        }
        self.rejected_total as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_enqueue_within_capacity() {
        let q = BoundedQueue::new(4, "test");
        assert!(q.try_enqueue(1).is_ok());
        assert!(q.try_enqueue(2).is_ok());
        assert!(q.try_enqueue(3).is_ok());
        assert!(q.try_enqueue(4).is_ok());
    }

    #[test]
    fn try_enqueue_at_capacity_returns_queue_full() {
        let q = BoundedQueue::new(2, "event");
        assert!(q.try_enqueue(1).is_ok());
        assert!(q.try_enqueue(2).is_ok());
        let err = q.try_enqueue(3).unwrap_err();
        assert_eq!(
            err,
            TransportError::QueueFull {
                queue: "event",
                capacity: 2,
            }
        );
    }

    #[test]
    fn take_receiver_once() {
        let mut q: BoundedQueue<()> = BoundedQueue::new(4, "test");
        assert!(!q.receiver_taken());
        assert!(q.take_receiver().is_some());
        assert!(q.receiver_taken());
        assert!(q.take_receiver().is_none());
    }

    #[test]
    fn sender_clone_works() {
        let q = BoundedQueue::new(4, "test");
        let tx2 = q.sender();
        assert!(q.try_enqueue(1).is_ok());
        assert!(tx2.try_send(2).is_ok());
    }

    #[test]
    fn closed_channel_returns_channel_closed() {
        let mut q = BoundedQueue::new(4, "control");
        let rx = q.take_receiver().unwrap();
        drop(rx);
        let err = q.try_enqueue(1).unwrap_err();
        assert_eq!(err, TransportError::ChannelClosed { channel: "control" });
    }

    #[test]
    fn independent_queues_no_cross_blocking() {
        // Fill the event queue to capacity.
        let event_q = BoundedQueue::new(2, "event");
        assert!(event_q.try_enqueue("e1").is_ok());
        assert!(event_q.try_enqueue("e2").is_ok());
        assert!(event_q.try_enqueue("e3").is_err()); // Full.

        // Control queue is still available.
        let control_q = BoundedQueue::new(2, "control");
        assert!(control_q.try_enqueue("c1").is_ok());
        assert!(control_q.try_enqueue("c2").is_ok());
    }

    #[test]
    fn pressure_metrics_initial() {
        let p = QueuePressure::default();
        assert!(!p.is_under_pressure());
        assert_eq!(p.rejection_rate(), 0.0);
    }

    #[test]
    fn pressure_metrics_with_rejections() {
        let p = QueuePressure {
            enqueued_total: 8,
            rejected_total: 2,
            current_depth: 4,
        };
        assert!(p.is_under_pressure());
        assert!((p.rejection_rate() - 0.2).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn async_drain_receiver() {
        let mut q: BoundedQueue<i32> = BoundedQueue::new(4, "test");
        q.try_enqueue(10).unwrap();
        q.try_enqueue(20).unwrap();

        let mut rx = q.take_receiver().unwrap();
        assert_eq!(rx.recv().await, Some(10));
        assert_eq!(rx.recv().await, Some(20));
    }
}
