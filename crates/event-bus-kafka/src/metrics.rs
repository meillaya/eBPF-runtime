// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Timeout/backpressure metrics for the Kafka publisher.
//!
//! All publish operations update these counters, enabling
//! observability of the event bus health without requiring a
//! live Kafka broker. The metrics are designed for export to
//! Prometheus (task 20 observability) but are standalone here.

#![forbid(unsafe_code)]

/// Publisher metrics counters.
///
/// All counters are monotonically increasing. Reset is not
/// supported (Prometheus counter semantics).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PublisherMetrics {
    /// Total batches submitted for publishing.
    pub batches_submitted: u64,
    /// Total batches durably accepted by Kafka.
    pub batches_accepted: u64,
    /// Total batches that timed out before acceptance.
    pub batches_timed_out: u64,
    /// Total batches rejected due to queue full (backpressure).
    pub batches_rejected_queue_full: u64,
    /// Total batches routed to the DLQ (schema rejection).
    pub batches_dlq: u64,
    /// Total declared duplicates (idempotent producer
    /// deduplication). These are NOT hidden loss — they are
    /// batches that were already durably accepted.
    pub declared_duplicates: u64,
    /// Total produce retries (transient failures recovered by
    /// the idempotent producer).
    pub retries_total: u64,
    /// Total unrecoverable producer errors.
    pub unrecoverable_errors: u64,
    /// Total broker unavailability events.
    pub broker_unavailable_events: u64,
    /// Current in-flight produce requests (gauge, not counter).
    pub in_flight: usize,
    /// Peak in-flight produce requests observed.
    pub peak_in_flight: usize,
}

impl PublisherMetrics {
    /// Create a new zeroed metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a batch submission.
    pub fn record_submit(&mut self) {
        self.batches_submitted += 1;
    }

    /// Record a durable acceptance.
    pub fn record_accept(&mut self) {
        self.batches_accepted += 1;
    }

    /// Record a timeout.
    pub fn record_timeout(&mut self) {
        self.batches_timed_out += 1;
    }

    /// Record a queue-full rejection (backpressure).
    pub fn record_queue_full(&mut self) {
        self.batches_rejected_queue_full += 1;
    }

    /// Record a DLQ routing.
    pub fn record_dlq(&mut self) {
        self.batches_dlq += 1;
    }

    /// Record a declared duplicate.
    pub fn record_duplicate(&mut self) {
        self.declared_duplicates += 1;
    }

    /// Record a produce retry.
    pub fn record_retry(&mut self) {
        self.retries_total += 1;
    }

    /// Record an unrecoverable error.
    pub fn record_unrecoverable(&mut self) {
        self.unrecoverable_errors += 1;
    }

    /// Record a broker unavailability event.
    pub fn record_broker_unavailable(&mut self) {
        self.broker_unavailable_events += 1;
    }

    /// Update the in-flight gauge and peak.
    pub fn set_in_flight(&mut self, count: usize) {
        self.in_flight = count;
        if count > self.peak_in_flight {
            self.peak_in_flight = count;
        }
    }

    /// Verify zero hidden loss: every submitted batch is
    /// accounted for as accepted, timed out, queue-full, DLQ,
    /// duplicate, or unrecoverable.
    ///
    /// Returns true if the invariant holds.
    pub fn verify_no_hidden_loss(&self) -> bool {
        let accounted = self.batches_accepted
            + self.batches_timed_out
            + self.batches_rejected_queue_full
            + self.batches_dlq
            + self.declared_duplicates
            + self.unrecoverable_errors
            + self.broker_unavailable_events;
        // In-flight batches are not yet accounted.
        accounted + self.in_flight as u64 == self.batches_submitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_zeroed() {
        let m = PublisherMetrics::new();
        assert_eq!(m.batches_submitted, 0);
        assert_eq!(m.batches_accepted, 0);
        assert_eq!(m.in_flight, 0);
    }

    #[test]
    fn record_accept_increments() {
        let mut m = PublisherMetrics::new();
        m.record_submit();
        m.record_accept();
        assert_eq!(m.batches_submitted, 1);
        assert_eq!(m.batches_accepted, 1);
    }

    #[test]
    fn no_hidden_loss_happy_path() {
        let mut m = PublisherMetrics::new();
        for _ in 0..10 {
            m.record_submit();
            m.record_accept();
        }
        assert!(m.verify_no_hidden_loss());
    }

    #[test]
    fn no_hidden_loss_with_failures() {
        let mut m = PublisherMetrics::new();
        // 5 accepted, 2 timeout, 1 queue full, 1 DLQ, 1 dup
        for _ in 0..10 {
            m.record_submit();
        }
        for _ in 0..5 {
            m.record_accept();
        }
        for _ in 0..2 {
            m.record_timeout();
        }
        m.record_queue_full();
        m.record_dlq();
        m.record_duplicate();
        assert!(m.verify_no_hidden_loss());
    }

    #[test]
    fn hidden_loss_detected() {
        let mut m = PublisherMetrics::new();
        m.record_submit();
        m.record_submit();
        m.record_accept(); // Only 1 accepted, 1 unaccounted
        assert!(!m.verify_no_hidden_loss());
    }

    #[test]
    fn in_flight_tracking() {
        let mut m = PublisherMetrics::new();
        m.set_in_flight(3);
        assert_eq!(m.in_flight, 3);
        assert_eq!(m.peak_in_flight, 3);
        m.set_in_flight(1);
        assert_eq!(m.in_flight, 1);
        assert_eq!(m.peak_in_flight, 3); // Peak preserved
    }

    #[test]
    fn in_flight_accounted_in_no_loss() {
        let mut m = PublisherMetrics::new();
        m.record_submit();
        m.record_submit();
        m.record_accept();
        m.set_in_flight(1); // 1 still in flight
        assert!(m.verify_no_hidden_loss());
    }

    #[test]
    fn retry_counter() {
        let mut m = PublisherMetrics::new();
        m.record_retry();
        m.record_retry();
        assert_eq!(m.retries_total, 2);
    }
}
