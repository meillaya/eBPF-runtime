// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Redacted live event fanout with WebSocket cursors and
//! reconnect.
//!
//! The [`LiveHub`] manages per-cluster event fanout to
//! subscribers. Each subscriber has a bounded ring buffer.
//! Slow clients that cannot keep up are shed (disconnected)
//! rather than allowed to grow unbounded buffers.
//!
//! Live events are HINTS from in-flight Kafka/gRPC streams.
//! They are NOT authoritative — the subscriber can query
//! ClickHouse for the definitive historical record. The live
//! stream provides low-latency notification of new events.
//!
//! # Cursor-based reconnect
//!
//! Each event in the ring buffer has a monotonic sequence
//! number. A reconnecting subscriber provides its last-seen
//! cursor (sequence number) and receives all events after that
//! cursor that are still retained in the buffer. If the cursor
//! is older than the oldest retained event, the subscriber
//! receives a `LiveCursorExpired` error and must fall back to
//! a historical ClickHouse query.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::error::{ControlPlaneError, Result};

/// A live event hint (redacted, safe for fanout).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveEvent {
    /// Monotonic sequence number within the cluster stream.
    pub seq: u64,
    /// The event ID (for cross-referencing with ClickHouse).
    pub event_id: String,
    /// The event kind (proto name).
    pub event_kind: String,
    /// The node that emitted the event.
    pub node_name: String,
    /// The cluster this event belongs to.
    pub cluster: String,
    /// Monotonic timestamp (ns).
    pub ts_monotonic_ns: u64,
    /// Redacted payload (secrets masked).
    pub payload: String,
}

/// A subscriber's view into the live stream.
#[derive(Debug)]
pub struct Subscriber {
    /// Unique subscriber ID.
    pub id: u64,
    /// The cluster this subscriber is watching.
    pub cluster: String,
    /// Bounded ring buffer of pending events.
    buffer: Vec<LiveEvent>,
    /// Maximum buffer capacity.
    cap: usize,
    /// Number of consecutive publishes the subscriber has
    /// missed (not consumed).
    missed: u32,
    /// Whether the subscriber has been shed.
    shed: bool,
    /// The last sequence number consumed by the subscriber.
    last_consumed_seq: u64,
}

impl Subscriber {
    /// Create a new subscriber with a bounded buffer.
    fn new(id: u64, cluster: String, cap: usize) -> Self {
        Self {
            id,
            cluster,
            buffer: Vec::with_capacity(cap),
            cap,
            missed: 0,
            shed: false,
            last_consumed_seq: 0,
        }
    }

    /// Push an event into the subscriber's buffer.
    /// Returns `false` if the buffer is full (slow client).
    fn push(&mut self, event: &LiveEvent) -> bool {
        if self.shed {
            return false;
        }
        if self.buffer.len() >= self.cap {
            self.missed += 1;
            return false;
        }
        self.buffer.push(event.clone());
        true
    }

    /// Drain up to `max` events from the buffer.
    /// Returns the drained events.
    pub fn drain(&mut self, max: usize) -> Vec<LiveEvent> {
        let count = max.min(self.buffer.len());
        let drained: Vec<LiveEvent> = self.buffer.drain(..count).collect();
        if let Some(last) = drained.last() {
            self.last_consumed_seq = last.seq;
        }
        // Reset missed counter on successful consumption.
        if !drained.is_empty() {
            self.missed = 0;
        }
        drained
    }

    /// The number of pending events in the buffer.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the subscriber has been shed.
    pub fn is_shed(&self) -> bool {
        self.shed
    }

    /// The number of consecutive missed publishes.
    pub fn missed_count(&self) -> u32 {
        self.missed
    }

    /// The last consumed sequence number.
    pub fn last_consumed_seq(&self) -> u64 {
        self.last_consumed_seq
    }
}

/// Per-cluster live event ring buffer.
#[derive(Debug)]
struct ClusterStream {
    /// Retained events (bounded ring buffer).
    events: Vec<LiveEvent>,
    /// Maximum retention capacity.
    cap: usize,
    /// Next sequence number.
    next_seq: u64,
}

impl ClusterStream {
    fn new(cap: usize) -> Self {
        Self {
            events: Vec::with_capacity(cap),
            cap,
            next_seq: 1,
        }
    }

    /// Publish an event to the cluster stream.
    /// Returns the assigned sequence number.
    fn publish(&mut self, mut event: LiveEvent) -> u64 {
        let seq = self.next_seq;
        event.seq = seq;
        self.next_seq += 1;

        if self.events.len() >= self.cap {
            // Evict oldest event.
            self.events.remove(0);
        }
        self.events.push(event);
        seq
    }

    /// The oldest retained sequence number.
    fn oldest_seq(&self) -> Option<u64> {
        self.events.first().map(|e| e.seq)
    }

    /// Get events after a given sequence number (for reconnect).
    fn events_after(&self, after_seq: u64) -> Vec<LiveEvent> {
        self.events
            .iter()
            .filter(|e| e.seq > after_seq)
            .cloned()
            .collect()
    }
}

/// The live event fanout hub.
///
/// Manages per-cluster event streams and subscriber fanout.
/// All operations are bounded: ring buffers have fixed
/// capacity, and slow clients are shed.
#[derive(Debug)]
pub struct LiveHub {
    /// Per-cluster event streams.
    streams: Mutex<HashMap<String, ClusterStream>>,
    /// All subscribers (id → subscriber).
    subscribers: Mutex<HashMap<u64, Subscriber>>,
    /// Next subscriber ID.
    next_sub_id: Mutex<u64>,
    /// Buffer capacity per subscriber.
    buffer_cap: usize,
    /// Slow-client shedding threshold.
    slow_threshold: u32,
}

impl LiveHub {
    /// Create a new live hub with the given buffer capacity and
    /// slow-client threshold.
    pub fn new(buffer_cap: usize, slow_threshold: u32) -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            subscribers: Mutex::new(HashMap::new()),
            next_sub_id: Mutex::new(1),
            buffer_cap,
            slow_threshold,
        }
    }

    /// Subscribe to a cluster's live event stream.
    /// Returns the subscriber ID.
    pub fn subscribe(&self, cluster: &str) -> u64 {
        let mut next_id = self.next_sub_id.lock();
        let id = *next_id;
        *next_id += 1;

        let sub = Subscriber::new(id, cluster.to_string(), self.buffer_cap);
        self.subscribers.lock().insert(id, sub);

        // Ensure the cluster stream exists.
        let mut streams = self.streams.lock();
        streams
            .entry(cluster.to_string())
            .or_insert_with(|| ClusterStream::new(self.buffer_cap * 4));

        id
    }

    /// Unsubscribe a subscriber.
    pub fn unsubscribe(&self, sub_id: u64) {
        self.subscribers.lock().remove(&sub_id);
    }

    /// Publish a live event hint to a cluster stream and fan
    /// out to all subscribers of that cluster.
    ///
    /// Slow subscribers (buffer full for `slow_threshold`
    /// consecutive publishes) are shed.
    ///
    /// Returns the assigned sequence number.
    pub fn publish(&self, cluster: &str, mut event: LiveEvent) -> u64 {
        // Assign sequence number and store in the cluster
        // stream.
        let seq = {
            let mut streams = self.streams.lock();
            let stream = streams
                .entry(cluster.to_string())
                .or_insert_with(|| ClusterStream::new(self.buffer_cap * 4));
            let seq = stream.next_seq;
            event.seq = seq;
            stream.publish(event.clone())
        };

        // Fan out the seq-assigned event to subscribers.
        let mut subscribers = self.subscribers.lock();
        let mut to_shed = Vec::new();

        for sub in subscribers.values_mut() {
            if sub.cluster != cluster || sub.shed {
                continue;
            }
            if !sub.push(&event) {
                // Buffer full: increment missed counter.
                if sub.missed >= self.slow_threshold {
                    to_shed.push(sub.id);
                }
            }
        }

        // Shed slow clients.
        for id in to_shed {
            if let Some(sub) = subscribers.get_mut(&id) {
                sub.shed = true;
                sub.buffer.clear();
            }
        }

        seq
    }

    /// Drain events from a subscriber's buffer.
    pub fn drain(&self, sub_id: u64, max: usize) -> Result<Vec<LiveEvent>> {
        let mut subscribers = self.subscribers.lock();
        let sub = subscribers
            .get_mut(&sub_id)
            .ok_or(ControlPlaneError::Internal(format!(
                "subscriber {sub_id} not found"
            )))?;

        if sub.shed {
            return Err(ControlPlaneError::SlowClientShed {
                cap: self.buffer_cap,
            });
        }

        Ok(sub.drain(max))
    }

    /// Reconnect a subscriber from a cursor (sequence number).
    ///
    /// Returns all events after the cursor that are still
    /// retained in the cluster stream. If the cursor is older
    /// than the oldest retained event, returns
    /// `LiveCursorExpired`.
    pub fn reconnect(&self, cluster: &str, cursor_seq: u64) -> Result<Vec<LiveEvent>> {
        let streams = self.streams.lock();
        let stream = streams
            .get(cluster)
            .ok_or_else(|| ControlPlaneError::NoLiveStream {
                cluster: cluster.to_string(),
            })?;

        // Check if the cursor is within the retained window.
        if let Some(oldest) = stream.oldest_seq() {
            if cursor_seq < oldest && cursor_seq != 0 {
                return Err(ControlPlaneError::LiveCursorExpired {
                    requested: cursor_seq,
                    oldest,
                });
            }
        }

        Ok(stream.events_after(cursor_seq))
    }

    /// The number of active (non-shed) subscribers for a
    /// cluster.
    pub fn active_subscriber_count(&self, cluster: &str) -> usize {
        self.subscribers
            .lock()
            .values()
            .filter(|s| s.cluster == cluster && !s.shed)
            .count()
    }

    /// Whether a subscriber has been shed.
    pub fn is_shed(&self, sub_id: u64) -> bool {
        self.subscribers
            .lock()
            .get(&sub_id)
            .map(|s| s.shed)
            .unwrap_or(true)
    }

    /// The oldest retained sequence for a cluster.
    pub fn oldest_seq(&self, cluster: &str) -> Option<u64> {
        self.streams
            .lock()
            .get(cluster)
            .and_then(|s| s.oldest_seq())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event(event_id: &str, cluster: &str) -> LiveEvent {
        LiveEvent {
            seq: 0, // assigned by hub
            event_id: event_id.to_string(),
            event_kind: "EVENT_KIND_FILE_OPEN".to_string(),
            node_name: "node-1".to_string(),
            cluster: cluster.to_string(),
            ts_monotonic_ns: 1_000_000,
            payload: r#"{"path":"/etc/hostname"}"#.to_string(),
        }
    }

    #[test]
    fn subscribe_and_publish() {
        let hub = LiveHub::new(16, 4);
        let sub_id = hub.subscribe("prod");

        let seq = hub.publish("prod", test_event("evt-001", "prod"));
        assert_eq!(seq, 1);

        let events = hub.drain(sub_id, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-001");
        assert_eq!(events[0].seq, 1);
    }

    #[test]
    fn cluster_isolation_in_fanout() {
        let hub = LiveHub::new(16, 4);
        let sub_prod = hub.subscribe("prod");
        let sub_staging = hub.subscribe("staging");

        hub.publish("prod", test_event("evt-001", "prod"));
        hub.publish("staging", test_event("evt-002", "staging"));

        let prod_events = hub.drain(sub_prod, 10).unwrap();
        assert_eq!(prod_events.len(), 1);
        assert_eq!(prod_events[0].event_id, "evt-001");

        let staging_events = hub.drain(sub_staging, 10).unwrap();
        assert_eq!(staging_events.len(), 1);
        assert_eq!(staging_events[0].event_id, "evt-002");
    }

    #[test]
    fn slow_client_shed() {
        let hub = LiveHub::new(2, 2); // buffer cap 2, threshold 2
        let sub_id = hub.subscribe("prod");

        // Fill the buffer (cap = 2).
        hub.publish("prod", test_event("evt-001", "prod"));
        hub.publish("prod", test_event("evt-002", "prod"));

        // Buffer is now full. Next publishes increment missed.
        hub.publish("prod", test_event("evt-003", "prod")); // missed = 1
        assert!(!hub.is_shed(sub_id));

        hub.publish("prod", test_event("evt-004", "prod")); // missed = 2 >= threshold
        assert!(hub.is_shed(sub_id));

        // Draining a shed subscriber returns an error.
        let result = hub.drain(sub_id, 10);
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::SlowClientShed { .. }
        ));
    }

    #[test]
    fn drain_resets_missed_counter() {
        let hub = LiveHub::new(2, 3);
        let sub_id = hub.subscribe("prod");

        // Fill buffer.
        hub.publish("prod", test_event("evt-001", "prod"));
        hub.publish("prod", test_event("evt-002", "prod"));

        // One missed publish.
        hub.publish("prod", test_event("evt-003", "prod"));

        // Drain to reset.
        let events = hub.drain(sub_id, 10).unwrap();
        assert_eq!(events.len(), 2);

        // Now the subscriber can receive again.
        hub.publish("prod", test_event("evt-004", "prod"));
        let events = hub.drain(sub_id, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-004");
    }

    #[test]
    fn cursor_reconnect() {
        let hub = LiveHub::new(16, 4);
        let _sub_id = hub.subscribe("prod");

        // Publish 5 events.
        for i in 1..=5 {
            hub.publish("prod", test_event(&format!("evt-{i:03}"), "prod"));
        }

        // Reconnect from cursor 3 (get events 4 and 5).
        let events = hub.reconnect("prod", 3).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 4);
        assert_eq!(events[1].seq, 5);
    }

    #[test]
    fn cursor_reconnect_from_zero() {
        let hub = LiveHub::new(16, 4);
        let _sub_id = hub.subscribe("prod");

        hub.publish("prod", test_event("evt-001", "prod"));
        hub.publish("prod", test_event("evt-002", "prod"));

        // Cursor 0 means "give me everything".
        let events = hub.reconnect("prod", 0).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn cursor_expired_when_too_old() {
        let hub = LiveHub::new(4, 4); // small buffer
        let _sub_id = hub.subscribe("prod");

        // Publish more events than the stream cap (4 * 4 = 16).
        for i in 1..=20 {
            hub.publish("prod", test_event(&format!("evt-{i:03}"), "prod"));
        }

        // The oldest retained event should be > 1.
        let oldest = hub.oldest_seq("prod").unwrap();
        assert!(oldest > 1);

        // Reconnecting with a cursor older than oldest fails.
        let result = hub.reconnect("prod", 1);
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::LiveCursorExpired { .. }
        ));
    }

    #[test]
    fn reconnect_unknown_cluster() {
        let hub = LiveHub::new(16, 4);
        let result = hub.reconnect("nonexistent", 0);
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::NoLiveStream { .. }
        ));
    }

    #[test]
    fn unsubscribe_removes_subscriber() {
        let hub = LiveHub::new(16, 4);
        let sub_id = hub.subscribe("prod");
        assert_eq!(hub.active_subscriber_count("prod"), 1);

        hub.unsubscribe(sub_id);
        assert_eq!(hub.active_subscriber_count("prod"), 0);
    }

    #[test]
    fn multiple_subscribers_receive_same_events() {
        let hub = LiveHub::new(16, 4);
        let sub1 = hub.subscribe("prod");
        let sub2 = hub.subscribe("prod");

        hub.publish("prod", test_event("evt-001", "prod"));

        let events1 = hub.drain(sub1, 10).unwrap();
        let events2 = hub.drain(sub2, 10).unwrap();
        assert_eq!(events1.len(), 1);
        assert_eq!(events2.len(), 1);
        assert_eq!(events1[0].event_id, events2[0].event_id);
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let hub = LiveHub::new(16, 4);
        let sub_id = hub.subscribe("prod");

        for i in 1..=5 {
            let seq = hub.publish("prod", test_event(&format!("evt-{i}"), "prod"));
            assert_eq!(seq, i as u64);
        }

        let events = hub.drain(sub_id, 10).unwrap();
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.seq, (i + 1) as u64);
        }
    }
}
