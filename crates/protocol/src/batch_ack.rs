// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Event batch ACK state machine.
//!
//! States: `Pending → Accepted / Rejected`.
//!
//! Every batch carries an idempotency key. Duplicate submissions
//! are detected and rejected with `DuplicateIdempotencyKey`.
//! Batch bounds (message count, message size) are validated
//! before the ACK transitions.

#![forbid(unsafe_code)]

use crate::bounds::MessageBounds;
use crate::error::{ProtocolError, ProtocolResult};
use crate::events::Batch;
use crate::idempotency::{IdempotencyKey, IdempotencyTracker};

/// Batch ACK state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BatchAckState {
    /// Batch received, not yet acknowledged.
    Pending,
    /// Batch accepted and durably acknowledged.
    Accepted,
    /// Batch rejected (oversized, invalid, duplicate).
    Rejected,
}

impl std::fmt::Display for BatchAckState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Pending => "Pending",
            Self::Accepted => "Accepted",
            Self::Rejected => "Rejected",
        };
        f.write_str(name)
    }
}

/// The batch ACK state machine. Validates batch bounds,
/// enforces idempotency, and tracks the ACK lifecycle.
#[derive(Debug)]
pub struct BatchAckMachine {
    state: BatchAckState,
    bounds: MessageBounds,
    idempotency: IdempotencyTracker,
    /// The idempotency key of the current batch (if any).
    current_key: Option<IdempotencyKey>,
    /// Transition log for audit.
    transitions: Vec<String>,
}

impl Default for BatchAckMachine {
    fn default() -> Self {
        Self::new(MessageBounds::default())
    }
}

impl BatchAckMachine {
    /// Create a new batch ACK machine with the given bounds.
    pub fn new(bounds: MessageBounds) -> Self {
        Self {
            state: BatchAckState::Pending,
            bounds,
            idempotency: IdempotencyTracker::new(),
            current_key: None,
            transitions: vec!["init: Pending".into()],
        }
    }

    /// Current state.
    pub fn state(&self) -> BatchAckState {
        self.state
    }

    /// The transition log.
    pub fn transitions(&self) -> &[String] {
        &self.transitions
    }

    fn transition(&mut self, to: BatchAckState, reason: &str) {
        self.transitions
            .push(format!("{} -> {to}: {reason}", self.state));
        self.state = to;
    }

    /// Submit a batch for acknowledgement.
    ///
    /// Validates:
    /// 1. Idempotency key uniqueness.
    /// 2. Batch bounds (message count, message size).
    /// 3. Schema major version (must be >= 1).
    ///
    /// On success, transitions to Accepted.
    /// On failure, transitions to Rejected.
    pub fn submit(&mut self, key: &IdempotencyKey, batch: &Batch) -> ProtocolResult<()> {
        // Check idempotency first.
        self.idempotency.check_and_record(key)?;

        // Validate schema major.
        if batch.schema_major < 1 {
            self.current_key = Some(key.clone());
            self.transition(
                BatchAckState::Rejected,
                &format!("stale schema major {}", batch.schema_major),
            );
            return Err(ProtocolError::StaleProtocolMajor {
                client_major: batch.schema_major,
                server_major: 1,
            });
        }

        // Validate batch bounds.
        if let Err(e) = self.bounds.validate_batch(batch) {
            self.current_key = Some(key.clone());
            self.transition(BatchAckState::Rejected, &format!("bounds violation: {e}"));
            return Err(e);
        }

        // All checks passed.
        self.current_key = Some(key.clone());
        self.transition(
            BatchAckState::Accepted,
            &format!("batch {} accepted ({} events)", key, batch.events.len()),
        );
        Ok(())
    }

    /// Reset the machine to Pending for the next batch.
    pub fn reset(&mut self) {
        self.current_key = None;
        self.transition(BatchAckState::Pending, "reset for next batch");
    }

    /// Whether the current batch was accepted.
    pub fn is_accepted(&self) -> bool {
        self.state == BatchAckState::Accepted
    }

    /// Whether the current batch was rejected.
    pub fn is_rejected(&self) -> bool {
        self.state == BatchAckState::Rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Event, EventKind};

    fn make_event(seq: u64) -> Event {
        Event {
            event_id: format!("00000000-0000-0000-0000-{seq:012}"),
            seq,
            ts_monotonic_ns: 0,
            sensor: "ops".into(),
            event_kind: EventKind::FileOpen,
            valids: Default::default(),
        }
    }

    fn make_batch(count: usize) -> Batch {
        Batch {
            schema_major: 1,
            schema_minor: 0,
            events: (0..count as u64).map(make_event).collect(),
            agent_generation: "gen-1".into(),
            node_name: "node-1".into(),
            boot_id_hex: "00".repeat(16),
        }
    }

    #[test]
    fn happy_path_accept() {
        let mut sm = BatchAckMachine::default();
        let key = IdempotencyKey::from_counter(1);
        let batch = make_batch(5);
        sm.submit(&key, &batch).unwrap();
        assert_eq!(sm.state(), BatchAckState::Accepted);
        assert!(sm.is_accepted());
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut sm = BatchAckMachine::default();
        let key = IdempotencyKey::from_raw("batch-abc");
        let batch = make_batch(1);
        sm.submit(&key, &batch).unwrap();

        sm.reset();
        let err = sm.submit(&key, &batch).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::DuplicateIdempotencyKey {
                key: "batch-abc".into(),
            }
        );
    }

    #[test]
    fn oversized_batch_rejected() {
        let bounds = MessageBounds {
            max_batch_messages: 3,
            ..Default::default()
        };
        let mut sm = BatchAckMachine::new(bounds);
        let key = IdempotencyKey::from_counter(1);
        let batch = make_batch(5);
        let err = sm.submit(&key, &batch).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::OversizedBatch {
                actual_count: 5,
                max_count: 3,
            }
        );
        assert_eq!(sm.state(), BatchAckState::Rejected);
    }

    #[test]
    fn stale_schema_major_rejected() {
        let mut sm = BatchAckMachine::default();
        let key = IdempotencyKey::from_counter(1);
        let mut batch = make_batch(1);
        batch.schema_major = 0;
        let err = sm.submit(&key, &batch).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::StaleProtocolMajor {
                client_major: 0,
                server_major: 1,
            }
        );
        assert_eq!(sm.state(), BatchAckState::Rejected);
    }

    #[test]
    fn reset_allows_new_batch() {
        let mut sm = BatchAckMachine::default();
        let key1 = IdempotencyKey::from_counter(1);
        sm.submit(&key1, &make_batch(1)).unwrap();
        sm.reset();
        assert_eq!(sm.state(), BatchAckState::Pending);

        let key2 = IdempotencyKey::from_counter(2);
        sm.submit(&key2, &make_batch(1)).unwrap();
        assert_eq!(sm.state(), BatchAckState::Accepted);
    }

    #[test]
    fn empty_batch_accepted() {
        let mut sm = BatchAckMachine::default();
        let key = IdempotencyKey::from_counter(1);
        sm.submit(&key, &make_batch(0)).unwrap();
        assert!(sm.is_accepted());
    }

    #[test]
    fn transition_log_records_all() {
        let mut sm = BatchAckMachine::default();
        let key = IdempotencyKey::from_counter(1);
        sm.submit(&key, &make_batch(1)).unwrap();
        // init + accept = 2
        assert_eq!(sm.transitions().len(), 2);
    }

    #[test]
    fn distinct_keys_both_accepted() {
        let mut sm = BatchAckMachine::default();
        sm.submit(&IdempotencyKey::from_counter(1), &make_batch(1))
            .unwrap();
        sm.reset();
        sm.submit(&IdempotencyKey::from_counter(2), &make_batch(1))
            .unwrap();
        assert!(sm.is_accepted());
    }
}
