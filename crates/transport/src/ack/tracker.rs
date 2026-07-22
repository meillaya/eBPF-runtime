// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ACK tracker and outbox deletion.

use std::collections::HashMap;

use crate::error::{TransportError, TransportResult};

use super::{AckState, KafkaAcceptance};

/// Trait for deleting outbox rows after ACK.
///
/// The transport crate does not depend on `storage-local`
/// directly (to avoid a circular dependency through the agent
/// crate). Instead, the agent wires up the concrete
/// `LocalStorage` implementation at startup.
pub trait OutboxDeleter: Send + Sync {
    /// Delete the outbox row for the given batch ID.
    /// Returns true if a row was deleted.
    fn delete_outbox_row(&self, batch_id: &str) -> TransportResult<bool>;
}

/// In-memory outbox deleter for tests.
#[derive(Debug, Default)]
pub struct MockOutboxDeleter {
    /// The batch IDs that exist in the mock outbox.
    rows: parking_lot::Mutex<Vec<String>>,
}

impl MockOutboxDeleter {
    /// Create a mock outbox with the given batch IDs.
    pub fn new(batch_ids: Vec<String>) -> Self {
        Self {
            rows: parking_lot::Mutex::new(batch_ids),
        }
    }

    /// The current outbox rows.
    pub fn rows(&self) -> Vec<String> {
        self.rows.lock().clone()
    }
}

impl OutboxDeleter for MockOutboxDeleter {
    fn delete_outbox_row(&self, batch_id: &str) -> TransportResult<bool> {
        let mut rows = self.rows.lock();
        if let Some(pos) = rows.iter().position(|r| r == batch_id) {
            rows.remove(pos);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Tracks batch ACK state and enforces the durable-acceptance
/// invariant.
pub struct AckTracker {
    /// batch_id → current ACK state.
    states: HashMap<String, AckState>,
    /// batch_id → Kafka acceptance confirmation.
    acceptances: HashMap<String, KafkaAcceptance>,
    /// The outbox deleter (wired at startup).
    outbox_deleter: Option<Box<dyn OutboxDeleter>>,
}

impl std::fmt::Debug for AckTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AckTracker")
            .field("states", &self.states)
            .field("acceptances", &self.acceptances)
            .field(
                "outbox_deleter",
                &self.outbox_deleter.as_ref().map(|_| "<dyn OutboxDeleter>"),
            )
            .finish()
    }
}

impl AckTracker {
    /// Create a new tracker without an outbox deleter.
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            acceptances: HashMap::new(),
            outbox_deleter: None,
        }
    }

    /// Create a tracker with an outbox deleter.
    pub fn with_outbox_deleter(deleter: Box<dyn OutboxDeleter>) -> Self {
        Self {
            states: HashMap::new(),
            acceptances: HashMap::new(),
            outbox_deleter: Some(deleter),
        }
    }

    /// Register a batch as sent (awaiting Kafka acceptance).
    pub fn register_sent(&mut self, batch_id: impl Into<String>) {
        let id = batch_id.into();
        self.states.insert(id, AckState::AwaitingKafkaAcceptance);
    }

    /// Record durable Kafka acceptance for a batch.
    ///
    /// This is the ONLY path that permits an ACK. The batch
    /// transitions from `AwaitingKafkaAcceptance` to
    /// `KafkaAccepted`.
    pub fn record_kafka_acceptance(&mut self, acceptance: KafkaAcceptance) -> TransportResult<()> {
        let state = self.states.get(&acceptance.batch_id);
        match state {
            None => {
                return Err(TransportError::OutboxError {
                    reason: format!("unknown batch_id: {}", acceptance.batch_id),
                });
            }
            Some(AckState::AwaitingKafkaAcceptance) => {
                // Valid transition.
            }
            Some(AckState::KafkaAccepted) | Some(AckState::AckedAndDeleted) => {
                // Idempotent: already accepted.
                return Ok(());
            }
        }

        self.states
            .insert(acceptance.batch_id.clone(), AckState::KafkaAccepted);
        self.acceptances
            .insert(acceptance.batch_id.clone(), acceptance);
        Ok(())
    }

    /// Attempt a receipt-only ACK (ACK without Kafka
    /// acceptance). This is ALWAYS rejected.
    pub fn try_receipt_only_ack(&self, batch_id: &str) -> TransportResult<()> {
        // Receipt-only ACK is structurally forbidden.
        Err(TransportError::ReceiptOnlyAck {
            batch_id: batch_id.to_string(),
        })
    }

    /// Complete the ACK: transition to `AckedAndDeleted` and
    /// delete the outbox row.
    ///
    /// Requires prior `KafkaAccepted` state. Returns an error
    /// if the batch has not been durably accepted.
    pub fn complete_ack(&mut self, batch_id: &str) -> TransportResult<()> {
        let state =
            self.states
                .get(batch_id)
                .copied()
                .ok_or_else(|| TransportError::OutboxError {
                    reason: format!("unknown batch_id: {batch_id}"),
                })?;

        match state {
            AckState::AwaitingKafkaAcceptance => {
                // Cannot ACK before Kafka acceptance.
                return Err(TransportError::ReceiptOnlyAck {
                    batch_id: batch_id.to_string(),
                });
            }
            AckState::KafkaAccepted => {
                // Valid: proceed to delete outbox row.
            }
            AckState::AckedAndDeleted => {
                // Idempotent: already done.
                return Ok(());
            }
        }

        // Delete the outbox row.
        if let Some(deleter) = &self.outbox_deleter {
            deleter.delete_outbox_row(batch_id)?;
        }

        self.states
            .insert(batch_id.to_string(), AckState::AckedAndDeleted);
        Ok(())
    }

    /// The current ACK state of a batch.
    pub fn state(&self, batch_id: &str) -> Option<AckState> {
        self.states.get(batch_id).copied()
    }

    /// The Kafka acceptance for a batch (if accepted).
    pub fn acceptance(&self, batch_id: &str) -> Option<&KafkaAcceptance> {
        self.acceptances.get(batch_id)
    }

    /// The number of batches awaiting Kafka acceptance.
    pub fn awaiting_count(&self) -> usize {
        self.states
            .values()
            .filter(|s| **s == AckState::AwaitingKafkaAcceptance)
            .count()
    }

    /// The number of batches fully ACKed and deleted.
    pub fn acked_count(&self) -> usize {
        self.states
            .values()
            .filter(|s| **s == AckState::AckedAndDeleted)
            .count()
    }

    /// All batch IDs in the given state.
    pub fn batches_in_state(&self, state: AckState) -> Vec<String> {
        self.states
            .iter()
            .filter(|(_, s)| **s == state)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

impl Default for AckTracker {
    fn default() -> Self {
        Self::new()
    }
}
