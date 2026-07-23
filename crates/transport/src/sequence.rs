// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Boot/agent generation and sequence reconciliation.
//!
//! The agent assigns a monotonically increasing sequence number
//! to every event batch within a boot generation. On reconnect,
//! the control plane reports the last ACKed sequence; the agent
//! replays from `last_acked + 1`. A boot generation change
//! (reboot) resets the sequence to 0.
//!
//! Reconciliation detects:
//! - **Gaps**: the next sequence is > last_acked + 1 (lost
//!   batches in transit).
//! - **Duplicates**: the next sequence is <= last_acked (already
//!   processed; safe to skip).
//! - **Generation change**: the boot_id or agent_generation
//!   changed (full reset).

#![forbid(unsafe_code)]

use crate::error::{TransportError, TransportResult};

/// Tracks the agent's boot/agent generation and monotonic
/// sequence for reconciliation on reconnect.
#[derive(Debug, Clone)]
pub struct SequenceTracker {
    /// Linux boot_id (hex-encoded). Changes on reboot.
    boot_id_hex: String,
    /// Agent generation (monotonic per-agent). Changes on
    /// agent restart or upgrade.
    agent_generation: String,
    /// The next sequence number to assign.
    next_seq: u64,
    /// The last sequence acknowledged by the control plane.
    last_acked_seq: Option<u64>,
    /// The boot_id at which the last ACK was received.
    last_acked_boot_id: Option<String>,
    /// The agent generation at which the last ACK was received.
    last_acked_generation: Option<String>,
}

/// The result of a reconciliation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationAction {
    /// Sequences are contiguous; continue normally.
    Continue,
    /// A gap was detected; replay from `replay_from_seq`.
    ReplayFrom {
        /// The sequence to replay from (last_acked + 1).
        replay_from_seq: u64,
    },
    /// The batch is a duplicate; skip it.
    SkipDuplicate {
        /// The duplicate sequence number.
        duplicate_seq: u64,
    },
    /// The boot/agent generation changed; reset sequences.
    GenerationReset {
        /// The new boot_id.
        new_boot_id: String,
        /// The new agent generation.
        new_generation: String,
    },
}

impl SequenceTracker {
    /// Create a new tracker for the given boot/agent generation.
    pub fn new(boot_id_hex: impl Into<String>, agent_generation: impl Into<String>) -> Self {
        Self {
            boot_id_hex: boot_id_hex.into(),
            agent_generation: agent_generation.into(),
            next_seq: 0,
            last_acked_seq: None,
            last_acked_boot_id: None,
            last_acked_generation: None,
        }
    }

    /// The current boot_id.
    pub fn boot_id_hex(&self) -> &str {
        &self.boot_id_hex
    }

    /// The current agent generation.
    pub fn agent_generation(&self) -> &str {
        &self.agent_generation
    }

    /// The next sequence number to assign.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The last acknowledged sequence (if any).
    pub fn last_acked_seq(&self) -> Option<u64> {
        self.last_acked_seq
    }

    /// Assign the next sequence number and advance the counter.
    pub fn assign_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    /// Record an ACK from the control plane.
    pub fn record_ack(&mut self, acked_seq: u64) {
        self.last_acked_seq = Some(acked_seq);
        self.last_acked_boot_id = Some(self.boot_id_hex.clone());
        self.last_acked_generation = Some(self.agent_generation.clone());
    }

    /// Reconcile the local sequence state with the control
    /// plane's reported last-ACKed sequence on reconnect.
    ///
    /// Returns the action the agent should take.
    pub fn reconcile(
        &mut self,
        server_last_acked_seq: Option<u64>,
        server_boot_id: &str,
        server_generation: &str,
    ) -> ReconciliationAction {
        // Generation change: full reset.
        if server_boot_id != self.boot_id_hex || server_generation != self.agent_generation {
            let action = ReconciliationAction::GenerationReset {
                new_boot_id: self.boot_id_hex.clone(),
                new_generation: self.agent_generation.clone(),
            };
            // Reset sequence state for the new generation.
            self.next_seq = 0;
            self.last_acked_seq = None;
            self.last_acked_boot_id = None;
            self.last_acked_generation = None;
            return action;
        }

        match server_last_acked_seq {
            None => {
                // Server has no ACK record; replay everything.
                ReconciliationAction::ReplayFrom { replay_from_seq: 0 }
            }
            Some(server_seq) => {
                // Update our ACK watermark.
                self.last_acked_seq = Some(server_seq);
                self.last_acked_boot_id = Some(self.boot_id_hex.clone());
                self.last_acked_generation = Some(self.agent_generation.clone());

                if self.next_seq <= server_seq {
                    // We haven't sent anything beyond what the
                    // server ACKed; continue from next_seq.
                    ReconciliationAction::Continue
                } else if self.next_seq == server_seq + 1 {
                    // Contiguous; continue.
                    ReconciliationAction::Continue
                } else {
                    // Gap: server ACKed up to server_seq, but
                    // we've sent up to next_seq - 1. Replay
                    // from server_seq + 1.
                    ReconciliationAction::ReplayFrom {
                        replay_from_seq: server_seq + 1,
                    }
                }
            }
        }
    }

    /// Check whether a batch with the given sequence would be a
    /// duplicate (already ACKed by the server).
    pub fn is_duplicate(&self, seq: u64) -> bool {
        self.last_acked_seq
            .map(|acked| seq <= acked)
            .unwrap_or(false)
    }

    /// Validate that the next sequence is contiguous with the
    /// last ACKed sequence. Returns an error if a gap is
    /// detected.
    pub fn validate_contiguous(&self, seq: u64) -> TransportResult<()> {
        if let Some(acked) = self.last_acked_seq {
            if seq > acked + 1 {
                return Err(TransportError::SequenceGap {
                    last_acked_seq: acked,
                    next_seq: seq,
                    agent_generation: self.agent_generation.clone(),
                });
            }
        }
        Ok(())
    }

    /// The number of unacknowledged batches (sent but not yet
    /// ACKed).
    pub fn unacked_count(&self) -> u64 {
        match self.last_acked_seq {
            None => self.next_seq,
            Some(acked) => self.next_seq.saturating_sub(acked + 1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> SequenceTracker {
        SequenceTracker::new("00".repeat(16), "gen-1")
    }

    #[test]
    fn assign_seq_monotonic() {
        let mut t = tracker();
        assert_eq!(t.assign_seq(), 0);
        assert_eq!(t.assign_seq(), 1);
        assert_eq!(t.assign_seq(), 2);
        assert_eq!(t.next_seq(), 3);
    }

    #[test]
    fn record_ack_updates_watermark() {
        let mut t = tracker();
        t.assign_seq();
        t.assign_seq();
        t.record_ack(1);
        assert_eq!(t.last_acked_seq(), Some(1));
        assert_eq!(t.unacked_count(), 0);
    }

    #[test]
    fn unacked_count_no_acks() {
        let mut t = tracker();
        t.assign_seq();
        t.assign_seq();
        t.assign_seq();
        assert_eq!(t.unacked_count(), 3);
    }

    #[test]
    fn unacked_count_partial_acks() {
        let mut t = tracker();
        for _ in 0..5 {
            t.assign_seq();
        }
        t.record_ack(2);
        // Sent 0..4, ACKed through 2 → unacked: 3, 4.
        assert_eq!(t.unacked_count(), 2);
    }

    #[test]
    fn reconcile_contiguous() {
        let mut t = tracker();
        t.assign_seq(); // 0
        t.assign_seq(); // 1
        t.record_ack(1);
        // next_seq = 2, server ACKed 1 → next_seq == server_seq + 1 → contiguous.

        let action = t.reconcile(Some(1), &"00".repeat(16), "gen-1");
        assert_eq!(action, ReconciliationAction::Continue);
    }

    #[test]
    fn reconcile_gap_detected() {
        let mut t = tracker();
        for _ in 0..10 {
            t.assign_seq();
        }
        // Server only ACKed through 3; we sent through 9.
        let action = t.reconcile(Some(3), &"00".repeat(16), "gen-1");
        assert_eq!(
            action,
            ReconciliationAction::ReplayFrom { replay_from_seq: 4 }
        );
    }

    #[test]
    fn reconcile_no_server_ack() {
        let mut t = tracker();
        t.assign_seq();
        let action = t.reconcile(None, &"00".repeat(16), "gen-1");
        assert_eq!(
            action,
            ReconciliationAction::ReplayFrom { replay_from_seq: 0 }
        );
    }

    #[test]
    fn reconcile_generation_change() {
        let mut t = tracker();
        t.assign_seq();
        t.record_ack(0);

        // Different boot_id → generation reset.
        let action = t.reconcile(Some(0), &"ff".repeat(16), "gen-1");
        assert!(matches!(
            action,
            ReconciliationAction::GenerationReset { .. }
        ));
        assert_eq!(t.next_seq(), 0);
        assert_eq!(t.last_acked_seq(), None);
    }

    #[test]
    fn reconcile_agent_generation_change() {
        let mut t = tracker();
        t.assign_seq();

        let action = t.reconcile(Some(0), &"00".repeat(16), "gen-2");
        assert!(matches!(
            action,
            ReconciliationAction::GenerationReset { .. }
        ));
    }

    #[test]
    fn is_duplicate_after_ack() {
        let mut t = tracker();
        t.assign_seq(); // 0
        t.assign_seq(); // 1
        t.record_ack(1);

        assert!(t.is_duplicate(0));
        assert!(t.is_duplicate(1));
        assert!(!t.is_duplicate(2));
    }

    #[test]
    fn validate_contiguous_ok() {
        let mut t = tracker();
        t.assign_seq(); // 0
        t.record_ack(0);
        assert!(t.validate_contiguous(1).is_ok());
    }

    #[test]
    fn validate_contiguous_gap() {
        let mut t = tracker();
        t.assign_seq(); // 0
        t.record_ack(0);
        let err = t.validate_contiguous(5).unwrap_err();
        assert!(matches!(err, TransportError::SequenceGap { .. }));
    }

    #[test]
    fn saturating_seq_at_u64_max() {
        let mut t = tracker();
        t.next_seq = u64::MAX;
        let seq = t.assign_seq();
        assert_eq!(seq, u64::MAX);
        // Should not overflow.
        assert_eq!(t.next_seq(), u64::MAX);
    }
}
