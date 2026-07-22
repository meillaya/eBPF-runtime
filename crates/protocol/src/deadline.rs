// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Deadline propagation for gRPC-style operations.
//!
//! Deadlines are monotonic expiry timestamps (epoch milliseconds).
//! They propagate across RPC boundaries: a server receiving a
//! request with 500ms remaining inherits that remaining budget,
//! never a fresh default.

#![forbid(unsafe_code)]

use crate::error::{ProtocolError, ProtocolResult};

/// Default deadline in milliseconds (anchored in
/// `bench/schemas/protocol.v1.json`).
pub const DEFAULT_DEADLINE_MS: u64 = 30_000;

/// A monotonic deadline for an operation.
///
/// The deadline is an absolute epoch-millisecond timestamp.
/// `is_expired()` compares against the supplied `now` to avoid
/// hidden clock reads in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    /// Absolute expiry time in epoch milliseconds.
    pub deadline_epoch_ms: u64,
}

impl Deadline {
    /// Create a deadline from an absolute epoch-millisecond timestamp.
    pub fn at(deadline_epoch_ms: u64) -> Self {
        Self { deadline_epoch_ms }
    }

    /// Create a deadline `duration_ms` from `now_epoch_ms`.
    pub fn from_now(now_epoch_ms: u64, duration_ms: u64) -> Self {
        Self {
            deadline_epoch_ms: now_epoch_ms.saturating_add(duration_ms),
        }
    }

    /// Create the default deadline from `now_epoch_ms`.
    pub fn default_from_now(now_epoch_ms: u64) -> Self {
        Self::from_now(now_epoch_ms, DEFAULT_DEADLINE_MS)
    }

    /// Whether the deadline has expired at `now_epoch_ms`.
    pub fn is_expired(&self, now_epoch_ms: u64) -> bool {
        now_epoch_ms >= self.deadline_epoch_ms
    }

    /// Remaining time in milliseconds at `now_epoch_ms`.
    /// Returns 0 if expired.
    pub fn remaining_ms(&self, now_epoch_ms: u64) -> u64 {
        self.deadline_epoch_ms.saturating_sub(now_epoch_ms)
    }

    /// Check the deadline and return `Err(ExpiredDeadline)` if
    /// it has passed.
    pub fn check(&self, now_epoch_ms: u64) -> ProtocolResult<()> {
        if self.is_expired(now_epoch_ms) {
            return Err(ProtocolError::ExpiredDeadline {
                deadline_epoch_ms: self.deadline_epoch_ms,
                now_epoch_ms,
            });
        }
        Ok(())
    }

    /// Propagate the deadline across an RPC boundary: the child
    /// inherits the MINIMUM of the parent's remaining budget and
    /// the child's own default. This prevents a child from
    /// outliving its parent's deadline.
    pub fn propagate(&self, now_epoch_ms: u64, child_default_ms: u64) -> Self {
        let remaining = self.remaining_ms(now_epoch_ms);
        let child_budget = remaining.min(child_default_ms);
        Self::from_now(now_epoch_ms, child_budget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_expired_before_deadline() {
        let d = Deadline::at(1000);
        assert!(!d.is_expired(999));
        assert!(d.is_expired(1000));
        assert!(d.is_expired(1001));
    }

    #[test]
    fn from_now_computes_correctly() {
        let d = Deadline::from_now(500, 300);
        assert_eq!(d.deadline_epoch_ms, 800);
    }

    #[test]
    fn remaining_ms() {
        let d = Deadline::at(1000);
        assert_eq!(d.remaining_ms(700), 300);
        assert_eq!(d.remaining_ms(1000), 0);
        assert_eq!(d.remaining_ms(1100), 0);
    }

    #[test]
    fn check_ok_before_deadline() {
        let d = Deadline::at(1000);
        assert!(d.check(999).is_ok());
    }

    #[test]
    fn check_expired_returns_exact_error() {
        let d = Deadline::at(1000);
        let err = d.check(1001).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::ExpiredDeadline {
                deadline_epoch_ms: 1000,
                now_epoch_ms: 1001,
            }
        );
    }

    #[test]
    fn propagate_inherits_minimum() {
        // Parent has 200ms remaining; child default is 5000ms.
        let parent = Deadline::at(1200);
        let child = parent.propagate(1000, 5000);
        // Child should inherit 200ms (the minimum).
        assert_eq!(child.deadline_epoch_ms, 1200);
    }

    #[test]
    fn propagate_uses_child_default_when_smaller() {
        // Parent has 10000ms remaining; child default is 500ms.
        let parent = Deadline::at(11000);
        let child = parent.propagate(1000, 500);
        // Child should use its own 500ms default.
        assert_eq!(child.deadline_epoch_ms, 1500);
    }

    #[test]
    fn propagate_expired_parent() {
        let parent = Deadline::at(500);
        let child = parent.propagate(1000, 5000);
        // Parent already expired; remaining = 0.
        assert_eq!(child.deadline_epoch_ms, 1000);
        assert!(child.is_expired(1000));
    }

    #[test]
    fn default_deadline_matches_schema() {
        assert_eq!(DEFAULT_DEADLINE_MS, 30_000);
    }

    #[test]
    fn saturating_add_prevents_overflow() {
        let d = Deadline::from_now(u64::MAX, 100);
        assert_eq!(d.deadline_epoch_ms, u64::MAX);
    }
}
