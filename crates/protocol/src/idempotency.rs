// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Idempotency keys for duplicate detection.
//!
//! Every mutating RPC carries an idempotency key (UUID v4 or
//! monotonic counter). The server tracks seen keys and rejects
//! duplicates with `ProtocolError::DuplicateIdempotencyKey`.
//! Anchored in `bench/schemas/protocol.v1.json`.

#![forbid(unsafe_code)]

use crate::error::{ProtocolError, ProtocolResult};
use std::collections::HashSet;

/// Idempotency key format (anchored in protocol.v1.json).
pub const IDEMPOTENCY_KEY_FORMAT: &str = "uuid_v4_or_monotonic_u64";

/// Maximum number of idempotency keys the tracker retains
/// before evicting the oldest (bounded memory).
pub const MAX_TRACKED_KEYS: usize = 100_000;

/// An idempotency key: either a UUID v4 string or a monotonic
/// u64 counter value rendered as a string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct IdempotencyKey(pub String);

impl IdempotencyKey {
    /// Create a key from a UUID v4.
    pub fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id.to_string())
    }

    /// Create a key from a monotonic counter value.
    pub fn from_counter(value: u64) -> Self {
        Self(value.to_string())
    }

    /// Create a key from a raw string (caller ensures uniqueness
    /// semantics).
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Duplicate-detection tracker for idempotency keys.
///
/// Bounded: retains at most `MAX_TRACKED_KEYS` entries. When the
/// bound is reached, the tracker clears (a full reset is cheaper
/// than LRU eviction for the MVP; the window is large enough that
/// legitimate retries land within it).
#[derive(Debug)]
pub struct IdempotencyTracker {
    seen: HashSet<IdempotencyKey>,
}

impl Default for IdempotencyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl IdempotencyTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    /// Check whether a key has been seen. If not, record it and
    /// return `Ok(())`. If it has, return
    /// `Err(DuplicateIdempotencyKey)`.
    pub fn check_and_record(&mut self, key: &IdempotencyKey) -> ProtocolResult<()> {
        if self.seen.contains(key) {
            return Err(ProtocolError::DuplicateIdempotencyKey { key: key.0.clone() });
        }

        // Bounded memory: clear when at capacity.
        if self.seen.len() >= MAX_TRACKED_KEYS {
            self.seen.clear();
        }

        self.seen.insert(key.clone());
        Ok(())
    }

    /// Whether a key has been seen (without recording).
    pub fn contains(&self, key: &IdempotencyKey) -> bool {
        self.seen.contains(key)
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the tracker is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Clear all tracked keys.
    pub fn clear(&mut self) {
        self.seen.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_key_round_trips() {
        let id = uuid::Uuid::new_v4();
        let key = IdempotencyKey::from_uuid(id);
        assert_eq!(key.as_str(), id.to_string());
    }

    #[test]
    fn counter_key_round_trips() {
        let key = IdempotencyKey::from_counter(42);
        assert_eq!(key.as_str(), "42");
    }

    #[test]
    fn first_key_accepted() {
        let mut tracker = IdempotencyTracker::new();
        let key = IdempotencyKey::from_counter(1);
        assert!(tracker.check_and_record(&key).is_ok());
        assert!(tracker.contains(&key));
    }

    #[test]
    fn duplicate_key_rejected() {
        let mut tracker = IdempotencyTracker::new();
        let key = IdempotencyKey::from_raw("abc-123");
        assert!(tracker.check_and_record(&key).is_ok());
        let err = tracker.check_and_record(&key).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::DuplicateIdempotencyKey {
                key: "abc-123".into(),
            }
        );
    }

    #[test]
    fn distinct_keys_accepted() {
        let mut tracker = IdempotencyTracker::new();
        for i in 0..100 {
            let key = IdempotencyKey::from_counter(i);
            assert!(tracker.check_and_record(&key).is_ok());
        }
        assert_eq!(tracker.len(), 100);
    }

    #[test]
    fn tracker_clears_at_capacity() {
        let mut tracker = IdempotencyTracker::new();
        // Fill to capacity.
        for i in 0..MAX_TRACKED_KEYS {
            let key = IdempotencyKey::from_counter(i as u64);
            assert!(tracker.check_and_record(&key).is_ok());
        }
        assert_eq!(tracker.len(), MAX_TRACKED_KEYS);

        // Next insert triggers clear.
        let key = IdempotencyKey::from_counter(MAX_TRACKED_KEYS as u64);
        assert!(tracker.check_and_record(&key).is_ok());
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn clear_empties_tracker() {
        let mut tracker = IdempotencyTracker::new();
        let key = IdempotencyKey::from_counter(1);
        tracker.check_and_record(&key).unwrap();
        tracker.clear();
        assert!(tracker.is_empty());
        // Key can be re-used after clear.
        assert!(tracker.check_and_record(&key).is_ok());
    }

    #[test]
    fn idempotency_key_format_constant() {
        assert_eq!(IDEMPOTENCY_KEY_FORMAT, "uuid_v4_or_monotonic_u64");
    }
}
