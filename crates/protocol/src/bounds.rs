// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Message size bounds and compression configuration.
//!
//! All constants are anchored in `bench/schemas/protocol.v1.json`.
//! The defaults here match the schema; the bench harness reads the
//! schema, NOT these constants.

#![forbid(unsafe_code)]

use crate::error::{ProtocolError, ProtocolResult};
use crate::events::Batch;

/// Default maximum size of a single serialized message: 1 MiB.
pub const DEFAULT_MAX_MESSAGE_SIZE_BYTES: usize = 1_048_576;

/// Default maximum number of messages per batch.
pub const DEFAULT_MAX_BATCH_MESSAGES: usize = 1_000;

/// Compression algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Compression {
    /// No compression.
    None,
    /// Zstandard (zstd) compression.
    Zstd,
}

/// Message bounds configuration. Anchored by
/// `bench/schemas/protocol.v1.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageBounds {
    /// Maximum serialized size of a single message in bytes.
    pub max_message_size_bytes: usize,
    /// Maximum number of messages per batch.
    pub max_batch_messages: usize,
    /// Compression algorithm for the batch payload.
    pub compression: Compression,
    /// Maximum compressed batch size in bytes (0 = no limit
    /// beyond max_message_size_bytes * max_batch_messages).
    pub max_compressed_batch_bytes: usize,
}

impl Default for MessageBounds {
    fn default() -> Self {
        Self {
            max_message_size_bytes: DEFAULT_MAX_MESSAGE_SIZE_BYTES,
            max_batch_messages: DEFAULT_MAX_BATCH_MESSAGES,
            compression: Compression::None,
            max_compressed_batch_bytes: 0,
        }
    }
}

impl MessageBounds {
    /// Validate a batch against the configured bounds.
    ///
    /// Checks:
    /// 1. Batch message count <= max_batch_messages.
    /// 2. Each serialized event <= max_message_size_bytes.
    pub fn validate_batch(&self, batch: &Batch) -> ProtocolResult<()> {
        // Check batch size (message count).
        if batch.events.len() > self.max_batch_messages {
            return Err(ProtocolError::OversizedBatch {
                actual_count: batch.events.len(),
                max_count: self.max_batch_messages,
            });
        }

        // Check each event's serialized size.
        for event in &batch.events {
            let serialized =
                serde_json::to_vec(event).map_err(|e| ProtocolError::InvalidPolicy {
                    reason: format!("event serialization failed: {e}"),
                })?;
            if serialized.len() > self.max_message_size_bytes {
                return Err(ProtocolError::OversizedMessage {
                    actual_bytes: serialized.len(),
                    max_bytes: self.max_message_size_bytes,
                });
            }
        }

        Ok(())
    }

    /// Validate a single serialized message size.
    pub fn validate_message_size(&self, size_bytes: usize) -> ProtocolResult<()> {
        if size_bytes > self.max_message_size_bytes {
            return Err(ProtocolError::OversizedMessage {
                actual_bytes: size_bytes,
                max_bytes: self.max_message_size_bytes,
            });
        }
        Ok(())
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
    fn default_bounds_match_schema() {
        let bounds = MessageBounds::default();
        assert_eq!(bounds.max_message_size_bytes, 1_048_576);
        assert_eq!(bounds.max_batch_messages, 1_000);
    }

    #[test]
    fn valid_batch_passes() {
        let bounds = MessageBounds::default();
        let batch = make_batch(10);
        assert!(bounds.validate_batch(&batch).is_ok());
    }

    #[test]
    fn oversized_batch_rejected() {
        let bounds = MessageBounds {
            max_batch_messages: 5,
            ..Default::default()
        };
        let batch = make_batch(6);
        let err = bounds.validate_batch(&batch).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::OversizedBatch {
                actual_count: 6,
                max_count: 5,
            }
        );
    }

    #[test]
    fn oversized_message_rejected() {
        let bounds = MessageBounds {
            max_message_size_bytes: 10, // absurdly small
            ..Default::default()
        };
        let batch = make_batch(1);
        let err = bounds.validate_batch(&batch).unwrap_err();
        match err {
            ProtocolError::OversizedMessage { max_bytes, .. } => {
                assert_eq!(max_bytes, 10);
            }
            other => panic!("expected OversizedMessage, got {other:?}"),
        }
    }

    #[test]
    fn validate_message_size_ok() {
        let bounds = MessageBounds::default();
        assert!(bounds.validate_message_size(100).is_ok());
        assert!(bounds.validate_message_size(1_048_576).is_ok());
    }

    #[test]
    fn validate_message_size_too_large() {
        let bounds = MessageBounds::default();
        let err = bounds.validate_message_size(1_048_577).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::OversizedMessage {
                actual_bytes: 1_048_577,
                max_bytes: 1_048_576,
            }
        );
    }

    #[test]
    fn empty_batch_passes() {
        let bounds = MessageBounds::default();
        let batch = make_batch(0);
        assert!(bounds.validate_batch(&batch).is_ok());
    }

    #[test]
    fn exactly_at_limit_passes() {
        let bounds = MessageBounds {
            max_batch_messages: 3,
            ..Default::default()
        };
        let batch = make_batch(3);
        assert!(bounds.validate_batch(&batch).is_ok());
    }
}
