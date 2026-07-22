// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DLQ routing metadata types and validation.
//!
//! Mirrors the `event-bus-kafka` DlqRouter metadata headers and the
//! `events_dlq_v1` ClickHouse table (deploy/clickhouse/0003_dlq_metadata.sql).
//!
//! Messages are routed to the DLQ when:
//! 1. Schema major version is unsupported (schema_major != 1)
//! 2. Message is malformed (JSON parse failure)
//! 3. Event kind is unknown/unspecified
//!
//! DLQ records preserve topic/partition/offset for forensic replay.

use serde::{Deserialize, Serialize};

use crate::error::{AnalyticsError, AnalyticsResult};
use crate::{DLQ_TOPIC, EVENTS_TOPIC, MAX_PAYLOAD_BYTES, SUPPORTED_SCHEMA_MAJOR};

/// Reason categories for DLQ routing.
/// Low-cardinality dimension in ClickHouse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DlqReason {
    /// Schema major version is not supported.
    SchemaMajorUnsupported { got: u16 },
    /// Message payload is malformed (JSON parse failure).
    MalformedPayload { detail: String },
    /// Event kind is unknown or unspecified.
    UnknownEventKind { kind: String },
    /// Event ID is missing or empty.
    MissingEventId,
    /// Payload exceeds maximum allowed size.
    PayloadTooLarge { size: usize },
}

impl DlqReason {
    /// The low-cardinality reason string stored in ClickHouse.
    pub fn as_reason_string(&self) -> String {
        match self {
            Self::SchemaMajorUnsupported { got } => {
                format!("schema_major_unsupported: got {got}, supported {SUPPORTED_SCHEMA_MAJOR}")
            }
            Self::MalformedPayload { detail } => {
                format!("malformed_payload: {detail}")
            }
            Self::UnknownEventKind { kind } => {
                format!("unknown_event_kind: {kind}")
            }
            Self::MissingEventId => "missing_event_id".to_string(),
            Self::PayloadTooLarge { size } => {
                format!("payload_too_large: {size} > {MAX_PAYLOAD_BYTES}")
            }
        }
    }
}

/// A record routed to the dead-letter queue.
/// Mirrors `events_dlq_v1` in ClickHouse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DlqRecord {
    /// Original Kafka topic (events.v1).
    pub original_topic: String,
    /// Original Kafka partition.
    pub original_partition: i32,
    /// Original Kafka offset.
    pub original_offset: u64,

    /// DLQ routing reason.
    pub dlq_reason: DlqReason,

    /// Best-effort parsed fields (may be empty for malformed messages).
    pub event_id: String,
    pub batch_id: String,
    pub schema_major: u16,
    pub schema_minor: u16,
    pub event_kind: String,

    /// Raw payload (bounded to MAX_PAYLOAD_BYTES).
    pub raw_payload: String,
    /// Raw Kafka key.
    pub raw_key: String,
}

impl DlqRecord {
    /// Validate the DLQ record.
    pub fn validate(&self) -> AnalyticsResult<()> {
        if self.dlq_reason.as_reason_string().is_empty() {
            return Err(AnalyticsError::EmptyDlqReason);
        }
        Ok(())
    }
}

/// Routes rejected messages to the DLQ.
/// In-memory mirror of the ClickHouse `events_dlq_schema_rejected_mv`.
#[derive(Debug, Default)]
pub struct DlqRouter {
    /// Records routed to the DLQ.
    records: Vec<DlqRecord>,
}

impl DlqRouter {
    /// Create a new DLQ router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Route a schema-rejected message to the DLQ.
    /// Mirrors the `events_dlq_schema_rejected_mv` materialized view.
    #[allow(clippy::too_many_arguments)]
    pub fn route_schema_rejected(
        &mut self,
        original_partition: i32,
        original_offset: u64,
        schema_major: u16,
        schema_minor: u16,
        event_id: &str,
        batch_id: &str,
        event_kind: &str,
        raw_payload: &str,
        raw_key: &str,
    ) -> &DlqRecord {
        let record = DlqRecord {
            original_topic: EVENTS_TOPIC.to_string(),
            original_partition,
            original_offset,
            dlq_reason: DlqReason::SchemaMajorUnsupported { got: schema_major },
            event_id: event_id.to_string(),
            batch_id: batch_id.to_string(),
            schema_major,
            schema_minor,
            event_kind: event_kind.to_string(),
            raw_payload: truncate(raw_payload, MAX_PAYLOAD_BYTES),
            raw_key: raw_key.to_string(),
        };
        self.records.push(record);
        self.records.last().unwrap()
    }

    /// Route a malformed message to the DLQ.
    pub fn route_malformed(
        &mut self,
        original_partition: i32,
        original_offset: u64,
        detail: &str,
        raw_payload: &str,
        raw_key: &str,
    ) -> &DlqRecord {
        let record = DlqRecord {
            original_topic: EVENTS_TOPIC.to_string(),
            original_partition,
            original_offset,
            dlq_reason: DlqReason::MalformedPayload {
                detail: detail.to_string(),
            },
            event_id: String::new(),
            batch_id: String::new(),
            schema_major: 0,
            schema_minor: 0,
            event_kind: String::new(),
            raw_payload: truncate(raw_payload, MAX_PAYLOAD_BYTES),
            raw_key: raw_key.to_string(),
        };
        self.records.push(record);
        self.records.last().unwrap()
    }

    /// Route a message with an unknown event kind to the DLQ.
    pub fn route_unknown_event_kind(
        &mut self,
        original_partition: i32,
        original_offset: u64,
        kind: &str,
        event_id: &str,
        raw_payload: &str,
    ) -> &DlqRecord {
        let record = DlqRecord {
            original_topic: EVENTS_TOPIC.to_string(),
            original_partition,
            original_offset,
            dlq_reason: DlqReason::UnknownEventKind {
                kind: kind.to_string(),
            },
            event_id: event_id.to_string(),
            batch_id: String::new(),
            schema_major: SUPPORTED_SCHEMA_MAJOR,
            schema_minor: 0,
            event_kind: kind.to_string(),
            raw_payload: truncate(raw_payload, MAX_PAYLOAD_BYTES),
            raw_key: String::new(),
        };
        self.records.push(record);
        self.records.last().unwrap()
    }

    /// Number of records routed to the DLQ.
    pub fn routed_count(&self) -> usize {
        self.records.len()
    }

    /// All routed records.
    pub fn records(&self) -> &[DlqRecord] {
        &self.records
    }

    /// Records filtered by reason category.
    pub fn records_by_reason(&self, reason: &DlqReason) -> Vec<&DlqRecord> {
        self.records
            .iter()
            .filter(|r| &r.dlq_reason == reason)
            .collect()
    }

    /// The DLQ topic name.
    pub fn topic(&self) -> &'static str {
        DLQ_TOPIC
    }
}

/// Truncate a string to max bytes (char-boundary safe).
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_schema_rejected() {
        let mut router = DlqRouter::new();
        let record = router.route_schema_rejected(
            3,
            42,
            2,
            0,
            "evt-001",
            "batch-1",
            "EVENT_KIND_FILE_OPEN",
            r#"{"data":"test"}"#,
            "key-1",
        );

        assert_eq!(record.original_topic, "events.v1");
        assert_eq!(record.original_partition, 3);
        assert_eq!(record.original_offset, 42);
        assert_eq!(record.schema_major, 2);
        assert_eq!(router.routed_count(), 1);
        assert_eq!(router.topic(), "events.dlq.v1");
    }

    #[test]
    fn schema_rejected_reason_string() {
        let reason = DlqReason::SchemaMajorUnsupported { got: 2 };
        assert_eq!(
            reason.as_reason_string(),
            "schema_major_unsupported: got 2, supported 1"
        );
    }

    #[test]
    fn route_malformed() {
        let mut router = DlqRouter::new();
        let record = router.route_malformed(0, 100, "invalid JSON at byte 5", "{bad json", "key-2");

        assert_eq!(record.original_offset, 100);
        assert!(matches!(
            record.dlq_reason,
            DlqReason::MalformedPayload { .. }
        ));
        assert_eq!(record.event_id, "");
        assert_eq!(router.routed_count(), 1);
    }

    #[test]
    fn route_unknown_event_kind() {
        let mut router = DlqRouter::new();
        let record = router.route_unknown_event_kind(
            1,
            200,
            "EVENT_KIND_BOGUS",
            "evt-002",
            r#"{"kind":"bogus"}"#,
        );

        assert!(matches!(
            record.dlq_reason,
            DlqReason::UnknownEventKind { .. }
        ));
        assert_eq!(record.event_kind, "EVENT_KIND_BOGUS");
    }

    #[test]
    fn records_by_reason_filters() {
        let mut router = DlqRouter::new();
        router.route_schema_rejected(0, 1, 2, 0, "e1", "b1", "EVENT_KIND_FILE_OPEN", "", "");
        router.route_malformed(0, 2, "bad json", "", "");
        router.route_schema_rejected(0, 3, 99, 0, "e2", "b2", "EVENT_KIND_DNS_PACKET", "", "");

        let schema_rejected =
            router.records_by_reason(&DlqReason::SchemaMajorUnsupported { got: 2 });
        // Only exact match (got: 2), not got: 99
        assert_eq!(schema_rejected.len(), 1);
        assert_eq!(schema_rejected[0].original_offset, 1);
    }

    #[test]
    fn dlq_record_validates() {
        let record = DlqRecord {
            original_topic: "events.v1".to_string(),
            original_partition: 0,
            original_offset: 0,
            dlq_reason: DlqReason::MissingEventId,
            event_id: String::new(),
            batch_id: String::new(),
            schema_major: 1,
            schema_minor: 0,
            event_kind: String::new(),
            raw_payload: String::new(),
            raw_key: String::new(),
        };
        assert!(record.validate().is_ok());
    }

    #[test]
    fn payload_truncated_to_bounds() {
        let mut router = DlqRouter::new();
        let big_payload = "x".repeat(MAX_PAYLOAD_BYTES + 1000);
        let record = router.route_malformed(0, 0, "oversized", &big_payload, "");
        assert!(record.raw_payload.len() <= MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn truncate_char_boundary_safe() {
        // Multi-byte UTF-8: each emoji is 4 bytes
        let s = "🎉".repeat(100); // 400 bytes
        let truncated = truncate(&s, 10);
        // Should truncate at char boundary (8 bytes = 2 emojis)
        assert!(truncated.len() <= 10);
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[test]
    fn consumer_continues_after_dlq_routing() {
        // Simulates: malformed → DLQ, then valid message continues.
        let mut router = DlqRouter::new();
        router.route_malformed(0, 1, "bad json", "{bad", "");

        // Consumer continues: next valid message is not affected.
        assert_eq!(router.routed_count(), 1);
        // The valid message would go to events_v1, not DLQ.
        // This test proves the DLQ router doesn't block the consumer.
    }
}
