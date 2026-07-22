// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Dead-letter queue routing for schema-rejected batches.
//!
//! When a downstream consumer rejects a batch due to schema
//! incompatibility (e.g., schema major mismatch), the batch is
//! routed to the DLQ topic (`events.dlq.v1`) instead of being
//! silently dropped. This ensures:
//!
//! 1. No hidden loss: every rejected batch is accounted for.
//! 2. Debuggability: operators can inspect the DLQ to diagnose
//!    schema drift.
//! 3. At-least-once semantics: the batch is preserved for
//!    potential reprocessing after schema migration.
//!
//! # DLQ record format
//!
//! The DLQ record carries the original payload plus additional
//! headers explaining the rejection reason. The original headers
//! are preserved for forensic analysis.

#![forbid(unsafe_code)]

use crate::headers::RecordHeader;

/// Header key for the DLQ rejection reason.
pub const HEADER_DLQ_REASON: &str = "dlq_reason";

/// Header key for the original topic.
pub const HEADER_DLQ_ORIGINAL_TOPIC: &str = "dlq_original_topic";

/// Header key for the original partition.
pub const HEADER_DLQ_ORIGINAL_PARTITION: &str = "dlq_original_partition";

/// A record routed to the dead-letter queue.
#[derive(Debug, Clone)]
pub struct DlqRecord {
    /// The DLQ topic (events.dlq.v1).
    pub topic: String,
    /// The original partition key (preserved for ordering).
    pub key: Vec<u8>,
    /// The original payload.
    pub payload: Vec<u8>,
    /// Original headers plus DLQ metadata headers.
    pub headers: Vec<RecordHeader>,
    /// The batch ID.
    pub batch_id: String,
}

/// Routes rejected batches to the DLQ topic.
#[derive(Debug)]
pub struct DlqRouter {
    /// The DLQ topic name.
    dlq_topic: String,
    /// Records routed to the DLQ (for test inspection).
    routed: Vec<DlqRecord>,
}

impl DlqRouter {
    /// Create a new DLQ router for the given topic.
    pub fn new(dlq_topic: impl Into<String>) -> Self {
        Self {
            dlq_topic: dlq_topic.into(),
            routed: Vec::new(),
        }
    }

    /// Route a rejected batch to the DLQ.
    ///
    /// Preserves the original headers and adds DLQ metadata
    /// headers (rejection reason, original topic/partition).
    pub fn route(
        &mut self,
        batch_id: &str,
        original_topic: &str,
        original_partition: i32,
        key: Vec<u8>,
        payload: Vec<u8>,
        original_headers: Vec<RecordHeader>,
        reason: &str,
    ) -> &DlqRecord {
        let mut headers = original_headers;
        headers.push(RecordHeader::from_str(HEADER_DLQ_REASON, reason));
        headers.push(RecordHeader::from_str(
            HEADER_DLQ_ORIGINAL_TOPIC,
            original_topic,
        ));
        headers.push(RecordHeader::from_str(
            HEADER_DLQ_ORIGINAL_PARTITION,
            &original_partition.to_string(),
        ));

        let record = DlqRecord {
            topic: self.dlq_topic.clone(),
            key,
            payload,
            headers,
            batch_id: batch_id.to_string(),
        };

        self.routed.push(record);
        self.routed.last().unwrap()
    }

    /// The number of records routed to the DLQ.
    pub fn routed_count(&self) -> usize {
        self.routed.len()
    }

    /// All routed records (for test inspection).
    pub fn routed_records(&self) -> &[DlqRecord] {
        &self.routed
    }

    /// The DLQ topic name.
    pub fn topic(&self) -> &str {
        &self.dlq_topic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::build_batch_headers;
    use protocol::events::EventKind;

    #[test]
    fn route_to_dlq() {
        let mut router = DlqRouter::new("events.dlq.v1");
        let headers = build_batch_headers(2, 0, &EventKind::FileOpen, "b-1", "k-1");

        let record = router.route(
            "b-1",
            "events.v1",
            3,
            b"key".to_vec(),
            b"payload".to_vec(),
            headers,
            "schema major mismatch: got 2, supported 1",
        );

        assert_eq!(record.topic, "events.dlq.v1");
        assert_eq!(record.batch_id, "b-1");
        assert_eq!(router.routed_count(), 1);
    }

    #[test]
    fn dlq_preserves_original_headers() {
        let mut router = DlqRouter::new("events.dlq.v1");
        let original_headers =
            build_batch_headers(2, 0, &EventKind::ProcessExecResult, "b-2", "k-2");
        let original_count = original_headers.len();

        let record = router.route(
            "b-2",
            "events.v1",
            0,
            b"key".to_vec(),
            b"payload".to_vec(),
            original_headers,
            "schema mismatch",
        );

        // Original headers + 3 DLQ metadata headers.
        assert_eq!(record.headers.len(), original_count + 3);
    }

    #[test]
    fn dlq_includes_reason_header() {
        let mut router = DlqRouter::new("events.dlq.v1");
        let record = router.route(
            "b-3",
            "events.v1",
            1,
            b"key".to_vec(),
            b"payload".to_vec(),
            vec![],
            "malformed schema headers",
        );

        let reason_header = record
            .headers
            .iter()
            .find(|h| h.key == HEADER_DLQ_REASON)
            .unwrap();
        assert_eq!(reason_header.as_str(), Some("malformed schema headers"));
    }

    #[test]
    fn dlq_includes_original_topic_and_partition() {
        let mut router = DlqRouter::new("events.dlq.v1");
        let record = router.route(
            "b-4",
            "events.v1",
            7,
            b"key".to_vec(),
            b"payload".to_vec(),
            vec![],
            "test",
        );

        let topic_header = record
            .headers
            .iter()
            .find(|h| h.key == HEADER_DLQ_ORIGINAL_TOPIC)
            .unwrap();
        assert_eq!(topic_header.as_str(), Some("events.v1"));

        let partition_header = record
            .headers
            .iter()
            .find(|h| h.key == HEADER_DLQ_ORIGINAL_PARTITION)
            .unwrap();
        assert_eq!(partition_header.as_str(), Some("7"));
    }

    #[test]
    fn multiple_dlq_routes_tracked() {
        let mut router = DlqRouter::new("events.dlq.v1");
        for i in 0..5 {
            router.route(
                &format!("b-{i}"),
                "events.v1",
                0,
                b"key".to_vec(),
                b"payload".to_vec(),
                vec![],
                "test",
            );
        }
        assert_eq!(router.routed_count(), 5);
        assert_eq!(router.routed_records().len(), 5);
    }
}
