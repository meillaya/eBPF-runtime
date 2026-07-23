// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Protobuf schema/version headers for Kafka records.
//!
//! Every record published to `events.v1` carries headers that
//! identify the protobuf schema version and event kind. This
//! enables downstream consumers to validate schema compatibility
//! BEFORE deserializing the payload, and to route
//! schema-incompatible batches to the DLQ.
//!
//! # Header keys
//!
//! - `schema_major`: u32 big-endian (from protocol crate)
//! - `schema_minor`: u32 big-endian (from protocol crate)
//! - `event_kind`: UTF-8 proto enum name (e.g.,
//!   "EVENT_KIND_PROCESS_EXEC_RESULT")
//! - `batch_id`: UTF-8 deterministic batch identifier
//! - `idempotency_key`: UTF-8 idempotency key (from protocol
//!   crate)
//!
//! # Schema validation
//!
//! The downstream consumer checks `schema_major` against its
//! own supported major. A mismatch routes the batch to
//! `events.dlq.v1` (the DLQ path). This is the "rejected schema
//! at downstream" requirement.

#![forbid(unsafe_code)]

use protocol::events::EventKind;

/// Header key for the schema major version.
pub const HEADER_SCHEMA_MAJOR: &str = "schema_major";

/// Header key for the schema minor version.
pub const HEADER_SCHEMA_MINOR: &str = "schema_minor";

/// Header key for the event kind (proto enum name).
pub const HEADER_EVENT_KIND: &str = "event_kind";

/// Header key for the batch ID.
pub const HEADER_BATCH_ID: &str = "batch_id";

/// Header key for the idempotency key.
pub const HEADER_IDEMPOTENCY_KEY: &str = "idempotency_key";

/// A single Kafka record header (key-value pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHeader {
    /// The header key.
    pub key: String,
    /// The header value (raw bytes).
    pub value: Vec<u8>,
}

impl RecordHeader {
    /// Create a header with a UTF-8 string value.
    pub fn from_str(key: &str, value: &str) -> Self {
        Self {
            key: key.to_string(),
            value: value.as_bytes().to_vec(),
        }
    }

    /// Create a header with a u32 big-endian value.
    pub fn from_u32(key: &str, value: u32) -> Self {
        Self {
            key: key.to_string(),
            value: value.to_be_bytes().to_vec(),
        }
    }

    /// The value as a UTF-8 string (if valid).
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }

    /// The value as a u32 (if exactly 4 bytes).
    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() == 4 {
            Some(u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ]))
        } else {
            None
        }
    }
}

/// Build the standard headers for an event batch record.
///
/// Includes schema version, event kind, batch ID, and
/// idempotency key.
pub fn build_batch_headers(
    schema_major: u32,
    schema_minor: u32,
    event_kind: &EventKind,
    batch_id: &str,
    idempotency_key: &str,
) -> Vec<RecordHeader> {
    vec![
        RecordHeader::from_u32(HEADER_SCHEMA_MAJOR, schema_major),
        RecordHeader::from_u32(HEADER_SCHEMA_MINOR, schema_minor),
        RecordHeader::from_str(HEADER_EVENT_KIND, event_kind.as_proto_name()),
        RecordHeader::from_str(HEADER_BATCH_ID, batch_id),
        RecordHeader::from_str(HEADER_IDEMPOTENCY_KEY, idempotency_key),
    ]
}

/// Validate schema headers against a supported major version.
///
/// Returns `Ok(())` if the schema major matches the supported
/// major. Returns `Err(reason)` if the schema is incompatible
/// (triggering DLQ routing).
pub fn validate_schema_headers(
    headers: &[RecordHeader],
    supported_major: u32,
) -> Result<(), String> {
    let major_header = headers
        .iter()
        .find(|h| h.key == HEADER_SCHEMA_MAJOR)
        .ok_or_else(|| "missing schema_major header".to_string())?;

    let major = major_header
        .as_u32()
        .ok_or_else(|| "schema_major header is not a valid u32".to_string())?;

    if major != supported_major {
        return Err(format!(
            "schema major mismatch: got {major}, supported {supported_major}"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_headers_includes_all_keys() {
        let headers = build_batch_headers(
            1,
            0,
            &EventKind::ProcessExecResult,
            "batch-001",
            "idem-key-42",
        );
        assert_eq!(headers.len(), 5);

        let keys: Vec<&str> = headers.iter().map(|h| h.key.as_str()).collect();
        assert!(keys.contains(&HEADER_SCHEMA_MAJOR));
        assert!(keys.contains(&HEADER_SCHEMA_MINOR));
        assert!(keys.contains(&HEADER_EVENT_KIND));
        assert!(keys.contains(&HEADER_BATCH_ID));
        assert!(keys.contains(&HEADER_IDEMPOTENCY_KEY));
    }

    #[test]
    fn schema_major_round_trips() {
        let h = RecordHeader::from_u32(HEADER_SCHEMA_MAJOR, 1);
        assert_eq!(h.as_u32(), Some(1));
    }

    #[test]
    fn schema_minor_round_trips() {
        let h = RecordHeader::from_u32(HEADER_SCHEMA_MINOR, 3);
        assert_eq!(h.as_u32(), Some(3));
    }

    #[test]
    fn event_kind_header_uses_proto_name() {
        let headers = build_batch_headers(1, 0, &EventKind::ProcessExecResult, "b-1", "k-1");
        let kind_header = headers.iter().find(|h| h.key == HEADER_EVENT_KIND).unwrap();
        assert_eq!(kind_header.as_str(), Some("EVENT_KIND_PROCESS_EXEC_RESULT"));
    }

    #[test]
    fn validate_schema_headers_matching_major() {
        let headers = build_batch_headers(1, 0, &EventKind::FileOpen, "b-1", "k-1");
        assert!(validate_schema_headers(&headers, 1).is_ok());
    }

    #[test]
    fn validate_schema_headers_mismatched_major() {
        let headers = build_batch_headers(2, 0, &EventKind::FileOpen, "b-1", "k-1");
        let err = validate_schema_headers(&headers, 1).unwrap_err();
        assert!(err.contains("schema major mismatch"));
        assert!(err.contains("got 2"));
    }

    #[test]
    fn validate_schema_headers_missing_major() {
        let headers = vec![RecordHeader::from_str("other", "value")];
        let err = validate_schema_headers(&headers, 1).unwrap_err();
        assert!(err.contains("missing schema_major"));
    }

    #[test]
    fn validate_schema_headers_invalid_u32() {
        let headers = vec![RecordHeader::from_str(HEADER_SCHEMA_MAJOR, "not-a-number")];
        let err = validate_schema_headers(&headers, 1).unwrap_err();
        assert!(err.contains("not a valid u32"));
    }

    #[test]
    fn header_str_round_trip() {
        let h = RecordHeader::from_str("key", "hello world");
        assert_eq!(h.as_str(), Some("hello world"));
    }

    #[test]
    fn header_u32_wrong_length() {
        let h = RecordHeader {
            key: "bad".into(),
            value: vec![1, 2, 3], // 3 bytes, not 4
        };
        assert_eq!(h.as_u32(), None);
    }
}
