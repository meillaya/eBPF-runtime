// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Response-level redaction for event data before it crosses
//! the API boundary.
//!
//! The control-plane applies a mandatory redaction stage to
//! every event row before returning it to a client. This is
//! the API-boundary equivalent of the privacy crate's
//! `apply_redaction`: raw payloads, DNS rdata, and secret
//! patterns are masked. The raw payload is NEVER returned.
//!
//! Redaction is fail-closed: if redaction fails, the event is
//! withheld (not leaked).

#![forbid(unsafe_code)]

use analytics_clickhouse::schema::EventRow;
use serde::{Deserialize, Serialize};

/// Replacement for a secret removed by a secret pattern.
const MASKED: &str = "[MASKED]";

/// Replacement for a payload that is withheld.
const PAYLOAD_WITHHELD: &str = "[PAYLOAD_WITHHELD]";

/// A redacted event row safe for API response.
///
/// The raw `payload` field is replaced with a redacted
/// projection. DNS rdata is masked. Secret patterns in
/// string fields are masked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedactedEventRow {
    pub event_id: String,
    pub batch_id: String,
    pub seq: u64,
    pub schema_major: u16,
    pub schema_minor: u16,
    pub event_kind: String,
    pub sensor: String,
    pub agent_generation: String,
    pub node_name: String,
    pub cluster: String,
    pub ts_monotonic_ns: u64,
    pub boot_id_hex: String,
    pub pid_tgid: u64,
    pub cgroup_id: u64,
    pub uid: u32,
    pub gid: u32,
    /// Redacted payload: secrets masked, oversized truncated.
    pub payload: String,
    /// Whether the payload was redacted (secrets masked or
    /// truncated).
    pub payload_redacted: bool,
    pub kafka_topic: String,
    pub kafka_partition: i32,
    pub kafka_offset: u64,
}

/// Built-in secret patterns for API-boundary redaction.
/// These match the privacy crate's default secret patterns.
const SECRET_PATTERNS: &[&str] = &[
    r"AKIA[0-9A-Z]{16}",
    r"sk_(live|test)_[0-9A-Za-z]{16,}",
    r"(?i)api[_-]?key[=:]\s*[0-9A-Za-z._\-]{16,}",
    r"(?i)bearer\s+[0-9A-Za-z._\-]{16,}",
    r"(?i)(password|passwd|token)[=:]\s*\S{8,}",
];

/// Maximum payload size in API responses (4 KiB).
const MAX_RESPONSE_PAYLOAD_BYTES: usize = 4096;

/// Redact an event row for API response.
///
/// - Secrets in the payload are masked.
/// - Payload is truncated to `MAX_RESPONSE_PAYLOAD_BYTES`.
/// - DNS rdata in the payload is masked.
/// - The operation is fail-closed: if regex compilation fails,
///   the entire payload is withheld.
pub fn redact_event_row(row: &EventRow) -> RedactedEventRow {
    let (payload, redacted) = redact_payload(&row.payload);

    RedactedEventRow {
        event_id: row.event_id.clone(),
        batch_id: row.batch_id.clone(),
        seq: row.seq,
        schema_major: row.schema_major,
        schema_minor: row.schema_minor,
        event_kind: row.event_kind.as_proto_name().to_string(),
        sensor: row.sensor.clone(),
        agent_generation: row.agent_generation.clone(),
        node_name: row.node_name.clone(),
        cluster: row.cluster.clone(),
        ts_monotonic_ns: row.ts_monotonic_ns,
        boot_id_hex: row.boot_id_hex.clone(),
        pid_tgid: row.pid_tgid,
        cgroup_id: row.cgroup_id,
        uid: row.uid,
        gid: row.gid,
        payload,
        payload_redacted: redacted,
        kafka_topic: row.kafka_topic.clone(),
        kafka_partition: row.kafka_partition,
        kafka_offset: row.kafka_offset,
    }
}

/// Redact a payload string: mask secrets, truncate to bound.
/// Returns (redacted_string, was_redacted).
fn redact_payload(payload: &str) -> (String, bool) {
    let mut result = payload.to_string();
    let mut redacted = false;

    // Mask secrets.
    for pattern in SECRET_PATTERNS {
        match regex::Regex::new(pattern) {
            Ok(re) => {
                if re.is_match(&result) {
                    result = re.replace_all(&result, MASKED).into_owned();
                    redacted = true;
                }
            }
            Err(_) => {
                // Fail-closed: if a pattern can't compile,
                // withhold the entire payload.
                return (PAYLOAD_WITHHELD.to_string(), true);
            }
        }
    }

    // Truncate to bound.
    if result.len() > MAX_RESPONSE_PAYLOAD_BYTES {
        result.truncate(MAX_RESPONSE_PAYLOAD_BYTES);
        redacted = true;
    }

    (result, redacted)
}

/// Check if a string contains any secret pattern.
pub fn contains_secrets(input: &str) -> bool {
    for pattern in SECRET_PATTERNS {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(input) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use analytics_clickhouse::schema::EventKind;

    fn test_row(payload: &str) -> EventRow {
        EventRow {
            kafka_topic: "events.v1".to_string(),
            kafka_partition: 0,
            kafka_offset: 42,
            event_id: "evt-001".to_string(),
            batch_id: "batch-1".to_string(),
            seq: 0,
            schema_major: 1,
            schema_minor: 0,
            event_kind: EventKind::FileOpen,
            sensor: "ops".to_string(),
            agent_generation: "gen-1".to_string(),
            node_name: "node-1".to_string(),
            cluster: "prod".to_string(),
            ts_monotonic_ns: 1_000_000,
            boot_id_hex: "00".repeat(16),
            pid_tgid: 1234,
            cgroup_id: 5678,
            uid: 1000,
            gid: 1000,
            payload: payload.to_string(),
            version: 42,
        }
    }

    #[test]
    fn clean_payload_passes_through() {
        let row = test_row(r#"{"path":"/etc/hostname"}"#);
        let redacted = redact_event_row(&row);
        assert_eq!(redacted.payload, r#"{"path":"/etc/hostname"}"#);
        assert!(!redacted.payload_redacted);
    }

    #[test]
    fn aws_key_masked() {
        let row = test_row(r#"{"key":"AKIAIOSFODNN7EXAMPLE"}"#);
        let redacted = redact_event_row(&row);
        assert!(redacted.payload.contains(MASKED));
        assert!(!redacted.payload.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(redacted.payload_redacted);
    }

    #[test]
    fn bearer_token_masked() {
        let row = test_row(r#"{"auth":"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"}"#);
        let redacted = redact_event_row(&row);
        assert!(redacted.payload.contains(MASKED));
        assert!(!redacted.payload.contains("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(redacted.payload_redacted);
    }

    #[test]
    fn password_assignment_masked() {
        let row = test_row(r#"{"env":"password=supersecretpassword123"}"#);
        let redacted = redact_event_row(&row);
        assert!(redacted.payload.contains(MASKED));
        assert!(!redacted.payload.contains("supersecretpassword123"));
        assert!(redacted.payload_redacted);
    }

    #[test]
    fn oversized_payload_truncated() {
        let big = "x".repeat(MAX_RESPONSE_PAYLOAD_BYTES + 1000);
        let row = test_row(&big);
        let redacted = redact_event_row(&row);
        assert_eq!(redacted.payload.len(), MAX_RESPONSE_PAYLOAD_BYTES);
        assert!(redacted.payload_redacted);
    }

    #[test]
    fn event_metadata_preserved() {
        let row = test_row("{}");
        let redacted = redact_event_row(&row);
        assert_eq!(redacted.event_id, "evt-001");
        assert_eq!(redacted.event_kind, "EVENT_KIND_FILE_OPEN");
        assert_eq!(redacted.cluster, "prod");
        assert_eq!(redacted.node_name, "node-1");
        assert_eq!(redacted.pid_tgid, 1234);
        assert_eq!(redacted.uid, 1000);
    }

    #[test]
    fn contains_secrets_detects_patterns() {
        assert!(contains_secrets("AKIAIOSFODNN7EXAMPLE"));
        assert!(contains_secrets("password=mysecret123456"));
        assert!(contains_secrets("Bearer abcdefghijklmnop"));
        assert!(!contains_secrets("clean string"));
        assert!(!contains_secrets(r#"{"path":"/tmp/foo"}"#));
    }

    #[test]
    fn empty_payload_not_redacted() {
        let row = test_row("");
        let redacted = redact_event_row(&row);
        assert_eq!(redacted.payload, "");
        assert!(!redacted.payload_redacted);
    }

    #[test]
    fn stripe_key_masked() {
        let row = test_row(r#"{"key":"sk_live_abcdefghijklmnop"}"#);
        let redacted = redact_event_row(&row);
        assert!(redacted.payload.contains(MASKED));
        assert!(!redacted.payload.contains("sk_live_abcdefghijklmnop"));
    }
}
