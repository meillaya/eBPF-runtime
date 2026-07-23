// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ClickHouse column types mirroring the `events_v1` table schema.
//!
//! These types mirror the protocol crate's `Event`/`Batch` types
//! and the ClickHouse DDL in `deploy/clickhouse/0001_events_v1.sql`.

use serde::{Deserialize, Serialize};

use crate::error::{AnalyticsError, AnalyticsResult};
use crate::{MAX_PAYLOAD_BYTES, SUPPORTED_SCHEMA_MAJOR};

/// Known event kinds (mirrors `protocol::events::EventKind`).
/// Low-cardinality dimension in ClickHouse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    Unspecified,
    ProcessFork,
    ProcessExecResult,
    ProcessExit,
    FileOpen,
    FileCreate,
    FileUnlink,
    FileRename,
    NetworkConnect,
    NetworkAccept,
    NetworkState,
    DnsPacket,
    SyscallEnter,
    SyscallExit,
    LsmDenyOwn,
    Identity,
}

impl EventKind {
    /// Parse from the proto JSON enum name.
    pub fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "EVENT_KIND_UNSPECIFIED" => Some(Self::Unspecified),
            "EVENT_KIND_PROCESS_FORK" => Some(Self::ProcessFork),
            "EVENT_KIND_PROCESS_EXEC_RESULT" => Some(Self::ProcessExecResult),
            "EVENT_KIND_PROCESS_EXIT" => Some(Self::ProcessExit),
            "EVENT_KIND_FILE_OPEN" => Some(Self::FileOpen),
            "EVENT_KIND_FILE_CREATE" => Some(Self::FileCreate),
            "EVENT_KIND_FILE_UNLINK" => Some(Self::FileUnlink),
            "EVENT_KIND_FILE_RENAME" => Some(Self::FileRename),
            "EVENT_KIND_NETWORK_CONNECT" => Some(Self::NetworkConnect),
            "EVENT_KIND_NETWORK_ACCEPT" => Some(Self::NetworkAccept),
            "EVENT_KIND_NETWORK_STATE" => Some(Self::NetworkState),
            "EVENT_KIND_DNS_PACKET" => Some(Self::DnsPacket),
            "EVENT_KIND_SYSCALL_ENTER" => Some(Self::SyscallEnter),
            "EVENT_KIND_SYSCALL_EXIT" => Some(Self::SyscallExit),
            "EVENT_KIND_LSM_DENY_OWN" => Some(Self::LsmDenyOwn),
            "EVENT_KIND_IDENTITY" => Some(Self::Identity),
            _ => None,
        }
    }

    /// The proto JSON enum name.
    pub fn as_proto_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "EVENT_KIND_UNSPECIFIED",
            Self::ProcessFork => "EVENT_KIND_PROCESS_FORK",
            Self::ProcessExecResult => "EVENT_KIND_PROCESS_EXEC_RESULT",
            Self::ProcessExit => "EVENT_KIND_PROCESS_EXIT",
            Self::FileOpen => "EVENT_KIND_FILE_OPEN",
            Self::FileCreate => "EVENT_KIND_FILE_CREATE",
            Self::FileUnlink => "EVENT_KIND_FILE_UNLINK",
            Self::FileRename => "EVENT_KIND_FILE_RENAME",
            Self::NetworkConnect => "EVENT_KIND_NETWORK_CONNECT",
            Self::NetworkAccept => "EVENT_KIND_NETWORK_ACCEPT",
            Self::NetworkState => "EVENT_KIND_NETWORK_STATE",
            Self::DnsPacket => "EVENT_KIND_DNS_PACKET",
            Self::SyscallEnter => "EVENT_KIND_SYSCALL_ENTER",
            Self::SyscallExit => "EVENT_KIND_SYSCALL_EXIT",
            Self::LsmDenyOwn => "EVENT_KIND_LSM_DENY_OWN",
            Self::Identity => "EVENT_KIND_IDENTITY",
        }
    }

    /// Whether this is the unspecified sentinel (consumers reject it).
    pub fn is_unspecified(&self) -> bool {
        matches!(self, Self::Unspecified)
    }
}

/// A row in the `events_v1` ClickHouse table.
///
/// Mirrors the DDL in `deploy/clickhouse/0001_events_v1.sql` and
/// the protocol crate's `Event`/`Batch` types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventRow {
    // Kafka transport metadata
    pub kafka_topic: String,
    pub kafka_partition: i32,
    pub kafka_offset: u64,

    // Event identity
    pub event_id: String,
    pub batch_id: String,
    pub seq: u64,

    // Schema versioning
    pub schema_major: u16,
    pub schema_minor: u16,

    // Low-cardinality dimensions
    pub event_kind: EventKind,
    pub sensor: String,
    pub agent_generation: String,
    pub node_name: String,
    pub cluster: String,

    // Typed common columns
    pub ts_monotonic_ns: u64,
    pub boot_id_hex: String,
    pub pid_tgid: u64,
    pub cgroup_id: u64,
    pub uid: u32,
    pub gid: u32,

    // Bounded payload
    pub payload: String,

    // Version for ReplacingMergeTree deduplication
    pub version: u64,
}

impl EventRow {
    /// Validate the event row for ingestion.
    ///
    /// Checks:
    /// 1. event_id is non-empty
    /// 2. schema_major is supported
    /// 3. event_kind is not Unspecified
    /// 4. payload is within bounds
    pub fn validate(&self) -> AnalyticsResult<()> {
        if self.event_id.is_empty() {
            return Err(AnalyticsError::EmptyEventId);
        }
        if self.schema_major != SUPPORTED_SCHEMA_MAJOR {
            return Err(AnalyticsError::SchemaMajorUnsupported {
                got: self.schema_major,
                expected: SUPPORTED_SCHEMA_MAJOR,
            });
        }
        if self.event_kind.is_unspecified() {
            return Err(AnalyticsError::UnknownEventKind(
                "EVENT_KIND_UNSPECIFIED".to_string(),
            ));
        }
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(AnalyticsError::PayloadTooLarge {
                size: self.payload.len(),
                max: MAX_PAYLOAD_BYTES,
            });
        }
        Ok(())
    }

    /// Truncate the payload to the maximum allowed size.
    /// Returns true if truncation occurred.
    pub fn truncate_payload(&mut self) -> bool {
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            self.payload.truncate(MAX_PAYLOAD_BYTES);
            true
        } else {
            false
        }
    }
}

/// Build an EventRow from protocol-level fields.
/// Used by the materialized view transform logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRowBuilder {
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
    pub payload: String,
}

impl EventRowBuilder {
    /// Build a validated EventRow with Kafka metadata.
    pub fn build(
        self,
        kafka_topic: &str,
        kafka_partition: i32,
        kafka_offset: u64,
    ) -> AnalyticsResult<EventRow> {
        let event_kind = EventKind::from_proto_name(&self.event_kind)
            .ok_or_else(|| AnalyticsError::UnknownEventKind(self.event_kind.clone()))?;

        let mut row = EventRow {
            kafka_topic: kafka_topic.to_string(),
            kafka_partition,
            kafka_offset,
            event_id: self.event_id,
            batch_id: self.batch_id,
            seq: self.seq,
            schema_major: self.schema_major,
            schema_minor: self.schema_minor,
            event_kind,
            sensor: self.sensor,
            agent_generation: self.agent_generation,
            node_name: self.node_name,
            cluster: self.cluster,
            ts_monotonic_ns: self.ts_monotonic_ns,
            boot_id_hex: self.boot_id_hex,
            pid_tgid: self.pid_tgid,
            cgroup_id: self.cgroup_id,
            uid: self.uid,
            gid: self.gid,
            payload: self.payload,
            version: kafka_offset,
        };

        // Truncate payload to bounds (mirrors MV's substring()).
        row.truncate_payload();
        row.validate()?;
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_row() -> EventRow {
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
            payload: "{}".to_string(),
            version: 42,
        }
    }

    #[test]
    fn valid_row_passes_validation() {
        assert!(valid_row().validate().is_ok());
    }

    #[test]
    fn empty_event_id_rejected() {
        let mut row = valid_row();
        row.event_id = String::new();
        assert_eq!(row.validate().unwrap_err(), AnalyticsError::EmptyEventId);
    }

    #[test]
    fn unsupported_schema_major_rejected() {
        let mut row = valid_row();
        row.schema_major = 2;
        assert_eq!(
            row.validate().unwrap_err(),
            AnalyticsError::SchemaMajorUnsupported {
                got: 2,
                expected: 1
            }
        );
    }

    #[test]
    fn unspecified_event_kind_rejected() {
        let mut row = valid_row();
        row.event_kind = EventKind::Unspecified;
        assert!(matches!(
            row.validate().unwrap_err(),
            AnalyticsError::UnknownEventKind(_)
        ));
    }

    #[test]
    fn oversized_payload_rejected() {
        let mut row = valid_row();
        row.payload = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        assert_eq!(
            row.validate().unwrap_err(),
            AnalyticsError::PayloadTooLarge {
                size: MAX_PAYLOAD_BYTES + 1,
                max: MAX_PAYLOAD_BYTES,
            }
        );
    }

    #[test]
    fn truncate_payload_bounds_oversized() {
        let mut row = valid_row();
        row.payload = "x".repeat(MAX_PAYLOAD_BYTES + 100);
        assert!(row.truncate_payload());
        assert_eq!(row.payload.len(), MAX_PAYLOAD_BYTES);
        assert!(row.validate().is_ok());
    }

    #[test]
    fn truncate_payload_noop_when_within_bounds() {
        let mut row = valid_row();
        assert!(!row.truncate_payload());
    }

    #[test]
    fn event_kind_round_trips_proto_names() {
        let kinds = [
            EventKind::Unspecified,
            EventKind::ProcessFork,
            EventKind::ProcessExecResult,
            EventKind::ProcessExit,
            EventKind::FileOpen,
            EventKind::FileCreate,
            EventKind::FileUnlink,
            EventKind::FileRename,
            EventKind::NetworkConnect,
            EventKind::NetworkAccept,
            EventKind::NetworkState,
            EventKind::DnsPacket,
            EventKind::SyscallEnter,
            EventKind::SyscallExit,
            EventKind::LsmDenyOwn,
            EventKind::Identity,
        ];
        for k in &kinds {
            let name = k.as_proto_name();
            let parsed = EventKind::from_proto_name(name).unwrap();
            assert_eq!(*k, parsed);
        }
    }

    #[test]
    fn event_kind_rejects_unknown() {
        assert!(EventKind::from_proto_name("EVENT_KIND_BOGUS").is_none());
    }

    #[test]
    fn builder_produces_valid_row() {
        let builder = EventRowBuilder {
            event_id: "evt-002".to_string(),
            batch_id: "batch-2".to_string(),
            seq: 1,
            schema_major: 1,
            schema_minor: 0,
            event_kind: "EVENT_KIND_PROCESS_FORK".to_string(),
            sensor: "process".to_string(),
            agent_generation: "gen-1".to_string(),
            node_name: "node-1".to_string(),
            cluster: "prod".to_string(),
            ts_monotonic_ns: 2_000_000,
            boot_id_hex: "ab".repeat(16),
            pid_tgid: 9999,
            cgroup_id: 8888,
            uid: 0,
            gid: 0,
            payload: r#"{"comm":"bash"}"#.to_string(),
        };

        let row = builder.build("events.v1", 2, 100).unwrap();
        assert_eq!(row.event_kind, EventKind::ProcessFork);
        assert_eq!(row.kafka_partition, 2);
        assert_eq!(row.kafka_offset, 100);
        assert_eq!(row.version, 100);
    }

    #[test]
    fn builder_rejects_unknown_event_kind() {
        let builder = EventRowBuilder {
            event_id: "evt-003".to_string(),
            batch_id: "batch-3".to_string(),
            seq: 0,
            schema_major: 1,
            schema_minor: 0,
            event_kind: "EVENT_KIND_BOGUS".to_string(),
            sensor: String::new(),
            agent_generation: String::new(),
            node_name: String::new(),
            cluster: String::new(),
            ts_monotonic_ns: 0,
            boot_id_hex: String::new(),
            pid_tgid: 0,
            cgroup_id: 0,
            uid: 0,
            gid: 0,
            payload: String::new(),
        };

        assert!(matches!(
            builder.build("events.v1", 0, 0).unwrap_err(),
            AnalyticsError::UnknownEventKind(_)
        ));
    }

    #[test]
    fn builder_truncates_oversized_payload() {
        let builder = EventRowBuilder {
            event_id: "evt-004".to_string(),
            batch_id: "batch-4".to_string(),
            seq: 0,
            schema_major: 1,
            schema_minor: 0,
            event_kind: "EVENT_KIND_FILE_OPEN".to_string(),
            sensor: String::new(),
            agent_generation: String::new(),
            node_name: String::new(),
            cluster: String::new(),
            ts_monotonic_ns: 0,
            boot_id_hex: String::new(),
            pid_tgid: 0,
            cgroup_id: 0,
            uid: 0,
            gid: 0,
            payload: "x".repeat(MAX_PAYLOAD_BYTES + 500),
        };

        let row = builder.build("events.v1", 0, 0).unwrap();
        assert_eq!(row.payload.len(), MAX_PAYLOAD_BYTES);
    }
}
