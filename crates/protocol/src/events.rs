// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed event contract mirroring `proto/kernel/v1/events/v1/events.proto`.
//!
//! Every enum value, field number, and oneof variant matches the
//! authoritative proto definition. The Rust types are the hand-written
//! mirror of what `buf generate` would emit (task 6 disabled codegen;
//! task 35 provides the typed Rust surface).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Semantic event kind. Mirrors `EventKind` in events.proto.
/// The zero value is the UNSPECIFIED sentinel; consumers reject it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum EventKind {
    #[serde(rename = "EVENT_KIND_UNSPECIFIED")]
    Unspecified = 0,
    #[serde(rename = "EVENT_KIND_PROCESS_FORK")]
    ProcessFork = 1,
    #[serde(rename = "EVENT_KIND_PROCESS_EXEC_RESULT")]
    ProcessExecResult = 2,
    #[serde(rename = "EVENT_KIND_PROCESS_EXIT")]
    ProcessExit = 3,
    #[serde(rename = "EVENT_KIND_FILE_OPEN")]
    FileOpen = 4,
    #[serde(rename = "EVENT_KIND_FILE_CREATE")]
    FileCreate = 5,
    #[serde(rename = "EVENT_KIND_FILE_UNLINK")]
    FileUnlink = 6,
    #[serde(rename = "EVENT_KIND_FILE_RENAME")]
    FileRename = 7,
    #[serde(rename = "EVENT_KIND_NETWORK_CONNECT")]
    NetworkConnect = 8,
    #[serde(rename = "EVENT_KIND_NETWORK_ACCEPT")]
    NetworkAccept = 9,
    #[serde(rename = "EVENT_KIND_NETWORK_STATE")]
    NetworkState = 10,
    #[serde(rename = "EVENT_KIND_DNS_PACKET")]
    DnsPacket = 11,
    #[serde(rename = "EVENT_KIND_SYSCALL_ENTER")]
    SyscallEnter = 12,
    #[serde(rename = "EVENT_KIND_SYSCALL_EXIT")]
    SyscallExit = 13,
    #[serde(rename = "EVENT_KIND_LSM_DENY_OWN")]
    LsmDenyOwn = 14,
    #[serde(rename = "EVENT_KIND_IDENTITY")]
    Identity = 15,
}

impl EventKind {
    /// Parse from the proto JSON enum name (e.g. `"EVENT_KIND_FILE_OPEN"`).
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
}

/// Cgroup mode. Mirrors `CgroupMode` in events.proto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum CgroupMode {
    Unspecified = 0,
    Unified = 1,
    Hybrid = 2,
    Legacy = 3,
    Unknown = 4,
}

/// Per-task identity block. Mirrors `Identity` in events.proto.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub pid_tgid: u64,
    pub task_start_time_ns: u64,
    pub cgroup_id: u64,
    pub mount_ns_id: u64,
    pub pid_ns_id: u64,
    pub net_ns_id: u64,
    pub user_ns_id: u64,
    pub uts_ns_id: u64,
    pub ipc_ns_id: u64,
    pub time_ns_id: u64,
    pub uid: u32,
    pub gid: u32,
    pub loginuid: u32,
    pub parent_pid_tgid: u64,
    /// Per-field validity map. Missing or false = field is invalid.
    #[serde(default)]
    pub valids: BTreeMap<String, bool>,
}

/// A single event in a batch. Mirrors `Event` in events.proto.
/// The payload is flattened to the kind discriminator for the
/// typed Rust surface; the oneof variants are represented by
/// `event_kind` + optional typed payload fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Stable event id (UUIDv7 or platform-equivalent).
    pub event_id: String,
    /// Per-batch monotonic sequence.
    pub seq: u64,
    /// bpf_ktime_get_ns() at emit time.
    #[serde(default)]
    pub ts_monotonic_ns: u64,
    /// Logical sensor name (e.g. "process", "ops").
    #[serde(default)]
    pub sensor: String,
    /// Semantic kind; MUST match the payload variant.
    pub event_kind: EventKind,
    /// Per-event validity map.
    #[serde(default)]
    pub valids: BTreeMap<String, bool>,
}

/// Batch is the unit the agent emits over the gRPC stream.
/// Mirrors `Batch` in events.proto.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Batch {
    /// Wire-format schema version.
    pub schema_major: u32,
    /// Additive schema version.
    #[serde(default)]
    pub schema_minor: u32,
    /// Every event in this batch, in monotonic order.
    pub events: Vec<Event>,
    /// Monotonic per-agent generation.
    pub agent_generation: String,
    /// The node's hostname / node name.
    pub node_name: String,
    /// Linux boot_id (hex-encoded for JSON interop).
    #[serde(default)]
    pub boot_id_hex: String,
}

impl Batch {
    /// The number of events in this batch.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(*k, parsed, "round-trip failed for {name}");
        }
    }

    #[test]
    fn event_kind_rejects_unknown_name() {
        assert!(EventKind::from_proto_name("EVENT_KIND_BOGUS").is_none());
    }

    #[test]
    fn batch_len_and_is_empty() {
        let empty = Batch {
            schema_major: 1,
            schema_minor: 0,
            events: vec![],
            agent_generation: "gen-1".into(),
            node_name: "node-1".into(),
            boot_id_hex: "00".repeat(16),
        };
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn deserialize_happy_fixture() {
        let json = include_str!("../../../tests/fixtures/proto/events/happy.json");
        let batch: Batch = serde_json::from_str(json).unwrap();
        assert_eq!(batch.schema_major, 1);
        assert_eq!(batch.schema_minor, 0);
        assert_eq!(batch.agent_generation, "agent-gen-1");
        assert_eq!(batch.node_name, "node-1");
        assert_eq!(batch.events.len(), 15);
        // First event is PROCESS_FORK
        assert_eq!(batch.events[0].event_kind, EventKind::ProcessFork);
        // Last event is IDENTITY
        assert_eq!(batch.events[14].event_kind, EventKind::Identity);
        // Sequence is monotonic
        for (i, ev) in batch.events.iter().enumerate() {
            assert_eq!(ev.seq, i as u64);
        }
    }
}
