// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Decoded record and event identity types.

use agent_core::{
    BootId, CgroupId, EventId, EventPriority, Identity, Kind, MonotonicNs, NamespaceBundle,
    NormalizedEvent, PidTgid, Sequence, TaskStartNs, WallClock,
};
use serde::{Deserialize, Serialize};

/// DNS question/answer fields as the privacy layer sees them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedDns {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub an_count: u16,
    pub rdata: Vec<String>,
}

/// The bounded decoded view of an event's redactable fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedRecord {
    /// exec argv tokens.
    pub argv: Vec<String>,
    /// exec environment tokens (only exported when `env_enabled`).
    pub env: Vec<String>,
    /// file / exec path.
    pub path: String,
    /// generic argument tokens (e.g. syscall / cli arguments).
    pub arguments: Vec<String>,
    /// DNS question/answer fields, when the event is a DNS packet.
    pub dns: Option<DecodedDns>,
    /// generic log / line text subject to secret masking.
    pub message: String,
}

/// Decode the bounded [`DecodedRecord`] view from a normalized event's raw
/// payload. Fail-closed: any payload that is not a valid encoded record yields
/// an empty record (no redactable data exported).
pub fn decode_record(event: &NormalizedEvent) -> DecodedRecord {
    serde_json::from_slice(&event.raw.payload).unwrap_or_default()
}

/// The non-secret identity/metadata of an event, projected from a
/// [`NormalizedEvent`]. Carried verbatim onto the [`super::RedactedEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIdentity {
    pub kind: Kind,
    pub event_id: EventId,
    pub sequence: Sequence,
    pub monotonic_ns: MonotonicNs,
    pub wall_clock: WallClock,
    pub pid_tgid: PidTgid,
    pub task_start_ns: TaskStartNs,
    pub cgroup_id: CgroupId,
    pub boot_id: BootId,
    pub namespaces: NamespaceBundle,
    pub identity: Identity,
    pub priority: EventPriority,
    /// Enrichment attribution scope label.
    pub attribution_scope: Option<String>,
}

impl EventIdentity {
    /// Project the identity/metadata from a normalized event.
    pub fn from_event(event: &NormalizedEvent) -> Self {
        Self {
            kind: event.kind,
            event_id: event.event_id,
            sequence: event.sequence,
            monotonic_ns: event.monotonic_ns,
            wall_clock: event.wall_clock.clone(),
            pid_tgid: event.pid_tgid,
            task_start_ns: event.task_start_ns,
            cgroup_id: event.cgroup_id,
            boot_id: event.boot_id,
            namespaces: event.namespaces.clone(),
            identity: event.identity.clone(),
            priority: event.priority,
            attribution_scope: None,
        }
    }
}
