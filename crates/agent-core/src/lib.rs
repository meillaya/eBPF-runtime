// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Panic-free bounded ring ingestion and normalized event pipeline.

#![forbid(unsafe_code)]

mod channel;
mod dns_decoder;
mod dns_name;
mod model;
mod normalize;
mod pipeline;
mod process_graph;
mod socket_entry;
mod socket_opts;
mod socket_table;
mod synthetic;

pub use channel::{BoundedChannel, EventPriority, PriorityBoundedChannel, SendError};
pub use dns_decoder::{
    parse_dns_message, truncation_reason_from_error, DnsDecodeError, DnsMessage, DnsQuestion,
    DnsResourceRecord, TruncationReason, DNS_HEADER_SIZE, DNS_NAME_MAX, DNS_RDATA_MAX,
    DNS_RECORD_MAX, MAX_NAME_ITERATIONS,
};
pub use model::{
    BootId, CgroupId, ControlEvent, EventId, Identity, KillSwitchReason, KillSwitchState, Kind,
    MonotonicNs, NamespaceBundle, NormalizedEvent, PerSensorPayload, PidTgid, RawEvent, Sequence,
    TaskStartNs, WallClock,
};
pub use normalize::{from_raw, normalize_bytes};
pub use pipeline::{AgentCore, AgentCoreError, AgentCoreOpts};
pub use process_graph::{
    AncestryStatus, NodeState, ProcessGraph, ProcessGraphOpts, ProcessIdentity, ProcessNode,
};
pub use socket_entry::{
    SocketEntry, SocketFamily, SocketIdentity, SocketState, NAMESPACE_KIND_COUNT, NS_CGROUP,
    NS_IPC, NS_MNT, NS_NET, NS_PID, NS_TIME, NS_USER, NS_UTS,
};
pub use socket_opts::{CorrelationSet, SocketTableOpts, DEFAULT_CAPACITY, DEFAULT_TTL_SECONDS};
pub use socket_table::SocketTable;
pub use synthetic::synthetic_record;
