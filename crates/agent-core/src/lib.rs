// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Panic-free bounded ring ingestion and normalized event pipeline.

#![forbid(unsafe_code)]

mod channel;
mod model;
mod normalize;
mod pipeline;
mod synthetic;

pub use channel::{BoundedChannel, EventPriority, PriorityBoundedChannel, SendError};
pub use model::{
    BootId, CgroupId, ControlEvent, EventId, Identity, KillSwitchReason, KillSwitchState, Kind,
    MonotonicNs, NamespaceBundle, NormalizedEvent, PerSensorPayload, PidTgid, RawEvent, Sequence,
    TaskStartNs, WallClock,
};
pub use normalize::{from_raw, normalize_bytes};
pub use pipeline::{AgentCore, AgentCoreError, AgentCoreOpts};
pub use synthetic::synthetic_record;
