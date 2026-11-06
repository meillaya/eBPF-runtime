// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Re-export the shared event model.
//!
//! The decoder and its types live in `event-model` so the daemon, storage,
//! control plane, and dashboard-facing API all share one definition.

pub use event_model::{
    decode, Alert, Batch, Clock, DecodeFailure, DecodedEvent, DnsInfo, Event, IdentityInfo,
    LsmInfo, NetworkInfo, RedactionFlags, SyscallInfo,
};
