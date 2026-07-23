// SPDX-License-Identifier: Apache-2.0 OR MIT
//! kernel-v1 typed fleet protocol contracts.
//!
//! This crate provides the hand-written Rust mirror of the
//! protobuf contracts defined in `proto/kernel/v1/`. Task 6
//! disabled buf codegen; task 35 provides the typed Rust surface
//! with state machines, deadlines, idempotency keys, typed
//! status/error codes, and message bounds.
//!
//! # Modules
//!
//! - [`events`]: Event, Batch, EventKind (mirrors events.proto)
//! - [`control`]: PolicyStatus, Register, Stage/Ready/Commit,
//!   Health, Compatibility (mirrors control.proto)
//! - [`state_machine`]: Policy activation state machine
//!   (STAGE→READY→COMMIT→APPLIED/REJECTED)
//! - [`batch_ack`]: Event batch ACK state machine
//!   (Pending→Accepted/Rejected)
//! - [`identity`]: Agent registration, health, compatibility
//! - [`deadline`]: Deadline propagation
//! - [`idempotency`]: Idempotency keys and duplicate detection
//! - [`bounds`]: Message size bounds and compression
//! - [`error`]: Typed status/error codes
//!
//! # Generated-code freshness
//!
//! [`PROTO_SCHEMA_DIGEST`] is the SHA-256 of the concatenated
//! proto source files. The test `proto_freshness_check` verifies
//! the digest matches the on-disk protos, ensuring the Rust
//! types stay in sync with the authoritative contract.

#![forbid(unsafe_code)]

pub mod batch_ack;
pub mod bounds;
pub mod control;
pub mod deadline;
pub mod error;
pub mod events;
pub mod idempotency;
pub mod identity;
pub mod state_machine;

/// SHA-256 digest of the concatenated proto source files
/// (`events.proto` + `control.proto`). Used by the freshness
/// check to detect drift between the Rust types and the
/// authoritative proto contract.
pub const PROTO_SCHEMA_DIGEST: &str =
    "42da5dcee9cc8a8de2fdf472dd2e325d5e6fd0759e0fab864c6a6dc5985349b5";

/// The schema major version this crate implements.
pub const SCHEMA_MAJOR: u32 = 1;

/// The schema minor version this crate implements.
pub const SCHEMA_MINOR: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Verify the Rust protocol types are in sync with the
    /// authoritative proto files. If this test fails, the proto
    /// files changed and the Rust types must be updated (and
    /// `PROTO_SCHEMA_DIGEST` recomputed).
    #[test]
    fn proto_freshness_check() {
        let events_proto = include_str!("../../../proto/kernel/v1/events/v1/events.proto");
        let control_proto = include_str!("../../../proto/kernel/v1/control/v1/control.proto");

        let mut hasher = Sha256::new();
        hasher.update(events_proto.as_bytes());
        hasher.update(control_proto.as_bytes());
        let computed = format!("{:x}", hasher.finalize());

        assert_eq!(
            computed, PROTO_SCHEMA_DIGEST,
            "proto files changed; update Rust types and PROTO_SCHEMA_DIGEST"
        );
    }

    #[test]
    fn schema_version_constants() {
        assert_eq!(SCHEMA_MAJOR, 1);
        assert_eq!(SCHEMA_MINOR, 0);
    }
}
