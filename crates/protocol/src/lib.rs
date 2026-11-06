// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Generated gRPC transport contracts.
//!
//! The event payload itself is the versioned JSON `event_model::Batch` in
//! `BatchRequest.batch_json`. The protobuf envelope carries routing,
//! idempotency, and control messages only.

#![forbid(unsafe_code)]

/// Kernel fleet transport v1.
pub mod v1 {
    tonic::include_proto!("kernel.v1.transport");
}

/// Message size limits shared by client and server.
pub const MAX_BATCH_JSON_BYTES: usize = 1024 * 1024;
/// Maximum gRPC message size.
pub const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Supported protocol major version.
pub const PROTOCOL_MAJOR: u32 = 1;
