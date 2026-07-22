// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent/control-plane gRPC transport with separate
//! deadline-bound control and event streams.
//!
//! This crate provides:
//!
//! - **Separate channels**: independent control (kill-switch,
//!   policy) and event (batch telemetry) channels. Event
//!   backpressure NEVER blocks control delivery.
//! - **SPIFFE peer authorization**: fail-closed mTLS peer
//!   validation via `identity-spiffe`.
//! - **Sequence reconciliation**: boot/agent generation
//!   tracking, gap detection, replay on reconnect.
//! - **Bounded independent queues**: non-blocking backpressure
//!   with `try_send`; no cross-queue blocking.
//! - **Deadlock-free read/write loops**: separate tokio tasks
//!   for reading and writing; no lock held while awaiting.
//! - **Deadlines/keepalive/max-age/backoff**: protocol deadline
//!   propagation, gRPC keepalive, SVID max-age rotation,
//!   exponential backoff with jitter.
//! - **Compression/batch limits**: protocol `MessageBounds`
//!   enforcement.
//! - **Deterministic batch ACK**: ACK only after durable Kafka
//!   acceptance — never receipt-only.
//! - **SQLite outbox deletion**: outbox rows deleted after
//!   matching ACK (via `OutboxDeleter` trait).
//!
//! # BLOCKER NOTE
//!
//! This host does not have a running gRPC server or Kafka
//! broker. The transport logic is fully implemented and tested
//! with in-memory mocks and fixtures. Live gRPC/Kafka
//! integration re-opens on the declared self-hosted runner.
//!
//! # Integration
//!
//! - `protocol` (task 35): deadlines, message bounds, batch ACK
//!   state machine, idempotency keys.
//! - `identity-spiffe` (task 36): SPIFFE peer authorization,
//!   mTLS credentials, exponential backoff.
//! - `storage-local` (task 24): SQLite outbox (wired via
//!   `OutboxDeleter` trait at startup).

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod ack;
pub mod channel;
pub mod config;
pub mod error;
pub mod peer;
pub mod queue;
pub mod reconnect;
pub mod sequence;
pub mod transport;

// Re-export primary types for convenience.
pub use ack::{AckState, AckTracker, KafkaAcceptance, MockOutboxDeleter, OutboxDeleter};
pub use channel::{AckMessage, ControlChannel, ControlMessage, EventBatchMessage, EventChannel};
pub use config::TransportConfig;
pub use error::{TransportError, TransportResult};
pub use peer::PeerAuthorizer;
pub use queue::{BoundedQueue, QueuePressure};
pub use reconnect::ReconnectPolicy;
pub use sequence::{ReconciliationAction, SequenceTracker};
pub use transport::{Transport, TransportState};
