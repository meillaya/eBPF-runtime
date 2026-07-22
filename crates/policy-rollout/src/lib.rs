// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet two-phase policy rollout.
//!
//! Distributed state machine coordinating safe fleet-wide policy
//! activation: STAGE→READY→COMMIT→APPLIED/REJECTED with
//! reconciliation, rollback, idempotent SPIFFE-bound commands,
//! and full audit.
//!
//! # Invariants
//!
//! - **STAGE never activates**: policy is staged (inactive) until
//!   explicit COMMIT.
//! - **No activation from Kafka/NOTIFY**: only explicit commands
//!   trigger state transitions.
//! - **No wall clock as version**: monotonic counter or content
//!   hash only.
//! - **No applied from send-only**: agent must acknowledge with
//!   APPLIED report.
//! - **No relax on disconnect**: last-known-good maintained.
//! - **No silent activation**: all transitions explicit and
//!   audited.
//! - **Idempotent commands**: duplicates are safe.
//! - **SPIFFE-bound**: all commands require authorization.
//!
//! # BLOCKER
//!
//! This host has no live PostgreSQL, gRPC server, or multiple
//! agents. All logic is validated with in-memory mocks and
//! fixtures. Live distributed integration re-opens on the
//! declared self-hosted runner.

#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
pub mod digest;
pub mod error;
pub mod model;
pub mod reconcile;
pub mod state_machine;
pub mod store;

pub use audit::{AuditEntry, AuditLog};
pub use auth::RolloutAuthorizer;
pub use digest::{compute_policy_digest, sha256_hex, verify_digest};
pub use error::{RolloutError, RolloutResult};
pub use model::*;
pub use reconcile::Reconciler;
pub use state_machine::FleetRolloutCoordinator;
pub use store::{AgentStateStore, LastKnownGoodStore, PolicyVersionStore, RolloutStore};
