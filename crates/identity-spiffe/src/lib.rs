// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SPIFFE Workload API identity client for the eBPF runtime
//! security agent.
//!
//! This crate provides:
//!
//! - **SPIFFE ID validation**: parsing, exact trust-domain
//!   matching, selector-validated workload identity.
//! - **X.509 SVID management**: complete-set replace/redact
//!   semantics with zeroize-on-drop private key material.
//! - **Workload API client**: long-lived FetchX509SVID stream
//!   over protected Unix socket, reconnect with exponential
//!   backoff.
//! - **Credential rotation**: rustls mTLS config hot-rebuild
//!   before expiry, fail-closed on expired/redacted material.
//! - **Authorization callback**: binds SPIFFE IDs to
//!   agent/node/cluster identity for fleet registration.
//! - **Health/expiry metrics**: Prometheus gauges/counters for
//!   SVID expiry, rotation count, stream health.
//!
//! # Security invariants
//!
//! - Private keys are NEVER cached on disk (memory only,
//!   zeroized on drop).
//! - Trust domain matching is EXACT (no substring).
//! - Private keys are NEVER exposed in logs or Debug output.
//! - Expired/redacted material is NEVER used (fail closed).
//! - No insecure bootstrap (no plaintext fallback).
//! - No fallback to static tokens.
//!
//! # BLOCKER NOTE
//!
//! This host does not have a running SPIRE agent. The client
//! logic is fully implemented and tested with pinned ephemeral
//! fixtures. Live SPIRE integration requires a declared
//! self-hosted runner with SPIRE deployed.
//!
//! # Integration with protocol crate (task 35)
//!
//! The `authorization` module bridges SPIFFE IDs to the
//! protocol crate's `AgentIdentity::register()` flow. The
//! `credentials` module produces `rustls::ServerConfig` /
//! `rustls::ClientConfig` for gRPC mTLS channel credentials.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod authorization;
pub mod backoff;
pub mod credentials;
pub mod error;
pub mod metrics;
pub mod spiffe_id;
pub mod svid;
pub mod workload;

// Re-export primary types for convenience.
pub use authorization::{AgentBinding, AuthorizationCallback};
pub use backoff::ExponentialBackoff;
pub use credentials::CredentialManager;
pub use error::{SpiffeError, SpiffeResult};
pub use metrics::SpiffeMetrics;
pub use spiffe_id::{SpiffeId, SpiffeIdSelector};
pub use svid::{SvidSet, X509Bundle, X509Svid};
pub use workload::{
    FixtureSvidStream, StreamHealth, SvidEntry, SvidStream, WorkloadApiClient, X509SvidResponse,
    SPIFFE_ENDPOINT_SOCKET_ENV,
};
