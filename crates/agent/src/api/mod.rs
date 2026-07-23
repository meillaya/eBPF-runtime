// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Versioned local REST/WebSocket API for the standalone node service.
#![allow(clippy::result_large_err)]
//!
//! Safety invariants enforced here (plan task 26):
//! - The API only READS redacted events from local storage; it never exposes
//!   loader or BPF map mutation.
//! - The no-auth dev surface only ever binds to a loopback address. A
//!   non-loopback bind (e.g. `0.0.0.0`) is rejected by a strict check.
//! - Every returned event is a [`privacy::RedactedEvent`] projection; the raw
//!   pre-redaction payload is structurally absent, so the API cannot bypass
//!   redaction.
//! - Every query is bounded: pagination via opaque cursors, a hard page-size
//!   cap, a hard pagination-window cap, and a hard per-filter byte cap. The API
//!   never returns unbounded results.
//! - A slow WebSocket consumer is shed (typed rejection) without crashing the
//!   server.

pub mod error;
pub mod handlers;
pub mod helpers;
pub mod server;
pub mod views;
pub mod websocket;

use std::sync::Arc;

use observability::MetricsRegistry;
use storage_local::LocalStorage;
use tokio::sync::broadcast;

// Re-exports for public API compatibility.
pub use error::{ApiError, ApiErrorKind};
pub use helpers::{decode_cursor, encode_cursor};
pub use server::ApiServer;

// ---------------------------------------------------------------------------
// Bounded-query constants (mirrors of bench/schemas/storage.v1.json defaults)
// ---------------------------------------------------------------------------

/// Default page size for bounded paginated queries.
pub const DEFAULT_PAGE_LIMIT: usize = 100;
/// Hard upper bound on a single page size.
pub const MAX_PAGE_LIMIT: usize = 1000;
/// Hard upper bound on (cursor offset + limit).
pub const MAX_PAGE_WINDOW: usize = 10000;
/// Hard upper bound on the byte length of a single filter value / cursor.
pub const MAX_FILTER_BYTES: usize = 1024;
/// Bounded capacity of the live-event broadcast channel.
pub const WS_BROADCAST_CAPACITY: usize = 1024;
/// Maximum time a single WebSocket send may block before the consumer is
/// considered slow and shed.
pub const WS_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
/// Default loopback dev bind address.
pub const DEFAULT_DEV_BIND: &str = "127.0.0.1:9464";

/// Per-connection shared state.
pub(crate) struct ApiState {
    pub(crate) storage: Arc<LocalStorage>,
    pub(crate) registry: Arc<MetricsRegistry>,
    pub(crate) broadcaster: broadcast::Sender<String>,
}
