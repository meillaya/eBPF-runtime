// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded SQLCipher local history and durable outbox.
//!
//! This crate provides encrypted-at-rest local storage for redacted security
//! events using SQLCipher v4. The key is loaded from
//! `/var/lib/ebpf-agent/outbox.key` (root-readable 0600) or injected via a
//! test key. The key is NEVER stored in the DB, config, or log.
//!
//! Safety invariants:
//! - SQLCipher v4 HMAC and KDF are always enabled (never disabled).
//! - The database is always local (no network filesystem).
//! - ACK is only performed after the caller confirms remote durability.
//! - WAL mode enables concurrent readers with a single writer.

#![forbid(unsafe_code)]

mod error;
mod key;
mod query;
mod retention;
mod serialize;
mod storage;

pub use error::StorageError;
pub use key::{load_key_from_file, test_key, StorageKey, DEFAULT_KEY_PATH};
pub use query::{EventQuery, OutboxEntry, OutboxQuery};
pub use retention::{
    load_retention_policy, RetentionPolicy, RetentionResult, DEFAULT_RETENTION_BYTES,
    DEFAULT_RETENTION_SECONDS,
};
pub use serialize::redacted_event_from_json_value;
pub use storage::{current_timestamp, LocalStorage};
