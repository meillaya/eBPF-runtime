// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retention policy loaded from bench/schemas/supported-load.v1.json.

use std::path::Path;
use std::time::Duration;

use crate::error::StorageError;
use crate::storage::LocalStorage;

/// Default retention: 24 hours.
pub const DEFAULT_RETENTION_SECONDS: u64 = 86400;
/// Default retention: 4 GiB.
pub const DEFAULT_RETENTION_BYTES: u64 = 4_294_967_296;

/// The retention policy for the local database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub retention_seconds: u64,
    pub retention_bytes: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            retention_seconds: DEFAULT_RETENTION_SECONDS,
            retention_bytes: DEFAULT_RETENTION_BYTES,
        }
    }
}

/// The result of applying retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionResult {
    pub deleted_events: usize,
    pub deleted_batches: usize,
    pub db_size_bytes: u64,
}

/// Load the retention policy from the supported-load schema.
/// Falls back to defaults if the file or fields are missing.
pub fn load_retention_policy(schema_path: &Path) -> RetentionPolicy {
    let default = RetentionPolicy::default();
    let content = match std::fs::read_to_string(schema_path) {
        Ok(c) => c,
        Err(_) => return default,
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return default,
    };
    let retention_seconds = json
        .get("retention_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(default.retention_seconds);
    let retention_bytes = json
        .get("retention_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(default.retention_bytes);
    RetentionPolicy {
        retention_seconds,
        retention_bytes,
    }
}

impl LocalStorage {
    /// Return the retention policy. Loaded from
    /// `bench/schemas/supported-load.v1.json` if available, otherwise
    /// defaults (86400 seconds, 4 GiB).
    pub fn retention_policy(&self) -> RetentionPolicy {
        // Try workspace-relative path first, then absolute.
        let candidates = [
            Path::new("bench/schemas/supported-load.v1.json"),
            Path::new("/home/mei/projects/kernels/kernel-v1/bench/schemas/supported-load.v1.json"),
        ];
        for path in &candidates {
            if path.exists() {
                return load_retention_policy(path);
            }
        }
        RetentionPolicy::default()
    }

    /// Apply the retention policy. Deletes acknowledged events/batches
    /// older than retention_seconds. If the database exceeds
    /// retention_bytes, deletes the oldest acknowledged events until
    /// the size is below the limit.
    pub fn apply_retention(&self) -> Result<RetentionResult, StorageError> {
        let policy = self.retention_policy();
        let duration = Duration::from_secs(policy.retention_seconds);

        let deleted_events = self.delete_acked_events(duration)?;
        let deleted_batches = self.delete_acked_batches(duration)?;

        // If the database still exceeds the byte limit, delete oldest
        // acknowledged events until below the limit.
        let mut total_deleted_events = deleted_events;
        let mut db_size = self.db_size_bytes()?;
        if db_size > policy.retention_bytes {
            loop {
                let conn = self.conn.lock();
                let deleted: usize = conn
                    .execute(
                        "DELETE FROM events WHERE acked = 1 AND event_id = (
                            SELECT event_id FROM events WHERE acked = 1
                            ORDER BY created_at ASC LIMIT 1
                        )",
                        [],
                    )
                    .map_err(|e| StorageError::RetentionFailed(e.to_string()))?;
                drop(conn);
                if deleted == 0 {
                    break;
                }
                total_deleted_events += deleted;
                db_size = self.db_size_bytes()?;
                if db_size <= policy.retention_bytes {
                    break;
                }
            }
        }

        Ok(RetentionResult {
            deleted_events: total_deleted_events,
            deleted_batches,
            db_size_bytes: db_size,
        })
    }
}
