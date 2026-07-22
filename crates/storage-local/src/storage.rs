// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Core LocalStorage: open, migrations, insert, ack, delete, checkpoint,
//! integrity check.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use privacy::RedactedEvent;
use rusqlite::Connection;

use crate::error::StorageError;
use crate::key::StorageKey;
use crate::serialize::serialize_event;

/// The canonical local storage handle. Wraps a single-writer SQLite
/// connection protected by a mutex.
pub struct LocalStorage {
    pub(crate) conn: Mutex<Connection>,
}

impl std::fmt::Debug for LocalStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalStorage { conn: <redacted> }")
    }
}

impl LocalStorage {
    /// Open the database at `path` with the given key. The key is NEVER
    /// stored in the DB, config, or log. SQLCipher v4 HMAC/KDF are always
    /// enabled. The database is always local (no network filesystem).
    pub fn open(path: &Path, key: &StorageKey) -> Result<Self, StorageError> {
        let conn = Connection::open(path).map_err(StorageError::from_sqlite)?;
        // Set the encryption key FIRST, before any other operation.
        // Use execute_batch to avoid pragma_update quoting issues.
        let hex_key = key.to_hex();
        conn.execute_batch(&format!("PRAGMA key = \"x'{hex_key}'\";"))
            .map_err(StorageError::from_sqlite)?;
        // Verify the key is correct by reading sqlite_master.
        let result: Result<i64, _> =
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0));
        if let Err(e) = result {
            return Err(StorageError::from_sqlite(e));
        }
        // Set WAL mode for concurrent readers (after key is verified).
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(StorageError::from_sqlite)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open with a test key (all zeros). Used ONLY in tests.
    pub fn open_with_test_key(path: &Path) -> Result<Self, StorageError> {
        Self::open(path, &crate::key::test_key())
    }

    /// Run schema migrations. Idempotent.
    pub fn run_migrations(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock();
        let batch = "
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                event_kind INTEGER NOT NULL,
                payload BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                acked INTEGER NOT NULL DEFAULT 0,
                acked_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS outbox (
                batch_id TEXT PRIMARY KEY,
                event_ids TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                acked INTEGER NOT NULL DEFAULT 0,
                acked_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );
            INSERT INTO schema_version (version)
                SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
        ";
        conn.execute_batch(batch)
            .map_err(|e| StorageError::MigrationFailed(e.to_string()))
    }

    /// Get the current schema version.
    pub fn schema_version(&self) -> Result<i64, StorageError> {
        let conn = self.conn.lock();
        let result: Result<i64, _> =
            conn.query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
                r.get(0)
            });
        result.map_err(|e| StorageError::QueryFailed(e.to_string()))
    }

    /// Insert a redacted event. Returns the event_id (UUID v4).
    /// The event is inserted with `acked = 0`.
    pub fn insert_event(&self, event: &RedactedEvent) -> Result<String, StorageError> {
        let event_id = uuid::Uuid::new_v4().to_string();
        let kind_i32 = event_kind_to_i32(event);
        let payload = serialize_event(event)
            .map_err(|e| StorageError::InsertFailed(e.to_string()))?;
        let now = current_timestamp();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_kind, payload, created_at, acked)
             VALUES (?1, ?2, ?3, ?4, 0)",
            rusqlite::params![event_id, kind_i32, payload, now],
        )
        .map_err(|e| StorageError::from_sqlite(e))?;
        Ok(event_id)
    }

    /// Insert a batch of event IDs into the outbox. Returns the batch_id.
    pub fn insert_batch(&self, event_ids: &[String]) -> Result<String, StorageError> {
        let batch_id = uuid::Uuid::new_v4().to_string();
        let ids_json = serde_json::to_string(event_ids)
            .map_err(|e| StorageError::InsertFailed(e.to_string()))?;
        let now = current_timestamp();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO outbox (batch_id, event_ids, created_at, acked)
             VALUES (?1, ?2, ?3, 0)",
            rusqlite::params![batch_id, ids_json, now],
        )
        .map_err(|e| StorageError::from_sqlite(e))?;
        Ok(batch_id)
    }

    /// Mark an event as acknowledged. The event is NOT deleted.
    /// The caller is responsible for ensuring remote durability BEFORE
    /// calling this method.
    pub fn ack_event(&self, event_id: &str) -> Result<(), StorageError> {
        let now = current_timestamp();
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE events SET acked = 1, acked_at = ?1 WHERE event_id = ?2",
            rusqlite::params![now, event_id],
        )
        .map_err(|e| StorageError::from_sqlite(e))?;
        Ok(())
    }

    /// Mark a batch as acknowledged. All events in the batch are also
    /// marked as acknowledged. The caller is responsible for ensuring
    /// remote durability BEFORE calling this method.
    pub fn ack_batch(&self, batch_id: &str) -> Result<(), StorageError> {
        let now = current_timestamp();
        let conn = self.conn.lock();
        // Get the event IDs in this batch.
        let ids_json: Result<String, _> = conn.query_row(
            "SELECT event_ids FROM outbox WHERE batch_id = ?1",
            rusqlite::params![batch_id],
            |r| r.get(0),
        );
        if let Ok(ids_json) = ids_json {
            if let Ok(ids) = serde_json::from_str::<Vec<String>>(&ids_json) {
                for id in &ids {
                    conn.execute(
                        "UPDATE events SET acked = 1, acked_at = ?1 WHERE event_id = ?2",
                        rusqlite::params![now, id],
                    )
                    .map_err(|e| StorageError::from_sqlite(e))?;
                }
            }
        }
        conn.execute(
            "UPDATE outbox SET acked = 1, acked_at = ?1 WHERE batch_id = ?2",
            rusqlite::params![now, batch_id],
        )
        .map_err(|e| StorageError::from_sqlite(e))?;
        Ok(())
    }

    /// Delete acknowledged events older than the given duration.
    pub fn delete_acked_events(&self, older_than: std::time::Duration) -> Result<usize, StorageError> {
        let cutoff = current_timestamp() - older_than.as_secs() as i64;
        let conn = self.conn.lock();
        let deleted = conn
            .execute(
                "DELETE FROM events WHERE acked = 1 AND created_at <= ?1",
                rusqlite::params![cutoff],
            )
            .map_err(|e| StorageError::from_sqlite(e))?;
        Ok(deleted)
    }

    /// Delete acknowledged batches older than the given duration.
    pub fn delete_acked_batches(&self, older_than: std::time::Duration) -> Result<usize, StorageError> {
        let cutoff = current_timestamp() - older_than.as_secs() as i64;
        let conn = self.conn.lock();
        let deleted = conn
            .execute(
                "DELETE FROM outbox WHERE acked = 1 AND created_at <= ?1",
                rusqlite::params![cutoff],
            )
            .map_err(|e| StorageError::from_sqlite(e))?;
        Ok(deleted)
    }

    /// Run PRAGMA wal_checkpoint(TRUNCATE) to bound the WAL size.
    pub fn checkpoint(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .map_err(|e| StorageError::CheckpointFailed(e.to_string()))
    }

    /// Run PRAGMA integrity_check and PRAGMA cipher_integrity_check.
    pub fn integrity_check(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock();
        let result: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(|e| StorageError::IntegrityCheckFailed(e.to_string()))?;
        if result != "ok" {
            return Err(StorageError::IntegrityCheckFailed(result));
        }
        // cipher_integrity_check may not be available on all builds;
        // treat errors as non-fatal if the pragma is unknown.
        let cipher_result: Result<String, _> =
            conn.query_row("PRAGMA cipher_integrity_check", [], |r| r.get(0));
        if let Ok(msg) = cipher_result {
            if !msg.is_empty() && msg != "ok" {
                return Err(StorageError::IntegrityCheckFailed(msg));
            }
        }
        Ok(())
    }

    /// Get the database file size in bytes.
    pub fn db_size_bytes(&self) -> Result<u64, StorageError> {
        let conn = self.conn.lock();
        let pages: i64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        let page_size: i64 = conn
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        Ok((pages * page_size) as u64)
    }

    /// Check if an event exists and is unacked.
    pub fn is_event_unacked(&self, event_id: &str) -> Result<bool, StorageError> {
        let conn = self.conn.lock();
        let result: Result<i64, _> = conn.query_row(
            "SELECT acked FROM events WHERE event_id = ?1",
            rusqlite::params![event_id],
            |r| r.get(0),
        );
        match result {
            Ok(acked) => Ok(acked == 0),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(StorageError::from_sqlite(e)),
        }
    }
}

/// Current UNIX timestamp in seconds.
pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Map a RedactedEvent's kind to an i32 for storage.
fn event_kind_to_i32(event: &RedactedEvent) -> i32 {
    use agent_core::Kind;
    match event.kind {
        Kind::ProcessFork => 1,
        Kind::ProcessExecResult => 2,
        Kind::ProcessExit => 3,
        Kind::FileOpen => 4,
        Kind::FileCreate => 5,
        Kind::FileUnlink => 6,
        Kind::FileRename => 7,
        Kind::FileTruncate => 8,
        Kind::NetworkConnect => 9,
        Kind::NetworkAccept => 10,
        Kind::NetworkState => 11,
        Kind::DnsPacket => 12,
        Kind::LsmDenyOwn => 15,
        Kind::SyscallEnter => 25,
        Kind::SyscallExit => 26,
        Kind::Identity => 27,
    }
}
