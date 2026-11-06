// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Encrypted local event store and durable outbox.
//!
//! SQLCipher protects events at rest. The outbox row holds the exact batch
//! payload sent to the control plane, so a retry does not depend on
//! re-serializing events that may have been pruned. An outbox row is deleted
//! only after the control plane acknowledges it.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use event_model::{Alert, Batch, Event};
use parking_lot::Mutex;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension};
use thiserror::Error;

/// A 32-byte SQLCipher key.
#[derive(Clone)]
pub struct StorageKey([u8; 32]);

impl StorageKey {
    /// Generate a fresh key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Load a 32-byte key from a file.
    pub fn load(path: &Path) -> Result<Self, StorageError> {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            return Err(StorageError::BadKeyLength(bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    /// Write the key with mode 0600.
    pub fn save(&self, path: &Path) -> Result<(), StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }

    /// Test key used only by tests.
    pub fn test() -> Self {
        Self([0u8; 32])
    }
}

/// One unacknowledged batch.
#[derive(Debug, Clone)]
pub struct OutboxBatch {
    /// Batch id.
    pub batch_id: String,
    /// Exact batch JSON.
    pub payload: Vec<u8>,
    /// Delivery attempts so far.
    pub attempts: u32,
}

/// Local storage errors.
#[derive(Debug, Error)]
pub enum StorageError {
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// SQLite failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Key file has the wrong size.
    #[error("storage key must be 32 bytes, got {0}")]
    BadKeyLength(usize),
    /// Serialization failure.
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The database schema is newer than this binary.
    #[error("schema version {found} is newer than supported version {supported}")]
    SchemaTooNew {
        /// Found version.
        found: i64,
        /// Supported version.
        supported: i64,
    },
}

const SCHEMA_VERSION: i64 = 1;

/// Encrypted local store.
pub struct LocalStorage {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl LocalStorage {
    /// Open or create the database at `path`.
    pub fn open(path: &Path, key: &StorageKey) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", key.hex()))?;
        // Read before any write to verify the key.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let storage = Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        };
        storage.run_migrations()?;
        Ok(storage)
    }

    /// Run schema migrations. Idempotent.
    pub fn run_migrations(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                sensor TEXT NOT NULL,
                payload BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                acked INTEGER NOT NULL DEFAULT 0,
                acked_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
            CREATE INDEX IF NOT EXISTS idx_events_unacked ON events(acked, created_at);
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                acked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS outbox (
                batch_id TEXT PRIMARY KEY,
                event_ids TEXT NOT NULL,
                payload BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                acked INTEGER NOT NULL DEFAULT 0,
                acked_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_outbox_due ON outbox(acked, next_attempt_at);
            CREATE TABLE IF NOT EXISTS policy_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version TEXT NOT NULL,
                digest TEXT NOT NULL,
                content BLOB NOT NULL,
                applied_at INTEGER NOT NULL
            );
            PRAGMA user_version = 1;
            ",
        )?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StorageError::SchemaTooNew {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(())
    }

    /// Insert an event. Duplicate ids are ignored.
    pub fn insert_event(&self, event: &Event) -> Result<(), StorageError> {
        let payload = serde_json::to_vec(event)?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, kind, sensor, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![event.event_id, event.kind, event.sensor, payload, now()],
        )?;
        Ok(())
    }

    /// Insert an alert. Duplicate ids are ignored.
    pub fn insert_alert(&self, alert: &Alert) -> Result<(), StorageError> {
        let payload = serde_json::to_vec(alert)?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO alerts (alert_id, payload, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![alert.alert_id, payload, now()],
        )?;
        Ok(())
    }

    /// Insert a batch into the outbox.
    pub fn insert_batch(&self, batch: &Batch) -> Result<(), StorageError> {
        let payload = serde_json::to_vec(batch)?;
        let event_ids: Vec<&str> = batch.events.iter().map(|e| e.event_id.as_str()).collect();
        let ids = serde_json::to_string(&event_ids)?;
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO outbox
             (batch_id, event_ids, payload, created_at, attempts, next_attempt_at)
             VALUES (?1, ?2, ?3, ?4, 0, 0)",
            rusqlite::params![batch.batch_id, ids, payload, now()],
        )?;
        Ok(())
    }

    /// Return batches whose next attempt is due.
    pub fn due_batches(&self, limit: usize) -> Result<Vec<OutboxBatch>, StorageError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT batch_id, payload, attempts FROM outbox
             WHERE acked = 0 AND next_attempt_at <= ?1
             ORDER BY created_at ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![now(), limit as i64], |row| {
            Ok(OutboxBatch {
                batch_id: row.get(0)?,
                payload: row.get(1)?,
                attempts: row.get(2)?,
            })
        })?;
        let mut batches = Vec::new();
        for row in rows {
            batches.push(row?);
        }
        Ok(batches)
    }

    /// Mark a batch and its events acknowledged in one transaction.
    pub fn ack_batch(&self, batch_id: &str) -> Result<(), StorageError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let ids: Option<String> = tx
            .query_row(
                "SELECT event_ids FROM outbox WHERE batch_id = ?1",
                rusqlite::params![batch_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(ids) = ids {
            let ids: Vec<String> = serde_json::from_str(&ids).unwrap_or_default();
            for id in ids {
                tx.execute(
                    "UPDATE events SET acked = 1, acked_at = ?1 WHERE event_id = ?2",
                    rusqlite::params![now(), id],
                )?;
            }
        }
        tx.execute(
            "UPDATE outbox SET acked = 1, acked_at = ?1 WHERE batch_id = ?2",
            rusqlite::params![now(), batch_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Record a failed attempt and schedule the next one.
    pub fn retry_batch(&self, batch_id: &str, delay_secs: u64) -> Result<(), StorageError> {
        let next = now() + delay_secs as i64;
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE outbox SET attempts = attempts + 1, next_attempt_at = ?1 WHERE batch_id = ?2",
            rusqlite::params![next, batch_id],
        )?;
        Ok(())
    }

    /// Query recent events, newest first.
    pub fn query_events(
        &self,
        limit: usize,
        kind: Option<&str>,
    ) -> Result<Vec<Event>, StorageError> {
        let conn = self.conn.lock();
        let mut statement = if kind.is_some() {
            conn.prepare(
                "SELECT payload FROM events WHERE kind = ?1 ORDER BY created_at DESC LIMIT ?2",
            )?
        } else {
            conn.prepare("SELECT payload FROM events ORDER BY created_at DESC LIMIT ?1")?
        };
        let payloads: Vec<Vec<u8>> = if let Some(kind) = kind {
            let rows =
                statement.query_map(rusqlite::params![kind, limit as i64], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        } else {
            let rows = statement.query_map(rusqlite::params![limit as i64], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut events = Vec::new();
        for payload in payloads {
            events.push(serde_json::from_slice(&payload)?);
        }
        Ok(events)
    }

    /// Query recent alerts, newest first.
    pub fn query_alerts(&self, limit: usize) -> Result<Vec<Alert>, StorageError> {
        let conn = self.conn.lock();
        let mut statement =
            conn.prepare("SELECT payload FROM alerts ORDER BY created_at DESC LIMIT ?1")?;
        let rows = statement.query_map(rusqlite::params![limit as i64], |row| row.get(0))?;
        let mut alerts = Vec::new();
        for row in rows {
            let payload: Vec<u8> = row?;
            alerts.push(serde_json::from_slice(&payload)?);
        }
        Ok(alerts)
    }

    /// Number of unacked batches.
    pub fn outbox_depth(&self) -> Result<u64, StorageError> {
        let conn = self.conn.lock();
        let count: i64 =
            conn.query_row("SELECT count(*) FROM outbox WHERE acked = 0", [], |row| {
                row.get(0)
            })?;
        Ok(count as u64)
    }

    /// Delete acknowledged rows older than `seconds`.
    pub fn prune(&self, seconds: u64) -> Result<u64, StorageError> {
        let cutoff = now() - seconds as i64;
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM events WHERE acked = 1 AND acked_at <= ?1",
            rusqlite::params![cutoff],
        )?;
        tx.execute(
            "DELETE FROM alerts WHERE acked = 1 AND created_at <= ?1",
            rusqlite::params![cutoff],
        )?;
        let deleted = tx.execute(
            "DELETE FROM outbox WHERE acked = 1 AND acked_at <= ?1",
            rusqlite::params![cutoff],
        )?;
        tx.commit()?;
        Ok(deleted as u64)
    }

    /// Store the active policy.
    pub fn set_policy(
        &self,
        version: &str,
        digest: &str,
        content: &[u8],
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO policy_state (id, version, digest, content, applied_at)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
               version = excluded.version,
               digest = excluded.digest,
               content = excluded.content,
               applied_at = excluded.applied_at",
            rusqlite::params![version, digest, content, now()],
        )?;
        Ok(())
    }

    /// Load the active policy.
    pub fn get_policy(&self) -> Result<Option<(String, String, Vec<u8>)>, StorageError> {
        let conn = self.conn.lock();
        let result = conn
            .query_row(
                "SELECT version, digest, content FROM policy_state WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        Ok(result)
    }

    /// Checkpoint the WAL and bound its size.
    pub fn checkpoint(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }

    /// Run SQLCipher integrity checks.
    pub fn integrity_check(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock();
        let check: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if check != "ok" {
            return Err(StorageError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        Ok(())
    }

    /// Database file size in bytes.
    pub fn size_bytes(&self) -> u64 {
        std::fs::metadata(&self.path)
            .map(|meta| meta.len())
            .unwrap_or(0)
    }

    /// Current schema version.
    pub fn schema_version(&self) -> Result<i64, StorageError> {
        let conn = self.conn.lock();
        Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_model::{Batch, Event};

    fn event(id: &str) -> Event {
        Event {
            time: "2026-01-01T00:00:00Z".to_string(),
            sensor: "file".to_string(),
            kind: "FileOpen".to_string(),
            event_id: id.to_string(),
            boot_id: "b".repeat(32),
            seq: 1,
            path: Some("/etc/shadow".to_string()),
            ..Default::default()
        }
    }

    fn batch(id: &str) -> Batch {
        Batch {
            batch_id: id.to_string(),
            agent_id: "agent-1".to_string(),
            cluster: "dev".to_string(),
            node_name: "node-1".to_string(),
            agent_generation: "gen-1".to_string(),
            boot_id: "b".repeat(32),
            schema_major: 1,
            schema_minor: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            events: vec![event("a".repeat(64).as_str())],
            alerts: Vec::new(),
        }
    }

    #[test]
    fn duplicate_events_and_batches_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::open(&dir.path().join("db"), &StorageKey::test()).unwrap();
        let event = event("a".repeat(64).as_str());
        storage.insert_event(&event).unwrap();
        storage.insert_event(&event).unwrap();
        assert_eq!(storage.query_events(10, None).unwrap().len(), 1);

        let batch = batch("batch-1");
        storage.insert_batch(&batch).unwrap();
        storage.insert_batch(&batch).unwrap();
        assert_eq!(storage.outbox_depth().unwrap(), 1);
    }

    #[test]
    fn ack_marks_event_and_batch() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::open(&dir.path().join("db"), &StorageKey::test()).unwrap();
        let event = event("a".repeat(64).as_str());
        storage.insert_event(&event).unwrap();
        let mut batch = batch("batch-1");
        batch.events = vec![event];
        storage.insert_batch(&batch).unwrap();
        assert_eq!(storage.due_batches(10).unwrap().len(), 1);
        storage.ack_batch("batch-1").unwrap();
        assert_eq!(storage.due_batches(10).unwrap().len(), 0);
        assert_eq!(storage.outbox_depth().unwrap(), 0);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let first = StorageKey::generate();
        drop(LocalStorage::open(&path, &first).unwrap());
        let second = StorageKey::generate();
        assert!(LocalStorage::open(&path, &second).is_err());
    }

    #[test]
    fn retry_schedules_batch() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::open(&dir.path().join("db"), &StorageKey::test()).unwrap();
        storage.insert_batch(&batch("batch-1")).unwrap();
        storage.retry_batch("batch-1", 60).unwrap();
        assert!(storage.due_batches(10).unwrap().is_empty());
    }

    #[test]
    fn policy_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::open(&dir.path().join("db"), &StorageKey::test()).unwrap();
        storage.set_policy("3", "digest", b"rules: []").unwrap();
        let (version, digest, content) = storage.get_policy().unwrap().unwrap();
        assert_eq!(version, "3");
        assert_eq!(digest, "digest");
        assert_eq!(content, b"rules: []");
    }
}
