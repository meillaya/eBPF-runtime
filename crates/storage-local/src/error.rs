// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed errors for the storage-local crate.

use thiserror::Error;

/// All errors that can occur in the local storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The key file at the expected path does not exist.
    #[error("key file missing")]
    KeyFileMissing,
    /// The key file exists but is not exactly 32 bytes.
    #[error("key file invalid size: {0} bytes (expected 32)")]
    KeyFileInvalidSize(usize),
    /// The database was opened with the wrong key.
    #[error("wrong key: database is encrypted or corrupted")]
    WrongKey,
    /// PRAGMA integrity_check or cipher_integrity_check failed.
    #[error("integrity check failed: {0}")]
    IntegrityCheckFailed(String),
    /// A schema migration failed.
    #[error("migration failed: {0}")]
    MigrationFailed(String),
    /// An insert operation failed.
    #[error("insert failed: {0}")]
    InsertFailed(String),
    /// A query operation failed.
    #[error("query failed: {0}")]
    QueryFailed(String),
    /// A WAL checkpoint failed.
    #[error("checkpoint failed: {0}")]
    CheckpointFailed(String),
    /// A retention operation failed.
    #[error("retention failed: {0}")]
    RetentionFailed(String),
    /// The database is locked by another writer.
    #[error("database locked")]
    DatabaseLocked,
    /// The disk is full (SQLITE_FULL).
    #[error("full disk: no space left on device")]
    FullDisk,
    /// An I/O error occurred.
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    /// An underlying SQLite error.
    #[error("sqlite error: {0}")]
    SqlError(#[from] rusqlite::Error),
}

impl StorageError {
    /// Map a rusqlite error to the appropriate typed variant.
    pub fn from_sqlite(err: rusqlite::Error) -> Self {
        match &err {
            rusqlite::Error::SqliteFailure(sqlite_err, msg) => {
                let code = sqlite_err.code;
                let msg_str = msg.clone().unwrap_or_default();
                match code {
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                        Self::DatabaseLocked
                    }
                    rusqlite::ErrorCode::DiskFull => Self::FullDisk,
                    rusqlite::ErrorCode::NotADatabase => Self::WrongKey,
                    _ => {
                        if msg_str.contains("file is not a database")
                            || msg_str.contains("file is encrypted")
                        {
                            Self::WrongKey
                        } else if msg_str.contains("disk I/O error")
                            || msg_str.contains("unable to open database")
                        {
                            Self::FullDisk
                        } else {
                            Self::SqlError(err)
                        }
                    }
                }
            }
            _ => Self::SqlError(err),
        }
    }
}
