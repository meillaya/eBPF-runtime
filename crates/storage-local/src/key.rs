// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Storage key loading. The key is NEVER stored in the DB, config, or log.

use std::path::Path;

use crate::error::StorageError;

/// The 32-byte SQLCipher key. Loaded from a file or injected; NEVER logged
/// or persisted.
#[derive(Clone)]
pub struct StorageKey {
    pub key_bytes: [u8; 32],
}

impl std::fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print key material.
        f.write_str("StorageKey([REDACTED])")
    }
}

impl StorageKey {
    /// Encode the key as a hex string for use in PRAGMA key.
    pub fn to_hex(&self) -> String {
        self.key_bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Load the 32-byte key from a file. The file must be exactly 32 bytes.
/// Returns `StorageError::KeyFileMissing` if the file does not exist.
/// Returns `StorageError::KeyFileInvalidSize(n)` if the file is not 32 bytes.
pub fn load_key_from_file(path: &Path) -> Result<StorageKey, StorageError> {
    if !path.exists() {
        return Err(StorageError::KeyFileMissing);
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() != 32 {
        return Err(StorageError::KeyFileInvalidSize(bytes.len()));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(StorageKey { key_bytes })
}

/// The canonical production key path (root-readable 0600).
pub const DEFAULT_KEY_PATH: &str = "/var/lib/ebpf-agent/outbox.key";

/// Create a test key (all zeros). Used ONLY in tests.
pub fn test_key() -> StorageKey {
    StorageKey {
        key_bytes: [0u8; 32],
    }
}
