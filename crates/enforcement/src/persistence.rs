// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Last-known-good persistence and startup audit-only restore.
//!
//! The enforcement engine persists the last successfully applied
//! policy generation to a JSON file. On restart, the engine loads
//! this file and restores the active generation — but forces every
//! entry to **audit mode** (startup audit-only invariant). A deny
//! policy must be explicitly re-committed through the full
//! STAGE→READY→COMMIT path after a restart.
//!
//! The persistence format is a JSON-serialized `PolicyGeneration`.
//! The file is written atomically (write-to-temp + rename) to avoid
//! corruption on crash.
//!
//! **Auto-relax prohibition**: the engine does NOT auto-relax
//! last-known-good on disconnect. Only an explicit ROLLBACK or
//! KILL SWITCH command changes enforcement state. A loader
//! disconnect alone does not modify the persisted policy.

#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::EnforcementError;
use crate::policy::PolicyGeneration;

/// Default path for the last-known-good state file.
pub const DEFAULT_LKG_PATH: &str = "/var/lib/ebpf-agent/enforcement-lkg.json";

/// Persist a policy generation as the last-known-good state.
///
/// Writes atomically: the generation is serialized to a temporary
/// file in the same directory, then renamed over the target. This
/// prevents a crash mid-write from corrupting the LKG file.
pub fn persist_last_known_good(
    generation: &PolicyGeneration,
    path: &Path,
) -> Result<(), EnforcementError> {
    let json =
        serde_json::to_string_pretty(generation).map_err(|e| EnforcementError::PersistenceIo {
            message: format!("serialize: {e}"),
        })?;

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| EnforcementError::PersistenceIo {
            message: format!("create dir {}: {e}", parent.display()),
        })?;
    }

    // Atomic write: temp file + rename.
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, json.as_bytes()).map_err(|e| EnforcementError::PersistenceIo {
        message: format!("write temp {}: {e}", tmp_path.display()),
    })?;
    fs::rename(&tmp_path, path).map_err(|e| EnforcementError::PersistenceIo {
        message: format!("rename {} -> {}: {e}", tmp_path.display(), path.display()),
    })?;

    Ok(())
}

/// Load the last-known-good policy generation from disk.
///
/// Returns `None` if the file does not exist (first boot).
/// Returns `Err` if the file exists but is corrupt.
pub fn load_last_known_good(path: &Path) -> Result<Option<PolicyGeneration>, EnforcementError> {
    match fs::read_to_string(path) {
        Ok(json) => {
            let gen: PolicyGeneration =
                serde_json::from_str(&json).map_err(|e| EnforcementError::PersistenceIo {
                    message: format!("deserialize {}: {e}", path.display()),
                })?;
            Ok(Some(gen))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(EnforcementError::PersistenceIo {
            message: format!("read {}: {e}", path.display()),
        }),
    }
}

/// The persistence manager. Wraps a path and provides
/// save/load operations for the last-known-good state.
#[derive(Debug, Clone)]
pub struct PersistenceManager {
    /// Path to the LKG file.
    path: PathBuf,
}

impl PersistenceManager {
    /// Create a manager targeting the given path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Create a manager targeting the default path.
    pub fn default_path() -> Self {
        Self::new(DEFAULT_LKG_PATH)
    }

    /// Save the generation as the last-known-good state.
    pub fn save(&self, generation: &PolicyGeneration) -> Result<(), EnforcementError> {
        persist_last_known_good(generation, &self.path)
    }

    /// Load the last-known-good state.
    pub fn load(&self) -> Result<Option<PolicyGeneration>, EnforcementError> {
        load_last_known_good(&self.path)
    }

    /// The path this manager targets.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{HookFamily, PolicyMode};

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lkg.json");
        let mgr = PersistenceManager::new(&path);

        let mut gen = PolicyGeneration::new_audit_only(7);
        gen.entry_for_mut(HookFamily::FileOpen).unwrap().mode = PolicyMode::Deny;
        gen.entry_for_mut(HookFamily::FileOpen).unwrap().version = 42;

        mgr.save(&gen).unwrap();
        let loaded = mgr.load().unwrap().unwrap();
        assert_eq!(loaded.generation, 7);
        assert_eq!(
            loaded.entry_for(HookFamily::FileOpen).unwrap().mode,
            PolicyMode::Deny
        );
        assert_eq!(loaded.entry_for(HookFamily::FileOpen).unwrap().version, 42);
    }

    #[test]
    fn load_missing_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let mgr = PersistenceManager::new(&path);
        assert!(mgr.load().unwrap().is_none());
    }

    #[test]
    fn load_corrupt_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.json");
        fs::write(&path, b"not json").unwrap();
        let mgr = PersistenceManager::new(&path);
        assert!(mgr.load().is_err());
    }

    #[test]
    fn atomic_write_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("dir").join("lkg.json");
        let mgr = PersistenceManager::new(&path);
        let gen = PolicyGeneration::new_audit_only(1);
        mgr.save(&gen).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn no_tmp_file_left_after_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lkg.json");
        let mgr = PersistenceManager::new(&path);
        let gen = PolicyGeneration::new_audit_only(1);
        mgr.save(&gen).unwrap();
        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists(), "temp file must be renamed away");
    }
}
