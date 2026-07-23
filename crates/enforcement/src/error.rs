// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed errors for the enforcement state machine.
//!
//! Every failure path in the staged-policy lifecycle maps to a
//! variant here so callers can match on the exact rejection reason
//! without string-parsing. The state machine NEVER panics on
//! invalid input; it returns `Err(EnforcementError::...)` and
//! transitions to `Rejected` where appropriate.

#![forbid(unsafe_code)]

use std::fmt;

/// Errors produced by the enforcement state machine and its
/// supporting subsystems (digest, kill switch, persistence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementError {
    /// The SHA-256 digest of the staged policy content does not
    /// match the digest declared in the STAGE command. The policy
    /// is rejected; no generation flip occurs.
    DigestMismatch {
        /// Hex-encoded expected digest (from the command).
        expected: String,
        /// Hex-encoded actual digest (computed from content).
        actual: String,
    },

    /// The command's version is not strictly greater than the
    /// current monotonic version. This covers both stale commands
    /// (version < current) and exact replays (version == current).
    VersionReplay {
        /// The version carried by the rejected command.
        command_version: u64,
        /// The current monotonic version the engine holds.
        current_version: u64,
    },

    /// The requested transition is not valid from the current
    /// state. For example, COMMIT before READY, or STAGE while
    /// already in the Committed state.
    InvalidTransition {
        /// The state the machine is currently in.
        from: String,
        /// The action that was attempted.
        action: String,
    },

    /// The kill switch is engaged (deny_disabled == 1). Deny-mode
    /// policies are suppressed to audit-only while the kill switch
    /// is active. This error is informational; the engine does not
    /// reject the policy, it degrades enforcement.
    KillSwitchActive,

    /// The policy content failed structural validation (e.g. unknown
    /// hook family, selector too long, invalid mode encoding).
    InvalidPolicy {
        /// Human-readable reason.
        reason: String,
    },

    /// Persistence I/O failure (read or write of last-known-good
    /// state). The engine continues in-memory; the offline state
    /// may be stale.
    PersistenceIo {
        /// Underlying I/O error description.
        message: String,
    },

    /// The loader is dead (fail-open). Deny links have been
    /// detached; observation policy follows its separate
    /// configuration. This is a terminal informational state.
    LoaderDead,
}

impl fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestMismatch { expected, actual } => {
                write!(f, "digest mismatch: expected {expected}, computed {actual}")
            }
            Self::VersionReplay {
                command_version,
                current_version,
            } => {
                write!(
                    f,
                    "version replay: command version {command_version} <= current {current_version}"
                )
            }
            Self::InvalidTransition { from, action } => {
                write!(f, "invalid transition: cannot {action} from {from}")
            }
            Self::KillSwitchActive => {
                write!(f, "kill switch active: deny suppressed to audit-only")
            }
            Self::InvalidPolicy { reason } => {
                write!(f, "invalid policy: {reason}")
            }
            Self::PersistenceIo { message } => {
                write!(f, "persistence I/O error: {message}")
            }
            Self::LoaderDead => {
                write!(
                    f,
                    "loader dead: deny links detached, observation follows separate config"
                )
            }
        }
    }
}

impl std::error::Error for EnforcementError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_mismatch_display_includes_both_hashes() {
        let err = EnforcementError::DigestMismatch {
            expected: "abc123".into(),
            actual: "def456".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("abc123"), "must contain expected hash");
        assert!(msg.contains("def456"), "must contain actual hash");
    }

    #[test]
    fn version_replay_display_includes_both_versions() {
        let err = EnforcementError::VersionReplay {
            command_version: 3,
            current_version: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains('3'), "must contain command version");
        assert!(msg.contains('5'), "must contain current version");
    }

    #[test]
    fn all_variants_are_displayable() {
        let variants = [
            EnforcementError::DigestMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            EnforcementError::VersionReplay {
                command_version: 1,
                current_version: 2,
            },
            EnforcementError::InvalidTransition {
                from: "Idle".into(),
                action: "commit".into(),
            },
            EnforcementError::KillSwitchActive,
            EnforcementError::InvalidPolicy {
                reason: "bad hook".into(),
            },
            EnforcementError::PersistenceIo {
                message: "disk full".into(),
            },
            EnforcementError::LoaderDead,
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }
}
