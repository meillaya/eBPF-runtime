// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed errors for the fleet policy rollout state machine.
//!
//! Every failure path in the distributed rollout lifecycle maps to
//! a variant here so callers can match on the exact rejection reason
//! without string-parsing. The state machine NEVER panics on invalid
//! input; it returns `Err(RolloutError::...)` and records the failure
//! in the audit log.

#![forbid(unsafe_code)]

use std::fmt;

/// Errors produced by the fleet policy rollout state machine and
/// its supporting subsystems (auth, store, reconciliation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RolloutError {
    /// The command's version is not strictly greater than the
    /// current monotonic version. Covers both stale commands
    /// (version < current) and exact replays (version == current).
    VersionReplay {
        /// The version carried by the rejected command.
        command_version: u64,
        /// The current monotonic version the rollout holds.
        current_version: u64,
    },

    /// The SHA-256 digest of the policy content does not match
    /// the digest declared in the STAGE command. The policy is
    /// rejected; no activation occurs.
    DigestMismatch {
        /// Hex-encoded expected digest (from the command).
        expected: String,
        /// Hex-encoded actual digest (computed from content).
        actual: String,
    },

    /// The requested transition is not valid from the current
    /// state. For example, COMMIT before all agents are READY,
    /// or STAGE while a rollout is in progress.
    InvalidTransition {
        /// The state the machine is currently in.
        from: String,
        /// The action that was attempted.
        action: String,
    },

    /// The SPIFFE ID of the command issuer is not authorized
    /// for the requested operation.
    Unauthorized {
        /// The SPIFFE ID that was presented.
        spiffe_id: String,
        /// The operation that was attempted.
        operation: String,
        /// Human-readable reason.
        reason: String,
    },

    /// The referenced entity (policy version, rollout, agent)
    /// was not found.
    NotFound {
        /// The entity type (e.g. "policy_version", "rollout").
        entity: String,
        /// The key that was looked up.
        key: String,
    },

    /// The rollout has exceeded its deadline.
    Timeout {
        /// The rollout ID.
        rollout_id: u64,
        /// The tick at which the timeout was detected.
        current_tick: u64,
        /// The deadline tick.
        deadline_tick: u64,
    },

    /// An agent reported a digest mismatch during READY
    /// acknowledgment.
    AgentDigestMismatch {
        /// The agent's SPIFFE ID.
        agent_id: String,
        /// The expected digest.
        expected: String,
        /// The digest the agent computed.
        actual: String,
    },

    /// A duplicate command was detected (idempotent rejection).
    /// The command is safe to ignore.
    DuplicateCommand {
        /// Description of the duplicate.
        description: String,
    },

    /// The agent is not a target of the current rollout.
    AgentNotTargeted {
        /// The agent's SPIFFE ID.
        agent_id: String,
        /// The rollout ID.
        rollout_id: u64,
    },

    /// Optimistic concurrency conflict in the store.
    VersionConflict {
        /// The entity type.
        entity: String,
        /// Expected version.
        expected: i64,
        /// Found version.
        found: i64,
    },
}

impl fmt::Display for RolloutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionReplay {
                command_version,
                current_version,
            } => {
                write!(
                    f,
                    "version replay: command version {command_version} <= current {current_version}"
                )
            }
            Self::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "digest mismatch: expected {expected}, computed {actual}"
                )
            }
            Self::InvalidTransition { from, action } => {
                write!(f, "invalid transition: cannot {action} from {from}")
            }
            Self::Unauthorized {
                spiffe_id,
                operation,
                reason,
            } => {
                write!(
                    f,
                    "unauthorized: {spiffe_id} cannot {operation}: {reason}"
                )
            }
            Self::NotFound { entity, key } => {
                write!(f, "not found: {entity} with key {key}")
            }
            Self::Timeout {
                rollout_id,
                current_tick,
                deadline_tick,
            } => {
                write!(
                    f,
                    "timeout: rollout {rollout_id} exceeded deadline (tick {current_tick} > {deadline_tick})"
                )
            }
            Self::AgentDigestMismatch {
                agent_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "agent {agent_id} digest mismatch: expected {expected}, got {actual}"
                )
            }
            Self::DuplicateCommand { description } => {
                write!(f, "duplicate command: {description}")
            }
            Self::AgentNotTargeted {
                agent_id,
                rollout_id,
            } => {
                write!(
                    f,
                    "agent {agent_id} is not a target of rollout {rollout_id}"
                )
            }
            Self::VersionConflict {
                entity,
                expected,
                found,
            } => {
                write!(
                    f,
                    "version conflict on {entity}: expected {expected}, found {found}"
                )
            }
        }
    }
}

impl std::error::Error for RolloutError {}

/// Result type alias for rollout operations.
pub type RolloutResult<T> = Result<T, RolloutError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_replay_display_includes_both_versions() {
        let err = RolloutError::VersionReplay {
            command_version: 3,
            current_version: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains('3'), "must contain command version");
        assert!(msg.contains('5'), "must contain current version");
    }

    #[test]
    fn digest_mismatch_display_includes_both_hashes() {
        let err = RolloutError::DigestMismatch {
            expected: "abc123".into(),
            actual: "def456".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("abc123"), "must contain expected hash");
        assert!(msg.contains("def456"), "must contain actual hash");
    }

    #[test]
    fn unauthorized_display_includes_spiffe_id() {
        let err = RolloutError::Unauthorized {
            spiffe_id: "spiffe://kernel-v1.test/agent/prod/node-1".into(),
            operation: "commit".into(),
            reason: "not policy-admin".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("spiffe://kernel-v1.test/agent/prod/node-1"));
        assert!(msg.contains("commit"));
    }

    #[test]
    fn all_variants_are_displayable() {
        let variants = [
            RolloutError::VersionReplay {
                command_version: 1,
                current_version: 2,
            },
            RolloutError::DigestMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            RolloutError::InvalidTransition {
                from: "Staging".into(),
                action: "commit".into(),
            },
            RolloutError::Unauthorized {
                spiffe_id: "spiffe://td/agent/c/n".into(),
                operation: "stage".into(),
                reason: "denied".into(),
            },
            RolloutError::NotFound {
                entity: "rollout".into(),
                key: "42".into(),
            },
            RolloutError::Timeout {
                rollout_id: 1,
                current_tick: 100,
                deadline_tick: 50,
            },
            RolloutError::AgentDigestMismatch {
                agent_id: "agent-1".into(),
                expected: "abc".into(),
                actual: "def".into(),
            },
            RolloutError::DuplicateCommand {
                description: "stage v1".into(),
            },
            RolloutError::AgentNotTargeted {
                agent_id: "agent-1".into(),
                rollout_id: 1,
            },
            RolloutError::VersionConflict {
                entity: "rollout".into(),
                expected: 1,
                found: 2,
            },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }
}
