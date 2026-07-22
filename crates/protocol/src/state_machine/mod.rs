// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Policy activation state machine.
//!
//! Typed mirror of the enforcement crate's
//! STAGE→READY→COMMIT→APPLIED/REJECTED lifecycle, exposed as a
//! protocol-level validator the control plane and agent share.
//!
//! States: `Idle → Staged → Ready → Committed → Applied` with
//! `Rejected` reachable from Staged (digest mismatch) or any
//! state (explicit rejection).
//!
//! Invariants:
//! - STAGE never activates.
//! - Digest/version mismatch → REJECTED.
//! - Monotonic version: commands with version <= current are
//!   rejected (stale/replay protection).
//! - Idempotent: duplicate STAGE overwrites; duplicate COMMIT
//!   after APPLIED with the same version is a no-op.

#![forbid(unsafe_code)]

mod activation;

pub use activation::PolicyActivation;

use crate::control::PolicyStatus;

/// The protocol-level policy activation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PolicyActivationState {
    /// No pending policy.
    Idle,
    /// STAGE received; candidate held in inactive buffer.
    Staged,
    /// Digest verified; ready for COMMIT.
    Ready,
    /// COMMIT received; generation flip in progress (transient).
    Committed,
    /// New generation is active.
    Applied,
    /// Candidate rejected (digest mismatch, version replay,
    /// invalid content).
    Rejected,
}

impl std::fmt::Display for PolicyActivationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Idle => "Idle",
            Self::Staged => "Staged",
            Self::Ready => "Ready",
            Self::Committed => "Committed",
            Self::Applied => "Applied",
            Self::Rejected => "Rejected",
        };
        f.write_str(name)
    }
}

impl From<PolicyActivationState> for PolicyStatus {
    fn from(s: PolicyActivationState) -> Self {
        match s {
            PolicyActivationState::Idle => PolicyStatus::Unspecified,
            PolicyActivationState::Staged => PolicyStatus::Staged,
            PolicyActivationState::Ready => PolicyStatus::Ready,
            PolicyActivationState::Committed => PolicyStatus::Committed,
            PolicyActivationState::Applied => PolicyStatus::Applied,
            PolicyActivationState::Rejected => PolicyStatus::Rejected,
        }
    }
}

/// A STAGE command at the protocol level.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StageCommand {
    /// Monotonic version. Must be > current.
    pub version: u64,
    /// SHA-256 hex digest of the canonical policy content.
    pub content_digest: String,
}

/// A COMMIT command at the protocol level.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitCommand {
    /// The version to commit. Must match the staged version.
    pub version: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProtocolError;

    fn stage_cmd(version: u64) -> StageCommand {
        StageCommand {
            version,
            content_digest: format!("digest-v{version}"),
        }
    }

    fn commit_cmd(version: u64) -> CommitCommand {
        CommitCommand { version }
    }

    #[test]
    fn happy_path_stage_verify_commit_applied() {
        let mut sm = PolicyActivation::new();
        assert_eq!(sm.state(), PolicyActivationState::Idle);

        sm.stage(&stage_cmd(1)).unwrap();
        assert_eq!(sm.state(), PolicyActivationState::Staged);

        sm.verify("digest-v1").unwrap();
        assert_eq!(sm.state(), PolicyActivationState::Ready);

        sm.commit(&commit_cmd(1)).unwrap();
        assert_eq!(sm.state(), PolicyActivationState::Applied);
        assert_eq!(sm.monotonic_version(), 1);
    }

    #[test]
    fn commit_before_ready_is_invalid() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        let err = sm.commit(&commit_cmd(1)).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::InvalidTransition {
                from: "Staged".into(),
                action: "commit".into(),
            }
        );
    }

    #[test]
    fn verify_before_stage_is_invalid() {
        let mut sm = PolicyActivation::new();
        let err = sm.verify("anything").unwrap_err();
        assert_eq!(
            err,
            ProtocolError::InvalidTransition {
                from: "Idle".into(),
                action: "verify".into(),
            }
        );
    }

    #[test]
    fn digest_mismatch_rejects() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        let err = sm.verify("wrong-digest").unwrap_err();
        assert_eq!(sm.state(), PolicyActivationState::Rejected);
        match err {
            ProtocolError::DigestMismatch { expected, actual } => {
                assert_eq!(expected, "digest-v1");
                assert_eq!(actual, "wrong-digest");
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn version_replay_rejected() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        sm.verify("digest-v1").unwrap();
        sm.commit(&commit_cmd(1)).unwrap();

        // Re-stage with same version → replay.
        let err = sm.stage(&stage_cmd(1)).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::VersionReplay {
                command_version: 1,
                current_version: 1,
            }
        );
    }

    #[test]
    fn stale_version_rejected() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(5)).unwrap();
        sm.verify("digest-v5").unwrap();
        sm.commit(&commit_cmd(5)).unwrap();

        let err = sm.stage(&stage_cmd(3)).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::VersionReplay {
                command_version: 3,
                current_version: 5,
            }
        );
    }

    #[test]
    fn idempotent_restage() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        // Re-stage with higher version is fine.
        sm.stage(&stage_cmd(2)).unwrap();
        assert_eq!(sm.state(), PolicyActivationState::Staged);
        assert_eq!(sm.staged_version(), Some(2));
    }

    #[test]
    fn idempotent_duplicate_commit() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        sm.verify("digest-v1").unwrap();
        sm.commit(&commit_cmd(1)).unwrap();
        // Duplicate COMMIT after APPLIED is a no-op.
        assert!(sm.commit(&commit_cmd(1)).is_ok());
        assert_eq!(sm.state(), PolicyActivationState::Applied);
    }

    #[test]
    fn commit_version_mismatch() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        sm.verify("digest-v1").unwrap();
        let err = sm.commit(&commit_cmd(2)).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::VersionReplay {
                command_version: 2,
                current_version: 1,
            }
        );
    }

    #[test]
    fn stage_from_ready_is_invalid() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        sm.verify("digest-v1").unwrap();
        let err = sm.stage(&stage_cmd(2)).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::InvalidTransition {
                from: "Ready".into(),
                action: "stage".into(),
            }
        );
    }

    #[test]
    fn reject_from_idle_is_invalid() {
        let mut sm = PolicyActivation::new();
        let err = sm.reject("no reason").unwrap_err();
        assert_eq!(
            err,
            ProtocolError::InvalidTransition {
                from: "Idle".into(),
                action: "reject".into(),
            }
        );
    }

    #[test]
    fn reject_from_staged() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        sm.reject("operator cancel").unwrap();
        assert_eq!(sm.state(), PolicyActivationState::Rejected);
    }

    #[test]
    fn restage_after_rejected() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        sm.reject("bad policy").unwrap();
        // Re-attempt with higher version.
        sm.stage(&stage_cmd(2)).unwrap();
        assert_eq!(sm.state(), PolicyActivationState::Staged);
    }

    #[test]
    fn reset_returns_to_idle() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        sm.verify("digest-v1").unwrap();
        sm.commit(&commit_cmd(1)).unwrap();
        sm.reset("rollback");
        assert_eq!(sm.state(), PolicyActivationState::Idle);
        assert_eq!(sm.staged_version(), None);
    }

    #[test]
    fn new_rollout_after_applied() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        sm.verify("digest-v1").unwrap();
        sm.commit(&commit_cmd(1)).unwrap();
        // New rollout with higher version.
        sm.stage(&stage_cmd(2)).unwrap();
        assert_eq!(sm.state(), PolicyActivationState::Staged);
        sm.verify("digest-v2").unwrap();
        sm.commit(&commit_cmd(2)).unwrap();
        assert_eq!(sm.state(), PolicyActivationState::Applied);
        assert_eq!(sm.monotonic_version(), 2);
    }

    #[test]
    fn transition_log_records_all() {
        let mut sm = PolicyActivation::new();
        sm.stage(&stage_cmd(1)).unwrap();
        sm.verify("digest-v1").unwrap();
        sm.commit(&commit_cmd(1)).unwrap();
        // init + stage + verify + committed + applied = 5
        assert_eq!(sm.transitions().len(), 5);
    }

    #[test]
    fn state_converts_to_policy_status() {
        assert_eq!(
            PolicyStatus::from(PolicyActivationState::Staged),
            PolicyStatus::Staged
        );
        assert_eq!(
            PolicyStatus::from(PolicyActivationState::Applied),
            PolicyStatus::Applied
        );
        assert_eq!(
            PolicyStatus::from(PolicyActivationState::Rejected),
            PolicyStatus::Rejected
        );
    }
}
