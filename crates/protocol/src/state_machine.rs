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

use crate::control::PolicyStatus;
use crate::error::{ProtocolError, ProtocolResult};

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

/// The policy activation state machine. Validates transitions
/// and enforces monotonic version ordering.
#[derive(Debug)]
pub struct PolicyActivation {
    state: PolicyActivationState,
    staged_version: Option<u64>,
    staged_digest: Option<String>,
    monotonic_version: u64,
    /// Transition log for audit.
    transitions: Vec<String>,
}

impl Default for PolicyActivation {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyActivation {
    /// Create a fresh state machine at Idle, version 0.
    pub fn new() -> Self {
        Self {
            state: PolicyActivationState::Idle,
            staged_version: None,
            staged_digest: None,
            monotonic_version: 0,
            transitions: vec!["init: Idle".into()],
        }
    }

    /// Current state.
    pub fn state(&self) -> PolicyActivationState {
        self.state
    }

    /// Current monotonic version.
    pub fn monotonic_version(&self) -> u64 {
        self.monotonic_version
    }

    /// The staged version (if any).
    pub fn staged_version(&self) -> Option<u64> {
        self.staged_version
    }

    /// The transition log.
    pub fn transitions(&self) -> &[String] {
        &self.transitions
    }

    fn transition(&mut self, to: PolicyActivationState, reason: &str) {
        self.transitions
            .push(format!("{} -> {to}: {reason}", self.state));
        self.state = to;
    }

    /// **STAGE**: prepare the inactive generation with the new
    /// policy content.
    ///
    /// Valid from: Idle, Staged (idempotent re-stage), Rejected
    /// (re-attempt), Applied (new rollout with higher version).
    /// NOT valid from Ready or Committed (mid-transition).
    pub fn stage(&mut self, cmd: &StageCommand) -> ProtocolResult<()> {
        // Version must be strictly greater than monotonic.
        if cmd.version <= self.monotonic_version {
            return Err(ProtocolError::VersionReplay {
                command_version: cmd.version,
                current_version: self.monotonic_version,
            });
        }

        match self.state {
            PolicyActivationState::Idle
            | PolicyActivationState::Staged
            | PolicyActivationState::Rejected
            | PolicyActivationState::Applied => {
                self.staged_version = Some(cmd.version);
                self.staged_digest = Some(cmd.content_digest.clone());
                self.transition(
                    PolicyActivationState::Staged,
                    &format!("stage v{}", cmd.version),
                );
                Ok(())
            }
            PolicyActivationState::Ready | PolicyActivationState::Committed => {
                Err(ProtocolError::InvalidTransition {
                    from: self.state.to_string(),
                    action: "stage".into(),
                })
            }
        }
    }

    /// **VERIFY**: recompute the content digest and compare.
    /// Mismatch → Rejected.
    ///
    /// Valid from: Staged only.
    pub fn verify(&mut self, computed_digest: &str) -> ProtocolResult<()> {
        if self.state != PolicyActivationState::Staged {
            return Err(ProtocolError::InvalidTransition {
                from: self.state.to_string(),
                action: "verify".into(),
            });
        }

        let expected = self.staged_digest.clone().unwrap_or_default();
        if computed_digest != expected {
            self.transition(PolicyActivationState::Rejected, "digest mismatch");
            return Err(ProtocolError::DigestMismatch {
                expected,
                actual: computed_digest.to_string(),
            });
        }

        self.transition(PolicyActivationState::Ready, "digest verified");
        Ok(())
    }

    /// **COMMIT**: atomically flip the active/inactive
    /// generations.
    ///
    /// Valid from: Ready only. Duplicate COMMIT after Applied
    /// with the same version is a safe no-op (idempotent).
    pub fn commit(&mut self, cmd: &CommitCommand) -> ProtocolResult<()> {
        // Idempotent: duplicate COMMIT after APPLIED.
        if self.state == PolicyActivationState::Applied && self.staged_version == Some(cmd.version)
        {
            return Ok(());
        }

        if self.state != PolicyActivationState::Ready {
            return Err(ProtocolError::InvalidTransition {
                from: self.state.to_string(),
                action: "commit".into(),
            });
        }

        // Version must match the staged version.
        if self.staged_version != Some(cmd.version) {
            return Err(ProtocolError::VersionReplay {
                command_version: cmd.version,
                current_version: self.staged_version.unwrap_or(0),
            });
        }

        // Advance the monotonic version.
        if cmd.version <= self.monotonic_version {
            return Err(ProtocolError::VersionReplay {
                command_version: cmd.version,
                current_version: self.monotonic_version,
            });
        }
        self.monotonic_version = cmd.version;

        // Transient Committed state.
        self.transition(
            PolicyActivationState::Committed,
            &format!("commit v{}", cmd.version),
        );

        // Atomic generation flip.
        self.transition(PolicyActivationState::Applied, "generation flipped");
        Ok(())
    }

    /// **REJECT**: explicit rejection.
    ///
    /// Valid from any state except Idle.
    pub fn reject(&mut self, reason: &str) -> ProtocolResult<()> {
        if self.state == PolicyActivationState::Idle {
            return Err(ProtocolError::InvalidTransition {
                from: self.state.to_string(),
                action: "reject".into(),
            });
        }
        self.transition(PolicyActivationState::Rejected, reason);
        Ok(())
    }

    /// **RESET**: return to Idle (e.g. after rollback or
    /// loader death).
    pub fn reset(&mut self, reason: &str) {
        self.staged_version = None;
        self.staged_digest = None;
        self.transition(PolicyActivationState::Idle, reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
