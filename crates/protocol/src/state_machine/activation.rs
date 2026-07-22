// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Policy activation state machine implementation.

use crate::error::{ProtocolError, ProtocolResult};

use super::{CommitCommand, PolicyActivationState, StageCommand};

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
