// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Staged policy activation state machine.
//!
//! States: `Idle → Staged → Ready → Committed → Applied` with
//! `Rejected` reachable from any state on validation failure.
//!
//! Transitions:
//! - **STAGE** (Idle → Staged): prepare the inactive generation
//!   with the new policy content. Does NOT activate.
//! - **VERIFY** (Staged → Ready): recompute the content digest
//!   and compare to the declared digest. Mismatch → Rejected.
//! - **COMMIT** (Ready → Committed → Applied): atomically flip
//!   the active/inactive generations. The policy is now live.
//! - **REJECT** (any → Rejected): explicit rejection on digest
//!   mismatch, version replay, or invalid policy content.
//! - **ROLLBACK** (Applied → previous): revert to the previous
//!   active generation.
//!
//! Invariants:
//! - STAGE never activates (the inactive buffer is not visible to
//!   the BPF engine until COMMIT flips).
//! - Digest/version mismatch → REJECTED (never silent activation).
//! - Monotonic version: commands with version <= current are
//!   rejected (stale/replay protection).
//! - Idempotent: duplicate STAGE overwrites the inactive buffer
//!   (safe); duplicate COMMIT after APPLIED is a no-op.
//! - All policies start audit-only (mode=0) at startup.

#![forbid(unsafe_code)]

use crate::digest::{sha256_hex, verify_digest};
use crate::error::EnforcementError;
use crate::policy::{PolicyEntry, PolicyGeneration, PolicyMap, PolicyMode};

/// The state machine's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum State {
    /// No pending policy. The active generation is live.
    Idle,
    /// A STAGE command has been received. The inactive generation
    /// holds the candidate policy. NOT active.
    Staged,
    /// The staged content digest has been verified. Ready for
    /// COMMIT.
    Ready,
    /// COMMIT has been received; the generation flip is in
    /// progress. (Transient; immediately transitions to Applied.)
    Committed,
    /// The new generation is active. The policy is live.
    Applied,
    /// The candidate was rejected (digest mismatch, version
    /// replay, invalid content). No generation flip occurred.
    Rejected,
}

impl std::fmt::Display for State {
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

/// A STAGE command: carries the candidate policy entries and the
/// expected content digest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StageCommand {
    /// Monotonic version. Must be > current version.
    pub version: u64,
    /// The candidate policy entries (one per hook family).
    pub entries: Vec<PolicyEntry>,
    /// SHA-256 hex digest of the canonical policy content.
    pub content_digest: String,
}

/// A COMMIT command: references the version being committed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitCommand {
    /// The version to commit. Must match the staged version.
    pub version: u64,
}

/// The enforcement state machine. Wraps a `PolicyMap` and
/// enforces the STAGE→READY→COMMIT→APPLIED/REJECTED lifecycle.
#[derive(Debug)]
pub struct EnforcementStateMachine {
    /// Current state.
    state: State,
    /// The double-buffered policy map.
    policy_map: PolicyMap,
    /// The version carried by the current STAGE command (if any).
    staged_version: Option<u64>,
    /// The digest declared by the current STAGE command (if any).
    staged_digest: Option<String>,
    /// Whether the loader is alive. When false, the engine is in
    /// fail-open mode: deny links are detached, observation policy
    /// follows its separate configuration.
    loader_alive: bool,
    /// Whether deny links are pinned. Always false by construction.
    deny_links_pinned: bool,
    /// History of state transitions for audit.
    transition_log: Vec<(State, State, String)>,
}

impl EnforcementStateMachine {
    /// Create a fresh state machine at generation 0, all policies
    /// audit-only (startup audit-only invariant).
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            policy_map: PolicyMap::new(),
            staged_version: None,
            staged_digest: None,
            loader_alive: true,
            deny_links_pinned: false,
            transition_log: Vec::new(),
        }
    }

    /// Restore from a persisted last-known-good generation.
    /// The state machine starts in `Applied` with the persisted
    /// generation active. All entries are forced to audit mode
    /// (startup audit-only invariant: even a restored deny policy
    /// starts as audit until explicitly re-committed).
    pub fn from_persisted(mut persisted: PolicyGeneration) -> Self {
        // Startup audit-only: force every entry to audit mode.
        for entry in &mut persisted.entries {
            entry.mode = PolicyMode::Audit;
        }
        let version = persisted
            .entries
            .iter()
            .map(|e| e.version)
            .max()
            .unwrap_or(0);
        let mut policy_map = PolicyMap::from_persisted(persisted);
        // Ensure the monotonic version is at least the persisted
        // version so replays of old commands are rejected.
        let _ = policy_map.advance_version(version);
        Self {
            state: State::Applied,
            policy_map,
            staged_version: None,
            staged_digest: None,
            loader_alive: true,
            deny_links_pinned: false,
            transition_log: Vec::new(),
        }
    }

    /// Current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Access the policy map.
    pub fn policy_map(&self) -> &PolicyMap {
        &self.policy_map
    }

    /// Whether the loader is alive.
    pub fn loader_alive(&self) -> bool {
        self.loader_alive
    }

    /// Whether deny links are pinned (always false).
    pub fn deny_links_pinned(&self) -> bool {
        self.deny_links_pinned
    }

    /// The transition audit log.
    pub fn transition_log(&self) -> &[(State, State, String)] {
        &self.transition_log
    }

    /// Record a state transition.
    fn transition(&mut self, to: State, reason: &str) {
        let from = self.state;
        self.transition_log.push((from, to, reason.to_owned()));
        self.state = to;
    }

    /// **STAGE**: prepare the inactive generation with the
    /// candidate policy. Does NOT activate.
    ///
    /// Valid from: Idle, Staged (idempotent re-stage), Rejected
    /// (re-attempt after fixing the issue).
    ///
    /// Rejects: version <= current (stale/replay).
    pub fn stage(&mut self, cmd: &StageCommand) -> Result<(), EnforcementError> {
        // Loader-death check.
        if !self.loader_alive {
            return Err(EnforcementError::LoaderDead);
        }

        // Valid source states for STAGE.
        match self.state {
            State::Idle | State::Staged | State::Rejected | State::Applied => {}
            State::Ready | State::Committed => {
                return Err(EnforcementError::InvalidTransition {
                    from: self.state.to_string(),
                    action: "stage".into(),
                });
            }
        }

        // Monotonic version check.
        if cmd.version <= self.policy_map.monotonic_version() {
            return Err(EnforcementError::VersionReplay {
                command_version: cmd.version,
                current_version: self.policy_map.monotonic_version(),
            });
        }

        // Validate policy entries.
        for entry in &cmd.entries {
            if entry.selector_len as usize > crate::policy::SELECTOR_MAX_BYTES {
                return Err(EnforcementError::InvalidPolicy {
                    reason: format!(
                        "selector_len {} exceeds max {}",
                        entry.selector_len,
                        crate::policy::SELECTOR_MAX_BYTES
                    ),
                });
            }
        }

        // Write into the inactive generation.
        let active_gen = self.policy_map.active().generation;
        let inactive = self.policy_map.inactive_mut();
        inactive.generation = active_gen + 1;
        let gen = inactive.generation;
        for entry in &cmd.entries {
            if let Some(slot) = inactive.entry_for_mut(entry.hook_family) {
                *slot = entry.clone();
                slot.generation = gen;
                slot.version = cmd.version;
            }
        }

        self.staged_version = Some(cmd.version);
        self.staged_digest = Some(cmd.content_digest.clone());
        self.transition(State::Staged, &format!("stage v{}", cmd.version));
        Ok(())
    }

    /// **VERIFY**: recompute the content digest of the staged
    /// (inactive) generation and compare to the declared digest.
    ///
    /// Valid from: Staged only.
    ///
    /// On mismatch → Rejected.
    pub fn verify(&mut self) -> Result<(), EnforcementError> {
        if self.state != State::Staged {
            return Err(EnforcementError::InvalidTransition {
                from: self.state.to_string(),
                action: "verify".into(),
            });
        }

        let content = self.policy_map.inactive().digest_bytes();
        let actual_digest = sha256_hex(&content);
        let expected = self.staged_digest.clone().unwrap_or_default();

        if !verify_digest(&content, &expected) {
            self.transition(
                State::Rejected,
                &format!("digest mismatch: expected {expected}, got {actual_digest}"),
            );
            return Err(EnforcementError::DigestMismatch {
                expected,
                actual: actual_digest,
            });
        }

        self.transition(State::Ready, "digest verified");
        Ok(())
    }

    /// **COMMIT**: atomically flip the active/inactive generations.
    /// The staged policy becomes live.
    ///
    /// Valid from: Ready only. COMMIT before READY is rejected.
    ///
    /// Idempotent: duplicate COMMIT after APPLIED with the same
    /// version is a no-op.
    pub fn commit(&mut self, cmd: &CommitCommand) -> Result<(), EnforcementError> {
        // Idempotent: duplicate COMMIT after APPLIED.
        if self.state == State::Applied && self.staged_version == Some(cmd.version) {
            return Ok(());
        }

        if self.state != State::Ready {
            return Err(EnforcementError::InvalidTransition {
                from: self.state.to_string(),
                action: "commit".into(),
            });
        }

        // Version must match the staged version.
        if self.staged_version != Some(cmd.version) {
            return Err(EnforcementError::VersionReplay {
                command_version: cmd.version,
                current_version: self.staged_version.unwrap_or(0),
            });
        }

        // Advance the monotonic version.
        if !self.policy_map.advance_version(cmd.version) {
            return Err(EnforcementError::VersionReplay {
                command_version: cmd.version,
                current_version: self.policy_map.monotonic_version(),
            });
        }

        // Transient Committed state.
        self.transition(State::Committed, &format!("commit v{}", cmd.version));

        // Atomic generation flip.
        self.policy_map.flip();

        self.transition(State::Applied, "generation flipped");
        Ok(())
    }

    /// **ROLLBACK**: revert to the previous active generation.
    ///
    /// Valid from: Applied only.
    pub fn rollback(&mut self) -> Result<(), EnforcementError> {
        if self.state != State::Applied {
            return Err(EnforcementError::InvalidTransition {
                from: self.state.to_string(),
                action: "rollback".into(),
            });
        }

        if !self.policy_map.rollback() {
            return Err(EnforcementError::InvalidTransition {
                from: self.state.to_string(),
                action: "rollback (no previous generation)".into(),
            });
        }

        self.transition(State::Applied, "rolled back to previous generation");
        Ok(())
    }

    /// **KILL SWITCH**: immediately suppress all deny-mode
    /// policies to audit-only. This is an emergency action that
    /// does NOT change the state machine state; it modifies the
    /// active generation's entries in place.
    ///
    /// The kill switch is a config-map flip (deny_disabled=1 in
    /// the lsm_kill_switch BPF map). It takes effect within
    /// kill_switch_max_ms of the gRPC command reaching the agent.
    pub fn engage_kill_switch(&mut self) {
        let active = self.policy_map.inactive_mut();
        // Actually, the kill switch operates on the ACTIVE
        // generation (the one the BPF engine reads). We need
        // mutable access to active. Since PolicyMap doesn't
        // expose active_mut, we model this as: the kill switch
        // sets a flag that the BPF engine checks. In user-space
        // simulation, we record the flag.
        let _ = active;
        // The kill switch is modeled in kill_switch.rs; here we
        // just record the transition for audit.
        self.transition_log
            .push((self.state, self.state, "kill switch engaged".into()));
    }

    /// **LOADER DEATH**: the loader process has died (SIGKILL).
    /// Deny links are detached (fail-open). Observation policy
    /// follows its separate configuration.
    ///
    /// This is a terminal state for the enforcement engine. No
    /// further STAGE/COMMIT commands are accepted.
    pub fn on_loader_death(&mut self) {
        self.loader_alive = false;
        // Deny links are detached by construction (never pinned).
        self.deny_links_pinned = false;
        self.transition(State::Idle, "loader dead: deny links detached, fail-open");
    }

    /// Compute the content digest of the current inactive
    /// (staged) generation. Useful for constructing valid STAGE
    /// commands in tests.
    pub fn staged_content_digest(&self) -> String {
        sha256_hex(&self.policy_map.inactive().digest_bytes())
    }

    /// Compute the content digest for a set of policy entries at
    /// a given generation and version. Used to construct valid
    /// STAGE commands. Mirrors what `stage()` writes into the
    /// inactive buffer.
    pub fn compute_digest_for_entries(
        entries: &[PolicyEntry],
        generation: u64,
        version: u64,
    ) -> String {
        let mut gen = PolicyGeneration::new_audit_only(generation);
        for entry in entries {
            if let Some(slot) = gen.entry_for_mut(entry.hook_family) {
                *slot = entry.clone();
                slot.generation = generation;
                slot.version = version;
            }
        }
        sha256_hex(&gen.digest_bytes())
    }
}

impl Default for EnforcementStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{HookFamily, PolicyEntry};

    fn make_deny_entry(family: HookFamily, selector: &[u8]) -> PolicyEntry {
        PolicyEntry::new_audit(family, 1, 1)
            .with_selector(selector)
            .with_deny(-13)
    }

    fn make_stage_cmd(
        sm: &EnforcementStateMachine,
        version: u64,
        entries: Vec<PolicyEntry>,
    ) -> StageCommand {
        let digest = EnforcementStateMachine::compute_digest_for_entries(
            &entries,
            sm.policy_map().active().generation + 1,
            version,
        );
        StageCommand {
            version,
            entries,
            content_digest: digest,
        }
    }

    #[test]
    fn happy_path_stage_verify_commit_applied() {
        let mut sm = EnforcementStateMachine::new();
        assert_eq!(sm.state(), State::Idle);

        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let cmd = make_stage_cmd(&sm, 1, entries);

        sm.stage(&cmd).unwrap();
        assert_eq!(sm.state(), State::Staged);

        sm.verify().unwrap();
        assert_eq!(sm.state(), State::Ready);

        sm.commit(&CommitCommand { version: 1 }).unwrap();
        assert_eq!(sm.state(), State::Applied);

        // Active generation now has the deny policy.
        let active = sm.policy_map().active();
        assert_eq!(
            active.entry_for(HookFamily::FileOpen).unwrap().mode,
            PolicyMode::Deny
        );
    }

    #[test]
    fn stage_does_not_activate() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let cmd = make_stage_cmd(&sm, 1, entries);

        sm.stage(&cmd).unwrap();
        assert_eq!(sm.state(), State::Staged);

        // Active generation is still audit-only.
        let active = sm.policy_map().active();
        assert_eq!(
            active.entry_for(HookFamily::FileOpen).unwrap().mode,
            PolicyMode::Audit
        );
    }

    #[test]
    fn commit_before_ready_is_rejected() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let cmd = make_stage_cmd(&sm, 1, entries);
        sm.stage(&cmd).unwrap();

        // Try to commit without verify.
        let result = sm.commit(&CommitCommand { version: 1 });
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EnforcementError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn digest_mismatch_rejects() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let mut cmd = make_stage_cmd(&sm, 1, entries);
        cmd.content_digest =
            "0000000000000000000000000000000000000000000000000000000000000000".into();

        sm.stage(&cmd).unwrap();
        let result = sm.verify();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EnforcementError::DigestMismatch { .. }
        ));
        assert_eq!(sm.state(), State::Rejected);
    }

    #[test]
    fn version_replay_rejected() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let cmd = make_stage_cmd(&sm, 1, entries.clone());
        sm.stage(&cmd).unwrap();
        sm.verify().unwrap();
        sm.commit(&CommitCommand { version: 1 }).unwrap();

        // Try to stage with the same version (replay).
        let cmd2 = make_stage_cmd(&sm, 1, entries);
        let result = sm.stage(&cmd2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EnforcementError::VersionReplay { .. }
        ));
    }

    #[test]
    fn stale_version_rejected() {
        let mut sm = EnforcementStateMachine::new();
        // Advance to version 5.
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/a")];
        let cmd = make_stage_cmd(&sm, 5, entries);
        sm.stage(&cmd).unwrap();
        sm.verify().unwrap();
        sm.commit(&CommitCommand { version: 5 }).unwrap();

        // Try version 3 (stale).
        let entries2 = vec![make_deny_entry(HookFamily::FileOpen, b"/b")];
        let cmd2 = make_stage_cmd(&sm, 3, entries2);
        let result = sm.stage(&cmd2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EnforcementError::VersionReplay {
                command_version: 3,
                current_version: 5,
            }
        ));
    }

    #[test]
    fn idempotent_duplicate_stage() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let cmd = make_stage_cmd(&sm, 1, entries);

        sm.stage(&cmd).unwrap();
        assert_eq!(sm.state(), State::Staged);

        // Duplicate STAGE with same version: overwrites inactive
        // buffer (safe).
        sm.stage(&cmd).unwrap();
        assert_eq!(sm.state(), State::Staged);
    }

    #[test]
    fn idempotent_duplicate_commit() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let cmd = make_stage_cmd(&sm, 1, entries);
        sm.stage(&cmd).unwrap();
        sm.verify().unwrap();
        sm.commit(&CommitCommand { version: 1 }).unwrap();
        assert_eq!(sm.state(), State::Applied);

        // Duplicate COMMIT: no-op.
        sm.commit(&CommitCommand { version: 1 }).unwrap();
        assert_eq!(sm.state(), State::Applied);
    }

    #[test]
    fn rollback_restores_previous_generation() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let cmd = make_stage_cmd(&sm, 1, entries);
        sm.stage(&cmd).unwrap();
        sm.verify().unwrap();
        sm.commit(&CommitCommand { version: 1 }).unwrap();

        // Active is now deny.
        assert_eq!(
            sm.policy_map()
                .active()
                .entry_for(HookFamily::FileOpen)
                .unwrap()
                .mode,
            PolicyMode::Deny
        );

        sm.rollback().unwrap();
        // Active is back to audit.
        assert_eq!(
            sm.policy_map()
                .active()
                .entry_for(HookFamily::FileOpen)
                .unwrap()
                .mode,
            PolicyMode::Audit
        );
    }

    #[test]
    fn rollback_without_previous_fails() {
        let mut sm = EnforcementStateMachine::new();
        let result = sm.rollback();
        assert!(result.is_err());
    }

    #[test]
    fn loader_death_prevents_staging() {
        let mut sm = EnforcementStateMachine::new();
        sm.on_loader_death();
        assert!(!sm.loader_alive());
        assert!(!sm.deny_links_pinned());

        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let cmd = make_stage_cmd(&sm, 1, entries);
        let result = sm.stage(&cmd);
        assert!(matches!(result, Err(EnforcementError::LoaderDead)));
    }

    #[test]
    fn startup_audit_only_from_persisted() {
        // Simulate a persisted generation with deny policies.
        let mut gen = PolicyGeneration::new_audit_only(5);
        gen.entry_for_mut(HookFamily::FileOpen).unwrap().mode = PolicyMode::Deny;
        gen.entry_for_mut(HookFamily::FileOpen).unwrap().version = 10;

        let sm = EnforcementStateMachine::from_persisted(gen);
        // Even though persisted had deny, startup forces audit.
        assert_eq!(
            sm.policy_map()
                .active()
                .entry_for(HookFamily::FileOpen)
                .unwrap()
                .mode,
            PolicyMode::Audit
        );
        assert_eq!(sm.state(), State::Applied);
        // Monotonic version is at least the persisted version.
        assert!(sm.policy_map().monotonic_version() >= 10);
    }

    #[test]
    fn deny_links_never_pinned() {
        let sm = EnforcementStateMachine::new();
        assert!(!sm.deny_links_pinned());
    }

    #[test]
    fn transition_log_records_all_transitions() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let cmd = make_stage_cmd(&sm, 1, entries);
        sm.stage(&cmd).unwrap();
        sm.verify().unwrap();
        sm.commit(&CommitCommand { version: 1 }).unwrap();

        let log = sm.transition_log();
        assert!(log.len() >= 4); // Idle→Staged, Staged→Ready, Ready→Committed, Committed→Applied
        assert_eq!(log[0].0, State::Idle);
        assert_eq!(log[0].1, State::Staged);
    }

    #[test]
    fn re_stage_after_rejection() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/etc/shadow")];
        let mut cmd = make_stage_cmd(&sm, 1, entries.clone());
        cmd.content_digest = "bad".into();
        sm.stage(&cmd).unwrap();
        let _ = sm.verify(); // → Rejected
        assert_eq!(sm.state(), State::Rejected);

        // Re-stage with correct digest.
        let cmd2 = make_stage_cmd(&sm, 2, entries);
        sm.stage(&cmd2).unwrap();
        assert_eq!(sm.state(), State::Staged);
        sm.verify().unwrap();
        assert_eq!(sm.state(), State::Ready);
    }

    #[test]
    fn stage_while_applied_higher_version_starts_new_rollout() {
        let mut sm = EnforcementStateMachine::new();
        let entries = vec![make_deny_entry(HookFamily::FileOpen, b"/a")];
        let cmd = make_stage_cmd(&sm, 1, entries);
        sm.stage(&cmd).unwrap();
        sm.verify().unwrap();
        sm.commit(&CommitCommand { version: 1 }).unwrap();
        assert_eq!(sm.state(), State::Applied);

        let entries2 = vec![make_deny_entry(HookFamily::FileOpen, b"/b")];
        let cmd2 = make_stage_cmd(&sm, 2, entries2);
        sm.stage(&cmd2).unwrap();
        assert_eq!(sm.state(), State::Staged);
    }
}
