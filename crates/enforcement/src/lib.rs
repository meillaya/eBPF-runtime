// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent-side staged policy activation (task 34).
//!
//! This crate implements the enforcement lifecycle:
//!
//! - **Double-buffered policy map generations**: active/inactive
//!   buffers for atomic flip. The BPF LSM engine reads the active
//!   generation; STAGE writes to the inactive buffer; COMMIT swaps
//!   them in a single pointer exchange.
//!
//! - **Content digest verification**: every STAGE command carries a
//!   SHA-256 digest. VERIFY recomputes and compares; mismatch →
//!   REJECTED.
//!
//! - **STAGE→READY→COMMIT→APPLIED/REJECTED state machine**: explicit
//!   transitions, no silent activation. STAGE prepares; COMMIT
//!   activates.
//!
//! - **Monotonic version / replay checks**: commands with
//!   version ≤ current are rejected (stale/replay protection).
//!
//! - **Idempotent commands**: duplicate STAGE overwrites the
//!   inactive buffer (safe); duplicate COMMIT after APPLIED is a
//!   no-op.
//!
//! - **Atomic generation flip**: COMMIT swaps active/inactive in
//!   one step. The previous active is retained for rollback.
//!
//! - **Last-known-good offline state**: the applied generation is
//!   persisted to disk. On restart, it is restored in audit-only
//!   mode (startup audit-only invariant).
//!
//! - **Kill switch**: immediate config-map flip (deny_disabled=1)
//!   suppresses all deny-mode policies to audit-only within
//!   kill_switch_max_ms.
//!
//! - **Rollback**: revert to the previous generation on failure.
//!
//! - **Startup audit-only**: every policy starts in audit mode
//!   (mode=0), even after restore from persisted state.
//!
//! - **Explicit non-pinning of enforcement links**: deny links are
//!   NEVER pinned. Observation links may use distinct pin roots.
//!
//! - **Loader-death fail-open**: if the loader dies, deny links are
//!   detached; observation policy follows its separate
//!   configuration.
//!
//! # Schema anchor
//!
//! All numeric constants are anchored in
//! `bench/schemas/enforcement.v1.json`:
//! - `kill_switch_max_ms` = 5000
//! - `kill_switch_benchmark_pairs` = 10
//! - `audit_first_default_mode` = 0
//! - `max_policy_entries` = 4
//! - `selector_max_bytes` = 256

#![forbid(unsafe_code)]

mod digest;
mod error;
mod kill_switch;
mod persistence;
mod policy;
mod state_machine;

pub use digest::{sha256_hex, verify_digest};
pub use error::EnforcementError;
pub use kill_switch::{benchmark_kill_switch, KillSwitch, KillSwitchBenchmark};
pub use persistence::{
    load_last_known_good, persist_last_known_good, PersistenceManager, DEFAULT_LKG_PATH,
};
pub use policy::{
    HookFamily, PolicyEntry, PolicyGeneration, PolicyMap, PolicyMode, POLICY_SLOTS,
    SELECTOR_MAX_BYTES,
};
pub use state_machine::{CommitCommand, EnforcementStateMachine, StageCommand, State};

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Full lifecycle: stage → verify → commit → applied →
    /// rollback → re-stage → re-commit.
    #[test]
    fn full_lifecycle() {
        let mut sm = EnforcementStateMachine::new();

        // Stage a deny policy for file_open.
        let entry = PolicyEntry::new_audit(HookFamily::FileOpen, 1, 1)
            .with_selector(b"/etc/shadow")
            .with_deny(-13);
        let digest =
            EnforcementStateMachine::compute_digest_for_entries(std::slice::from_ref(&entry), 1, 1);
        let stage_cmd = StageCommand {
            version: 1,
            entries: vec![entry],
            content_digest: digest,
        };

        sm.stage(&stage_cmd).unwrap();
        assert_eq!(sm.state(), State::Staged);

        sm.verify().unwrap();
        assert_eq!(sm.state(), State::Ready);

        sm.commit(&CommitCommand { version: 1 }).unwrap();
        assert_eq!(sm.state(), State::Applied);

        // Active generation has deny.
        assert_eq!(
            sm.policy_map()
                .active()
                .entry_for(HookFamily::FileOpen)
                .unwrap()
                .mode,
            PolicyMode::Deny
        );

        // Rollback.
        sm.rollback().unwrap();
        assert_eq!(
            sm.policy_map()
                .active()
                .entry_for(HookFamily::FileOpen)
                .unwrap()
                .mode,
            PolicyMode::Audit
        );
    }

    /// Kill switch engages and disengages within threshold.
    #[test]
    fn kill_switch_within_threshold() {
        let result = benchmark_kill_switch(10, 5000);
        assert!(result.within_threshold);
    }

    /// Persistence roundtrip: save applied generation, restore
    /// in audit-only mode.
    #[test]
    fn persistence_startup_audit_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lkg.json");
        let mgr = PersistenceManager::new(&path);

        // Create a generation with deny.
        let mut gen = PolicyGeneration::new_audit_only(3);
        gen.entry_for_mut(HookFamily::BprmExec).unwrap().mode = PolicyMode::Deny;
        gen.entry_for_mut(HookFamily::BprmExec).unwrap().version = 10;

        mgr.save(&gen).unwrap();

        // Restore.
        let loaded = mgr.load().unwrap().unwrap();
        let sm = EnforcementStateMachine::from_persisted(loaded);

        // Startup audit-only: deny forced to audit.
        assert_eq!(
            sm.policy_map()
                .active()
                .entry_for(HookFamily::BprmExec)
                .unwrap()
                .mode,
            PolicyMode::Audit
        );
        // Monotonic version preserved.
        assert!(sm.policy_map().monotonic_version() >= 10);
    }

    /// Loader death: fail-open, no further staging.
    #[test]
    fn loader_death_fail_open() {
        let mut sm = EnforcementStateMachine::new();
        sm.on_loader_death();
        assert!(!sm.loader_alive());
        assert!(!sm.deny_links_pinned());

        let entry =
            PolicyEntry::new_audit(HookFamily::FileOpen, 1, 1).with_selector(b"/etc/shadow");
        let digest =
            EnforcementStateMachine::compute_digest_for_entries(std::slice::from_ref(&entry), 1, 1);
        let cmd = StageCommand {
            version: 1,
            entries: vec![entry],
            content_digest: digest,
        };
        assert!(matches!(sm.stage(&cmd), Err(EnforcementError::LoaderDead)));
    }

    /// Deny links are never pinned, even after commit.
    #[test]
    fn deny_links_never_pinned_after_commit() {
        let mut sm = EnforcementStateMachine::new();
        let entry = PolicyEntry::new_audit(HookFamily::FileOpen, 1, 1)
            .with_selector(b"/etc/shadow")
            .with_deny(-13);
        let digest =
            EnforcementStateMachine::compute_digest_for_entries(std::slice::from_ref(&entry), 1, 1);
        let cmd = StageCommand {
            version: 1,
            entries: vec![entry],
            content_digest: digest,
        };
        sm.stage(&cmd).unwrap();
        sm.verify().unwrap();
        sm.commit(&CommitCommand { version: 1 }).unwrap();
        assert!(!sm.deny_links_pinned());
        assert!(!sm.policy_map().deny_links_pinned());
    }

    /// Disconnect does NOT auto-relax last-known-good.
    #[test]
    fn disconnect_does_not_auto_relax_lkg() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lkg.json");
        let mgr = PersistenceManager::new(&path);

        let mut gen = PolicyGeneration::new_audit_only(5);
        gen.entry_for_mut(HookFamily::FileOpen).unwrap().mode = PolicyMode::Deny;
        gen.entry_for_mut(HookFamily::FileOpen).unwrap().version = 20;
        mgr.save(&gen).unwrap();

        // Simulate disconnect: loader dies.
        let mut sm = EnforcementStateMachine::new();
        sm.on_loader_death();

        // LKG file is unchanged.
        let loaded = mgr.load().unwrap().unwrap();
        assert_eq!(
            loaded.entry_for(HookFamily::FileOpen).unwrap().mode,
            PolicyMode::Deny
        );
        assert_eq!(loaded.generation, 5);
    }
}
