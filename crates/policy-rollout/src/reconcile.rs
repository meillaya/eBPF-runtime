// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Reconnect reconciliation for fleet policy rollout.
//!
//! When an agent reconnects, the control plane compares the
//! agent's reported state (active version, staged version) with
//! the expected state and determines the corrective action.
//!
//! Invariants:
//! - Disconnect does NOT relax the active policy (last-known-good
//!   maintained).
//! - Stale/replayed versions are rejected (monotonic check).
//! - Reconciliation is idempotent.
//! - All reconciliation actions are audited.

#![forbid(unsafe_code)]

use crate::audit::AuditLog;
use crate::error::RolloutResult;
use crate::model::{AgentStatusReport, ReconcileAction};
use crate::store::LastKnownGoodStore;

/// Reconciliation engine: determines corrective actions when an
/// agent reconnects.
#[derive(Debug)]
pub struct Reconciler {
    /// Reference to the last-known-good store.
    last_known_good: LastKnownGoodStore,
    /// The current fleet-wide active version.
    active_version: u64,
    /// The current staged version (if a rollout is in progress).
    staged_version: Option<u64>,
}

impl Reconciler {
    /// Create a new reconciler with the current fleet state.
    pub fn new(
        last_known_good: LastKnownGoodStore,
        active_version: u64,
        staged_version: Option<u64>,
    ) -> Self {
        Self {
            last_known_good,
            active_version,
            staged_version,
        }
    }

    /// Reconcile an agent's reported state with the expected
    /// state. Returns the corrective action.
    ///
    /// Decision logic:
    /// 1. If agent's active version == fleet active version →
    ///    UpToDate (check staged too).
    /// 2. If agent's active version > fleet active version →
    ///    AgentAhead (server state is stale).
    /// 3. If agent's active version < fleet active version →
    ///    AgentBehind (needs re-stage).
    /// 4. If agent has a staged version matching the current
    ///    rollout → Commit (agent missed the COMMIT).
    /// 5. If agent has a stale staged version → ReStage.
    pub fn reconcile(
        &self,
        report: &AgentStatusReport,
        audit: &mut AuditLog,
        tick: u64,
    ) -> RolloutResult<ReconcileAction> {
        let agent_id = &report.agent_spiffe_id;

        // Case 1: Agent is ahead of the fleet.
        if report.active_version > self.active_version {
            audit.append_success(
                agent_id,
                "reconcile.agent_ahead",
                &format!("agent:{agent_id}"),
                &format!(
                    "{{\"agent_version\":{},\"fleet_version\":{}}}",
                    report.active_version, self.active_version
                ),
                tick,
            );
            return Ok(ReconcileAction::AgentAhead {
                agent_version: report.active_version,
            });
        }

        // Case 2: Agent is behind the fleet.
        if report.active_version < self.active_version {
            audit.append_success(
                agent_id,
                "reconcile.agent_behind",
                &format!("agent:{agent_id}"),
                &format!(
                    "{{\"agent_version\":{},\"expected_version\":{}}}",
                    report.active_version, self.active_version
                ),
                tick,
            );
            return Ok(ReconcileAction::AgentBehind {
                agent_version: report.active_version,
                expected_version: self.active_version,
            });
        }

        // Case 3: Agent's active version matches. Check staged.
        if let Some(expected_staged) = self.staged_version {
            match report.staged_version {
                Some(agent_staged) if agent_staged == expected_staged => {
                    // Agent has the correct staged version.
                    // It may need a COMMIT.
                    audit.append_success(
                        agent_id,
                        "reconcile.commit_needed",
                        &format!("agent:{agent_id}"),
                        &format!("{{\"staged_version\":{agent_staged}}}"),
                        tick,
                    );
                    return Ok(ReconcileAction::Commit {
                        version: expected_staged,
                    });
                }
                Some(agent_staged) if agent_staged < expected_staged => {
                    // Agent has a stale staged version.
                    audit.append_success(
                        agent_id,
                        "reconcile.restage",
                        &format!("agent:{agent_id}"),
                        &format!(
                            "{{\"stale_version\":{agent_staged},\"expected_version\":{expected_staged}}}"
                        ),
                        tick,
                    );
                    return Ok(ReconcileAction::ReStage {
                        version: expected_staged,
                    });
                }
                Some(agent_staged) => {
                    // Agent has a newer staged version (shouldn't
                    // happen, but handle gracefully).
                    audit.append_success(
                        agent_id,
                        "reconcile.agent_ahead_staged",
                        &format!("agent:{agent_id}"),
                        &format!(
                            "{{\"agent_staged\":{agent_staged},\"expected_staged\":{expected_staged}}}"
                        ),
                        tick,
                    );
                    return Ok(ReconcileAction::AgentAhead {
                        agent_version: agent_staged,
                    });
                }
                None => {
                    // Agent has no staged version but should.
                    audit.append_success(
                        agent_id,
                        "reconcile.restage",
                        &format!("agent:{agent_id}"),
                        &format!("{{\"expected_version\":{expected_staged}}}"),
                        tick,
                    );
                    return Ok(ReconcileAction::ReStage {
                        version: expected_staged,
                    });
                }
            }
        }

        // Case 4: No staged version expected. Agent is up to date.
        // Verify the agent's digest matches the LKG.
        if let Some((lkg_version, lkg_digest)) = self.last_known_good.get(agent_id) {
            if report.active_version == lkg_version && report.active_digest != lkg_digest {
                // Digest mismatch: agent's active policy doesn't
                // match LKG. Re-stage.
                audit.append_failure(
                    agent_id,
                    "reconcile.digest_mismatch",
                    &format!("agent:{agent_id}"),
                    &format!(
                        "{{\"agent_digest\":\"{}\",\"lkg_digest\":\"{lkg_digest}\"}}",
                        report.active_digest
                    ),
                    "active digest does not match last-known-good",
                    tick,
                );
                return Ok(ReconcileAction::ReStage {
                    version: lkg_version,
                });
            }
        }

        audit.append_success(
            agent_id,
            "reconcile.up_to_date",
            &format!("agent:{agent_id}"),
            &format!("{{\"active_version\":{}}}", report.active_version),
            tick,
        );
        Ok(ReconcileAction::UpToDate)
    }

    /// The current fleet active version.
    pub fn active_version(&self) -> u64 {
        self.active_version
    }

    /// The current staged version (if any).
    pub fn staged_version(&self) -> Option<u64> {
        self.staged_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_report(
        agent_id: &str,
        active_version: u64,
        staged_version: Option<u64>,
    ) -> AgentStatusReport {
        AgentStatusReport {
            agent_spiffe_id: agent_id.to_string(),
            active_version,
            active_digest: format!("digest-v{active_version}"),
            staged_version,
        }
    }

    fn reconciler(active_version: u64, staged_version: Option<u64>) -> (Reconciler, AuditLog) {
        let mut lkg = LastKnownGoodStore::new();
        lkg.record_applied(
            "spiffe://kernel-v1.test/agent/prod/node-1",
            active_version,
            &format!("digest-v{active_version}"),
        );

        let reconciler = Reconciler::new(lkg, active_version, staged_version);
        let audit = AuditLog::new();
        (reconciler, audit)
    }

    #[test]
    fn up_to_date_agent() {
        let (rec, mut audit) = reconciler(5, None);
        let report = make_report("spiffe://kernel-v1.test/agent/prod/node-1", 5, None);
        let action = rec.reconcile(&report, &mut audit, 0).unwrap();
        assert_eq!(action, ReconcileAction::UpToDate);
    }

    #[test]
    fn agent_behind_needs_restage() {
        let (rec, mut audit) = reconciler(5, None);
        let report = make_report("spiffe://kernel-v1.test/agent/prod/node-1", 3, None);
        let action = rec.reconcile(&report, &mut audit, 0).unwrap();
        assert_eq!(
            action,
            ReconcileAction::AgentBehind {
                agent_version: 3,
                expected_version: 5,
            }
        );
    }

    #[test]
    fn agent_ahead_server_stale() {
        let (rec, mut audit) = reconciler(5, None);
        let report = make_report("spiffe://kernel-v1.test/agent/prod/node-1", 7, None);
        let action = rec.reconcile(&report, &mut audit, 0).unwrap();
        assert_eq!(action, ReconcileAction::AgentAhead { agent_version: 7 });
    }

    #[test]
    fn agent_needs_commit() {
        let (rec, mut audit) = reconciler(5, Some(6));
        let report = make_report("spiffe://kernel-v1.test/agent/prod/node-1", 5, Some(6));
        let action = rec.reconcile(&report, &mut audit, 0).unwrap();
        assert_eq!(action, ReconcileAction::Commit { version: 6 });
    }

    #[test]
    fn agent_stale_staged_needs_restage() {
        let (rec, mut audit) = reconciler(5, Some(7));
        let report = make_report("spiffe://kernel-v1.test/agent/prod/node-1", 5, Some(6));
        let action = rec.reconcile(&report, &mut audit, 0).unwrap();
        assert_eq!(action, ReconcileAction::ReStage { version: 7 });
    }

    #[test]
    fn agent_missing_staged_needs_restage() {
        let (rec, mut audit) = reconciler(5, Some(6));
        let report = make_report("spiffe://kernel-v1.test/agent/prod/node-1", 5, None);
        let action = rec.reconcile(&report, &mut audit, 0).unwrap();
        assert_eq!(action, ReconcileAction::ReStage { version: 6 });
    }

    #[test]
    fn digest_mismatch_triggers_restage() {
        let mut lkg = LastKnownGoodStore::new();
        lkg.record_applied(
            "spiffe://kernel-v1.test/agent/prod/node-1",
            5,
            "correct-digest",
        );

        let rec = Reconciler::new(lkg, 5, None);
        let mut audit = AuditLog::new();

        let report = AgentStatusReport {
            agent_spiffe_id: "spiffe://kernel-v1.test/agent/prod/node-1".into(),
            active_version: 5,
            active_digest: "wrong-digest".into(),
            staged_version: None,
        };

        let action = rec.reconcile(&report, &mut audit, 0).unwrap();
        assert_eq!(action, ReconcileAction::ReStage { version: 5 });
    }

    #[test]
    fn reconciliation_is_audited() {
        let (rec, mut audit) = reconciler(5, None);
        let report = make_report("spiffe://kernel-v1.test/agent/prod/node-1", 5, None);
        rec.reconcile(&report, &mut audit, 0).unwrap();
        assert!(!audit.is_empty());
        assert!(!audit.query_by_action("reconcile.", 10).is_empty());
    }

    #[test]
    fn disconnect_does_not_relax_lkg() {
        // This test documents the invariant: disconnect does NOT
        // modify the last-known-good store. The LKG is only
        // updated by explicit APPLIED or ROLLBACK commands.
        let mut lkg = LastKnownGoodStore::new();
        lkg.record_applied("agent-1", 5, "digest-5");

        // Simulate disconnect: LKG is NOT modified.
        // (No method exists to relax LKG on disconnect.)
        assert_eq!(lkg.get("agent-1"), Some((5, "digest-5")));
    }
}
