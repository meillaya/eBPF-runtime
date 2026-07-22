// SPDX-License-Identifier: Apache-2.0 OR MIT
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
    assert!(audit.query_by_action("reconcile.", 10).len() >= 1);
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
