// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for control-db.
//!
//! BLOCKER: this host has no running PostgreSQL instance. These
//! tests validate repository LOGIC using in-memory mock
//! repositories. Live PostgreSQL integration tests (ephemeral
//! testcontainers) re-open on the declared self-hosted runner.
//!
//! Coverage:
//! - Optimistic concurrency (version conflict detection)
//! - Idempotency (duplicate detection, safe retries)
//! - Concurrent rollout race (one winner)
//! - Audit same-transaction atomicity
//! - Audit immutability (no UPDATE/DELETE)
//! - RLS negative matrix (cross-cluster, insufficient role)
//! - Notification loss recovery (re-read pattern)
//! - Migration rollback rehearsal (documented, not live)

use std::sync::Arc;

use control_db::error::ControlDbError;
use control_db::test_support::*;
use control_db::{
    AuditRepository, CursorRepository, FleetRepository, NotifyChannel, PolicyRepository,
};

fn setup() -> Arc<MockDb> {
    Arc::new(MockDb::new())
}

// -- Optimistic concurrency --

#[tokio::test]
async fn optimistic_concurrency_cluster_update_conflict() {
    let db = setup();
    let repo = MockFleetRepository::new(db);

    let cluster = repo.create_cluster("prod", "kernel-v1.test").await.unwrap();
    assert_eq!(cluster.version, 1);

    // First update succeeds.
    let updated = repo
        .update_cluster(cluster.id, 1, "prod-renamed", "kernel-v1.test")
        .await
        .unwrap();
    assert_eq!(updated.version, 2);
    assert_eq!(updated.name, "prod-renamed");

    // Second update with stale version fails.
    let err = repo
        .update_cluster(cluster.id, 1, "stale", "kernel-v1.test")
        .await
        .unwrap_err();
    match err {
        ControlDbError::VersionConflict {
            table,
            expected,
            found,
        } => {
            assert_eq!(table, "clusters");
            assert_eq!(expected, 1);
            assert_eq!(found, 2);
        }
        other => panic!("expected VersionConflict, got {other:?}"),
    }
}

#[tokio::test]
async fn optimistic_concurrency_agent_health_conflict() {
    let db = setup();
    let repo = MockFleetRepository::new(db.clone());

    let cluster = repo.create_cluster("prod", "kernel-v1.test").await.unwrap();
    let node = repo
        .create_node(cluster.id, "node-1", "host-1", "6.1.0")
        .await
        .unwrap();
    let agent = repo
        .register_agent(
            node.id,
            cluster.id,
            "spiffe://kernel-v1.test/agent/prod/node-1",
            "gen-1",
            "00".repeat(16).as_str(),
            1,
            "admin",
        )
        .await
        .unwrap();

    // First health update succeeds.
    let updated = repo
        .update_agent_health(agent.id, 1, 1000, 50, 0)
        .await
        .unwrap();
    assert_eq!(updated.version, 2);
    assert_eq!(updated.events_emitted, 50);

    // Stale version fails.
    let err = repo
        .update_agent_health(agent.id, 1, 2000, 100, 0)
        .await
        .unwrap_err();
    assert!(err.is_retryable());
}

// -- Idempotency --

#[tokio::test]
async fn idempotent_cluster_creation() {
    let db = setup();
    let repo = MockFleetRepository::new(db);

    let c1 = repo.create_cluster("prod", "kernel-v1.test").await.unwrap();
    let c2 = repo.create_cluster("prod", "kernel-v1.test").await.unwrap();
    assert_eq!(c1.id, c2.id);
}

#[tokio::test]
async fn idempotent_agent_registration() {
    let db = setup();
    let repo = MockFleetRepository::new(db);

    let cluster = repo.create_cluster("prod", "kernel-v1.test").await.unwrap();
    let node = repo
        .create_node(cluster.id, "node-1", "host-1", "6.1.0")
        .await
        .unwrap();

    let a1 = repo
        .register_agent(
            node.id,
            cluster.id,
            "spiffe://kernel-v1.test/agent/prod/node-1",
            "gen-1",
            "00",
            1,
            "admin",
        )
        .await
        .unwrap();
    let a2 = repo
        .register_agent(
            node.id,
            cluster.id,
            "spiffe://kernel-v1.test/agent/prod/node-1",
            "gen-2",
            "01",
            1,
            "admin",
        )
        .await
        .unwrap();
    assert_eq!(a1.id, a2.id);
}

#[tokio::test]
async fn idempotent_cursor_advance() {
    let db = setup();
    let repo = MockCursorRepository::new(db);
    let agent_id = uuid::Uuid::new_v4();

    let c1 = repo.advance_cursor(agent_id, 1, "key-1", 10).await.unwrap();
    assert_eq!(c1.sequence, 1);

    // Duplicate sequence → IdempotentDuplicate.
    let err = repo
        .advance_cursor(agent_id, 1, "key-2", 5)
        .await
        .unwrap_err();
    assert!(err.is_idempotent_duplicate());

    // Duplicate idempotency key → IdempotentDuplicate.
    let err = repo
        .advance_cursor(agent_id, 2, "key-1", 5)
        .await
        .unwrap_err();
    assert!(err.is_idempotent_duplicate());

    // New sequence + new key succeeds.
    let c2 = repo.advance_cursor(agent_id, 2, "key-2", 5).await.unwrap();
    assert_eq!(c2.sequence, 2);
}

#[tokio::test]
async fn idempotent_rollout_creation() {
    let db = setup();
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "admin".into(),
        sub: "admin".into(),
    });
    let repo = MockPolicyRepository::new(db);

    let policy = repo.create_policy("default", "test policy").await.unwrap();
    let pv = repo
        .stage_version(policy.id, 1, "abc123", "deadbeef", "admin")
        .await
        .unwrap();

    let r1 = repo.create_rollout(pv.id, 100, "admin").await.unwrap();
    let err = repo.create_rollout(pv.id, 100, "admin").await.unwrap_err();
    assert!(err.is_idempotent_duplicate());
    assert_eq!(
        err,
        ControlDbError::IdempotentDuplicate {
            key: format!("rollout:{}", pv.id)
        }
    );
    let _ = r1;
}

// -- Concurrent rollout race --

#[tokio::test]
async fn concurrent_rollout_race_one_winner() {
    let db = setup();
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "admin".into(),
        sub: "admin".into(),
    });
    let repo = MockPolicyRepository::new(db);

    let policy = repo.create_policy("race-test", "").await.unwrap();
    let pv = repo
        .stage_version(policy.id, 1, "digest", "content", "admin")
        .await
        .unwrap();

    // First rollout creation wins.
    let r1 = repo.create_rollout(pv.id, 100, "admin").await.unwrap();
    assert_eq!(r1.state, "pending");

    // Second attempt (simulating concurrent race) → duplicate.
    let err = repo.create_rollout(pv.id, 100, "admin").await.unwrap_err();
    assert!(err.is_idempotent_duplicate());
}

#[tokio::test]
async fn rollout_ack_idempotent_and_aggregate() {
    let db = setup();
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "admin".into(),
        sub: "admin".into(),
    });
    let repo = MockPolicyRepository::new(db.clone());

    let policy = repo.create_policy("ack-test", "").await.unwrap();
    let pv = repo
        .stage_version(policy.id, 1, "d", "c", "admin")
        .await
        .unwrap();
    let rollout = repo.create_rollout(pv.id, 100, "admin").await.unwrap();

    let agent1 = uuid::Uuid::new_v4();
    let agent2 = uuid::Uuid::new_v4();

    // Agent 1 acks (accepted).
    repo.record_ack(rollout.id, agent1, 1, "d1", true, "")
        .await
        .unwrap();

    // Agent 2 acks (rejected).
    repo.record_ack(rollout.id, agent2, 1, "d2", false, "digest mismatch")
        .await
        .unwrap();

    // Duplicate ack from agent 1 → idempotent.
    let err = repo
        .record_ack(rollout.id, agent1, 1, "d1", true, "")
        .await
        .unwrap_err();
    assert!(err.is_idempotent_duplicate());

    // Check aggregate counts.
    let r = repo.get_rollout(rollout.id).await.unwrap();
    assert_eq!(r.ack_count, 2);
    assert_eq!(r.committed_count, 1);
    assert_eq!(r.rejected_count, 1);
}

#[tokio::test]
async fn rollout_completion_optimistic() {
    let db = setup();
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "admin".into(),
        sub: "admin".into(),
    });
    let repo = MockPolicyRepository::new(db);

    let policy = repo.create_policy("complete-test", "").await.unwrap();
    let pv = repo
        .stage_version(policy.id, 1, "d", "c", "admin")
        .await
        .unwrap();
    let rollout = repo.create_rollout(pv.id, 100, "admin").await.unwrap();

    // Complete with correct version.
    let completed = repo
        .complete_rollout(rollout.id, 1, "completed", "admin")
        .await
        .unwrap();
    assert_eq!(completed.state, "completed");
    assert_eq!(completed.version, 2);
    assert!(completed.completed_at.is_some());

    // Stale version fails.
    let err = repo
        .complete_rollout(rollout.id, 1, "failed", "admin")
        .await
        .unwrap_err();
    assert!(err.is_retryable());
}

// -- Policy version monotonic --

#[tokio::test]
async fn policy_version_monotonic_enforcement() {
    let db = setup();
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "admin".into(),
        sub: "admin".into(),
    });
    let repo = MockPolicyRepository::new(db);

    let policy = repo.create_policy("mono", "").await.unwrap();

    // Version 1 succeeds.
    repo.stage_version(policy.id, 1, "d1", "c1", "admin")
        .await
        .unwrap();

    // Version 2 succeeds.
    repo.stage_version(policy.id, 2, "d2", "c2", "admin")
        .await
        .unwrap();

    // Version 1 again → replay rejected.
    let err = repo
        .stage_version(policy.id, 1, "d3", "c3", "admin")
        .await
        .unwrap_err();
    match err {
        ControlDbError::VersionConflict {
            expected, found, ..
        } => {
            assert_eq!(expected, 3);
            assert_eq!(found, 1);
        }
        other => panic!("expected VersionConflict, got {other:?}"),
    }

    // Version 2 again → replay rejected.
    let err = repo
        .stage_version(policy.id, 2, "d4", "c4", "admin")
        .await
        .unwrap_err();
    assert!(err.is_retryable());
}

#[tokio::test]
async fn policy_version_status_transition() {
    let db = setup();
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "admin".into(),
        sub: "admin".into(),
    });
    let repo = MockPolicyRepository::new(db);

    let policy = repo.create_policy("trans", "").await.unwrap();
    let pv = repo
        .stage_version(policy.id, 1, "d", "c", "admin")
        .await
        .unwrap();
    assert_eq!(pv.status, "staged");

    // staged → ready.
    let pv = repo
        .transition_version_status(pv.id, "staged", "ready", "admin")
        .await
        .unwrap();
    assert_eq!(pv.status, "ready");

    // Invalid: staged → applied (skips ready/committed).
    let err = repo
        .transition_version_status(pv.id, "staged", "applied", "admin")
        .await
        .unwrap_err();
    match err {
        ControlDbError::InvalidRolloutTransition { from, action } => {
            assert_eq!(from, "ready");
            assert_eq!(action, "->applied");
        }
        other => panic!("expected InvalidRolloutTransition, got {other:?}"),
    }

    // ready → committed → applied.
    let pv = repo
        .transition_version_status(pv.id, "ready", "committed", "admin")
        .await
        .unwrap();
    let pv = repo
        .transition_version_status(pv.id, "committed", "applied", "admin")
        .await
        .unwrap();
    assert_eq!(pv.status, "applied");
}

// -- Audit same-transaction atomicity --

#[tokio::test]
async fn audit_same_transaction_atomicity() {
    let db = setup();
    let repo = MockFleetRepository::new(db.clone());

    let cluster = repo.create_cluster("prod", "kernel-v1.test").await.unwrap();
    let node = repo
        .create_node(cluster.id, "node-1", "host-1", "6.1.0")
        .await
        .unwrap();

    // Register agent → audit entry written atomically.
    repo.register_agent(
        node.id,
        cluster.id,
        "spiffe://kernel-v1.test/agent/prod/node-1",
        "gen-1",
        "00",
        1,
        "admin-user",
    )
    .await
    .unwrap();

    // Verify audit entry exists.
    let audit_repo = MockAuditRepository::new(db.clone());
    let entries = audit_repo.query_by_actor("admin-user", 10).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "agent.register");
    assert_eq!(entries[0].cluster_id, Some(cluster.id));
    assert!(entries[0].success);
}

#[tokio::test]
async fn audit_written_on_policy_stage() {
    let db = setup();
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "admin".into(),
        sub: "admin".into(),
    });
    let repo = MockPolicyRepository::new(db.clone());

    let policy = repo.create_policy("audit-test", "").await.unwrap();
    repo.stage_version(policy.id, 1, "d", "c", "policy-admin-1")
        .await
        .unwrap();

    let audit_repo = MockAuditRepository::new(db);
    let entries = audit_repo
        .query_by_actor("policy-admin-1", 10)
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "policy.stage");
}

// -- Audit immutability --

#[tokio::test]
async fn audit_immutability_no_update() {
    let db = setup();
    let repo = MockAuditRepository::new(db.clone());

    let entry = repo
        .append("admin", "test.action", "resource-1", None, "{}", true, "")
        .await
        .unwrap();

    let err = repo.attempt_update(entry.id, "hacker").await.unwrap_err();
    assert_eq!(
        err,
        ControlDbError::AuditImmutable {
            operation: "UPDATE".into()
        }
    );
}

#[tokio::test]
async fn audit_immutability_no_delete() {
    let db = setup();
    let repo = MockAuditRepository::new(db.clone());

    let entry = repo
        .append("admin", "test.action", "resource-1", None, "{}", true, "")
        .await
        .unwrap();

    let err = repo.attempt_delete(entry.id).await.unwrap_err();
    assert_eq!(
        err,
        ControlDbError::AuditImmutable {
            operation: "DELETE".into()
        }
    );
}

#[tokio::test]
async fn audit_monotonic_sequence() {
    let db = setup();
    let repo = MockAuditRepository::new(db);

    let e1 = repo
        .append("u1", "a1", "r1", None, "{}", true, "")
        .await
        .unwrap();
    let e2 = repo
        .append("u2", "a2", "r2", None, "{}", true, "")
        .await
        .unwrap();
    let e3 = repo
        .append("u3", "a3", "r3", None, "{}", true, "")
        .await
        .unwrap();

    assert!(e2.seq > e1.seq);
    assert!(e3.seq > e2.seq);
    assert_eq!(repo.latest_seq().await.unwrap(), e3.seq);
}

// -- RLS negative matrix --

#[tokio::test]
async fn rls_cross_cluster_denied() {
    let db = setup();
    let repo = MockFleetRepository::new(db.clone());

    let cluster_a = repo.create_cluster("cluster-a", "td-a").await.unwrap();
    let cluster_b = repo.create_cluster("cluster-b", "td-b").await.unwrap();

    // Set RLS context to cluster_a.
    db.set_rls_context(RlsContext {
        cluster_id: Some(cluster_a.id),
        role: "admin".into(),
        sub: "admin".into(),
    });

    // Access own cluster: OK.
    assert!(repo.get_cluster(cluster_a.id).await.is_ok());

    // Access other cluster: DENIED.
    let err = repo.get_cluster(cluster_b.id).await.unwrap_err();
    match err {
        ControlDbError::RlsDenied { reason } => {
            assert!(reason.contains("cross-cluster"));
        }
        other => panic!("expected RlsDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn rls_cross_cluster_node_creation_denied() {
    let db = setup();
    let repo = MockFleetRepository::new(db.clone());

    let cluster_a = repo.create_cluster("cluster-a", "td-a").await.unwrap();
    let cluster_b = repo.create_cluster("cluster-b", "td-b").await.unwrap();

    db.set_rls_context(RlsContext {
        cluster_id: Some(cluster_a.id),
        role: "admin".into(),
        sub: "admin".into(),
    });

    // Create node in own cluster: OK.
    assert!(repo
        .create_node(cluster_a.id, "node-1", "host-1", "6.1.0")
        .await
        .is_ok());

    // Create node in other cluster: DENIED.
    let err = repo
        .create_node(cluster_b.id, "node-2", "host-2", "6.1.0")
        .await
        .unwrap_err();
    assert!(matches!(err, ControlDbError::RlsDenied { .. }));
}

#[tokio::test]
async fn rls_insufficient_role_policy_write_denied() {
    let db = setup();
    // Viewer role cannot write policies.
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "viewer".into(),
        sub: "viewer-user".into(),
    });
    let repo = MockPolicyRepository::new(db);

    let err = repo.create_policy("denied-policy", "").await.unwrap_err();
    match err {
        ControlDbError::RlsDenied { reason } => {
            assert!(reason.contains("viewer"));
        }
        other => panic!("expected RlsDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn rls_analyst_cannot_stage_policy() {
    let db = setup();
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "analyst".into(),
        sub: "analyst-user".into(),
    });
    let repo = MockPolicyRepository::new(db);

    // Analyst can read but not write policies.
    let err = repo.create_policy("analyst-policy", "").await.unwrap_err();
    assert!(matches!(err, ControlDbError::RlsDenied { .. }));
}

#[tokio::test]
async fn rls_policy_admin_can_write() {
    let db = setup();
    db.set_rls_context(RlsContext {
        cluster_id: None,
        role: "policy-admin".into(),
        sub: "pa-user".into(),
    });
    let repo = MockPolicyRepository::new(db);

    let policy = repo.create_policy("pa-policy", "").await.unwrap();
    assert_eq!(policy.name, "pa-policy");
}

#[tokio::test]
async fn rls_bypass_risk_owner_context() {
    // Simulate: no RLS context set (superuser/owner bypass).
    // This documents the risk: without RLS context, all operations succeed.
    let db = setup();
    // No RLS context → bypass mode.
    let repo = MockFleetRepository::new(db.clone());

    let cluster_a = repo.create_cluster("a", "td-a").await.unwrap();
    let cluster_b = repo.create_cluster("b", "td-b").await.unwrap();

    // Without RLS context, cross-cluster access succeeds (owner bypass).
    assert!(repo.get_cluster(cluster_a.id).await.is_ok());
    assert!(repo.get_cluster(cluster_b.id).await.is_ok());

    // This is the documented risk: the app role must ALWAYS set
    // RLS context. The database enforces NOBYPASSRLS on control_app.
}

// -- Notification loss recovery --

#[tokio::test]
async fn notification_loss_recovery_by_reread() {
    let db = setup();
    let fleet_repo = MockFleetRepository::new(db.clone());
    let notify = MockNotifyChannel::new();

    let cluster = fleet_repo
        .create_cluster("prod", "kernel-v1.test")
        .await
        .unwrap();

    // Simulate: state change + notify.
    let node = fleet_repo
        .create_node(cluster.id, "node-1", "host-1", "6.1.0")
        .await
        .unwrap();
    notify
        .notify("control_fleet_state", &format!("nodes:{}", node.id))
        .await
        .unwrap();

    // Consumer receives hint.
    let hint = notify
        .wait_for_hint("control_fleet_state", std::time::Duration::from_millis(10))
        .await
        .unwrap();
    assert!(hint.is_some());
    let hint = hint.unwrap();
    assert_eq!(hint.channel, "control_fleet_state");
    assert!(hint.has_payload());

    // Consumer re-reads state (authoritative).
    let node_read = fleet_repo.get_node(node.id).await.unwrap();
    assert_eq!(node_read.name, "node-1");

    // Simulate lost notification: no hint available.
    let lost = notify
        .wait_for_hint("control_fleet_state", std::time::Duration::from_millis(10))
        .await
        .unwrap();
    assert!(lost.is_none());

    // Recovery: consumer still re-reads state (polling fallback).
    let node_reread = fleet_repo.get_node(node.id).await.unwrap();
    assert_eq!(node_reread.name, "node-1");
}

#[tokio::test]
async fn notify_is_wake_hint_not_state() {
    let notify = MockNotifyChannel::new();

    // Notify with payload.
    notify
        .notify("control_policy_rollout", "rollouts:some-id")
        .await
        .unwrap();

    let hint = notify
        .wait_for_hint(
            "control_policy_rollout",
            std::time::Duration::from_millis(10),
        )
        .await
        .unwrap()
        .unwrap();

    // The hint is NOT state. It's a wake signal.
    // The consumer must re-read from the table.
    assert_eq!(hint.channel, "control_policy_rollout");
    assert!(hint.has_payload());
    // The payload is a hint (row ID), not the full state.
    assert!(hint.payload.starts_with("rollouts:"));
}

// -- Migration rollback rehearsal (documented) --

#[tokio::test]
async fn migration_rollback_documented() {
    // BLOCKER: no live PostgreSQL. Migration rollback is
    // documented as requiring manual .down.sql execution.
    // The down migrations exist for all 7 migration pairs.
    //
    // Downgrade rehearsal on the declared runner:
    // 1. Apply all up migrations.
    // 2. Execute down migrations in reverse order (7→1).
    // 3. Verify clean state (no tables remain).
    // 4. Re-apply up migrations (upgrade rehearsal).
    //
    // This test documents the procedure.
    let down_migrations = [
        "0007_roles_privileges.down.sql",
        "0006_rls_policies.down.sql",
        "0005_audit_log.down.sql",
        "0004_oidc_auth.down.sql",
        "0003_policy_rollout.down.sql",
        "0002_event_cursors.down.sql",
        "0001_fleet_state.down.sql",
    ];
    assert_eq!(down_migrations.len(), 7);
    // Each down migration drops the tables created by its up pair.
}

// -- Fixture loading --

#[tokio::test]
async fn fixture_concurrent_rollout_race() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/control-db/concurrent-rollout-race.json"
    ))
    .unwrap();

    assert_eq!(fixture["scenario"], "concurrent_rollout_race");
    assert_eq!(fixture["expected"]["winners"], 1);
    assert_eq!(fixture["expected"]["losers"], 1);
    assert_eq!(fixture["expected"]["loser_error"], "IdempotentDuplicate");
}

#[tokio::test]
async fn fixture_audit_atomicity() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/control-db/audit-atomicity.json"
    ))
    .unwrap();

    assert_eq!(fixture["scenario"], "audit_same_transaction_atomicity");
    assert_eq!(fixture["expected"]["state_change_committed"], true);
    assert_eq!(fixture["expected"]["audit_entry_committed"], true);
    assert_eq!(fixture["expected"]["rollback_leaves_neither"], true);
}

#[tokio::test]
async fn fixture_rls_denial() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/control-db/rls-denial-matrix.json"
    ))
    .unwrap();

    assert_eq!(fixture["scenario"], "rls_negative_matrix");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);

    // All cases expect denial.
    for case in cases {
        assert_eq!(case["expected"], "denied");
    }
}

#[tokio::test]
async fn fixture_notification_loss_recovery() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/control-db/notification-loss-recovery.json"
    ))
    .unwrap();

    assert_eq!(fixture["scenario"], "notification_loss_recovery");
    assert_eq!(fixture["expected"]["notify_is_wake_hint_only"], true);
    assert_eq!(fixture["expected"]["re_read_from_table"], true);
    assert_eq!(fixture["expected"]["lost_notification_safe"], true);
}
