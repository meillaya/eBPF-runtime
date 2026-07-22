// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Tests for the fleet rollout coordinator.
use super::*;
use crate::auth::RolloutAuthorizer;
use crate::digest::compute_policy_digest;
use crate::error::RolloutError;
use crate::model::*;

fn authorizer() -> RolloutAuthorizer {
    RolloutAuthorizer::new(
        "kernel-v1.test",
        vec!["spiffe://kernel-v1.test/operator/admin".into()],
    )
}

fn coordinator() -> FleetRolloutCoordinator {
    FleetRolloutCoordinator::new(authorizer())
}

fn make_policy(version: u64, targets: Vec<String>) -> PolicyVersion {
    let content = format!("policy-v{version}");
    let digest = compute_policy_digest(content.as_bytes());
    PolicyVersion {
        version,
        content_bytes: content.into_bytes(),
        content_digest: digest,
        targets,
        created_by: "spiffe://kernel-v1.test/operator/admin".into(),
    }
}

fn stage_cmd(version: u64, targets: Vec<String>) -> StageCommand {
    StageCommand {
        policy_version: make_policy(version, targets),
        actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        threshold_percent: 100,
        deadline_ticks: 100,
    }
}

fn two_agent_targets() -> Vec<String> {
    vec![
        "spiffe://kernel-v1.test/agent/prod/node-1".into(),
        "spiffe://kernel-v1.test/agent/prod/node-2".into(),
    ]
}

// -- Happy path: two agents stage/commit/apply --

#[test]
fn happy_path_two_agents_full_success() {
    let mut coord = coordinator();
    let targets = two_agent_targets();

    // STAGE.
    let rollout_id = coord.stage(&stage_cmd(1, targets.clone())).unwrap();
    assert_eq!(rollout_id, 1);

    let rollout = coord.rollouts().get(rollout_id).unwrap();
    assert_eq!(rollout.phase, RolloutPhase::AwaitingReady);
    assert_eq!(rollout.target_count(), 2);

    // READY from both agents.
    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();

    coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
            computed_digest: digest.clone(),
        })
        .unwrap();

    coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[1].clone(),
            version: 1,
            computed_digest: digest.clone(),
        })
        .unwrap();

    // Threshold met (100%).
    let rollout = coord.rollouts().get(rollout_id).unwrap();
    assert!(rollout.threshold_met());

    // COMMIT.
    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();

    let rollout = coord.rollouts().get(rollout_id).unwrap();
    assert_eq!(rollout.phase, RolloutPhase::Committing);

    // APPLIED from both agents.
    coord
        .applied(&AppliedReport {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
        })
        .unwrap();

    coord
        .applied(&AppliedReport {
            agent_spiffe_id: targets[1].clone(),
            version: 1,
        })
        .unwrap();

    // Rollout completed.
    let rollout = coord.rollouts().get(rollout_id).unwrap();
    assert_eq!(rollout.phase, RolloutPhase::Completed);
    assert_eq!(coord.active_version(), 1);

    // Audit log has entries.
    assert!(coord.audit().len() > 5);
}

// -- Subset targets --

#[test]
fn subset_targets_only_targeted_agents() {
    let mut coord = coordinator();
    let targets = vec!["spiffe://kernel-v1.test/agent/prod/node-1".into()];

    let rollout_id = coord.stage(&stage_cmd(1, targets.clone())).unwrap();
    let rollout = coord.rollouts().get(rollout_id).unwrap();
    assert_eq!(rollout.target_count(), 1);

    // Non-target agent cannot READY.
    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();
    let err = coord
        .ready(&ReadyAck {
            agent_spiffe_id: "spiffe://kernel-v1.test/agent/prod/node-99".into(),
            version: 1,
            computed_digest: digest,
        })
        .unwrap_err();
    assert!(matches!(err, RolloutError::AgentNotTargeted { .. }));
}

// -- Duplicate commands (idempotent) --

#[test]
fn duplicate_stage_is_idempotent() {
    let mut coord = coordinator();
    let targets = two_agent_targets();

    let id1 = coord.stage(&stage_cmd(1, targets.clone())).unwrap();
    let id2 = coord.stage(&stage_cmd(1, targets)).unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn duplicate_ready_is_idempotent() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    coord.stage(&stage_cmd(1, targets.clone())).unwrap();

    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();

    let ack = ReadyAck {
        agent_spiffe_id: targets[0].clone(),
        version: 1,
        computed_digest: digest,
    };

    coord.ready(&ack).unwrap();
    // Duplicate READY is safe.
    coord.ready(&ack).unwrap();
}

#[test]
fn duplicate_commit_is_idempotent() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    coord.stage(&stage_cmd(1, targets.clone())).unwrap();

    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();

    for t in &targets {
        coord
            .ready(&ReadyAck {
                agent_spiffe_id: t.clone(),
                version: 1,
                computed_digest: digest.clone(),
            })
            .unwrap();
    }

    let cmd = CommitCommand {
        version: 1,
        actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
    };
    coord.commit(&cmd).unwrap();
    // Duplicate COMMIT is safe.
    coord.commit(&cmd).unwrap();
}

#[test]
fn duplicate_applied_is_idempotent() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    coord.stage(&stage_cmd(1, targets.clone())).unwrap();

    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();

    for t in &targets {
        coord
            .ready(&ReadyAck {
                agent_spiffe_id: t.clone(),
                version: 1,
                computed_digest: digest.clone(),
            })
            .unwrap();
    }

    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();

    let report = AppliedReport {
        agent_spiffe_id: targets[0].clone(),
        version: 1,
    };
    coord.applied(&report).unwrap();
    // Duplicate APPLIED is safe (rollout still active with 2 agents).
    coord.applied(&report).unwrap();
}

// -- Commit before ready --

#[test]
fn operator_can_force_commit_before_threshold() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    coord.stage(&stage_cmd(1, targets)).unwrap();

    // Operator can force commit even without READY acks.
    let result = coord.commit(&CommitCommand {
        version: 1,
        actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
    });
    assert!(result.is_ok());
}

// -- Digest mismatch --

#[test]
fn stage_with_bad_digest_rejected() {
    let mut coord = coordinator();
    let mut cmd = stage_cmd(1, two_agent_targets());
    cmd.policy_version.content_digest = "bad-digest".into();

    let err = coord.stage(&cmd).unwrap_err();
    assert!(matches!(err, RolloutError::DigestMismatch { .. }));
}

#[test]
fn agent_ready_with_bad_digest_rejected() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    coord.stage(&stage_cmd(1, targets.clone())).unwrap();

    let err = coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
            computed_digest: "wrong-digest".into(),
        })
        .unwrap_err();
    assert!(matches!(err, RolloutError::AgentDigestMismatch { .. }));

    // Agent should be marked Rejected.
    let rollout = coord.rollouts().active_rollout().unwrap();
    assert_eq!(
        rollout.agent_states.get(&targets[0]),
        Some(&AgentRolloutState::Rejected)
    );
}

// -- Stale/replayed version --

#[test]
fn stale_version_rejected() {
    let mut coord = coordinator();
    let targets = two_agent_targets();

    // Complete rollout v1.
    let _rollout_id = coord.stage(&stage_cmd(1, targets.clone())).unwrap();
    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();
    for t in &targets {
        coord
            .ready(&ReadyAck {
                agent_spiffe_id: t.clone(),
                version: 1,
                computed_digest: digest.clone(),
            })
            .unwrap();
    }
    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();
    for t in &targets {
        coord
            .applied(&AppliedReport {
                agent_spiffe_id: t.clone(),
                version: 1,
            })
            .unwrap();
    }
    assert_eq!(coord.active_version(), 1);

    // Try to stage v1 again (replay).
    let err = coord.stage(&stage_cmd(1, targets)).unwrap_err();
    assert!(matches!(err, RolloutError::VersionReplay { .. }));
}

// -- Agent disconnect --

#[test]
fn agent_disconnect_maintains_last_known_good() {
    let mut coord = coordinator();
    let targets = two_agent_targets();

    // Complete rollout v1.
    coord.stage(&stage_cmd(1, targets.clone())).unwrap();
    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();
    for t in &targets {
        coord
            .ready(&ReadyAck {
                agent_spiffe_id: t.clone(),
                version: 1,
                computed_digest: digest.clone(),
            })
            .unwrap();
    }
    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();
    for t in &targets {
        coord
            .applied(&AppliedReport {
                agent_spiffe_id: t.clone(),
                version: 1,
            })
            .unwrap();
    }

    // Agent disconnects.
    coord.agent_disconnected(&targets[0]).unwrap();

    // LKG is maintained (NOT relaxed).
    assert_eq!(
        coord.last_known_good().get(&targets[0]),
        Some((1, digest.as_str()))
    );
}

// -- Timeout --

#[test]
fn timeout_transitions_to_timed_out() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    coord.stage(&stage_cmd(1, targets)).unwrap();

    // Advance past deadline.
    coord.advance_tick(200);
    let timed_out = coord.check_timeout().unwrap();
    assert!(timed_out);

    let rollout = coord.rollouts().get(1).unwrap();
    assert_eq!(rollout.phase, RolloutPhase::TimedOut);
}

#[test]
fn timeout_with_applied_agents_becomes_partial() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    coord.stage(&stage_cmd(1, targets.clone())).unwrap();

    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();

    // One agent readies and applies.
    coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
            computed_digest: digest,
        })
        .unwrap();
    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();
    coord
        .applied(&AppliedReport {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
        })
        .unwrap();

    // Advance past deadline (second agent never responded).
    coord.advance_tick(200);
    coord.check_timeout().unwrap();

    let rollout = coord.rollouts().get(1).unwrap();
    assert_eq!(rollout.phase, RolloutPhase::Partial);
}

// -- Cancel --

#[test]
fn cancel_in_progress_rollout() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    let rollout_id = coord.stage(&stage_cmd(1, targets)).unwrap();

    coord
        .cancel(&CancelCommand {
            rollout_id,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();

    let rollout = coord.rollouts().get(rollout_id).unwrap();
    assert_eq!(rollout.phase, RolloutPhase::Cancelled);
}

#[test]
fn cancel_completed_rollout_rejected() {
    let mut coord = coordinator();
    let targets = vec!["spiffe://kernel-v1.test/agent/prod/node-1".into()];
    let rollout_id = coord.stage(&stage_cmd(1, targets.clone())).unwrap();

    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();

    coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
            computed_digest: digest,
        })
        .unwrap();
    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();
    coord
        .applied(&AppliedReport {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
        })
        .unwrap();

    let err = coord
        .cancel(&CancelCommand {
            rollout_id,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap_err();
    assert!(matches!(err, RolloutError::InvalidTransition { .. }));
}

// -- Rollback --

#[test]
fn rollback_to_previous_version() {
    let mut coord = coordinator();
    let targets = vec!["spiffe://kernel-v1.test/agent/prod/node-1".into()];

    // Complete rollout v1.
    let id1 = coord.stage(&stage_cmd(1, targets.clone())).unwrap();
    let digest1 = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();
    coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
            computed_digest: digest1.clone(),
        })
        .unwrap();
    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();
    coord
        .applied(&AppliedReport {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
        })
        .unwrap();
    assert_eq!(coord.active_version(), 1);

    // Complete rollout v2.
    let id2 = coord.stage(&stage_cmd(2, targets.clone())).unwrap();
    let digest2 = coord
        .policy_versions()
        .get(2)
        .unwrap()
        .content_digest
        .clone();
    coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[0].clone(),
            version: 2,
            computed_digest: digest2,
        })
        .unwrap();
    coord
        .commit(&CommitCommand {
            version: 2,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();
    coord
        .applied(&AppliedReport {
            agent_spiffe_id: targets[0].clone(),
            version: 2,
        })
        .unwrap();
    assert_eq!(coord.active_version(), 2);

    // Rollback v2.
    coord
        .rollback(&RollbackCommand {
            rollout_id: id2,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();

    assert_eq!(coord.active_version(), 1);
    let rollout = coord.rollouts().get(id2).unwrap();
    assert_eq!(rollout.phase, RolloutPhase::RolledBack);

    // Agent reverted to v1.
    assert_eq!(coord.agent_states().get_state(&targets[0]), Some((1, None)));
    assert_eq!(
        coord.last_known_good().get(&targets[0]),
        Some((1, digest1.as_str()))
    );

    let _ = id1; // Used for sequencing.
}

// -- Authorization --

#[test]
fn unauthorized_operator_rejected() {
    let mut coord = coordinator();
    let mut cmd = stage_cmd(1, two_agent_targets());
    cmd.actor_spiffe_id = "spiffe://kernel-v1.test/operator/evil".into();

    let err = coord.stage(&cmd).unwrap_err();
    assert!(matches!(err, RolloutError::Unauthorized { .. }));
}

#[test]
fn wrong_trust_domain_rejected() {
    let mut coord = coordinator();
    let mut cmd = stage_cmd(1, two_agent_targets());
    cmd.actor_spiffe_id = "spiffe://evil.example/operator/admin".into();

    let err = coord.stage(&cmd).unwrap_err();
    assert!(matches!(err, RolloutError::Unauthorized { .. }));
}

// -- Audit --

#[test]
fn all_transitions_audited() {
    let mut coord = coordinator();
    let targets = vec!["spiffe://kernel-v1.test/agent/prod/node-1".into()];

    coord.stage(&stage_cmd(1, targets.clone())).unwrap();
    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();
    coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
            computed_digest: digest,
        })
        .unwrap();
    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();
    coord
        .applied(&AppliedReport {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
        })
        .unwrap();

    // Check audit log has entries for each transition.
    let audit = coord.audit();
    assert!(audit.query_by_action("rollout.stage", 10).len() >= 1);
    assert!(audit.query_by_action("agent.ready", 10).len() >= 1);
    assert!(audit.query_by_action("rollout.commit", 10).len() >= 1);
    assert!(audit.query_by_action("agent.applied", 10).len() >= 1);
    assert!(audit.query_by_action("rollout.completed", 10).len() >= 1);
}

// -- Partial rollout (one rejects) --

#[test]
fn partial_rollout_one_rejects() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    coord.stage(&stage_cmd(1, targets.clone())).unwrap();

    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();

    // Agent 1 readies.
    coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
            computed_digest: digest.clone(),
        })
        .unwrap();

    // Agent 2 rejects (bad digest).
    let err = coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[1].clone(),
            version: 1,
            computed_digest: "bad-digest".into(),
        })
        .unwrap_err();
    assert!(matches!(err, RolloutError::AgentDigestMismatch { .. }));

    // Operator commits (only agent 1 is ready).
    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();

    // Agent 1 applies.
    coord
        .applied(&AppliedReport {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
        })
        .unwrap();

    // Rollout is Partial (agent 1 applied, agent 2 rejected).
    let rollout = coord.rollouts().get(1).unwrap();
    assert_eq!(rollout.phase, RolloutPhase::Partial);

    // Agent 1's policy is active; agent 2 keeps previous.
    assert_eq!(coord.agent_states().get_state(&targets[0]), Some((1, None)));
    // Agent 2 was never applied, so no state change.
}

// -- Never activate from Kafka/NOTIFY --
// (This is a design invariant: activation only happens via
// explicit COMMIT command. There is no Kafka/NOTIFY path in
// this crate. The test documents the invariant.)

#[test]
fn no_activation_without_explicit_commit() {
    let mut coord = coordinator();
    let targets = two_agent_targets();
    coord.stage(&stage_cmd(1, targets.clone())).unwrap();

    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();

    // Both agents ready.
    for t in &targets {
        coord
            .ready(&ReadyAck {
                agent_spiffe_id: t.clone(),
                version: 1,
                computed_digest: digest.clone(),
            })
            .unwrap();
    }

    // Without COMMIT, agents are still Ready (not Applied).
    let rollout = coord.rollouts().get(1).unwrap();
    assert_eq!(rollout.phase, RolloutPhase::AwaitingReady);
    assert_eq!(rollout.count_in_state(AgentRolloutState::Ready), 2);
    assert_eq!(rollout.count_in_state(AgentRolloutState::Applied), 0);
}

// -- Never mark applied from send-only --

#[test]
fn applied_requires_agent_acknowledgment() {
    let mut coord = coordinator();
    let targets = vec!["spiffe://kernel-v1.test/agent/prod/node-1".into()];
    coord.stage(&stage_cmd(1, targets.clone())).unwrap();

    let digest = coord
        .policy_versions()
        .get(1)
        .unwrap()
        .content_digest
        .clone();

    coord
        .ready(&ReadyAck {
            agent_spiffe_id: targets[0].clone(),
            version: 1,
            computed_digest: digest,
        })
        .unwrap();

    coord
        .commit(&CommitCommand {
            version: 1,
            actor_spiffe_id: "spiffe://kernel-v1.test/operator/admin".into(),
        })
        .unwrap();

    // Without APPLIED report from agent, the agent is still
    // in Ready state (not Applied).
    let rollout = coord.rollouts().get(1).unwrap();
    assert_eq!(
        rollout.agent_states.get(&targets[0]),
        Some(&AgentRolloutState::Ready)
    );
    assert_eq!(rollout.phase, RolloutPhase::Committing);
}
