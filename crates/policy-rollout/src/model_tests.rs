// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn make_policy(version: u64) -> PolicyVersion {
    PolicyVersion {
        version,
        content_bytes: format!("policy-v{version}").into_bytes(),
        content_digest: format!("digest-v{version}"),
        targets: vec![],
        created_by: "spiffe://kernel-v1.test/operator/admin".into(),
    }
}

fn make_rollout(agent_count: usize) -> FleetRollout {
    let mut agent_states = HashMap::new();
    for i in 0..agent_count {
        agent_states.insert(
            format!("spiffe://kernel-v1.test/agent/prod/node-{i}"),
            AgentRolloutState::Pending,
        );
    }
    FleetRollout {
        id: 1,
        policy_version: make_policy(1),
        phase: RolloutPhase::Staging,
        agent_states,
        threshold_percent: 100,
        started_at_tick: 0,
        deadline_tick: 100,
        version: 1,
        previous_version: None,
    }
}

#[test]
fn count_in_state() {
    let mut r = make_rollout(3);
    assert_eq!(r.count_in_state(AgentRolloutState::Pending), 3);

    let key = "spiffe://kernel-v1.test/agent/prod/node-0".to_string();
    r.agent_states.insert(key, AgentRolloutState::Ready);
    assert_eq!(r.count_in_state(AgentRolloutState::Ready), 1);
    assert_eq!(r.count_in_state(AgentRolloutState::Pending), 2);
}

#[test]
fn threshold_met_at_100_percent() {
    let mut r = make_rollout(2);
    r.threshold_percent = 100;
    assert!(!r.threshold_met());

    let keys: Vec<String> = r.agent_states.keys().cloned().collect();
    r.agent_states
        .insert(keys[0].clone(), AgentRolloutState::Ready);
    assert!(!r.threshold_met());

    r.agent_states
        .insert(keys[1].clone(), AgentRolloutState::Ready);
    assert!(r.threshold_met());
}

#[test]
fn threshold_met_at_50_percent() {
    let mut r = make_rollout(4);
    r.threshold_percent = 50;

    let keys: Vec<String> = r.agent_states.keys().cloned().collect();
    r.agent_states
        .insert(keys[0].clone(), AgentRolloutState::Ready);
    r.agent_states
        .insert(keys[1].clone(), AgentRolloutState::Ready);
    assert!(r.threshold_met()); // 2/4 = 50%
}

#[test]
fn all_applied() {
    let mut r = make_rollout(2);
    assert!(!r.all_applied());

    let keys: Vec<String> = r.agent_states.keys().cloned().collect();
    r.agent_states
        .insert(keys[0].clone(), AgentRolloutState::Applied);
    assert!(!r.all_applied());

    r.agent_states
        .insert(keys[1].clone(), AgentRolloutState::Applied);
    assert!(r.all_applied());
}

#[test]
fn terminal_phases() {
    let mut r = make_rollout(1);
    assert!(!r.is_terminal());

    r.phase = RolloutPhase::Completed;
    assert!(r.is_terminal());

    r.phase = RolloutPhase::Partial;
    assert!(r.is_terminal());

    r.phase = RolloutPhase::Cancelled;
    assert!(r.is_terminal());

    r.phase = RolloutPhase::RolledBack;
    assert!(r.is_terminal());

    r.phase = RolloutPhase::TimedOut;
    assert!(r.is_terminal());

    r.phase = RolloutPhase::Staging;
    assert!(!r.is_terminal());
}

#[test]
fn empty_rollout_threshold_not_met() {
    let r = make_rollout(0);
    assert!(!r.threshold_met());
    assert!(!r.all_applied());
}

#[test]
fn policy_version_serde_roundtrip() {
    let pv = make_policy(42);
    let json = serde_json::to_string(&pv).unwrap();
    let decoded: PolicyVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(pv, decoded);
}

#[test]
fn agent_state_display() {
    assert_eq!(AgentRolloutState::Pending.to_string(), "Pending");
    assert_eq!(AgentRolloutState::Applied.to_string(), "Applied");
    assert_eq!(AgentRolloutState::Rejected.to_string(), "Rejected");
}

#[test]
fn rollout_phase_display() {
    assert_eq!(RolloutPhase::Staging.to_string(), "Staging");
    assert_eq!(RolloutPhase::Completed.to_string(), "Completed");
    assert_eq!(RolloutPhase::RolledBack.to_string(), "RolledBack");
}
