// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn make_pv(version: u64) -> PolicyVersion {
    PolicyVersion {
        version,
        content_bytes: format!("policy-v{version}").into_bytes(),
        content_digest: format!("digest-v{version}"),
        targets: vec![],
        created_by: "spiffe://kernel-v1.test/operator/admin".into(),
    }
}

// -- PolicyVersionStore --

#[test]
fn insert_monotonic() {
    let mut store = PolicyVersionStore::new();
    store.insert(make_pv(1)).unwrap();
    store.insert(make_pv(2)).unwrap();
    assert_eq!(store.max_version(), 2);
    assert_eq!(store.len(), 2);
}

#[test]
fn insert_stale_rejected() {
    let mut store = PolicyVersionStore::new();
    store.insert(make_pv(5)).unwrap();
    let err = store.insert(make_pv(3)).unwrap_err();
    assert!(matches!(err, RolloutError::VersionReplay { .. }));
}

#[test]
fn insert_replay_is_idempotent() {
    let mut store = PolicyVersionStore::new();
    store.insert(make_pv(1)).unwrap();
    // Idempotent: same version, same digest → no-op.
    store.insert(make_pv(1)).unwrap();
    assert_eq!(store.len(), 1);
}

#[test]
fn insert_same_version_different_content_conflict() {
    let mut store = PolicyVersionStore::new();
    store.insert(make_pv(1)).unwrap();
    let mut pv = make_pv(1);
    pv.content_digest = "different-digest".into();
    let err = store.insert(pv).unwrap_err();
    assert!(matches!(err, RolloutError::VersionConflict { .. }));
}

#[test]
fn get_existing() {
    let mut store = PolicyVersionStore::new();
    store.insert(make_pv(1)).unwrap();
    assert!(store.get(1).is_ok());
    assert!(store.get(2).is_err());
}

#[test]
fn latest_version() {
    let mut store = PolicyVersionStore::new();
    assert!(store.latest().is_none());
    store.insert(make_pv(1)).unwrap();
    store.insert(make_pv(5)).unwrap();
    assert_eq!(store.latest().unwrap().version, 5);
}

// -- RolloutStore --

#[test]
fn rollout_insert_assigns_id() {
    let mut store = RolloutStore::new();
    let rollout = FleetRollout {
        id: 0,
        policy_version: make_pv(1),
        phase: crate::model::RolloutPhase::Staging,
        agent_states: HashMap::new(),
        threshold_percent: 100,
        started_at_tick: 0,
        deadline_tick: 100,
        version: 0,
        previous_version: None,
    };
    let id1 = store.insert(rollout.clone());
    let id2 = store.insert(rollout);
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
}

#[test]
fn rollout_optimistic_concurrency() {
    let mut store = RolloutStore::new();
    let rollout = FleetRollout {
        id: 0,
        policy_version: make_pv(1),
        phase: crate::model::RolloutPhase::Staging,
        agent_states: HashMap::new(),
        threshold_percent: 100,
        started_at_tick: 0,
        deadline_tick: 100,
        version: 0,
        previous_version: None,
    };
    let id = store.insert(rollout);

    // Update with correct version.
    store
        .update(id, 1, |r| {
            r.phase = crate::model::RolloutPhase::AwaitingReady;
        })
        .unwrap();
    assert_eq!(store.get(id).unwrap().version, 2);

    // Update with stale version → conflict.
    let err = store.update(id, 1, |_| {}).unwrap_err();
    assert!(matches!(err, RolloutError::VersionConflict { .. }));
}

#[test]
fn active_rollout() {
    let mut store = RolloutStore::new();
    assert!(store.active_rollout().is_none());

    let rollout = FleetRollout {
        id: 0,
        policy_version: make_pv(1),
        phase: crate::model::RolloutPhase::Staging,
        agent_states: HashMap::new(),
        threshold_percent: 100,
        started_at_tick: 0,
        deadline_tick: 100,
        version: 0,
        previous_version: None,
    };
    store.insert(rollout);
    assert!(store.active_rollout().is_some());
}

// -- LastKnownGoodStore --

#[test]
fn lkg_record_and_get() {
    let mut store = LastKnownGoodStore::new();
    store.record_applied("agent-1", 5, "digest-5");
    assert_eq!(store.get("agent-1"), Some((5, "digest-5")));
    assert_eq!(store.get("agent-2"), None);
}

#[test]
fn lkg_rollback() {
    let mut store = LastKnownGoodStore::new();
    store.record_applied("agent-1", 5, "digest-5");
    store.rollback("agent-1", Some((3, "digest-3".into())));
    assert_eq!(store.get("agent-1"), Some((3, "digest-3")));
}

#[test]
fn lkg_rollback_to_none() {
    let mut store = LastKnownGoodStore::new();
    store.record_applied("agent-1", 5, "digest-5");
    store.rollback("agent-1", None);
    assert_eq!(store.get("agent-1"), None);
}

// -- AgentStateStore --

#[test]
fn agent_state_tracking() {
    let mut store = AgentStateStore::new();
    store.set_state("agent-1", 3, Some(5));
    assert_eq!(store.get_state("agent-1"), Some((3, Some(5))));
    assert_eq!(store.get_state("agent-2"), None);
}

#[test]
fn agent_mark_applied() {
    let mut store = AgentStateStore::new();
    store.mark_staged("agent-1", 5);
    assert_eq!(store.get_state("agent-1"), Some((0, Some(5))));

    store.mark_applied("agent-1", 5);
    assert_eq!(store.get_state("agent-1"), Some((5, None)));
}
