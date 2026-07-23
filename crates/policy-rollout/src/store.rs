// SPDX-License-Identifier: Apache-2.0 OR MIT
//! In-memory policy store (mock PostgreSQL) for fleet rollout.
//!
//! Mirrors the control-db `PolicyRepository` pattern: optimistic
//! concurrency via version columns, idempotent inserts, and
//! monotonic version checks. No live PostgreSQL required.
//!
//! BLOCKER: this host has no running PostgreSQL instance. This
//! store validates all rollout logic in-memory. Live PostgreSQL
//! integration re-opens on the declared self-hosted runner.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::error::{RolloutError, RolloutResult};
use crate::model::{FleetRollout, PolicyVersion};

/// In-memory policy version store.
///
/// Stores immutable policy versions keyed by monotonic version
/// number. Enforces:
/// - Monotonic version ordering (no stale/replay).
/// - Content-addressed uniqueness (same digest = same version).
/// - Immutability (versions cannot be modified after insert).
#[derive(Debug, Default)]
pub struct PolicyVersionStore {
    /// version → PolicyVersion.
    versions: HashMap<u64, PolicyVersion>,
    /// The highest version number seen.
    max_version: u64,
}

impl PolicyVersionStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a policy version. Enforces monotonic ordering:
    /// the version must be strictly greater than the current max.
    ///
    /// Idempotent: inserting the same version with the same
    /// content is a safe no-op.
    pub fn insert(&mut self, pv: PolicyVersion) -> RolloutResult<()> {
        if let Some(existing) = self.versions.get(&pv.version) {
            // Idempotent: same version, same content → no-op.
            if existing.content_digest == pv.content_digest {
                return Ok(());
            }
            // Same version, different content → conflict.
            return Err(RolloutError::VersionConflict {
                entity: "policy_version".into(),
                expected: existing.version as i64,
                found: pv.version as i64,
            });
        }

        // Monotonic check.
        if pv.version <= self.max_version {
            return Err(RolloutError::VersionReplay {
                command_version: pv.version,
                current_version: self.max_version,
            });
        }

        self.max_version = pv.version;
        self.versions.insert(pv.version, pv);
        Ok(())
    }

    /// Get a policy version by version number.
    pub fn get(&self, version: u64) -> RolloutResult<&PolicyVersion> {
        self.versions
            .get(&version)
            .ok_or_else(|| RolloutError::NotFound {
                entity: "policy_version".into(),
                key: version.to_string(),
            })
    }

    /// Get the latest (highest) version.
    pub fn latest(&self) -> Option<&PolicyVersion> {
        self.versions.get(&self.max_version)
    }

    /// The highest version number.
    pub fn max_version(&self) -> u64 {
        self.max_version
    }

    /// The number of stored versions.
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }
}

/// In-memory rollout store.
///
/// Stores fleet rollouts keyed by rollout ID. Enforces optimistic
/// concurrency via version columns.
#[derive(Debug, Default)]
pub struct RolloutStore {
    /// rollout_id → FleetRollout.
    rollouts: HashMap<u64, FleetRollout>,
    /// The next rollout ID to assign.
    next_id: u64,
}

impl RolloutStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            rollouts: HashMap::new(),
            next_id: 1,
        }
    }

    /// Insert a new rollout. Assigns a monotonic rollout ID.
    pub fn insert(&mut self, mut rollout: FleetRollout) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        rollout.id = id;
        rollout.version = 1;
        self.rollouts.insert(id, rollout);
        id
    }

    /// Get a rollout by ID.
    pub fn get(&self, id: u64) -> RolloutResult<&FleetRollout> {
        self.rollouts
            .get(&id)
            .ok_or_else(|| RolloutError::NotFound {
                entity: "rollout".into(),
                key: id.to_string(),
            })
    }

    /// Get a mutable rollout by ID.
    pub fn get_mut(&mut self, id: u64) -> RolloutResult<&mut FleetRollout> {
        self.rollouts
            .get_mut(&id)
            .ok_or_else(|| RolloutError::NotFound {
                entity: "rollout".into(),
                key: id.to_string(),
            })
    }

    /// Update a rollout with optimistic concurrency check.
    /// The expected_version must match the current version.
    pub fn update(
        &mut self,
        id: u64,
        expected_version: i64,
        f: impl FnOnce(&mut FleetRollout),
    ) -> RolloutResult<()> {
        let rollout = self.get_mut(id)?;
        if rollout.version != expected_version {
            return Err(RolloutError::VersionConflict {
                entity: "rollout".into(),
                expected: expected_version,
                found: rollout.version,
            });
        }
        f(rollout);
        rollout.version += 1;
        Ok(())
    }

    /// Get the active (non-terminal) rollout, if any.
    pub fn active_rollout(&self) -> Option<&FleetRollout> {
        self.rollouts.values().find(|r| !r.is_terminal())
    }

    /// The number of stored rollouts.
    pub fn len(&self) -> usize {
        self.rollouts.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.rollouts.is_empty()
    }
}

/// Per-agent last-known-good state.
///
/// Tracks the last successfully applied policy version per agent.
/// On rollback or failure, the agent reverts to this version.
/// Disconnect does NOT relax the last-known-good.
#[derive(Debug, Default)]
pub struct LastKnownGoodStore {
    /// agent SPIFFE ID → (version, digest).
    lkg: HashMap<String, (u64, String)>,
}

impl LastKnownGoodStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful application as the new last-known-good.
    pub fn record_applied(&mut self, agent_id: &str, version: u64, digest: &str) {
        self.lkg
            .insert(agent_id.to_string(), (version, digest.to_string()));
    }

    /// Get the last-known-good for an agent.
    pub fn get(&self, agent_id: &str) -> Option<(u64, &str)> {
        self.lkg.get(agent_id).map(|(v, d)| (*v, d.as_str()))
    }

    /// Rollback: revert to the previous last-known-good.
    /// Returns the previous version if one exists.
    pub fn rollback(&mut self, agent_id: &str, previous: Option<(u64, String)>) {
        match previous {
            Some((v, d)) => {
                self.lkg.insert(agent_id.to_string(), (v, d));
            }
            None => {
                self.lkg.remove(agent_id);
            }
        }
    }

    /// The number of agents with recorded LKG.
    pub fn len(&self) -> usize {
        self.lkg.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.lkg.is_empty()
    }
}

/// Per-agent staged state tracker.
///
/// Tracks what version each agent has staged (inactive) and
/// what version is active. Used for reconciliation on reconnect.
#[derive(Debug, Default)]
pub struct AgentStateStore {
    /// agent SPIFFE ID → (active_version, staged_version).
    states: HashMap<String, (u64, Option<u64>)>,
}

impl AgentStateStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the agent's active and staged versions.
    pub fn set_state(&mut self, agent_id: &str, active_version: u64, staged_version: Option<u64>) {
        self.states
            .insert(agent_id.to_string(), (active_version, staged_version));
    }

    /// Get the agent's state.
    pub fn get_state(&self, agent_id: &str) -> Option<(u64, Option<u64>)> {
        self.states.get(agent_id).copied()
    }

    /// Mark an agent as having applied a version (active = version,
    /// staged = None).
    pub fn mark_applied(&mut self, agent_id: &str, version: u64) {
        self.states.insert(agent_id.to_string(), (version, None));
    }

    /// Mark an agent as having staged a version.
    pub fn mark_staged(&mut self, agent_id: &str, staged_version: u64) {
        let entry = self.states.entry(agent_id.to_string()).or_insert((0, None));
        entry.1 = Some(staged_version);
    }

    /// The number of tracked agents.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

#[cfg(test)]
mod tests {
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
}
