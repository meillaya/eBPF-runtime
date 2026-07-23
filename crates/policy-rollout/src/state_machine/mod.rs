// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet two-phase policy rollout state machine.
//!
//! Distributed state machine coordinating STAGE→READY→COMMIT→
//! APPLIED/REJECTED across multiple agents.
//!
//! Invariants:
//! - STAGE never activates (policy is staged but inactive).
//! - READY requires agent acknowledgment (never mark ready from
//!   send-only).
//! - COMMIT requires threshold met or explicit operator command.
//! - APPLIED requires agent confirmation (never mark applied from
//!   send-only).
//! - Monotonic version: commands with version <= current are
//!   rejected (stale/replay protection).
//! - All commands are idempotent (duplicates are safe).
//! - All commands are SPIFFE-bound (authorization required).
//! - Disconnect does NOT relax active policy (last-known-good
//!   maintained).
//! - Every transition is audited.

#![forbid(unsafe_code)]

mod admin;
mod commit;
mod health;
mod ready;
mod report;
mod stage;

#[cfg(test)]
mod tests;

use crate::audit::AuditLog;
use crate::auth::RolloutAuthorizer;
use crate::store::{AgentStateStore, LastKnownGoodStore, PolicyVersionStore, RolloutStore};

/// The fleet policy rollout coordinator.
///
/// Manages the distributed two-phase activation of policy versions
/// across a fleet of agents. All state is held in-memory (mock
/// PostgreSQL); live database integration is deferred to the
/// declared self-hosted runner.
#[derive(Debug)]
pub struct FleetRolloutCoordinator {
    /// Immutable policy version store.
    pub(crate) policy_versions: PolicyVersionStore,
    /// Rollout store with optimistic concurrency.
    pub(crate) rollouts: RolloutStore,
    /// Per-agent last-known-good state.
    pub(crate) last_known_good: LastKnownGoodStore,
    /// Per-agent active/staged state.
    pub(crate) agent_states: AgentStateStore,
    /// Append-only audit log.
    pub(crate) audit: AuditLog,
    /// SPIFFE command authorizer.
    pub(crate) authorizer: RolloutAuthorizer,
    /// Current monotonic tick (NOT wall clock).
    pub(crate) current_tick: u64,
    /// The current active policy version (fleet-wide).
    pub(crate) active_version: u64,
}

impl FleetRolloutCoordinator {
    /// Create a new coordinator with the given authorizer.
    pub fn new(authorizer: RolloutAuthorizer) -> Self {
        Self {
            policy_versions: PolicyVersionStore::new(),
            rollouts: RolloutStore::new(),
            last_known_good: LastKnownGoodStore::new(),
            agent_states: AgentStateStore::new(),
            audit: AuditLog::new(),
            authorizer,
            current_tick: 0,
            active_version: 0,
        }
    }

    /// Advance the monotonic tick. Returns the new tick.
    pub fn advance_tick(&mut self, ticks: u64) -> u64 {
        self.current_tick += ticks;
        self.current_tick
    }

    /// Current monotonic tick.
    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// The current active policy version.
    pub fn active_version(&self) -> u64 {
        self.active_version
    }

    /// Access the audit log.
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Access the policy version store.
    pub fn policy_versions(&self) -> &PolicyVersionStore {
        &self.policy_versions
    }

    /// Access the rollout store.
    pub fn rollouts(&self) -> &RolloutStore {
        &self.rollouts
    }

    /// Access the last-known-good store.
    pub fn last_known_good(&self) -> &LastKnownGoodStore {
        &self.last_known_good
    }

    /// Access the agent state store.
    pub fn agent_states(&self) -> &AgentStateStore {
        &self.agent_states
    }

    /// Register an agent in the agent state store (for testing
    /// and fleet inventory simulation).
    pub fn register_agent(&mut self, agent_spiffe_id: &str, active_version: u64) {
        self.agent_states
            .set_state(agent_spiffe_id, active_version, None);
    }
}
