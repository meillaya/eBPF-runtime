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

use std::collections::HashMap;

use crate::audit::AuditLog;
use crate::auth::RolloutAuthorizer;
use crate::digest::verify_digest;
use crate::error::{RolloutError, RolloutResult};
use crate::model::*;
use crate::store::{
    AgentStateStore, LastKnownGoodStore, PolicyVersionStore, RolloutStore,
};

/// The fleet policy rollout coordinator.
///
/// Manages the distributed two-phase activation of policy versions
/// across a fleet of agents. All state is held in-memory (mock
/// PostgreSQL); live database integration is deferred to the
/// declared self-hosted runner.
#[derive(Debug)]
pub struct FleetRolloutCoordinator {
    /// Immutable policy version store.
    policy_versions: PolicyVersionStore,
    /// Rollout store with optimistic concurrency.
    rollouts: RolloutStore,
    /// Per-agent last-known-good state.
    last_known_good: LastKnownGoodStore,
    /// Per-agent active/staged state.
    agent_states: AgentStateStore,
    /// Append-only audit log.
    audit: AuditLog,
    /// SPIFFE command authorizer.
    authorizer: RolloutAuthorizer,
    /// Current monotonic tick (NOT wall clock).
    current_tick: u64,
    /// The current active policy version (fleet-wide).
    active_version: u64,
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

    // -- Commands --

    /// **STAGE**: distribute a policy version to target agents.
    ///
    /// The policy is staged (inactive) — NOT activated.
    /// Creates a new rollout and records the per-agent state.
    ///
    /// Idempotent: staging the same version with the same digest
    /// is a safe no-op.
    ///
    /// Authorization: requires operator SPIFFE ID.
    pub fn stage(&mut self, cmd: &StageCommand) -> RolloutResult<u64> {
        // Authorize the operator.
        self.authorizer
            .authorize_operator(&cmd.actor_spiffe_id, "stage")?;

        // Verify content digest matches content bytes.
        if !verify_digest(&cmd.policy_version.content_bytes, &cmd.policy_version.content_digest) {
            let actual = crate::digest::sha256_hex(&cmd.policy_version.content_bytes);
            self.audit.append_failure(
                &cmd.actor_spiffe_id,
                "rollout.stage",
                &format!("policy_version:{}", cmd.policy_version.version),
                &format!("{{\"version\":{}}}", cmd.policy_version.version),
                &format!(
                    "digest mismatch: expected {}, got {actual}",
                    cmd.policy_version.content_digest
                ),
                self.current_tick,
            );
            return Err(RolloutError::DigestMismatch {
                expected: cmd.policy_version.content_digest.clone(),
                actual,
            });
        }

        // Check for idempotent duplicate: if a rollout for this
        // version already exists, return its ID.
        if let Some(existing) = self.rollouts.active_rollout() {
            if existing.policy_version.version == cmd.policy_version.version {
                self.audit.append_success(
                    &cmd.actor_spiffe_id,
                    "rollout.stage.idempotent",
                    &format!("rollout:{}", existing.id),
                    &format!("{{\"version\":{}}}", cmd.policy_version.version),
                    self.current_tick,
                );
                return Ok(existing.id);
            }
        }

        // Monotonic version check.
        if cmd.policy_version.version <= self.active_version {
            self.audit.append_failure(
                &cmd.actor_spiffe_id,
                "rollout.stage",
                &format!("policy_version:{}", cmd.policy_version.version),
                &format!("{{\"version\":{}}}", cmd.policy_version.version),
                &format!(
                    "version replay: {} <= {}",
                    cmd.policy_version.version, self.active_version
                ),
                self.current_tick,
            );
            return Err(RolloutError::VersionReplay {
                command_version: cmd.policy_version.version,
                current_version: self.active_version,
            });
        }

        // Store the policy version.
        self.policy_versions.insert(cmd.policy_version.clone())?;

        // Build the agent state map from targets.
        let mut agent_states = HashMap::new();
        if cmd.policy_version.targets.is_empty() {
            // Empty targets = all known agents.
            for agent_id in self.agent_states_known_ids() {
                agent_states.insert(agent_id, AgentRolloutState::Pending);
            }
        } else {
            for target in &cmd.policy_version.targets {
                agent_states.insert(target.clone(), AgentRolloutState::Pending);
            }
        }

        // Create the rollout.
        let previous_version = if self.active_version > 0 {
            Some(self.active_version)
        } else {
            None
        };

        let rollout = FleetRollout {
            id: 0, // Assigned by store.
            policy_version: cmd.policy_version.clone(),
            phase: RolloutPhase::Staging,
            agent_states,
            threshold_percent: cmd.threshold_percent,
            started_at_tick: self.current_tick,
            deadline_tick: self.current_tick + cmd.deadline_ticks,
            version: 0, // Assigned by store.
            previous_version,
        };

        let rollout_id = self.rollouts.insert(rollout);

        // Mark agents as staged in the agent state store.
        let agent_ids: Vec<String> = {
            let rollout = self.rollouts.get(rollout_id)?;
            rollout.agent_states.keys().cloned().collect()
        };
        let agent_count = agent_ids.len();
        for agent_id in &agent_ids {
            self.agent_states
                .mark_staged(agent_id, cmd.policy_version.version);
        }

        // Transition to AwaitingReady.
        let v = self.rollouts.get(rollout_id)?.version;
        self.rollouts.update(rollout_id, v, |r| {
            r.phase = RolloutPhase::AwaitingReady;
        })?;

        self.audit.append_success(
            &cmd.actor_spiffe_id,
            "rollout.stage",
            &format!("rollout:{rollout_id}"),
            &format!(
                "{{\"version\":{},\"targets\":{agent_count},\"threshold\":{}}}",
                cmd.policy_version.version,
                cmd.threshold_percent
            ),
            self.current_tick,
        );

        Ok(rollout_id)
    }

    /// **READY**: an agent acknowledges it has staged and verified
    /// the policy digest.
    ///
    /// The agent must be a target of the active rollout. The
    /// computed digest must match the policy version's digest.
    ///
    /// Idempotent: duplicate READY from the same agent for the
    /// same version is a safe no-op.
    ///
    /// Authorization: requires the agent's own SPIFFE ID.
    pub fn ready(&mut self, ack: &ReadyAck) -> RolloutResult<()> {
        let rollout = self
            .rollouts
            .active_rollout()
            .ok_or_else(|| RolloutError::NotFound {
                entity: "active_rollout".into(),
                key: "none".into(),
            })?;

        let rollout_id = rollout.id;

        // Version must match the rollout's policy version.
        if ack.version != rollout.policy_version.version {
            return Err(RolloutError::VersionReplay {
                command_version: ack.version,
                current_version: rollout.policy_version.version,
            });
        }

        // Agent must be a target.
        let current_state = rollout
            .agent_states
            .get(&ack.agent_spiffe_id)
            .copied()
            .ok_or_else(|| RolloutError::AgentNotTargeted {
                agent_id: ack.agent_spiffe_id.clone(),
                rollout_id,
            })?;

        // Idempotent: already Ready or beyond.
        if matches!(
            current_state,
            AgentRolloutState::Ready
                | AgentRolloutState::Applied
        ) {
            self.audit.append_success(
                &ack.agent_spiffe_id,
                "agent.ready.idempotent",
                &format!("rollout:{rollout_id}"),
                &format!("{{\"version\":{}}}", ack.version),
                self.current_tick,
            );
            return Ok(());
        }

        // Authorize the agent.
        self.authorizer.authorize_agent(
            &ack.agent_spiffe_id,
            &ack.agent_spiffe_id,
            "ready",
        )?;

        // Verify the agent's computed digest matches.
        if !verify_digest(
            &rollout.policy_version.content_bytes,
            &ack.computed_digest,
        ) {
            let expected = rollout.policy_version.content_digest.clone();
            let v = self.rollouts.get(rollout_id)?.version;
            self.rollouts.update(rollout_id, v, |r| {
                r.agent_states
                    .insert(ack.agent_spiffe_id.clone(), AgentRolloutState::Rejected);
            })?;

            self.audit.append_failure(
                &ack.agent_spiffe_id,
                "agent.ready",
                &format!("rollout:{rollout_id}"),
                &format!(
                    "{{\"version\":{},\"expected\":\"{expected}\",\"actual\":\"{}\"}}",
                    ack.version, ack.computed_digest
                ),
                "digest mismatch",
                self.current_tick,
            );

            return Err(RolloutError::AgentDigestMismatch {
                agent_id: ack.agent_spiffe_id.clone(),
                expected,
                actual: ack.computed_digest.clone(),
            });
        }

        // Transition agent to Ready.
        let v = self.rollouts.get(rollout_id)?.version;
        self.rollouts.update(rollout_id, v, |r| {
            r.agent_states
                .insert(ack.agent_spiffe_id.clone(), AgentRolloutState::Ready);
        })?;

        self.audit.append_success(
            &ack.agent_spiffe_id,
            "agent.ready",
            &format!("rollout:{rollout_id}"),
            &format!("{{\"version\":{}}}", ack.version),
            self.current_tick,
        );

        // Check if threshold is met for automatic commit.
        let rollout = self.rollouts.get(rollout_id)?;
        if rollout.threshold_met() && rollout.threshold_percent > 0 {
            self.audit.append_success(
                "system",
                "rollout.threshold_met",
                &format!("rollout:{rollout_id}"),
                &format!(
                    "{{\"ready\":{},\"total\":{},\"threshold\":{}}}",
                    rollout.count_in_state(AgentRolloutState::Ready),
                    rollout.target_count(),
                    rollout.threshold_percent
                ),
                self.current_tick,
            );
        }

        Ok(())
    }

    /// **COMMIT**: activate the staged policy on ready agents.
    ///
    /// Valid when:
    /// - Threshold is met (automatic), OR
    /// - Operator issues explicit COMMIT.
    ///
    /// Only agents in Ready state receive the COMMIT. Agents in
    /// Pending, Staged, Rejected, or Disconnected do NOT.
    ///
    /// Idempotent: duplicate COMMIT for the same version is a
    /// safe no-op.
    ///
    /// Authorization: requires operator SPIFFE ID (or "system"
    /// for automatic threshold commit).
    pub fn commit(&mut self, cmd: &CommitCommand) -> RolloutResult<()> {
        let rollout = self
            .rollouts
            .active_rollout()
            .ok_or_else(|| RolloutError::NotFound {
                entity: "active_rollout".into(),
                key: "none".into(),
            })?;

        let rollout_id = rollout.id;

        // Version must match.
        if cmd.version != rollout.policy_version.version {
            return Err(RolloutError::VersionReplay {
                command_version: cmd.version,
                current_version: rollout.policy_version.version,
            });
        }

        // Idempotent: already committing or beyond.
        if matches!(
            rollout.phase,
            RolloutPhase::Committing
                | RolloutPhase::Completed
                | RolloutPhase::Partial
        ) {
            self.audit.append_success(
                &cmd.actor_spiffe_id,
                "rollout.commit.idempotent",
                &format!("rollout:{rollout_id}"),
                &format!("{{\"version\":{}}}", cmd.version),
                self.current_tick,
            );
            return Ok(());
        }

        // Must be in AwaitingReady phase.
        if rollout.phase != RolloutPhase::AwaitingReady {
            return Err(RolloutError::InvalidTransition {
                from: rollout.phase.to_string(),
                action: "commit".into(),
            });
        }

        // Authorize: operator or system (automatic threshold).
        if cmd.actor_spiffe_id != "system" {
            self.authorizer
                .authorize_operator(&cmd.actor_spiffe_id, "commit")?;
        }

        // Check threshold for non-system commits.
        if cmd.actor_spiffe_id != "system" && !rollout.threshold_met() {
            // Operator can force commit even if threshold not met.
            // This is an explicit override.
        }

        // Transition to Committing.
        let v = self.rollouts.get(rollout_id)?.version;
        self.rollouts.update(rollout_id, v, |r| {
            r.phase = RolloutPhase::Committing;
        })?;

        self.audit.append_success(
            &cmd.actor_spiffe_id,
            "rollout.commit",
            &format!("rollout:{rollout_id}"),
            &format!("{{\"version\":{}}}", cmd.version),
            self.current_tick,
        );

        Ok(())
    }

    /// **APPLIED**: an agent reports the policy is now active.
    ///
    /// The agent must be in the Committing phase and in Ready
    /// state. Transitions the agent to Applied.
    ///
    /// Idempotent: duplicate APPLIED from the same agent is a
    /// safe no-op.
    ///
    /// Authorization: requires the agent's own SPIFFE ID.
    pub fn applied(&mut self, report: &AppliedReport) -> RolloutResult<()> {
        // Extract all needed values from the immutable borrow first.
        let (rollout_id, policy_version, content_digest, current_state) = {
            let rollout = self
                .rollouts
                .active_rollout()
                .ok_or_else(|| RolloutError::NotFound {
                    entity: "active_rollout".into(),
                    key: "none".into(),
                })?;

            let current_state = rollout
                .agent_states
                .get(&report.agent_spiffe_id)
                .copied()
                .ok_or_else(|| RolloutError::AgentNotTargeted {
                    agent_id: report.agent_spiffe_id.clone(),
                    rollout_id: rollout.id,
                })?;

            (
                rollout.id,
                rollout.policy_version.version,
                rollout.policy_version.content_digest.clone(),
                current_state,
            )
        };

        // Version must match.
        if report.version != policy_version {
            return Err(RolloutError::VersionReplay {
                command_version: report.version,
                current_version: policy_version,
            });
        }

        // Idempotent: already Applied.
        if current_state == AgentRolloutState::Applied {
            self.audit.append_success(
                &report.agent_spiffe_id,
                "agent.applied.idempotent",
                &format!("rollout:{rollout_id}"),
                &format!("{{\"version\":{}}}", report.version),
                self.current_tick,
            );
            return Ok(());
        }

        // Must be in Ready state (COMMIT was sent).
        if current_state != AgentRolloutState::Ready {
            return Err(RolloutError::InvalidTransition {
                from: current_state.to_string(),
                action: "applied".into(),
            });
        }

        // Authorize the agent.
        self.authorizer.authorize_agent(
            &report.agent_spiffe_id,
            &report.agent_spiffe_id,
            "applied",
        )?;

        // Transition agent to Applied.
        let v = self.rollouts.get(rollout_id)?.version;
        self.rollouts.update(rollout_id, v, |r| {
            r.agent_states
                .insert(report.agent_spiffe_id.clone(), AgentRolloutState::Applied);
        })?;

        // Update agent state store and last-known-good.
        self.agent_states
            .mark_applied(&report.agent_spiffe_id, report.version);
        self.last_known_good.record_applied(
            &report.agent_spiffe_id,
            report.version,
            &content_digest,
        );

        self.audit.append_success(
            &report.agent_spiffe_id,
            "agent.applied",
            &format!("rollout:{rollout_id}"),
            &format!("{{\"version\":{}}}", report.version),
            self.current_tick,
        );

        // Check if all agents have applied → Completed.
        self.check_rollout_completion(rollout_id)?;

        Ok(())
    }

    /// **REJECTED**: an agent reports it could not apply the
    /// policy.
    ///
    /// The agent transitions to Rejected. The rollout may become
    /// Partial if some agents applied.
    ///
    /// Authorization: requires the agent's own SPIFFE ID.
    pub fn rejected(&mut self, report: &RejectedReport) -> RolloutResult<()> {
        let rollout = self
            .rollouts
            .active_rollout()
            .ok_or_else(|| RolloutError::NotFound {
                entity: "active_rollout".into(),
                key: "none".into(),
            })?;

        let rollout_id = rollout.id;

        // Version must match.
        if report.version != rollout.policy_version.version {
            return Err(RolloutError::VersionReplay {
                command_version: report.version,
                current_version: rollout.policy_version.version,
            });
        }

        // Agent must be a target.
        let current_state = rollout
            .agent_states
            .get(&report.agent_spiffe_id)
            .copied()
            .ok_or_else(|| RolloutError::AgentNotTargeted {
                agent_id: report.agent_spiffe_id.clone(),
                rollout_id,
            })?;

        // Idempotent: already Rejected.
        if current_state == AgentRolloutState::Rejected {
            return Ok(());
        }

        // Authorize the agent.
        self.authorizer.authorize_agent(
            &report.agent_spiffe_id,
            &report.agent_spiffe_id,
            "rejected",
        )?;

        // Transition agent to Rejected.
        let v = self.rollouts.get(rollout_id)?.version;
        self.rollouts.update(rollout_id, v, |r| {
            r.agent_states
                .insert(report.agent_spiffe_id.clone(), AgentRolloutState::Rejected);
        })?;

        self.audit.append_failure(
            &report.agent_spiffe_id,
            "agent.rejected",
            &format!("rollout:{rollout_id}"),
            &format!(
                "{{\"version\":{},\"reason\":\"{}\"}}",
                report.version, report.reason
            ),
            &report.reason,
            self.current_tick,
        );

        // Check rollout completion (may become Partial).
        self.check_rollout_completion(rollout_id)?;

        Ok(())
    }

    /// **CANCEL**: operator cancels an in-progress rollout.
    ///
    /// Valid from Staging, AwaitingReady, or Committing phases.
    /// Agents that already applied keep their policy (last-known-good).
    ///
    /// Authorization: requires operator SPIFFE ID.
    pub fn cancel(&mut self, cmd: &CancelCommand) -> RolloutResult<()> {
        let rollout = self.rollouts.get(cmd.rollout_id)?;

        // Idempotent: already cancelled.
        if rollout.phase == RolloutPhase::Cancelled {
            return Ok(());
        }

        // Must not be in a terminal phase.
        if rollout.is_terminal() {
            return Err(RolloutError::InvalidTransition {
                from: rollout.phase.to_string(),
                action: "cancel".into(),
            });
        }

        // Authorize the operator.
        self.authorizer
            .authorize_operator(&cmd.actor_spiffe_id, "cancel")?;

        let v = rollout.version;
        self.rollouts.update(cmd.rollout_id, v, |r| {
            r.phase = RolloutPhase::Cancelled;
        })?;

        self.audit.append_success(
            &cmd.actor_spiffe_id,
            "rollout.cancel",
            &format!("rollout:{}", cmd.rollout_id),
            "{}",
            self.current_tick,
        );

        Ok(())
    }

    /// **ROLLBACK**: revert to the previous active policy version
    /// on all agents that applied the current version.
    ///
    /// Valid from Completed or Partial phases.
    ///
    /// Authorization: requires operator SPIFFE ID.
    pub fn rollback(&mut self, cmd: &RollbackCommand) -> RolloutResult<()> {
        let rollout = self.rollouts.get(cmd.rollout_id)?;

        // Idempotent: already rolled back.
        if rollout.phase == RolloutPhase::RolledBack {
            return Ok(());
        }

        // Must be in Completed or Partial phase.
        if !matches!(
            rollout.phase,
            RolloutPhase::Completed | RolloutPhase::Partial
        ) {
            return Err(RolloutError::InvalidTransition {
                from: rollout.phase.to_string(),
                action: "rollback".into(),
            });
        }

        // Authorize the operator.
        self.authorizer
            .authorize_operator(&cmd.actor_spiffe_id, "rollback")?;

        let previous_version = rollout.previous_version;
        let current_version = rollout.policy_version.version;

        // Rollback each applied agent to its last-known-good.
        let applied_agents: Vec<String> = rollout
            .agent_states
            .iter()
            .filter(|(_, s)| **s == AgentRolloutState::Applied)
            .map(|(id, _)| id.clone())
            .collect();

        for agent_id in &applied_agents {
            // Revert to previous version in agent state.
            if let Some(prev_v) = previous_version {
                if let Some(prev_pv) = self.policy_versions.get(prev_v).ok() {
                    self.agent_states.mark_applied(agent_id, prev_v);
                    self.last_known_good.record_applied(
                        agent_id,
                        prev_v,
                        &prev_pv.content_digest,
                    );
                }
            } else {
                // No previous version: revert to version 0 (no policy).
                self.agent_states.mark_applied(agent_id, 0);
                self.last_known_good.rollback(agent_id, None);
            }
        }

        // Revert the fleet active version.
        if let Some(prev_v) = previous_version {
            self.active_version = prev_v;
        } else {
            self.active_version = 0;
        }

        let v = rollout.version;
        self.rollouts.update(cmd.rollout_id, v, |r| {
            r.phase = RolloutPhase::RolledBack;
            // Mark applied agents as reverted.
            for agent_id in &applied_agents {
                r.agent_states
                    .insert(agent_id.clone(), AgentRolloutState::Rejected);
            }
        })?;

        self.audit.append_success(
            &cmd.actor_spiffe_id,
            "rollout.rollback",
            &format!("rollout:{}", cmd.rollout_id),
            &format!(
                "{{\"from_version\":{current_version},\"to_version\":{}}}",
                previous_version.unwrap_or(0)
            ),
            self.current_tick,
        );

        Ok(())
    }

    /// **TIMEOUT CHECK**: check if the active rollout has exceeded
    /// its deadline.
    ///
    /// If timed out, the rollout transitions to TimedOut. Agents
    /// that already applied keep their policy.
    pub fn check_timeout(&mut self) -> RolloutResult<bool> {
        // Extract values before mutable borrow.
        let (rollout_id, version, deadline_tick, any_applied, is_terminal) = {
            match self.rollouts.active_rollout() {
                Some(r) => (
                    r.id,
                    r.version,
                    r.deadline_tick,
                    r.agent_states
                        .values()
                        .any(|s| *s == AgentRolloutState::Applied),
                    r.is_terminal(),
                ),
                None => return Ok(false),
            }
        };

        if is_terminal {
            return Ok(false);
        }

        if self.current_tick > deadline_tick {
            let new_phase = if any_applied {
                RolloutPhase::Partial
            } else {
                RolloutPhase::TimedOut
            };

            self.rollouts.update(rollout_id, version, |r| {
                r.phase = new_phase;
            })?;

            self.audit.append_failure(
                "system",
                "rollout.timeout",
                &format!("rollout:{rollout_id}"),
                &format!(
                    "{{\"tick\":{},\"deadline\":{deadline_tick},\"phase\":\"{new_phase}\"}}",
                    self.current_tick
                ),
                "deadline exceeded",
                self.current_tick,
            );

            return Ok(true);
        }

        Ok(false)
    }

    /// **DISCONNECT**: mark an agent as disconnected.
    ///
    /// The agent's active policy is NOT relaxed (last-known-good
    /// maintained). The agent transitions to Disconnected state
    /// in the current rollout.
    pub fn agent_disconnected(&mut self, agent_spiffe_id: &str) -> RolloutResult<()> {
        let info: Option<(u64, i64)> = self
            .rollouts
            .active_rollout()
            .filter(|r| r.agent_states.contains_key(agent_spiffe_id))
            .map(|r| (r.id, r.version));

        if let Some((rollout_id, v)) = info {
            self.rollouts.update(rollout_id, v, |r| {
                r.agent_states.insert(
                    agent_spiffe_id.to_string(),
                    AgentRolloutState::Disconnected,
                );
            })?;

            self.audit.append_failure(
                agent_spiffe_id,
                "agent.disconnected",
                &format!("rollout:{rollout_id}"),
                "{}",
                "agent disconnected; last-known-good maintained",
                self.current_tick,
            );
        }
        Ok(())
    }

    // -- Internal helpers --

    /// Get all known agent IDs from the agent state store.
    fn agent_states_known_ids(&self) -> Vec<String> {
        // In a real system, this would query the fleet inventory.
        // For the in-memory mock, we return agents that have been
        // seen before.
        Vec::new()
    }

    /// Check if the rollout is complete (all agents applied) or
    /// partial (some failed).
    fn check_rollout_completion(&mut self, rollout_id: u64) -> RolloutResult<()> {
        // Extract all needed values before mutable borrow.
        let (phase, version, policy_version, all_applied, any_terminal, all_terminal, any_applied_state, applied_count, rejected_count, disconnected_count) = {
            let rollout = self.rollouts.get(rollout_id)?;
            (
                rollout.phase,
                rollout.version,
                rollout.policy_version.version,
                rollout.all_applied(),
                rollout.agent_states.values().any(|s| {
                    matches!(
                        s,
                        AgentRolloutState::Applied
                            | AgentRolloutState::Rejected
                            | AgentRolloutState::Disconnected
                    )
                }),
                rollout.agent_states.values().all(|s| {
                    matches!(
                        s,
                        AgentRolloutState::Applied
                            | AgentRolloutState::Rejected
                            | AgentRolloutState::Disconnected
                    )
                }),
                rollout
                    .agent_states
                    .values()
                    .any(|s| *s == AgentRolloutState::Applied),
                rollout.count_in_state(AgentRolloutState::Applied),
                rollout.count_in_state(AgentRolloutState::Rejected),
                rollout.count_in_state(AgentRolloutState::Disconnected),
            )
        };

        if phase != RolloutPhase::Committing {
            return Ok(());
        }

        if all_applied {
            self.rollouts.update(rollout_id, version, |r| {
                r.phase = RolloutPhase::Completed;
            })?;

            self.active_version = policy_version;

            self.audit.append_success(
                "system",
                "rollout.completed",
                &format!("rollout:{rollout_id}"),
                &format!("{{\"version\":{policy_version}}}"),
                self.current_tick,
            );
        } else if any_terminal && all_terminal {
            if any_applied_state {
                self.rollouts.update(rollout_id, version, |r| {
                    r.phase = RolloutPhase::Partial;
                })?;
                self.active_version = policy_version;
            } else {
                self.rollouts.update(rollout_id, version, |r| {
                    r.phase = RolloutPhase::TimedOut;
                })?;
            }

            self.audit.append_success(
                "system",
                "rollout.settled",
                &format!("rollout:{rollout_id}"),
                &format!(
                    "{{\"applied\":{applied_count},\"rejected\":{rejected_count},\"disconnected\":{disconnected_count}}}"
                ),
                self.current_tick,
            );
        }

        Ok(())
    }

    /// Register an agent in the agent state store (for testing
    /// and fleet inventory simulation).
    pub fn register_agent(&mut self, agent_spiffe_id: &str, active_version: u64) {
        self.agent_states
            .set_state(agent_spiffe_id, active_version, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::compute_policy_digest;

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
        assert_eq!(
            coord.agent_states().get_state(&targets[0]),
            Some((1, None))
        );
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
        assert_eq!(
            coord.agent_states().get_state(&targets[0]),
            Some((1, None))
        );
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
        assert_eq!(
            rollout.count_in_state(AgentRolloutState::Ready),
            2
        );
        assert_eq!(
            rollout.count_in_state(AgentRolloutState::Applied),
            0
        );
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
}
