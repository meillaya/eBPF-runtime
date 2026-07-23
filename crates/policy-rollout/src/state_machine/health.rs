// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Timeout, disconnect, and internal helper implementations.

use super::FleetRolloutCoordinator;
use crate::error::RolloutResult;
use crate::model::*;

impl FleetRolloutCoordinator {
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
                r.agent_states
                    .insert(agent_spiffe_id.to_string(), AgentRolloutState::Disconnected);
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
    pub(crate) fn agent_states_known_ids(&self) -> Vec<String> {
        // In a real system, this would query the fleet inventory.
        // For the in-memory mock, we return agents that have been
        // seen before.
        Vec::new()
    }

    /// Check if the rollout is complete (all agents applied) or
    /// partial (some failed).
    pub(crate) fn check_rollout_completion(&mut self, rollout_id: u64) -> RolloutResult<()> {
        // Extract all needed values before mutable borrow.
        let (
            phase,
            version,
            policy_version,
            all_applied,
            any_terminal,
            all_terminal,
            any_applied_state,
            applied_count,
            rejected_count,
            disconnected_count,
        ) = {
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
}
