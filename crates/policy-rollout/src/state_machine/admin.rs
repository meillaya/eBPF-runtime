// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CANCEL and ROLLBACK command implementations.

use super::FleetRolloutCoordinator;
use crate::error::{RolloutError, RolloutResult};
use crate::model::*;

impl FleetRolloutCoordinator {
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
                if let Ok(prev_pv) = self.policy_versions.get(prev_v) {
                    self.agent_states.mark_applied(agent_id, prev_v);
                    self.last_known_good
                        .record_applied(agent_id, prev_v, &prev_pv.content_digest);
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
}
