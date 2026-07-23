// SPDX-License-Identifier: Apache-2.0 OR MIT
//! APPLIED and REJECTED report implementations.

use super::FleetRolloutCoordinator;
use crate::error::{RolloutError, RolloutResult};
use crate::model::*;

impl FleetRolloutCoordinator {
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
}
