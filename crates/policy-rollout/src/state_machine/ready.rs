// SPDX-License-Identifier: Apache-2.0 OR MIT
//! READY command implementation.

use super::FleetRolloutCoordinator;
use crate::digest::verify_digest;
use crate::error::{RolloutError, RolloutResult};
use crate::model::*;

impl FleetRolloutCoordinator {
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
            AgentRolloutState::Ready | AgentRolloutState::Applied
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
        self.authorizer
            .authorize_agent(&ack.agent_spiffe_id, &ack.agent_spiffe_id, "ready")?;

        // Verify the agent's computed digest matches.
        if !verify_digest(&rollout.policy_version.content_bytes, &ack.computed_digest) {
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
}
