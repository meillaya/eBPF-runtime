// SPDX-License-Identifier: Apache-2.0 OR MIT
//! STAGE command implementation.

use std::collections::HashMap;

use super::FleetRolloutCoordinator;
use crate::digest::verify_digest;
use crate::error::{RolloutError, RolloutResult};
use crate::model::*;

impl FleetRolloutCoordinator {
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
        if !verify_digest(
            &cmd.policy_version.content_bytes,
            &cmd.policy_version.content_digest,
        ) {
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
                cmd.policy_version.version, cmd.threshold_percent
            ),
            self.current_tick,
        );

        Ok(rollout_id)
    }
}
