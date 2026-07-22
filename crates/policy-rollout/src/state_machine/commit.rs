// SPDX-License-Identifier: Apache-2.0 OR MIT
//! COMMIT command implementation.

use super::FleetRolloutCoordinator;
use crate::error::{RolloutError, RolloutResult};
use crate::model::*;

impl FleetRolloutCoordinator {
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
            RolloutPhase::Committing | RolloutPhase::Completed | RolloutPhase::Partial
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
}
