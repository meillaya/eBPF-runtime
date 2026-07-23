// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Core model types for fleet two-phase policy rollout.
//!
//! Immutable policy versions are content-addressed (SHA-256 digest).
//! Versions use a monotonic counter — NEVER wall clock.
//! All commands carry the issuer's SPIFFE ID for authorization.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An immutable, content-addressed policy version.
///
/// Once created, a policy version cannot be modified. The
/// `content_digest` is the SHA-256 hex of `content_bytes`.
/// The `version` is a monotonic counter (never wall clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVersion {
    /// Monotonic version number. Must be strictly increasing.
    pub version: u64,
    /// Opaque policy content bytes.
    pub content_bytes: Vec<u8>,
    /// SHA-256 hex digest of `content_bytes` (content-addressed).
    pub content_digest: String,
    /// Target agent SPIFFE IDs. Empty means all agents in the
    /// cluster.
    pub targets: Vec<String>,
    /// SPIFFE ID of the actor who created this version.
    pub created_by: String,
}

/// Per-agent state within a fleet rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRolloutState {
    /// Agent has not yet received the STAGE command.
    Pending,
    /// Agent received the policy; it is staged but NOT active.
    Staged,
    /// Agent verified the digest and is ready for COMMIT.
    Ready,
    /// Agent received COMMIT and activated the policy.
    Applied,
    /// Agent rejected the policy (digest mismatch, invalid
    /// content, or explicit rejection).
    Rejected,
    /// Agent disconnected during the rollout. The agent
    /// maintains its last-known-good policy (NEVER relaxed).
    Disconnected,
}

impl std::fmt::Display for AgentRolloutState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Pending => "Pending",
            Self::Staged => "Staged",
            Self::Ready => "Ready",
            Self::Applied => "Applied",
            Self::Rejected => "Rejected",
            Self::Disconnected => "Disconnected",
        };
        f.write_str(name)
    }
}

/// The overall phase of a fleet rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RolloutPhase {
    /// Distributing policy to target agents (STAGE sent).
    Staging,
    /// Waiting for agents to report READY.
    AwaitingReady,
    /// Threshold met; COMMIT sent to ready agents.
    Committing,
    /// All target agents have applied the policy.
    Completed,
    /// Some agents applied, some failed/disconnected.
    /// The policy is active on the successful subset.
    Partial,
    /// The rollout exceeded its deadline.
    TimedOut,
    /// Operator cancelled the rollout.
    Cancelled,
    /// Rolled back to the previous active version.
    RolledBack,
}

impl std::fmt::Display for RolloutPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Staging => "Staging",
            Self::AwaitingReady => "AwaitingReady",
            Self::Committing => "Committing",
            Self::Completed => "Completed",
            Self::Partial => "Partial",
            Self::TimedOut => "TimedOut",
            Self::Cancelled => "Cancelled",
            Self::RolledBack => "RolledBack",
        };
        f.write_str(name)
    }
}

/// A fleet rollout: tracks the distributed two-phase activation
/// of a policy version across multiple agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetRollout {
    /// Unique rollout ID (monotonic).
    pub id: u64,
    /// The policy version being rolled out.
    pub policy_version: PolicyVersion,
    /// Current rollout phase.
    pub phase: RolloutPhase,
    /// Per-agent state: SPIFFE ID → state.
    pub agent_states: HashMap<String, AgentRolloutState>,
    /// Percentage of agents that must report READY before
    /// automatic COMMIT (0 = manual only, 100 = all).
    pub threshold_percent: u32,
    /// Monotonic tick when the rollout started (NOT wall clock).
    pub started_at_tick: u64,
    /// Monotonic tick deadline for timeout.
    pub deadline_tick: u64,
    /// Optimistic concurrency version.
    pub version: i64,
    /// The previous active policy version (for rollback).
    /// None if this is the first rollout.
    pub previous_version: Option<u64>,
}

impl FleetRollout {
    /// Count agents in a given state.
    pub fn count_in_state(&self, state: AgentRolloutState) -> usize {
        self.agent_states.values().filter(|s| **s == state).count()
    }

    /// Total number of target agents.
    pub fn target_count(&self) -> usize {
        self.agent_states.len()
    }

    /// Whether the READY threshold has been met.
    pub fn threshold_met(&self) -> bool {
        if self.target_count() == 0 {
            return false;
        }
        let ready = self.count_in_state(AgentRolloutState::Ready);
        let pct = (ready * 100) / self.target_count();
        pct >= self.threshold_percent as usize
    }

    /// Whether all target agents have applied.
    pub fn all_applied(&self) -> bool {
        !self.agent_states.is_empty()
            && self
                .agent_states
                .values()
                .all(|s| *s == AgentRolloutState::Applied)
    }

    /// Whether the rollout is in a terminal phase.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            RolloutPhase::Completed
                | RolloutPhase::Partial
                | RolloutPhase::TimedOut
                | RolloutPhase::Cancelled
                | RolloutPhase::RolledBack
        )
    }
}

// -- Commands --

/// STAGE command: distribute a policy version to target agents.
/// The policy is staged (inactive) — NOT activated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageCommand {
    /// The policy version to stage.
    pub policy_version: PolicyVersion,
    /// SPIFFE ID of the operator issuing the command.
    pub actor_spiffe_id: String,
    /// Threshold percent for automatic COMMIT (0 = manual).
    pub threshold_percent: u32,
    /// Deadline in monotonic ticks from now.
    pub deadline_ticks: u64,
}

/// READY acknowledgment: an agent confirms it has staged and
/// verified the policy digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyAck {
    /// The agent's SPIFFE ID.
    pub agent_spiffe_id: String,
    /// The policy version the agent is acknowledging.
    pub version: u64,
    /// The digest the agent computed from the staged content.
    pub computed_digest: String,
}

/// COMMIT command: activate the staged policy on ready agents.
/// Issued by an operator or automatically when threshold is met.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitCommand {
    /// The policy version to commit.
    pub version: u64,
    /// SPIFFE ID of the operator (or "system" for automatic).
    pub actor_spiffe_id: String,
}

/// APPLIED report: an agent confirms the policy is now active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedReport {
    /// The agent's SPIFFE ID.
    pub agent_spiffe_id: String,
    /// The policy version that was applied.
    pub version: u64,
}

/// REJECTED report: an agent reports it could not apply the
/// policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedReport {
    /// The agent's SPIFFE ID.
    pub agent_spiffe_id: String,
    /// The policy version that was rejected.
    pub version: u64,
    /// Human-readable rejection reason.
    pub reason: String,
}

/// CANCEL command: operator cancels an in-progress rollout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelCommand {
    /// The rollout ID to cancel.
    pub rollout_id: u64,
    /// SPIFFE ID of the operator.
    pub actor_spiffe_id: String,
}

/// ROLLBACK command: revert to the previous active policy
/// version on all agents that applied the current version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackCommand {
    /// The rollout ID to roll back.
    pub rollout_id: u64,
    /// SPIFFE ID of the operator.
    pub actor_spiffe_id: String,
}

/// Agent status report for reconciliation on reconnect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusReport {
    /// The agent's SPIFFE ID.
    pub agent_spiffe_id: String,
    /// The policy version currently active on the agent.
    pub active_version: u64,
    /// The digest of the active policy on the agent.
    pub active_digest: String,
    /// The policy version staged (inactive) on the agent, if
    /// any.
    pub staged_version: Option<u64>,
}

/// The result of a reconciliation check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconcileAction {
    /// Agent is up-to-date; no action needed.
    UpToDate,
    /// Agent needs to re-stage the current rollout policy.
    ReStage {
        /// The version to re-stage.
        version: u64,
    },
    /// Agent needs to commit the staged policy.
    Commit {
        /// The version to commit.
        version: u64,
    },
    /// Agent is on a newer version than expected (stale server
    /// state); server should update its records.
    AgentAhead {
        /// The version the agent reports.
        agent_version: u64,
    },
    /// Agent is on an older version; needs the latest active
    /// policy re-staged.
    AgentBehind {
        /// The version the agent has.
        agent_version: u64,
        /// The version the server expects.
        expected_version: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(version: u64) -> PolicyVersion {
        PolicyVersion {
            version,
            content_bytes: format!("policy-v{version}").into_bytes(),
            content_digest: format!("digest-v{version}"),
            targets: vec![],
            created_by: "spiffe://kernel-v1.test/operator/admin".into(),
        }
    }

    fn make_rollout(agent_count: usize) -> FleetRollout {
        let mut agent_states = HashMap::new();
        for i in 0..agent_count {
            agent_states.insert(
                format!("spiffe://kernel-v1.test/agent/prod/node-{i}"),
                AgentRolloutState::Pending,
            );
        }
        FleetRollout {
            id: 1,
            policy_version: make_policy(1),
            phase: RolloutPhase::Staging,
            agent_states,
            threshold_percent: 100,
            started_at_tick: 0,
            deadline_tick: 100,
            version: 1,
            previous_version: None,
        }
    }

    #[test]
    fn count_in_state() {
        let mut r = make_rollout(3);
        assert_eq!(r.count_in_state(AgentRolloutState::Pending), 3);

        let key = "spiffe://kernel-v1.test/agent/prod/node-0".to_string();
        r.agent_states.insert(key, AgentRolloutState::Ready);
        assert_eq!(r.count_in_state(AgentRolloutState::Ready), 1);
        assert_eq!(r.count_in_state(AgentRolloutState::Pending), 2);
    }

    #[test]
    fn threshold_met_at_100_percent() {
        let mut r = make_rollout(2);
        r.threshold_percent = 100;
        assert!(!r.threshold_met());

        let keys: Vec<String> = r.agent_states.keys().cloned().collect();
        r.agent_states
            .insert(keys[0].clone(), AgentRolloutState::Ready);
        assert!(!r.threshold_met());

        r.agent_states
            .insert(keys[1].clone(), AgentRolloutState::Ready);
        assert!(r.threshold_met());
    }

    #[test]
    fn threshold_met_at_50_percent() {
        let mut r = make_rollout(4);
        r.threshold_percent = 50;

        let keys: Vec<String> = r.agent_states.keys().cloned().collect();
        r.agent_states
            .insert(keys[0].clone(), AgentRolloutState::Ready);
        r.agent_states
            .insert(keys[1].clone(), AgentRolloutState::Ready);
        assert!(r.threshold_met()); // 2/4 = 50%
    }

    #[test]
    fn all_applied() {
        let mut r = make_rollout(2);
        assert!(!r.all_applied());

        let keys: Vec<String> = r.agent_states.keys().cloned().collect();
        r.agent_states
            .insert(keys[0].clone(), AgentRolloutState::Applied);
        assert!(!r.all_applied());

        r.agent_states
            .insert(keys[1].clone(), AgentRolloutState::Applied);
        assert!(r.all_applied());
    }

    #[test]
    fn terminal_phases() {
        let mut r = make_rollout(1);
        assert!(!r.is_terminal());

        r.phase = RolloutPhase::Completed;
        assert!(r.is_terminal());

        r.phase = RolloutPhase::Partial;
        assert!(r.is_terminal());

        r.phase = RolloutPhase::Cancelled;
        assert!(r.is_terminal());

        r.phase = RolloutPhase::RolledBack;
        assert!(r.is_terminal());

        r.phase = RolloutPhase::TimedOut;
        assert!(r.is_terminal());

        r.phase = RolloutPhase::Staging;
        assert!(!r.is_terminal());
    }

    #[test]
    fn empty_rollout_threshold_not_met() {
        let r = make_rollout(0);
        assert!(!r.threshold_met());
        assert!(!r.all_applied());
    }

    #[test]
    fn policy_version_serde_roundtrip() {
        let pv = make_policy(42);
        let json = serde_json::to_string(&pv).unwrap();
        let decoded: PolicyVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(pv, decoded);
    }

    #[test]
    fn agent_state_display() {
        assert_eq!(AgentRolloutState::Pending.to_string(), "Pending");
        assert_eq!(AgentRolloutState::Applied.to_string(), "Applied");
        assert_eq!(AgentRolloutState::Rejected.to_string(), "Rejected");
    }

    #[test]
    fn rollout_phase_display() {
        assert_eq!(RolloutPhase::Staging.to_string(), "Staging");
        assert_eq!(RolloutPhase::Completed.to_string(), "Completed");
        assert_eq!(RolloutPhase::RolledBack.to_string(), "RolledBack");
    }
}
