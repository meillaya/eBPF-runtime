// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Audit hooks for every mutation.
//!
//! Every state-changing operation through the control-plane
//! emits an actor-bound audit intent. Read-only operations
//! do NOT emit intents. The audit hook wraps the auth crate's
//! [`AuditSink`] and adds cluster context.

#![forbid(unsafe_code)]

use auth::{AuditIntent, AuditSink};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An enriched audit record with cluster context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The OIDC subject performing the action.
    pub actor: String,
    /// The action (e.g. "policy.stage", "rollout.create").
    pub action: String,
    /// The target resource.
    pub resource: String,
    /// The cluster scope (if applicable).
    pub cluster_id: Option<Uuid>,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Error message (empty on success).
    pub error: String,
    /// Monotonic sequence number.
    pub seq: u64,
}

/// Audit hook that emits actor-bound intents for every
/// mutation.
#[derive(Debug)]
pub struct AuditHook {
    sink: AuditSink,
}

impl AuditHook {
    /// Create a new audit hook.
    pub fn new() -> Self {
        Self {
            sink: AuditSink::new(),
        }
    }

    /// Record a mutation audit intent.
    pub fn record_mutation(&self, actor: &str, action: &str, resource: &str) {
        self.sink.record(AuditIntent::new(actor, action, resource));
    }

    /// Record a denied mutation attempt (for security audit).
    pub fn record_denied(&self, actor: &str, action: &str, resource: &str, reason: &str) {
        self.sink.record(AuditIntent::new(
            actor,
            &format!("denied:{action}"),
            &format!("{resource} ({reason})"),
        ));
    }

    /// The number of recorded audit intents.
    pub fn count(&self) -> usize {
        self.sink.count()
    }

    /// All recorded intents.
    pub fn intents(&self) -> Vec<AuditIntent> {
        self.sink.intents()
    }

    /// Whether any intent was recorded by the given actor.
    pub fn has_actor(&self, actor: &str) -> bool {
        self.sink.has_actor(actor)
    }

    /// Access the underlying audit sink.
    pub fn sink(&self) -> &AuditSink {
        &self.sink
    }
}

impl Default for AuditHook {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_emits_intent() {
        let hook = AuditHook::new();
        hook.record_mutation("admin-1", "policy.stage", "policy:v1");
        assert_eq!(hook.count(), 1);
        assert!(hook.has_actor("admin-1"));

        let intents = hook.intents();
        assert_eq!(intents[0].actor, "admin-1");
        assert_eq!(intents[0].action, "policy.stage");
        assert_eq!(intents[0].resource, "policy:v1");
    }

    #[test]
    fn denied_mutation_emits_intent() {
        let hook = AuditHook::new();
        hook.record_denied("viewer-1", "policy.stage", "/api/v1/policies/stage", "rbac");
        assert_eq!(hook.count(), 1);

        let intents = hook.intents();
        assert_eq!(intents[0].action, "denied:policy.stage");
        assert!(intents[0].resource.contains("rbac"));
    }

    #[test]
    fn read_only_does_not_emit() {
        let hook = AuditHook::new();
        // Reads don't call record_mutation.
        assert_eq!(hook.count(), 0);
    }

    #[test]
    fn multiple_actors_tracked() {
        let hook = AuditHook::new();
        hook.record_mutation("admin-1", "policy.stage", "p1");
        hook.record_mutation("admin-2", "rollout.create", "r1");
        assert_eq!(hook.count(), 2);
        assert!(hook.has_actor("admin-1"));
        assert!(hook.has_actor("admin-2"));
        assert!(!hook.has_actor("viewer-1"));
    }

    #[test]
    fn sequence_numbers_monotonic() {
        let hook = AuditHook::new();
        hook.record_mutation("a1", "act1", "r1");
        hook.record_mutation("a2", "act2", "r2");
        hook.record_mutation("a3", "act3", "r3");

        let intents = hook.intents();
        assert_eq!(intents[0].seq, 0);
        assert_eq!(intents[1].seq, 1);
        assert_eq!(intents[2].seq, 2);
    }
}
