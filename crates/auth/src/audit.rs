// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actor-bound audit intent emission for every mutation.
//!
//! Every state-changing operation emits an [`AuditIntent`]
//! binding the actor (sub), the action, and the target
//! resource. Read-only operations do NOT emit intents.

#![forbid(unsafe_code)]

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// An actor-bound audit intent for a mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditIntent {
    /// The OIDC subject (user identity) performing the action.
    pub actor: String,
    /// The action being performed (e.g. "admin", "write").
    pub action: String,
    /// The target resource (e.g. route path).
    pub resource: String,
    /// Monotonic sequence number for ordering.
    pub seq: u64,
}

impl AuditIntent {
    /// Create a new audit intent (seq is assigned by the sink).
    pub fn new(actor: &str, action: &str, resource: &str) -> Self {
        Self {
            actor: actor.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            seq: 0, // assigned by AuditSink
        }
    }
}

/// Append-only audit intent sink.
#[derive(Debug)]
pub struct AuditSink {
    intents: Mutex<Vec<AuditIntent>>,
    next_seq: Mutex<u64>,
}

impl AuditSink {
    /// Create an empty audit sink.
    pub fn new() -> Self {
        Self {
            intents: Mutex::new(Vec::new()),
            next_seq: Mutex::new(0),
        }
    }

    /// Record an audit intent, assigning a monotonic sequence
    /// number.
    pub fn record(&self, mut intent: AuditIntent) {
        let mut seq = self.next_seq.lock();
        intent.seq = *seq;
        *seq += 1;
        self.intents.lock().push(intent);
    }

    /// All recorded intents (clone for inspection).
    pub fn intents(&self) -> Vec<AuditIntent> {
        self.intents.lock().clone()
    }

    /// The number of recorded intents.
    pub fn count(&self) -> usize {
        self.intents.lock().len()
    }

    /// Whether any intent was recorded by the given actor.
    pub fn has_actor(&self, actor: &str) -> bool {
        self.intents.lock().iter().any(|i| i.actor == actor)
    }
}

impl Default for AuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_assigns_monotonic_seq() {
        let sink = AuditSink::new();
        sink.record(AuditIntent::new("user-1", "write", "/api/v1/policies"));
        sink.record(AuditIntent::new("user-2", "admin", "/api/v1/config"));
        let intents = sink.intents();
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].seq, 0);
        assert_eq!(intents[1].seq, 1);
    }

    #[test]
    fn actor_binding_is_correct() {
        let sink = AuditSink::new();
        sink.record(AuditIntent::new(
            "admin-1",
            "admin",
            "/api/v1/policies/stage",
        ));
        assert!(sink.has_actor("admin-1"));
        assert!(!sink.has_actor("user-1"));
    }

    #[test]
    fn intent_fields_populated() {
        let sink = AuditSink::new();
        sink.record(AuditIntent::new("u1", "write", "/api/v1/agents/register"));
        let intent = &sink.intents()[0];
        assert_eq!(intent.actor, "u1");
        assert_eq!(intent.action, "write");
        assert_eq!(intent.resource, "/api/v1/agents/register");
    }

    #[test]
    fn empty_sink_has_no_intents() {
        let sink = AuditSink::new();
        assert_eq!(sink.count(), 0);
        assert!(sink.intents().is_empty());
    }

    #[test]
    fn intent_serializes_to_json() {
        let intent = AuditIntent::new("u1", "admin", "/api/v1/config");
        let json = serde_json::to_string(&intent).unwrap();
        assert!(json.contains("\"actor\":\"u1\""));
        let back: AuditIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.actor, "u1");
    }
}
