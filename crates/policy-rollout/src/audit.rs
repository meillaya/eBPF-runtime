// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Append-only audit log for fleet policy rollout.
//!
//! Every command and state transition is recorded in the audit
//! log with a monotonic sequence number. The log is append-only:
//! no update, no delete. This mirrors the control-db audit_log
//! table's invariants.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// A single audit log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number (assigned by the log).
    pub seq: u64,
    /// The SPIFFE ID of the actor who triggered the event.
    pub actor: String,
    /// The action performed (e.g. "rollout.stage",
    /// "rollout.commit", "agent.ready").
    pub action: String,
    /// The resource affected (e.g. "rollout:1", "agent:spiffe://...").
    pub resource: String,
    /// JSON detail of the event.
    pub detail_json: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Error message (empty on success).
    pub error_msg: String,
    /// Monotonic tick when the event occurred (NOT wall clock).
    pub tick: u64,
}

/// Append-only in-memory audit log.
///
/// Mirrors the control-db `audit_log` table: INSERT only, no
/// UPDATE, no DELETE. Sequence numbers are monotonically
/// increasing.
#[derive(Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    next_seq: u64,
}

impl AuditLog {
    /// Create a new empty audit log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_seq: 1,
        }
    }

    /// Append an entry to the log. Returns the assigned sequence
    /// number.
    pub fn append(
        &mut self,
        actor: &str,
        action: &str,
        resource: &str,
        detail_json: &str,
        success: bool,
        error_msg: &str,
        tick: u64,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.push(AuditEntry {
            seq,
            actor: actor.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            detail_json: detail_json.to_string(),
            success,
            error_msg: error_msg.to_string(),
            tick,
        });
        seq
    }

    /// Append a success entry.
    pub fn append_success(
        &mut self,
        actor: &str,
        action: &str,
        resource: &str,
        detail_json: &str,
        tick: u64,
    ) -> u64 {
        self.append(actor, action, resource, detail_json, true, "", tick)
    }

    /// Append a failure entry.
    pub fn append_failure(
        &mut self,
        actor: &str,
        action: &str,
        resource: &str,
        detail_json: &str,
        error_msg: &str,
        tick: u64,
    ) -> u64 {
        self.append(actor, action, resource, detail_json, false, error_msg, tick)
    }

    /// All entries in order.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// The latest sequence number (0 if empty).
    pub fn latest_seq(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Query entries by actor (most recent first).
    pub fn query_by_actor(&self, actor: &str, limit: usize) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .rev()
            .filter(|e| e.actor == actor)
            .take(limit)
            .collect()
    }

    /// Query entries by action prefix (most recent first).
    pub fn query_by_action(&self, action_prefix: &str, limit: usize) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .rev()
            .filter(|e| e.action.starts_with(action_prefix))
            .take(limit)
            .collect()
    }

    /// Query entries for a specific resource.
    pub fn query_by_resource(&self, resource: &str, limit: usize) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .rev()
            .filter(|e| e.resource == resource)
            .take(limit)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_assigns_monotonic_seq() {
        let mut log = AuditLog::new();
        let s1 = log.append_success("actor-1", "rollout.stage", "rollout:1", "{}", 0);
        let s2 = log.append_success("actor-1", "rollout.commit", "rollout:1", "{}", 1);
        let s3 = log.append_failure(
            "actor-2",
            "agent.ready",
            "agent:node-1",
            "{}",
            "digest mismatch",
            2,
        );
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(s3, 3);
        assert_eq!(log.latest_seq(), 3);
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn append_only_no_update_no_delete() {
        let mut log = AuditLog::new();
        log.append_success("a", "b", "c", "{}", 0);
        // The API exposes no update or delete methods.
        // This test documents the invariant.
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn query_by_actor() {
        let mut log = AuditLog::new();
        log.append_success("operator-1", "rollout.stage", "rollout:1", "{}", 0);
        log.append_success("agent-1", "agent.ready", "agent:node-1", "{}", 1);
        log.append_success("operator-1", "rollout.commit", "rollout:1", "{}", 2);

        let results = log.query_by_actor("operator-1", 10);
        assert_eq!(results.len(), 2);
        // Most recent first.
        assert_eq!(results[0].action, "rollout.commit");
        assert_eq!(results[1].action, "rollout.stage");
    }

    #[test]
    fn query_by_action_prefix() {
        let mut log = AuditLog::new();
        log.append_success("a", "rollout.stage", "r:1", "{}", 0);
        log.append_success("a", "rollout.commit", "r:1", "{}", 1);
        log.append_success("a", "agent.ready", "a:1", "{}", 2);

        let results = log.query_by_action("rollout.", 10);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_by_resource() {
        let mut log = AuditLog::new();
        log.append_success("a", "rollout.stage", "rollout:1", "{}", 0);
        log.append_success("a", "rollout.commit", "rollout:1", "{}", 1);
        log.append_success("a", "rollout.stage", "rollout:2", "{}", 2);

        let results = log.query_by_resource("rollout:1", 10);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_respects_limit() {
        let mut log = AuditLog::new();
        for i in 0..10 {
            log.append_success("a", "action", "r", "{}", i);
        }
        let results = log.query_by_actor("a", 3);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn empty_log() {
        let log = AuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.latest_seq(), 0);
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn failure_entry_records_error() {
        let mut log = AuditLog::new();
        log.append_failure(
            "agent-1",
            "agent.ready",
            "agent:node-1",
            "{\"version\":1}",
            "digest mismatch",
            5,
        );
        let entry = &log.entries()[0];
        assert!(!entry.success);
        assert_eq!(entry.error_msg, "digest mismatch");
        assert_eq!(entry.tick, 5);
    }

    #[test]
    fn serde_roundtrip() {
        let entry = AuditEntry {
            seq: 1,
            actor: "operator".into(),
            action: "rollout.stage".into(),
            resource: "rollout:1".into(),
            detail_json: "{}".into(),
            success: true,
            error_msg: String::new(),
            tick: 0,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, decoded);
    }
}
