// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Row model structs for all control-db tables.
//!
//! Each struct maps 1:1 to a database table. Version fields
//! enable optimistic concurrency; SPIFFE IDs are stored as text.

#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A fleet cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cluster {
    pub id: Uuid,
    pub name: String,
    /// SPIFFE trust domain (e.g. "kernel-v1.test").
    pub trust_domain: String,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A node within a cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: Uuid,
    pub cluster_id: Uuid,
    pub name: String,
    pub hostname: String,
    pub kernel_release: String,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A registered agent with SPIFFE identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    pub id: Uuid,
    pub node_id: Uuid,
    pub cluster_id: Uuid,
    /// SPIFFE ID: spiffe://<trust_domain>/agent/<cluster>/<node>
    pub spiffe_id: String,
    pub agent_generation: String,
    pub boot_id_hex: String,
    pub protocol_major: i32,
    pub health_epoch_s: i64,
    pub events_emitted: i64,
    pub events_dropped: i64,
    pub version: i64,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Per-agent event ingress cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCursor {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub sequence: i64,
    pub idempotency_key: String,
    pub batch_size: i32,
    pub ingested_at: DateTime<Utc>,
}

/// A named policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A versioned policy content snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub version: i64,
    pub content_digest: String,
    pub content_hex: String,
    /// Status: staged/ready/committed/applied/rejected/stale.
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// A rollout target (which agents receive a policy version).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutTarget {
    pub id: Uuid,
    pub policy_version_id: Uuid,
    pub cluster_id: Uuid,
    /// None means all agents in the cluster.
    pub agent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// A policy rollout with aggregate progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rollout {
    pub id: Uuid,
    pub policy_version_id: Uuid,
    /// State: pending/in_progress/completed/failed/cancelled.
    pub state: String,
    pub threshold_percent: i32,
    pub committed_count: i32,
    pub ack_count: i32,
    pub rejected_count: i32,
    pub version: i64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// A per-agent rollout acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutAck {
    pub id: Uuid,
    pub rollout_id: Uuid,
    pub agent_id: Uuid,
    pub policy_version: i64,
    pub digest_hex: String,
    pub accepted: bool,
    pub rejected_reason: String,
    pub acked_at: DateTime<Utc>,
}

/// An OIDC role binding (group or sub → role).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcRoleBinding {
    pub id: Uuid,
    /// "group" or "sub".
    pub binding_type: String,
    pub principal: String,
    /// viewer/analyst/policy-admin/admin.
    pub role: String,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An OIDC session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcSession {
    pub id: Uuid,
    pub session_id: String,
    pub sub: String,
    pub role: String,
    pub groups_json: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// An OIDC revocation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcRevocation {
    pub id: Uuid,
    /// "session" or "sub".
    pub target_type: String,
    pub target: String,
    pub reason: String,
    pub revoked_by: String,
    pub revoked_at: DateTime<Utc>,
}

/// An append-only audit log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub seq: i64,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub cluster_id: Option<Uuid>,
    pub detail_json: String,
    pub success: bool,
    pub error_msg: String,
    pub created_at: DateTime<Utc>,
}
