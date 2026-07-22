// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed control-plane contract mirroring
//! `proto/kernel/v1/control/v1/control.proto`.
//!
//! Every enum value and message field matches the authoritative
//! proto definition. State transitions are typed enums, never
//! free strings.

#![forbid(unsafe_code)]

use crate::events::CgroupMode;
use serde::{Deserialize, Serialize};

/// Policy rollout status. Mirrors `PolicyStatus` in control.proto.
/// The lifecycle is STAGED → READY → COMMITTED → APPLIED (or
/// REJECTED at any transition). STALE is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum PolicyStatus {
    Unspecified = 0,
    Staged = 1,
    Ready = 2,
    Committed = 3,
    Applied = 4,
    Rejected = 5,
    Stale = 6,
}

impl PolicyStatus {
    /// Parse from the proto JSON enum name.
    pub fn from_proto_name(name: &str) -> Option<Self> {
        match name {
            "POLICY_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "POLICY_STATUS_STAGED" => Some(Self::Staged),
            "POLICY_STATUS_READY" => Some(Self::Ready),
            "POLICY_STATUS_COMMITTED" => Some(Self::Committed),
            "POLICY_STATUS_APPLIED" => Some(Self::Applied),
            "POLICY_STATUS_REJECTED" => Some(Self::Rejected),
            "POLICY_STATUS_STALE" => Some(Self::Stale),
            _ => None,
        }
    }

    /// The proto JSON enum name.
    pub fn as_proto_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "POLICY_STATUS_UNSPECIFIED",
            Self::Staged => "POLICY_STATUS_STAGED",
            Self::Ready => "POLICY_STATUS_READY",
            Self::Committed => "POLICY_STATUS_COMMITTED",
            Self::Applied => "POLICY_STATUS_APPLIED",
            Self::Rejected => "POLICY_STATUS_REJECTED",
            Self::Stale => "POLICY_STATUS_STALE",
        }
    }
}

impl std::fmt::Display for PolicyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_proto_name())
    }
}

/// Agent registration request. Mirrors `RegisterRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub node_name: String,
    pub hostname: String,
    pub cluster: String,
    pub agent_generation: String,
    /// Linux boot_id (hex-encoded for JSON interop).
    pub boot_id_hex: String,
    pub kernel_release: String,
    pub unprivileged_bpf_disabled: bool,
}

/// Agent registration response. Mirrors `RegisterResponse`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub policy_version: String,
    /// Active policy digest (hex-encoded for JSON interop).
    #[serde(default)]
    pub policy_digest_hex: String,
    pub policy_status: PolicyStatus,
    #[serde(default)]
    pub health: Option<Health>,
    #[serde(default)]
    pub compatibility: Option<Compatibility>,
}

/// Stage a new policy. Mirrors `StagePolicyRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagePolicyRequest {
    pub version: String,
    /// Digest of the staged BPF map bytes (hex-encoded).
    pub digest_hex: String,
    /// The staged inactive BPF map bytes (base64 or hex).
    #[serde(default)]
    pub inactive_pbf_bytes_hex: String,
    /// Empty = all agents in the cluster.
    #[serde(default)]
    pub target_agent_ids: Vec<String>,
}

/// Per-agent stage result. Mirrors `StagePolicyResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagePolicyResponse {
    pub policy_status: PolicyStatus,
    #[serde(default)]
    pub rejected_reasons: Vec<String>,
}

/// Agent's ready acknowledgement. Mirrors `ReadyAckStreamRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyAckStreamRequest {
    pub agent_id: String,
    pub policy_version: String,
    /// Digest the agent computed locally (hex-encoded).
    pub digest_hex: String,
    /// Agent-local hash_of_active (hex-encoded).
    pub hash_of_active_hex: String,
}

/// Control plane's per-ack confirmation. Mirrors `ReadyAckStreamResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyAckStreamResponse {
    pub accepted: bool,
    #[serde(default)]
    pub rejected_reasons: Vec<String>,
}

/// Commit the staged policy. Mirrors `CommitPolicyRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitPolicyRequest {
    pub version: String,
    pub digest_hex: String,
    /// 1..=100 inclusive.
    pub threshold_percent: u32,
}

/// Aggregate commit counts. Mirrors `CommitPolicyResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitPolicyResponse {
    pub committed_count: u32,
    pub ack_count: u32,
    pub rejected_count: u32,
}

/// Rollback request. Mirrors `RollbackPolicyRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPolicyRequest {
    /// Empty means "last known good".
    pub version: String,
    #[serde(default)]
    pub digest_hex: String,
}

/// Rollback response. Mirrors `RollbackPolicyResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPolicyResponse {
    pub committed_count: u32,
    pub ack_count: u32,
    pub rejected_count: u32,
}

/// Agent health snapshot. Mirrors `Health` in control.proto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    pub agent_id: String,
    pub node_name: String,
    pub cluster: String,
    pub epoch_unix_sec: i64,
    #[serde(default)]
    pub loaded_sensors: Vec<String>,
    #[serde(default)]
    pub degraded_sensors: Vec<String>,
    #[serde(default)]
    pub blocked_sensors: Vec<String>,
    #[serde(default)]
    pub events_emitted_total: u64,
    #[serde(default)]
    pub events_dropped_total: u64,
    #[serde(default)]
    pub supported_load_rate: u64,
}

/// Agent compatibility snapshot. Mirrors `Compatibility`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compatibility {
    pub kernel_release: String,
    pub bpf_lsm_active: bool,
    pub bpf_token_active: bool,
    pub cgroup_mode: CgroupMode,
    #[serde(default)]
    pub bpf_program_type_allowlist: Vec<String>,
}

/// Policy snapshot: the full policy state the control plane
/// exposes for a single agent. Combines status + version +
/// digest + health + compatibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub policy_version: String,
    pub policy_status: PolicyStatus,
    pub policy_digest_hex: String,
    pub monotonic_version: u64,
    #[serde(default)]
    pub health: Option<Health>,
    #[serde(default)]
    pub compatibility: Option<Compatibility>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_status_round_trips_proto_names() {
        let statuses = [
            PolicyStatus::Unspecified,
            PolicyStatus::Staged,
            PolicyStatus::Ready,
            PolicyStatus::Committed,
            PolicyStatus::Applied,
            PolicyStatus::Rejected,
            PolicyStatus::Stale,
        ];
        for s in &statuses {
            let name = s.as_proto_name();
            let parsed = PolicyStatus::from_proto_name(name).unwrap();
            assert_eq!(*s, parsed, "round-trip failed for {name}");
        }
    }

    #[test]
    fn policy_status_rejects_unknown() {
        assert!(PolicyStatus::from_proto_name("POLICY_STATUS_BOGUS").is_none());
    }

    #[test]
    fn policy_status_display() {
        assert_eq!(PolicyStatus::Applied.to_string(), "POLICY_STATUS_APPLIED");
    }

    #[test]
    fn register_request_serde_round_trip() {
        let req = RegisterRequest {
            node_name: "node-1".into(),
            hostname: "host-1".into(),
            cluster: "prod".into(),
            agent_generation: "gen-1".into(),
            boot_id_hex: "00".repeat(16),
            kernel_release: "6.1.0".into(),
            unprivileged_bpf_disabled: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RegisterRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn health_serde_round_trip() {
        let h = Health {
            agent_id: "spiffe://cluster/agent/1".into(),
            node_name: "node-1".into(),
            cluster: "prod".into(),
            epoch_unix_sec: 1_700_000_000,
            loaded_sensors: vec!["file".into(), "process".into()],
            degraded_sensors: vec![],
            blocked_sensors: vec!["lsm".into()],
            events_emitted_total: 42,
            events_dropped_total: 0,
            supported_load_rate: 100_000,
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: Health = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }
}
