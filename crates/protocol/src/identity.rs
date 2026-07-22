// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent identity: registration, health, compatibility
//! negotiation, and version negotiation.
//!
//! The agent identity is the SPIFFE-identified principal that
//! registers with the control plane, reports health, and
//! negotiates compatibility (cgroup mode, BPF LSM availability,
//! kernel release). Version negotiation rejects stale protocol
//! major versions.

#![forbid(unsafe_code)]

use crate::control::{Compatibility, Health, RegisterRequest, RegisterResponse};
use crate::error::{ProtocolError, ProtocolResult};
use crate::events::CgroupMode;

/// The server's current protocol major version.
pub const SERVER_PROTOCOL_MAJOR: u32 = 1;

/// Agent identity: the registered principal and its current
/// health/compatibility state.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// The agent's durable ID (SPIFFE SVID principal).
    pub agent_id: String,
    /// The registration request that created this identity.
    pub registration: RegisterRequest,
    /// Current health snapshot.
    pub health: Health,
    /// Current compatibility snapshot.
    pub compatibility: Compatibility,
    /// The negotiated protocol major version.
    pub protocol_major: u32,
}

impl AgentIdentity {
    /// Register a new agent identity.
    ///
    /// Validates:
    /// 1. Protocol major version compatibility.
    /// 2. Non-empty node name and agent generation.
    pub fn register(req: RegisterRequest, protocol_major: u32) -> ProtocolResult<Self> {
        // Version negotiation: reject stale major.
        if protocol_major < SERVER_PROTOCOL_MAJOR {
            return Err(ProtocolError::StaleProtocolMajor {
                client_major: protocol_major,
                server_major: SERVER_PROTOCOL_MAJOR,
            });
        }

        // Structural validation.
        if req.node_name.is_empty() {
            return Err(ProtocolError::InvalidPolicy {
                reason: "node_name must not be empty".into(),
            });
        }
        if req.agent_generation.is_empty() {
            return Err(ProtocolError::InvalidPolicy {
                reason: "agent_generation must not be empty".into(),
            });
        }

        let agent_id = format!("spiffe://kernel-v1/agent/{}/{}", req.cluster, req.node_name);

        let health = Health {
            agent_id: agent_id.clone(),
            node_name: req.node_name.clone(),
            cluster: req.cluster.clone(),
            epoch_unix_sec: 0,
            loaded_sensors: vec![],
            degraded_sensors: vec![],
            blocked_sensors: vec![],
            events_emitted_total: 0,
            events_dropped_total: 0,
            supported_load_rate: 0,
        };

        let compatibility = Compatibility {
            kernel_release: req.kernel_release.clone(),
            bpf_lsm_active: false,
            bpf_token_active: false,
            cgroup_mode: CgroupMode::Unspecified,
            bpf_program_type_allowlist: vec![],
        };

        Ok(Self {
            agent_id,
            registration: req,
            health,
            compatibility,
            protocol_major,
        })
    }

    /// Build a `RegisterResponse` from the current identity
    /// state.
    pub fn register_response(
        &self,
        policy_version: &str,
        policy_digest_hex: &str,
        policy_status: crate::control::PolicyStatus,
    ) -> RegisterResponse {
        RegisterResponse {
            policy_version: policy_version.to_string(),
            policy_digest_hex: policy_digest_hex.to_string(),
            policy_status,
            health: Some(self.health.clone()),
            compatibility: Some(self.compatibility.clone()),
        }
    }

    /// Update the health snapshot.
    pub fn update_health(&mut self, health: Health) {
        self.health = health;
    }

    /// Update the compatibility snapshot.
    pub fn update_compatibility(&mut self, compat: Compatibility) {
        self.compatibility = compat;
    }

    /// Negotiate compatibility: intersect the agent's BPF
    /// program type allowlist with the server's required set.
    /// Returns the intersection.
    pub fn negotiate_bpf_program_types(&self, server_required: &[String]) -> Vec<String> {
        self.compatibility
            .bpf_program_type_allowlist
            .iter()
            .filter(|t| server_required.contains(t))
            .cloned()
            .collect()
    }

    /// Whether the agent's cgroup mode is compatible with the
    /// server's requirement.
    pub fn cgroup_mode_compatible(&self, required: CgroupMode) -> bool {
        self.compatibility.cgroup_mode == required
            || self.compatibility.cgroup_mode == CgroupMode::Unspecified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request() -> RegisterRequest {
        RegisterRequest {
            node_name: "node-1".into(),
            hostname: "host-1".into(),
            cluster: "prod".into(),
            agent_generation: "gen-1".into(),
            boot_id_hex: "00".repeat(16),
            kernel_release: "6.1.0".into(),
            unprivileged_bpf_disabled: false,
        }
    }

    #[test]
    fn happy_registration() {
        let identity = AgentIdentity::register(make_request(), 1).unwrap();
        assert_eq!(identity.agent_id, "spiffe://kernel-v1/agent/prod/node-1");
        assert_eq!(identity.protocol_major, 1);
        assert_eq!(identity.health.node_name, "node-1");
    }

    #[test]
    fn stale_protocol_major_rejected() {
        let err = AgentIdentity::register(make_request(), 0).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::StaleProtocolMajor {
                client_major: 0,
                server_major: 1,
            }
        );
    }

    #[test]
    fn future_protocol_major_accepted() {
        // Forward-compatible: newer major is accepted.
        let identity = AgentIdentity::register(make_request(), 2).unwrap();
        assert_eq!(identity.protocol_major, 2);
    }

    #[test]
    fn empty_node_name_rejected() {
        let mut req = make_request();
        req.node_name = String::new();
        let err = AgentIdentity::register(req, 1).unwrap_err();
        match err {
            ProtocolError::InvalidPolicy { reason } => {
                assert!(reason.contains("node_name"));
            }
            other => panic!("expected InvalidPolicy, got {other:?}"),
        }
    }

    #[test]
    fn empty_agent_generation_rejected() {
        let mut req = make_request();
        req.agent_generation = String::new();
        let err = AgentIdentity::register(req, 1).unwrap_err();
        match err {
            ProtocolError::InvalidPolicy { reason } => {
                assert!(reason.contains("agent_generation"));
            }
            other => panic!("expected InvalidPolicy, got {other:?}"),
        }
    }

    #[test]
    fn register_response_includes_health_and_compat() {
        let identity = AgentIdentity::register(make_request(), 1).unwrap();
        let resp =
            identity.register_response("1.0.0", "abcd", crate::control::PolicyStatus::Applied);
        assert_eq!(resp.policy_version, "1.0.0");
        assert!(resp.health.is_some());
        assert!(resp.compatibility.is_some());
    }

    #[test]
    fn update_health() {
        let mut identity = AgentIdentity::register(make_request(), 1).unwrap();
        let new_health = Health {
            events_emitted_total: 100,
            ..identity.health.clone()
        };
        identity.update_health(new_health);
        assert_eq!(identity.health.events_emitted_total, 100);
    }

    #[test]
    fn negotiate_bpf_program_types() {
        let mut identity = AgentIdentity::register(make_request(), 1).unwrap();
        identity.compatibility.bpf_program_type_allowlist =
            vec!["kprobe".into(), "lsm".into(), "tracepoint".into()];
        let server_required = vec!["lsm".into(), "kprobe".into()];
        let result = identity.negotiate_bpf_program_types(&server_required);
        assert_eq!(result, vec!["kprobe".to_string(), "lsm".to_string()]);
    }

    #[test]
    fn cgroup_mode_compatible() {
        let mut identity = AgentIdentity::register(make_request(), 1).unwrap();
        identity.compatibility.cgroup_mode = CgroupMode::Unified;
        assert!(identity.cgroup_mode_compatible(CgroupMode::Unified));
        assert!(!identity.cgroup_mode_compatible(CgroupMode::Legacy));

        // Unspecified is always compatible.
        identity.compatibility.cgroup_mode = CgroupMode::Unspecified;
        assert!(identity.cgroup_mode_compatible(CgroupMode::Legacy));
    }

    #[test]
    fn server_protocol_major_constant() {
        assert_eq!(SERVER_PROTOCOL_MAJOR, 1);
    }
}
