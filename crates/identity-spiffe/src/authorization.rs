// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authorization callback: binds SPIFFE IDs to agent/node/cluster
//! identity.
//!
//! The authorization callback validates that a peer's SPIFFE ID
//! maps to an expected agent identity (agent/node/cluster). It
//! integrates with the protocol crate's `AgentIdentity` to
//! provide the durable principal for fleet registration.
//!
//! # Binding model
//!
//! A SPIFFE ID of the form:
//!   `spiffe://<trust-domain>/agent/<cluster>/<node>`
//!
//! is decomposed into:
//!   - trust_domain: the SPIFFE trust domain
//!   - cluster: the cluster identifier
//!   - node: the node name
//!
//! The callback validates:
//! 1. Exact trust domain match (NEVER substring).
//! 2. Path structure matches `/agent/<cluster>/<node>`.
//! 3. Cluster and node match expected values (if configured).
//!
//! Unauthorized selectors are rejected with
//! `SpiffeError::AuthorizationDenied`.

#![forbid(unsafe_code)]

use crate::error::{SpiffeError, SpiffeResult};
use crate::spiffe_id::{SpiffeId, SpiffeIdSelector};

/// The result of a successful authorization: the binding between
/// a SPIFFE ID and the agent/node/cluster identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBinding {
    /// The full SPIFFE ID string.
    pub spiffe_id: String,
    /// The trust domain.
    pub trust_domain: String,
    /// The cluster identifier (from path segment).
    pub cluster: String,
    /// The node name (from path segment).
    pub node: String,
    /// The agent identifier (SPIFFE ID used as durable principal).
    pub agent_id: String,
}

/// Authorization callback configuration.
///
/// Validates peer SPIFFE IDs against expected agent identity
/// patterns. Integrates with the protocol crate's
/// `AgentIdentity` for fleet registration.
#[derive(Debug, Clone)]
pub struct AuthorizationCallback {
    /// Selector for validating the SPIFFE ID structure.
    selector: SpiffeIdSelector,
    /// Expected cluster (if set, must match exactly).
    expected_cluster: Option<String>,
    /// Expected node (if set, must match exactly).
    expected_node: Option<String>,
}

impl AuthorizationCallback {
    /// Create an authorization callback for a trust domain.
    ///
    /// The callback expects SPIFFE IDs of the form:
    ///   `spiffe://<trust-domain>/agent/<cluster>/<node>`
    pub fn new(trust_domain: impl Into<String>) -> Self {
        let td = trust_domain.into();
        Self {
            selector: SpiffeIdSelector::new(td).with_path_prefix("/agent/"),
            expected_cluster: None,
            expected_node: None,
        }
    }

    /// Restrict authorization to a specific cluster.
    pub fn with_cluster(mut self, cluster: impl Into<String>) -> Self {
        self.expected_cluster = Some(cluster.into());
        self
    }

    /// Restrict authorization to a specific node.
    pub fn with_node(mut self, node: impl Into<String>) -> Self {
        self.expected_node = Some(node.into());
        self
    }

    /// The selector used for SPIFFE ID validation.
    pub fn selector(&self) -> &SpiffeIdSelector {
        &self.selector
    }

    /// Authorize a peer SPIFFE ID and produce an agent binding.
    ///
    /// Validates:
    /// 1. SPIFFE ID parses correctly.
    /// 2. Trust domain matches exactly (via selector).
    /// 3. Path has the form `/agent/<cluster>/<node>`.
    /// 4. Cluster matches expected (if configured).
    /// 5. Node matches expected (if configured).
    ///
    /// Returns `Err(AuthorizationDenied)` if any check fails.
    pub fn authorize(&self, peer_spiffe_id: &str) -> SpiffeResult<AgentBinding> {
        // Parse the SPIFFE ID.
        let id = SpiffeId::parse(peer_spiffe_id)?;

        // Validate against selector (exact trust domain + path prefix).
        id.validate_selector(&self.selector)
            .map_err(|e| SpiffeError::AuthorizationDenied {
                peer_spiffe_id: peer_spiffe_id.to_string(),
                reason: e.to_string(),
            })?;

        // Decompose path: /agent/<cluster>/<node>
        let path = id.path();
        let segments: Vec<&str> = path
            .strip_prefix('/')
            .unwrap_or(path)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        // Must have exactly: ["agent", "<cluster>", "<node>"]
        if segments.len() != 3 || segments[0] != "agent" {
            return Err(SpiffeError::AuthorizationDenied {
                peer_spiffe_id: peer_spiffe_id.to_string(),
                reason: format!("path must have form /agent/<cluster>/<node>, got '{path}'"),
            });
        }

        let cluster = segments[1].to_string();
        let node = segments[2].to_string();

        // Validate cluster if configured.
        if let Some(ref expected) = self.expected_cluster {
            if &cluster != expected {
                return Err(SpiffeError::AuthorizationDenied {
                    peer_spiffe_id: peer_spiffe_id.to_string(),
                    reason: format!("cluster '{cluster}' does not match expected '{expected}'"),
                });
            }
        }

        // Validate node if configured.
        if let Some(ref expected) = self.expected_node {
            if &node != expected {
                return Err(SpiffeError::AuthorizationDenied {
                    peer_spiffe_id: peer_spiffe_id.to_string(),
                    reason: format!("node '{node}' does not match expected '{expected}'"),
                });
            }
        }

        Ok(AgentBinding {
            spiffe_id: id.as_str().to_string(),
            trust_domain: id.trust_domain().to_string(),
            cluster,
            node,
            agent_id: id.as_str().to_string(),
        })
    }

    /// Authorize and produce a protocol-crate `RegisterRequest`
    /// for fleet registration.
    ///
    /// This bridges the SPIFFE identity to the protocol crate's
    /// `AgentIdentity::register()` flow.
    pub fn to_register_request(
        &self,
        peer_spiffe_id: &str,
        hostname: &str,
        agent_generation: &str,
        boot_id_hex: &str,
        kernel_release: &str,
    ) -> SpiffeResult<protocol::control::RegisterRequest> {
        let binding = self.authorize(peer_spiffe_id)?;

        Ok(protocol::control::RegisterRequest {
            node_name: binding.node,
            hostname: hostname.to_string(),
            cluster: binding.cluster,
            agent_generation: agent_generation.to_string(),
            boot_id_hex: boot_id_hex.to_string(),
            kernel_release: kernel_release.to_string(),
            unprivileged_bpf_disabled: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_valid_agent_id() {
        let cb = AuthorizationCallback::new("kernel-v1.test");
        let binding = cb
            .authorize("spiffe://kernel-v1.test/agent/prod/node-1")
            .unwrap();

        assert_eq!(binding.trust_domain, "kernel-v1.test");
        assert_eq!(binding.cluster, "prod");
        assert_eq!(binding.node, "node-1");
        assert_eq!(
            binding.agent_id,
            "spiffe://kernel-v1.test/agent/prod/node-1"
        );
    }

    #[test]
    fn authorize_with_cluster_restriction() {
        let cb = AuthorizationCallback::new("kernel-v1.test").with_cluster("prod");

        // Correct cluster.
        assert!(cb
            .authorize("spiffe://kernel-v1.test/agent/prod/node-1")
            .is_ok());

        // Wrong cluster.
        let err = cb
            .authorize("spiffe://kernel-v1.test/agent/staging/node-1")
            .unwrap_err();
        match err {
            SpiffeError::AuthorizationDenied { reason, .. } => {
                assert!(reason.contains("cluster"));
            }
            other => panic!("expected AuthorizationDenied, got {other:?}"),
        }
    }

    #[test]
    fn authorize_with_node_restriction() {
        let cb = AuthorizationCallback::new("kernel-v1.test").with_node("node-1");

        // Correct node.
        assert!(cb
            .authorize("spiffe://kernel-v1.test/agent/prod/node-1")
            .is_ok());

        // Wrong node.
        let err = cb
            .authorize("spiffe://kernel-v1.test/agent/prod/node-2")
            .unwrap_err();
        match err {
            SpiffeError::AuthorizationDenied { reason, .. } => {
                assert!(reason.contains("node"));
            }
            other => panic!("expected AuthorizationDenied, got {other:?}"),
        }
    }

    #[test]
    fn reject_wrong_trust_domain() {
        let cb = AuthorizationCallback::new("kernel-v1.test");
        let err = cb
            .authorize("spiffe://evil.example/agent/prod/node-1")
            .unwrap_err();
        assert!(matches!(err, SpiffeError::AuthorizationDenied { .. }));
    }

    #[test]
    fn reject_trust_domain_substring() {
        // "kernel-v1.test" must NOT match "kernel-v1.test.evil"
        let cb = AuthorizationCallback::new("kernel-v1.test");
        assert!(cb
            .authorize("spiffe://kernel-v1.test.evil/agent/prod/node-1")
            .is_err());
    }

    #[test]
    fn reject_non_agent_path() {
        let cb = AuthorizationCallback::new("kernel-v1.test");
        // Path doesn't start with /agent/
        assert!(cb
            .authorize("spiffe://kernel-v1.test/control/plane")
            .is_err());
    }

    #[test]
    fn reject_malformed_path() {
        let cb = AuthorizationCallback::new("kernel-v1.test");
        // Missing node segment.
        assert!(cb.authorize("spiffe://kernel-v1.test/agent/prod").is_err());
        // Too many segments.
        assert!(cb
            .authorize("spiffe://kernel-v1.test/agent/prod/node-1/extra")
            .is_err());
    }

    #[test]
    fn to_register_request_bridges_protocol() {
        let cb = AuthorizationCallback::new("kernel-v1.test");
        let req = cb
            .to_register_request(
                "spiffe://kernel-v1.test/agent/prod/node-1",
                "host-1",
                "gen-1",
                "00".repeat(16).as_str(),
                "6.1.0",
            )
            .unwrap();

        assert_eq!(req.node_name, "node-1");
        assert_eq!(req.cluster, "prod");
        assert_eq!(req.hostname, "host-1");
        assert_eq!(req.kernel_release, "6.1.0");

        // Verify it works with protocol crate's AgentIdentity.
        let identity = protocol::identity::AgentIdentity::register(req, 1).unwrap();
        assert_eq!(identity.agent_id, "spiffe://kernel-v1/agent/prod/node-1");
    }

    #[test]
    fn reject_invalid_spiffe_id() {
        let cb = AuthorizationCallback::new("kernel-v1.test");
        assert!(cb.authorize("not-a-spiffe-id").is_err());
        assert!(cb
            .authorize("https://kernel-v1.test/agent/prod/node-1")
            .is_err());
    }
}
