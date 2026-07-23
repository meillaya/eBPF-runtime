// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SPIFFE peer authorization for transport channels.
//!
//! Wraps the `identity-spiffe` crate's `AuthorizationCallback`
//! to validate peer SPIFFE IDs on both the control and event
//! channels. The transport is fail-closed: no valid SPIFFE mTLS
//! peer identity → no connection.
//!
//! # Trust domain matching
//!
//! Trust domain matching is EXACT (inherited from
//! `identity-spiffe`). `kernel-v1` does NOT match
//! `kernel-v1-evil` or `kernel-v1.test`.

#![forbid(unsafe_code)]

use identity_spiffe::authorization::{AgentBinding, AuthorizationCallback};

use crate::error::{TransportError, TransportResult};

/// Validates peer SPIFFE IDs for transport channels.
///
/// Delegates to `identity-spiffe`'s `AuthorizationCallback`
/// for the actual SPIFFE ID parsing and trust-domain matching.
#[derive(Debug, Clone)]
pub struct PeerAuthorizer {
    callback: AuthorizationCallback,
}

impl PeerAuthorizer {
    /// Create a peer authorizer for the given trust domain.
    ///
    /// The authorizer expects peer SPIFFE IDs of the form:
    ///   `spiffe://<trust-domain>/agent/<cluster>/<node>`
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            callback: AuthorizationCallback::new(trust_domain),
        }
    }

    /// Restrict authorization to a specific cluster.
    pub fn with_cluster(mut self, cluster: impl Into<String>) -> Self {
        self.callback = self.callback.with_cluster(cluster);
        self
    }

    /// Restrict authorization to a specific node.
    pub fn with_node(mut self, node: impl Into<String>) -> Self {
        self.callback = self.callback.with_node(node);
        self
    }

    /// Authorize a peer SPIFFE ID string.
    ///
    /// Returns the agent binding on success, or
    /// `PeerUnauthorized` on failure. The transport is
    /// fail-closed: any validation failure rejects the peer.
    pub fn authorize(&self, peer_spiffe_id: &str) -> TransportResult<AgentBinding> {
        self.callback
            .authorize(peer_spiffe_id)
            .map_err(|e| TransportError::PeerUnauthorized {
                peer_spiffe_id: peer_spiffe_id.to_string(),
                reason: e.to_string(),
            })
    }

    /// Authorize a peer SPIFFE ID, returning only whether it
    /// is authorized (without the binding).
    pub fn is_authorized(&self, peer_spiffe_id: &str) -> bool {
        self.callback.authorize(peer_spiffe_id).is_ok()
    }

    /// The underlying authorization callback.
    pub fn callback(&self) -> &AuthorizationCallback {
        &self.callback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TD: &str = "kernel-v1.test";

    #[test]
    fn valid_agent_spiffe_id_authorized() {
        let auth = PeerAuthorizer::new(TD);
        let binding = auth
            .authorize("spiffe://kernel-v1.test/agent/prod/node-1")
            .unwrap();
        assert_eq!(binding.trust_domain, TD);
        assert_eq!(binding.cluster, "prod");
        assert_eq!(binding.node, "node-1");
    }

    #[test]
    fn wrong_trust_domain_rejected() {
        let auth = PeerAuthorizer::new(TD);
        let err = auth
            .authorize("spiffe://evil.example/agent/prod/node-1")
            .unwrap_err();
        assert!(matches!(err, TransportError::PeerUnauthorized { .. }));
    }

    #[test]
    fn substring_trust_domain_rejected() {
        let auth = PeerAuthorizer::new(TD);
        // "kernel-v1.test.evil" is NOT "kernel-v1.test".
        assert!(!auth.is_authorized("spiffe://kernel-v1.test.evil/agent/prod/node-1"));
    }

    #[test]
    fn prefix_trust_domain_rejected() {
        let auth = PeerAuthorizer::new(TD);
        // "kernel-v1" is NOT "kernel-v1.test".
        assert!(!auth.is_authorized("spiffe://kernel-v1/agent/prod/node-1"));
    }

    #[test]
    fn cluster_restriction_enforced() {
        let auth = PeerAuthorizer::new(TD).with_cluster("prod");
        assert!(auth.is_authorized("spiffe://kernel-v1.test/agent/prod/node-1"));
        assert!(!auth.is_authorized("spiffe://kernel-v1.test/agent/staging/node-1"));
    }

    #[test]
    fn node_restriction_enforced() {
        let auth = PeerAuthorizer::new(TD).with_node("node-1");
        assert!(auth.is_authorized("spiffe://kernel-v1.test/agent/prod/node-1"));
        assert!(!auth.is_authorized("spiffe://kernel-v1.test/agent/prod/node-2"));
    }

    #[test]
    fn empty_spiffe_id_rejected() {
        let auth = PeerAuthorizer::new(TD);
        assert!(!auth.is_authorized(""));
    }

    #[test]
    fn non_spiffe_uri_rejected() {
        let auth = PeerAuthorizer::new(TD);
        assert!(!auth.is_authorized("https://kernel-v1.test/agent/prod/node-1"));
    }

    #[test]
    fn missing_agent_path_rejected() {
        let auth = PeerAuthorizer::new(TD);
        // Path must start with /agent/.
        assert!(!auth.is_authorized("spiffe://kernel-v1.test/workload/prod/node-1"));
    }
}
