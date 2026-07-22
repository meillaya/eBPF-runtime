// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SPIFFE-bound command authorization for fleet rollout.
//!
//! Every rollout command (STAGE, COMMIT, CANCEL, ROLLBACK) must
//! be issued by an authorized SPIFFE identity. Agent commands
//! (READY, APPLIED, REJECTED) must come from the agent's own
//! SPIFFE ID.
//!
//! Authorization rules:
//! - Operator commands (STAGE, COMMIT, CANCEL, ROLLBACK): require
//!   a SPIFFE ID in the operator trust domain with the
//!   `policy-admin` role.
//! - Agent commands (READY, APPLIED, REJECTED): require the
//!   agent's own SPIFFE ID (exact match).
//! - Trust domain is validated by EXACT match (never substring).

#![forbid(unsafe_code)]

use crate::error::{RolloutError, RolloutResult};

/// The trust domain for this deployment.
pub const DEFAULT_TRUST_DOMAIN: &str = "kernel-v1.test";

/// The operator path prefix in the SPIFFE ID.
pub const OPERATOR_PATH_PREFIX: &str = "/operator/";

/// The agent path prefix in the SPIFFE ID.
pub const AGENT_PATH_PREFIX: &str = "/agent/";

/// SPIFFE-based authorizer for rollout commands.
#[derive(Debug, Clone)]
pub struct RolloutAuthorizer {
    /// The expected trust domain (exact match).
    trust_domain: String,
    /// SPIFFE IDs authorized to issue operator commands
    /// (STAGE, COMMIT, CANCEL, ROLLBACK).
    operator_ids: Vec<String>,
}

impl RolloutAuthorizer {
    /// Create a new authorizer with the given trust domain and
    /// operator SPIFFE IDs.
    pub fn new(trust_domain: &str, operator_ids: Vec<String>) -> Self {
        Self {
            trust_domain: trust_domain.to_string(),
            operator_ids,
        }
    }

    /// Create an authorizer with the default trust domain and a
    /// single operator.
    pub fn with_default_operator(operator_id: &str) -> Self {
        Self {
            trust_domain: DEFAULT_TRUST_DOMAIN.to_string(),
            operator_ids: vec![operator_id.to_string()],
        }
    }

    /// Validate that a SPIFFE ID belongs to the expected trust
    /// domain. Uses EXACT match — never substring.
    pub fn validate_trust_domain(&self, spiffe_id: &str) -> RolloutResult<()> {
        let expected_prefix = format!("spiffe://{}/", self.trust_domain);
        if !spiffe_id.starts_with(&expected_prefix) {
            return Err(RolloutError::Unauthorized {
                spiffe_id: spiffe_id.to_string(),
                operation: "trust_domain_check".into(),
                reason: format!(
                    "trust domain mismatch: expected spiffe://{}//..., got {spiffe_id}",
                    self.trust_domain
                ),
            });
        }
        Ok(())
    }

    /// Authorize an operator command (STAGE, COMMIT, CANCEL,
    /// ROLLBACK). The issuer must be in the operator list.
    pub fn authorize_operator(&self, spiffe_id: &str, operation: &str) -> RolloutResult<()> {
        self.validate_trust_domain(spiffe_id)?;

        if !self.operator_ids.iter().any(|id| id == spiffe_id) {
            return Err(RolloutError::Unauthorized {
                spiffe_id: spiffe_id.to_string(),
                operation: operation.to_string(),
                reason: "not an authorized operator".into(),
            });
        }
        Ok(())
    }

    /// Authorize an agent command (READY, APPLIED, REJECTED).
    /// The agent's SPIFFE ID must match exactly.
    pub fn authorize_agent(
        &self,
        agent_spiffe_id: &str,
        expected_agent_id: &str,
        operation: &str,
    ) -> RolloutResult<()> {
        self.validate_trust_domain(agent_spiffe_id)?;

        if agent_spiffe_id != expected_agent_id {
            return Err(RolloutError::Unauthorized {
                spiffe_id: agent_spiffe_id.to_string(),
                operation: operation.to_string(),
                reason: format!("agent ID mismatch: expected {expected_agent_id}"),
            });
        }
        Ok(())
    }

    /// Check whether a SPIFFE ID is an operator.
    pub fn is_operator(&self, spiffe_id: &str) -> bool {
        self.operator_ids.iter().any(|id| id == spiffe_id)
    }

    /// Check whether a SPIFFE ID is in the expected trust domain.
    pub fn is_in_trust_domain(&self, spiffe_id: &str) -> bool {
        let prefix = format!("spiffe://{}/", self.trust_domain);
        spiffe_id.starts_with(&prefix)
    }
}

impl Default for RolloutAuthorizer {
    fn default() -> Self {
        Self::new(DEFAULT_TRUST_DOMAIN, vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorizer() -> RolloutAuthorizer {
        RolloutAuthorizer::new(
            "kernel-v1.test",
            vec!["spiffe://kernel-v1.test/operator/admin".into()],
        )
    }

    #[test]
    fn operator_authorized() {
        let auth = authorizer();
        assert!(auth
            .authorize_operator("spiffe://kernel-v1.test/operator/admin", "stage")
            .is_ok());
    }

    #[test]
    fn operator_not_in_list_rejected() {
        let auth = authorizer();
        let err = auth
            .authorize_operator("spiffe://kernel-v1.test/operator/other", "stage")
            .unwrap_err();
        assert!(matches!(err, RolloutError::Unauthorized { .. }));
    }

    #[test]
    fn wrong_trust_domain_rejected() {
        let auth = authorizer();
        let err = auth
            .authorize_operator("spiffe://evil.example/operator/admin", "stage")
            .unwrap_err();
        assert!(matches!(err, RolloutError::Unauthorized { .. }));
    }

    #[test]
    fn trust_domain_exact_match_not_substring() {
        let auth = authorizer();
        // "kernel-v1.test" should NOT match "kernel-v1.test.evil"
        assert!(!auth.is_in_trust_domain("spiffe://kernel-v1.test.evil/operator/admin"));
        // "kernel-v1" should NOT match "kernel-v1.test"
        let auth2 = RolloutAuthorizer::new("kernel-v1", vec![]);
        assert!(!auth2.is_in_trust_domain("spiffe://kernel-v1.test/operator/admin"));
    }

    #[test]
    fn agent_authorized_with_exact_match() {
        let auth = authorizer();
        assert!(auth
            .authorize_agent(
                "spiffe://kernel-v1.test/agent/prod/node-1",
                "spiffe://kernel-v1.test/agent/prod/node-1",
                "ready"
            )
            .is_ok());
    }

    #[test]
    fn agent_mismatch_rejected() {
        let auth = authorizer();
        let err = auth
            .authorize_agent(
                "spiffe://kernel-v1.test/agent/prod/node-1",
                "spiffe://kernel-v1.test/agent/prod/node-2",
                "ready",
            )
            .unwrap_err();
        assert!(matches!(err, RolloutError::Unauthorized { .. }));
    }

    #[test]
    fn agent_wrong_trust_domain_rejected() {
        let auth = authorizer();
        let err = auth
            .authorize_agent(
                "spiffe://evil.example/agent/prod/node-1",
                "spiffe://evil.example/agent/prod/node-1",
                "ready",
            )
            .unwrap_err();
        assert!(matches!(err, RolloutError::Unauthorized { .. }));
    }

    #[test]
    fn is_operator_check() {
        let auth = authorizer();
        assert!(auth.is_operator("spiffe://kernel-v1.test/operator/admin"));
        assert!(!auth.is_operator("spiffe://kernel-v1.test/agent/prod/node-1"));
    }

    #[test]
    fn default_authorizer_has_no_operators() {
        let auth = RolloutAuthorizer::default();
        assert!(!auth.is_operator("spiffe://kernel-v1.test/operator/admin"));
    }
}
