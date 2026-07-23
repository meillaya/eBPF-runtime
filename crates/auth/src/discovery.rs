// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC discovery with exact issuer pin.
//!
//! The issuer in the discovery document MUST exactly equal the
//! pinned issuer. Substring, prefix, or suffix matching is
//! NEVER accepted.

#![forbid(unsafe_code)]

use crate::error::{AuthError, AuthResult};
use serde::{Deserialize, Serialize};

/// Pinned OIDC provider configuration from the discovery
/// document (`.well-known/openid-configuration`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcDiscovery {
    /// The issuer identifier. MUST exactly match the pinned
    /// value.
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    /// RFC 8628 device authorization endpoint.
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub claims_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

impl OidcDiscovery {
    /// Validate a discovery document against a pinned issuer.
    ///
    /// The issuer comparison is EXACT (`!=`). A discovery
    /// document with issuer `https://dex.kernel-v1.test` does
    /// NOT match pin `https://dex.kernel-v1.test.evil` or
    /// `https://dex.kernel-v1` — no substring, prefix, or
    /// suffix matching.
    pub fn validate_pinned(&self, pinned_issuer: &str) -> AuthResult<()> {
        if self.issuer != pinned_issuer {
            return Err(AuthError::IssuerMismatch {
                expected: pinned_issuer.to_string(),
                actual: self.issuer.clone(),
            });
        }
        // Require the core endpoints.
        for field in [
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("jwks_uri", &self.jwks_uri),
        ] {
            if field.1.is_empty() {
                return Err(AuthError::DiscoveryMissingField {
                    field: field.0.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Parse and validate a discovery JSON document against a
    /// pinned issuer in one step.
    pub fn from_json_pinned(json: &str, pinned_issuer: &str) -> AuthResult<Self> {
        let doc: Self =
            serde_json::from_str(json).map_err(|e| AuthError::DiscoveryMissingField {
                field: format!("JSON parse: {e}"),
            })?;
        doc.validate_pinned(pinned_issuer)?;
        Ok(doc)
    }

    /// Whether the provider supports the device flow (RFC 8628).
    pub fn supports_device_flow(&self) -> bool {
        self.device_authorization_endpoint.is_some()
    }

    /// Whether the provider supports PKCE S256.
    pub fn supports_pkce_s256(&self) -> bool {
        self.code_challenge_methods_supported
            .iter()
            .any(|m| m == "S256")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINNED: &str = "https://dex.kernel-v1.test";

    fn fixture_json() -> String {
        include_str!("../../../tests/fixtures/oidc/discovery.json").to_string()
    }

    #[test]
    fn pinned_issuer_exact_match_passes() {
        let doc = OidcDiscovery::from_json_pinned(&fixture_json(), PINNED).unwrap();
        assert_eq!(doc.issuer, PINNED);
    }

    #[test]
    fn issuer_substring_rejected() {
        // "https://dex.kernel-v1" is a prefix of the real issuer.
        let err =
            OidcDiscovery::from_json_pinned(&fixture_json(), "https://dex.kernel-v1").unwrap_err();
        assert!(matches!(err, AuthError::IssuerMismatch { .. }));
    }

    #[test]
    fn issuer_suffix_rejected() {
        let err =
            OidcDiscovery::from_json_pinned(&fixture_json(), "https://dex.kernel-v1.test.evil")
                .unwrap_err();
        assert!(matches!(err, AuthError::IssuerMismatch { .. }));
    }

    #[test]
    fn issuer_case_sensitive() {
        let err = OidcDiscovery::from_json_pinned(&fixture_json(), "https://DEX.KERNEL-V1.TEST")
            .unwrap_err();
        assert!(matches!(err, AuthError::IssuerMismatch { .. }));
    }

    #[test]
    fn issuer_trailing_slash_rejected() {
        let err = OidcDiscovery::from_json_pinned(&fixture_json(), "https://dex.kernel-v1.test/")
            .unwrap_err();
        assert!(matches!(err, AuthError::IssuerMismatch { .. }));
    }

    #[test]
    fn missing_required_field_rejected() {
        let json = r#"{"issuer":"https://dex.kernel-v1.test","authorization_endpoint":"","token_endpoint":"https://x","jwks_uri":"https://x"}"#;
        let err = OidcDiscovery::from_json_pinned(json, PINNED).unwrap_err();
        assert!(matches!(err, AuthError::DiscoveryMissingField { .. }));
    }

    #[test]
    fn device_flow_support_detected() {
        let doc = OidcDiscovery::from_json_pinned(&fixture_json(), PINNED).unwrap();
        assert!(doc.supports_device_flow());
        assert!(doc.supports_pkce_s256());
    }

    #[test]
    fn no_implicit_flow_in_supported_response_types() {
        let doc = OidcDiscovery::from_json_pinned(&fixture_json(), PINNED).unwrap();
        // The fixture MUST NOT include "id_token" or "token"
        // (implicit flow).
        assert!(!doc
            .response_types_supported
            .contains(&"id_token".to_string()));
        assert!(!doc.response_types_supported.contains(&"token".to_string()));
        assert!(doc.response_types_supported.contains(&"code".to_string()));
    }
}
