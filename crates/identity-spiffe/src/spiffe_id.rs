// SPDX-License-Identifier: Apache-2.0 OR MIT
//! SPIFFE ID parsing, validation, and selector matching.
//!
//! A SPIFFE ID has the form `spiffe://trust-domain/path`.
//! Trust domain matching is EXACT — substring matching is
//! NEVER permitted. Selectors validate the path component
//! against expected workload identity patterns.

#![forbid(unsafe_code)]

use crate::error::{SpiffeError, SpiffeResult};

/// The URI scheme prefix for all SPIFFE IDs.
const SPIFFE_SCHEME: &str = "spiffe://";

/// A parsed, validated SPIFFE ID.
///
/// Invariants:
/// - `trust_domain` is non-empty and contains no `/`, `?`, `#`.
/// - `path` starts with `/` (or is empty for trust-domain-only IDs).
/// - The original string is preserved for display.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId {
    /// The trust domain (authority component).
    trust_domain: String,
    /// The path component (starts with `/` if non-empty).
    path: String,
    /// The full canonical SPIFFE ID string.
    canonical: String,
}

impl SpiffeId {
    /// Parse a SPIFFE ID from its string representation.
    ///
    /// Validates:
    /// 1. Scheme is exactly `spiffe://`.
    /// 2. Trust domain is non-empty.
    /// 3. Trust domain contains no `/`, `?`, `#`, or whitespace.
    /// 4. Path (if present) starts with `/`.
    /// 5. No fragment (`#`) or query (`?`) components.
    pub fn parse(raw: &str) -> SpiffeResult<Self> {
        // Must start with spiffe://
        let remainder =
            raw.strip_prefix(SPIFFE_SCHEME)
                .ok_or_else(|| SpiffeError::InvalidSpiffeId {
                    raw: raw.to_string(),
                    reason: "must start with 'spiffe://'".into(),
                })?;

        // No fragment or query allowed.
        if remainder.contains('#') || remainder.contains('?') {
            return Err(SpiffeError::InvalidSpiffeId {
                raw: raw.to_string(),
                reason: "fragment and query components are not permitted".into(),
            });
        }

        // Split trust domain from path at first `/`.
        let (trust_domain, path) = match remainder.find('/') {
            Some(idx) => (&remainder[..idx], &remainder[idx..]),
            None => (remainder, ""),
        };

        // Trust domain must be non-empty.
        if trust_domain.is_empty() {
            return Err(SpiffeError::InvalidSpiffeId {
                raw: raw.to_string(),
                reason: "trust domain must not be empty".into(),
            });
        }

        // Trust domain must not contain whitespace.
        if trust_domain.chars().any(|c| c.is_whitespace()) {
            return Err(SpiffeError::InvalidSpiffeId {
                raw: raw.to_string(),
                reason: "trust domain must not contain whitespace".into(),
            });
        }

        // Path must start with `/` if non-empty (guaranteed by split).
        // Validate no empty segments (double slashes) in path.
        if !path.is_empty() && path.contains("//") {
            return Err(SpiffeError::InvalidSpiffeId {
                raw: raw.to_string(),
                reason: "path must not contain empty segments (//)".into(),
            });
        }

        let canonical = format!("spiffe://{trust_domain}{path}");

        Ok(Self {
            trust_domain: trust_domain.to_string(),
            path: path.to_string(),
            canonical,
        })
    }

    /// The trust domain component.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The path component (may be empty).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The full canonical SPIFFE ID string.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Assert that this SPIFFE ID's trust domain EXACTLY matches
    /// the expected value. Substring matching is NEVER permitted.
    pub fn assert_trust_domain(&self, expected: &str) -> SpiffeResult<()> {
        if self.trust_domain != expected {
            return Err(SpiffeError::TrustDomainMismatch {
                expected: expected.to_string(),
                actual: self.trust_domain.clone(),
            });
        }
        Ok(())
    }

    /// Validate this SPIFFE ID against a selector policy.
    pub fn validate_selector(&self, selector: &SpiffeIdSelector) -> SpiffeResult<()> {
        selector.validate(self)
    }
}

impl std::fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical)
    }
}

/// A selector policy for validating SPIFFE IDs.
///
/// Selectors enforce:
/// - Exact trust domain match (NEVER substring).
/// - Optional exact path match.
/// - Optional path prefix match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeIdSelector {
    /// The required trust domain (exact match).
    pub trust_domain: String,
    /// If set, the path must exactly equal this value.
    pub path_exact: Option<String>,
    /// If set, the path must start with this prefix.
    pub path_prefix: Option<String>,
}

impl SpiffeIdSelector {
    /// Create a selector requiring an exact trust domain.
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            path_exact: None,
            path_prefix: None,
        }
    }

    /// Add an exact path requirement.
    pub fn with_path_exact(mut self, path: impl Into<String>) -> Self {
        self.path_exact = Some(path.into());
        self
    }

    /// Add a path prefix requirement.
    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path_prefix = Some(prefix.into());
        self
    }

    /// Validate a SPIFFE ID against this selector.
    ///
    /// Returns `Err(SelectorRejected)` if validation fails.
    pub fn validate(&self, id: &SpiffeId) -> SpiffeResult<()> {
        // Exact trust domain match — NEVER substring.
        if id.trust_domain() != self.trust_domain {
            return Err(SpiffeError::SelectorRejected {
                spiffe_id: id.as_str().to_string(),
                reason: format!(
                    "trust domain '{}' does not exactly match required '{}'",
                    id.trust_domain(),
                    self.trust_domain
                ),
            });
        }

        // Exact path match.
        if let Some(ref expected_path) = self.path_exact {
            if id.path() != expected_path {
                return Err(SpiffeError::SelectorRejected {
                    spiffe_id: id.as_str().to_string(),
                    reason: format!(
                        "path '{}' does not exactly match required '{}'",
                        id.path(),
                        expected_path
                    ),
                });
            }
        }

        // Path prefix match.
        if let Some(ref prefix) = self.path_prefix {
            if !id.path().starts_with(prefix.as_str()) {
                return Err(SpiffeError::SelectorRejected {
                    spiffe_id: id.as_str().to_string(),
                    reason: format!(
                        "path '{}' does not start with required prefix '{}'",
                        id.path(),
                        prefix
                    ),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_spiffe_id() {
        let id = SpiffeId::parse("spiffe://kernel-v1/agent/prod/node-1").unwrap();
        assert_eq!(id.trust_domain(), "kernel-v1");
        assert_eq!(id.path(), "/agent/prod/node-1");
        assert_eq!(id.as_str(), "spiffe://kernel-v1/agent/prod/node-1");
    }

    #[test]
    fn parse_trust_domain_only() {
        let id = SpiffeId::parse("spiffe://kernel-v1").unwrap();
        assert_eq!(id.trust_domain(), "kernel-v1");
        assert_eq!(id.path(), "");
    }

    #[test]
    fn reject_wrong_scheme() {
        let err = SpiffeId::parse("https://kernel-v1/agent").unwrap_err();
        match err {
            SpiffeError::InvalidSpiffeId { reason, .. } => {
                assert!(reason.contains("spiffe://"));
            }
            other => panic!("expected InvalidSpiffeId, got {other:?}"),
        }
    }

    #[test]
    fn reject_empty_trust_domain() {
        let err = SpiffeId::parse("spiffe:///agent").unwrap_err();
        match err {
            SpiffeError::InvalidSpiffeId { reason, .. } => {
                assert!(reason.contains("trust domain"));
            }
            other => panic!("expected InvalidSpiffeId, got {other:?}"),
        }
    }

    #[test]
    fn reject_fragment() {
        assert!(SpiffeId::parse("spiffe://kernel-v1/agent#frag").is_err());
    }

    #[test]
    fn reject_query() {
        assert!(SpiffeId::parse("spiffe://kernel-v1/agent?q=1").is_err());
    }

    #[test]
    fn reject_whitespace_in_trust_domain() {
        assert!(SpiffeId::parse("spiffe://kernel v1/agent").is_err());
    }

    #[test]
    fn reject_double_slash_in_path() {
        assert!(SpiffeId::parse("spiffe://kernel-v1/agent//node").is_err());
    }

    #[test]
    fn exact_trust_domain_match() {
        let id = SpiffeId::parse("spiffe://kernel-v1/agent/prod/node-1").unwrap();
        assert!(id.assert_trust_domain("kernel-v1").is_ok());
    }

    #[test]
    fn reject_trust_domain_substring() {
        // "kernel-v1" is NOT a substring match for "kernel-v1-evil"
        let id = SpiffeId::parse("spiffe://kernel-v1-evil/agent").unwrap();
        let err = id.assert_trust_domain("kernel-v1").unwrap_err();
        match err {
            SpiffeError::TrustDomainMismatch { expected, actual } => {
                assert_eq!(expected, "kernel-v1");
                assert_eq!(actual, "kernel-v1-evil");
            }
            other => panic!("expected TrustDomainMismatch, got {other:?}"),
        }
    }

    #[test]
    fn reject_trust_domain_superstring() {
        // "kernel-v1" must NOT match when expected is "kernel"
        let id = SpiffeId::parse("spiffe://kernel-v1/agent").unwrap();
        assert!(id.assert_trust_domain("kernel").is_err());
    }

    #[test]
    fn selector_exact_path() {
        let selector = SpiffeIdSelector::new("kernel-v1").with_path_exact("/agent/prod/node-1");
        let id = SpiffeId::parse("spiffe://kernel-v1/agent/prod/node-1").unwrap();
        assert!(selector.validate(&id).is_ok());

        let wrong = SpiffeId::parse("spiffe://kernel-v1/agent/prod/node-2").unwrap();
        assert!(selector.validate(&wrong).is_err());
    }

    #[test]
    fn selector_path_prefix() {
        let selector = SpiffeIdSelector::new("kernel-v1").with_path_prefix("/agent/");
        let id = SpiffeId::parse("spiffe://kernel-v1/agent/prod/node-1").unwrap();
        assert!(selector.validate(&id).is_ok());

        let wrong = SpiffeId::parse("spiffe://kernel-v1/control/plane").unwrap();
        assert!(selector.validate(&wrong).is_err());
    }

    #[test]
    fn selector_rejects_wrong_trust_domain() {
        let selector = SpiffeIdSelector::new("kernel-v1");
        let id = SpiffeId::parse("spiffe://evil.example/agent").unwrap();
        let err = selector.validate(&id).unwrap_err();
        match err {
            SpiffeError::SelectorRejected { reason, .. } => {
                assert!(reason.contains("does not exactly match"));
            }
            other => panic!("expected SelectorRejected, got {other:?}"),
        }
    }

    #[test]
    fn selector_trust_domain_only_no_substring() {
        // "kernel-v1" selector must NOT match "kernel-v1-attacker"
        let selector = SpiffeIdSelector::new("kernel-v1");
        let id = SpiffeId::parse("spiffe://kernel-v1-attacker/agent").unwrap();
        assert!(selector.validate(&id).is_err());
    }

    #[test]
    fn display_roundtrip() {
        let raw = "spiffe://kernel-v1/agent/prod/node-1";
        let id = SpiffeId::parse(raw).unwrap();
        assert_eq!(id.to_string(), raw);
    }
}
