// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed errors for the SPIFFE identity crate.
//!
//! Every failure path maps to a variant here so callers can match
//! on the exact rejection reason without string-parsing. The crate
//! NEVER panics on invalid identity input; it returns
//! `Err(SpiffeError::...)`.

#![forbid(unsafe_code)]

use std::fmt;

/// Typed error codes for SPIFFE identity operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpiffeError {
    /// The SPIFFE ID string is malformed (bad scheme, empty
    /// trust domain, invalid characters).
    InvalidSpiffeId {
        /// The raw string that failed to parse.
        raw: String,
        /// Human-readable reason.
        reason: String,
    },

    /// The trust domain does not exactly match the expected
    /// value. Substring matching is NEVER permitted.
    TrustDomainMismatch {
        /// The expected trust domain.
        expected: String,
        /// The trust domain found in the SVID.
        actual: String,
    },

    /// The SPIFFE ID was rejected by the selector policy
    /// (path mismatch, unauthorized workload).
    SelectorRejected {
        /// The SPIFFE ID that was rejected.
        spiffe_id: String,
        /// Why the selector rejected it.
        reason: String,
    },

    /// The SVID has expired and no replacement is available.
    /// Fail closed: never use expired material.
    SvidExpired {
        /// The SPIFFE ID of the expired SVID.
        spiffe_id: String,
        /// Unix timestamp (seconds) when the SVID expired.
        expired_at_unix: i64,
    },

    /// The Workload API stream disconnected.
    StreamDisconnected {
        /// Human-readable reason.
        reason: String,
    },

    /// The credential material has been redacted (zeroized)
    /// after a complete-set replacement. Using redacted
    /// material is a logic error.
    MaterialRedacted,

    /// No valid credentials are available (stream never
    /// connected, or all SVIDs expired without replacement).
    NoCredentials {
        /// Human-readable reason.
        reason: String,
    },

    /// The Workload API endpoint socket is not configured or
    /// not accessible.
    EndpointNotConfigured {
        /// The path that was attempted (or empty if env var
        /// was unset).
        path: String,
    },

    /// A certificate or key failed to parse.
    ParseError {
        /// What was being parsed.
        context: String,
        /// Underlying error message.
        source: String,
    },

    /// Authorization callback rejected the peer identity.
    AuthorizationDenied {
        /// The peer SPIFFE ID.
        peer_spiffe_id: String,
        /// Why authorization was denied.
        reason: String,
    },
}

impl fmt::Display for SpiffeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpiffeId { raw, reason } => {
                write!(f, "invalid SPIFFE ID '{raw}': {reason}")
            }
            Self::TrustDomainMismatch { expected, actual } => {
                write!(
                    f,
                    "trust domain mismatch: expected '{expected}', got '{actual}'"
                )
            }
            Self::SelectorRejected { spiffe_id, reason } => {
                write!(f, "selector rejected '{spiffe_id}': {reason}")
            }
            Self::SvidExpired {
                spiffe_id,
                expired_at_unix,
            } => {
                write!(f, "SVID '{spiffe_id}' expired at unix {expired_at_unix}")
            }
            Self::StreamDisconnected { reason } => {
                write!(f, "stream disconnected: {reason}")
            }
            Self::MaterialRedacted => {
                write!(f, "credential material has been redacted")
            }
            Self::NoCredentials { reason } => {
                write!(f, "no credentials available: {reason}")
            }
            Self::EndpointNotConfigured { path } => {
                if path.is_empty() {
                    write!(f, "SPIFFE_ENDPOINT_SOCKET not configured")
                } else {
                    write!(f, "workload endpoint not accessible: {path}")
                }
            }
            Self::ParseError { context, source } => {
                write!(f, "parse error ({context}): {source}")
            }
            Self::AuthorizationDenied {
                peer_spiffe_id,
                reason,
            } => {
                write!(f, "authorization denied for '{peer_spiffe_id}': {reason}")
            }
        }
    }
}

impl std::error::Error for SpiffeError {}

/// Typed result alias for SPIFFE identity operations.
pub type SpiffeResult<T> = Result<T, SpiffeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_display() {
        let variants = [
            SpiffeError::InvalidSpiffeId {
                raw: "http://bad".into(),
                reason: "wrong scheme".into(),
            },
            SpiffeError::TrustDomainMismatch {
                expected: "kernel-v1".into(),
                actual: "evil".into(),
            },
            SpiffeError::SelectorRejected {
                spiffe_id: "spiffe://kernel-v1/bad".into(),
                reason: "path not allowed".into(),
            },
            SpiffeError::SvidExpired {
                spiffe_id: "spiffe://kernel-v1/agent/prod/n1".into(),
                expired_at_unix: 1700000000,
            },
            SpiffeError::StreamDisconnected {
                reason: "connection reset".into(),
            },
            SpiffeError::MaterialRedacted,
            SpiffeError::NoCredentials {
                reason: "never connected".into(),
            },
            SpiffeError::EndpointNotConfigured {
                path: String::new(),
            },
            SpiffeError::ParseError {
                context: "certificate".into(),
                source: "invalid DER".into(),
            },
            SpiffeError::AuthorizationDenied {
                peer_spiffe_id: "spiffe://kernel-v1/agent/evil/n1".into(),
                reason: "cluster mismatch".into(),
            },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn trust_domain_mismatch_shows_both() {
        let err = SpiffeError::TrustDomainMismatch {
            expected: "kernel-v1".into(),
            actual: "evil.example".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("kernel-v1"));
        assert!(msg.contains("evil.example"));
    }

    #[test]
    fn endpoint_not_configured_empty_path() {
        let err = SpiffeError::EndpointNotConfigured {
            path: String::new(),
        };
        assert!(err.to_string().contains("not configured"));
    }
}
