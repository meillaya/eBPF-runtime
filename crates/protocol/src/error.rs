// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed protocol errors.
//!
//! Every failure path in the protocol state machines maps to a
//! variant here so callers can match on the exact rejection reason
//! without string-parsing. Mirrors the enforcement crate's
//! `EnforcementError` discipline: the protocol NEVER panics on
//! invalid input; it returns `Err(ProtocolError::...)`.

#![forbid(unsafe_code)]

use std::fmt;

/// Typed status/error codes for the fleet protocol.
///
/// Each variant maps to an exact gRPC-style status code so the
/// control plane and agent can match on the rejection reason
/// without parsing free strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The requested state transition is not valid from the
    /// current state (e.g. COMMIT before READY).
    InvalidTransition {
        /// The state the machine is currently in.
        from: String,
        /// The action that was attempted.
        action: String,
    },

    /// The command's version is not strictly greater than the
    /// current monotonic version (stale or replay).
    VersionReplay {
        /// The version carried by the rejected command.
        command_version: u64,
        /// The current monotonic version.
        current_version: u64,
    },

    /// The SHA-256 digest of the staged content does not match
    /// the declared digest.
    DigestMismatch {
        /// Hex-encoded expected digest.
        expected: String,
        /// Hex-encoded actual digest.
        actual: String,
    },

    /// A single message exceeds the maximum permitted size.
    OversizedMessage {
        /// Actual size in bytes.
        actual_bytes: usize,
        /// Maximum permitted size in bytes.
        max_bytes: usize,
    },

    /// A batch exceeds the maximum number of messages.
    OversizedBatch {
        /// Actual message count.
        actual_count: usize,
        /// Maximum permitted count.
        max_count: usize,
    },

    /// The deadline has expired before the operation completed.
    ExpiredDeadline {
        /// The deadline that expired (epoch millis).
        deadline_epoch_ms: u64,
        /// The current time when expiry was detected (epoch millis).
        now_epoch_ms: u64,
    },

    /// A duplicate idempotency key was detected.
    DuplicateIdempotencyKey {
        /// The duplicated key.
        key: String,
    },

    /// The protocol major version is stale (client speaks an
    /// older wire format the server no longer accepts).
    StaleProtocolMajor {
        /// The client's major version.
        client_major: u32,
        /// The server's required major version.
        server_major: u32,
    },

    /// An unknown field was encountered that the consumer cannot
    /// skip (forward-compatibility violation).
    UnknownField {
        /// The field number or name.
        field: String,
    },

    /// The policy content failed structural validation.
    InvalidPolicy {
        /// Human-readable reason.
        reason: String,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, action } => {
                write!(f, "invalid transition: cannot {action} from {from}")
            }
            Self::VersionReplay {
                command_version,
                current_version,
            } => {
                write!(
                    f,
                    "version replay: command version {command_version} <= current {current_version}"
                )
            }
            Self::DigestMismatch { expected, actual } => {
                write!(f, "digest mismatch: expected {expected}, computed {actual}")
            }
            Self::OversizedMessage {
                actual_bytes,
                max_bytes,
            } => {
                write!(
                    f,
                    "oversized message: {actual_bytes} bytes exceeds max {max_bytes}"
                )
            }
            Self::OversizedBatch {
                actual_count,
                max_count,
            } => {
                write!(
                    f,
                    "oversized batch: {actual_count} messages exceeds max {max_count}"
                )
            }
            Self::ExpiredDeadline {
                deadline_epoch_ms,
                now_epoch_ms,
            } => {
                write!(
                    f,
                    "expired deadline: deadline {deadline_epoch_ms} < now {now_epoch_ms}"
                )
            }
            Self::DuplicateIdempotencyKey { key } => {
                write!(f, "duplicate idempotency key: {key}")
            }
            Self::StaleProtocolMajor {
                client_major,
                server_major,
            } => {
                write!(
                    f,
                    "stale protocol major: client {client_major} < server {server_major}"
                )
            }
            Self::UnknownField { field } => {
                write!(f, "unknown field: {field}")
            }
            Self::InvalidPolicy { reason } => {
                write!(f, "invalid policy: {reason}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Typed result alias for protocol operations.
pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_displayable() {
        let variants = [
            ProtocolError::InvalidTransition {
                from: "Idle".into(),
                action: "commit".into(),
            },
            ProtocolError::VersionReplay {
                command_version: 1,
                current_version: 2,
            },
            ProtocolError::DigestMismatch {
                expected: "abc".into(),
                actual: "def".into(),
            },
            ProtocolError::OversizedMessage {
                actual_bytes: 2_000_000,
                max_bytes: 1_048_576,
            },
            ProtocolError::OversizedBatch {
                actual_count: 1001,
                max_count: 1000,
            },
            ProtocolError::ExpiredDeadline {
                deadline_epoch_ms: 100,
                now_epoch_ms: 200,
            },
            ProtocolError::DuplicateIdempotencyKey {
                key: "abc-123".into(),
            },
            ProtocolError::StaleProtocolMajor {
                client_major: 0,
                server_major: 1,
            },
            ProtocolError::UnknownField { field: "99".into() },
            ProtocolError::InvalidPolicy {
                reason: "bad hook".into(),
            },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    #[test]
    fn invalid_transition_includes_state_and_action() {
        let err = ProtocolError::InvalidTransition {
            from: "Staged".into(),
            action: "commit".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Staged"));
        assert!(msg.contains("commit"));
    }

    #[test]
    fn oversized_message_includes_sizes() {
        let err = ProtocolError::OversizedMessage {
            actual_bytes: 2_000_000,
            max_bytes: 1_048_576,
        };
        let msg = err.to_string();
        assert!(msg.contains("2000000"));
        assert!(msg.contains("1048576"));
    }
}
