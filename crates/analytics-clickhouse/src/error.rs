// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed error types for the analytics-clickhouse crate.

use thiserror::Error;

/// Errors from the analytics-clickhouse crate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnalyticsError {
    /// Schema major version is not supported.
    #[error("schema major {got} is not supported (expected {expected})")]
    SchemaMajorUnsupported { got: u16, expected: u16 },

    /// Event ID is empty.
    #[error("event_id must not be empty")]
    EmptyEventId,

    /// Payload exceeds the maximum allowed size.
    #[error("payload size {size} exceeds maximum {max}")]
    PayloadTooLarge { size: usize, max: usize },

    /// Migration SQL is not repeatable (contains destructive DDL).
    #[error("migration {file} is not repeatable: {reason}")]
    MigrationNotRepeatable { file: String, reason: String },

    /// Consumer lag exceeds the bounded threshold.
    #[error("consumer lag {lag} exceeds threshold {threshold} for partition {partition}")]
    ConsumerLagExceeded {
        partition: i32,
        lag: u64,
        threshold: u64,
    },

    /// DLQ reason is empty.
    #[error("dlq_reason must not be empty")]
    EmptyDlqReason,

    /// Invalid event kind (not in the known set).
    #[error("unknown event kind: {0}")]
    UnknownEventKind(String),

    /// Malformed message that cannot be parsed.
    #[error("malformed message: {reason}")]
    MalformedMessage { reason: String },
}

/// Result type for analytics operations.
pub type AnalyticsResult<T> = Result<T, AnalyticsError>;
