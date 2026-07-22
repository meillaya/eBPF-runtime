// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed errors for the control-db crate.
//!
//! Every error variant maps to a specific database invariant
//! violation: optimistic concurrency conflict, idempotency
//! duplicate, RLS denial, or audit immutability breach.

#![forbid(unsafe_code)]

/// Result alias for control-db operations.
pub type Result<T> = std::result::Result<T, ControlDbError>;

/// Errors from the control database layer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ControlDbError {
    /// Optimistic concurrency conflict: the row version did not
    /// match the expected version. The caller must re-read and
    /// retry.
    #[error(
        "optimistic concurrency conflict on {table}: expected version {expected}, found {found}"
    )]
    VersionConflict {
        table: String,
        expected: i64,
        found: i64,
    },

    /// Idempotency violation: a duplicate key was detected.
    /// The operation is a safe no-op (the original succeeded).
    #[error("idempotent duplicate: {key}")]
    IdempotentDuplicate { key: String },

    /// Row-level security denied the operation. This indicates
    /// a cross-cluster access attempt or insufficient role.
    #[error("RLS denied: {reason}")]
    RlsDenied { reason: String },

    /// Audit immutability breach: an UPDATE or DELETE was
    /// attempted on the audit log.
    #[error("audit immutability violation: {operation} not permitted")]
    AuditImmutable { operation: String },

    /// The requested row was not found.
    #[error("not found: {table} with {key}")]
    NotFound { table: String, key: String },

    /// A unique constraint was violated (non-idempotent).
    #[error("unique constraint violation: {constraint}")]
    UniqueViolation { constraint: String },

    /// The rollout state machine rejected a transition.
    #[error("invalid rollout transition: {from} -> {action}")]
    InvalidRolloutTransition { from: String, action: String },

    /// The advisory lock key was out of the bounded range.
    #[error("advisory lock key out of bounds: {key} (max {max})")]
    AdvisoryLockOutOfBounds { key: i64, max: i64 },

    /// Connection pool is exhausted or unavailable.
    #[error("pool error: {0}")]
    Pool(String),

    /// A SQL/database error from the driver.
    #[error("database error: {0}")]
    Database(String),

    /// Migration error.
    #[error("migration error: {0}")]
    Migration(String),
}

impl ControlDbError {
    /// Whether this error is retryable (optimistic conflict).
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::VersionConflict { .. })
    }

    /// Whether this error is an idempotent duplicate (safe no-op).
    pub fn is_idempotent_duplicate(&self) -> bool {
        matches!(self, Self::IdempotentDuplicate { .. })
    }
}
