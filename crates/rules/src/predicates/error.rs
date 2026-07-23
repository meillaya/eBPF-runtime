// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed errors for bounded, deterministic predicate evaluation.
//!
//! This is the evaluator's own error type, distinct from the parse/validate
//! [`crate::error::RuleError`]: parsing rejects structurally/semantically bad
//! rule documents, while evaluation rejects conditions that would exceed the
//! [`super::RuleBudget`] or that compare incompatible runtime types. Every
//! failure mode of [`super::PredicateEvaluator`] maps onto one variant here.
//!
//! Contract guarantees encoded by these variants:
//! - incompatible types are never coerced ([`RuleError::IncompatibleTypes`]);
//! - regex is bounded in size, complexity, and time
//!   ([`RuleError::RegexTooLarge`] / [`RuleError::RegexTooComplex`] /
//!   [`RuleError::RegexTooSlow`]);
//! - evaluation is bounded in depth and operation count
//!   ([`RuleError::NestingTooDeep`] / [`RuleError::TooManyOps`]);
//! - lists, exceptions, and sequences are bounded
//!   ([`RuleError::TooManyListItems`] / [`RuleError::TooManyExceptionItems`] /
//!   [`RuleError::TooManySequenceSteps`] / [`RuleError::SequenceWindowTooLarge`]).

/// All failures produced by bounded predicate evaluation.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    /// Two operands have incompatible runtime types and cannot be compared.
    /// The evaluator never coerces incompatible types.
    #[error("incompatible types: {0}")]
    IncompatibleTypes(String),

    /// A referenced event field is unknown or null (strict lookup only).
    /// Non-strict evaluation treats this as a non-match, not an error.
    #[error("unknown field: {0}")]
    UnknownField(String),

    /// An operator name is not a known operator.
    #[error("unknown operator: {0}")]
    UnknownOperator(String),

    /// A regex pattern failed to compile (or is empty).
    #[error("invalid regex: {0}")]
    InvalidRegex(String),

    /// A regex pattern exceeds the configured character bound.
    #[error("regex too large: {0}")]
    RegexTooLarge(String),

    /// A regex pattern is too complex (too many capture groups, or
    /// unbounded/nested quantifiers that risk catastrophic backtracking).
    #[error("regex too complex: {0}")]
    RegexTooComplex(String),

    /// A regex match exceeded the configured wall-clock time bound.
    #[error("regex too slow: {0}")]
    RegexTooSlow(String),

    /// Condition nesting depth exceeds the configured maximum.
    #[error("condition nesting too deep: depth {0} exceeds the budget")]
    NestingTooDeep(usize),

    /// Operation count exceeds the configured per-evaluation maximum.
    #[error("too many operations: {0} exceeds the budget")]
    TooManyOps(usize),

    /// A list has more items than the configured maximum.
    #[error("too many list items: {0} exceeds the budget")]
    TooManyListItems(usize),

    /// An exception value has more items than the configured maximum.
    #[error("too many exception items: {0} exceeds the budget")]
    TooManyExceptionItems(usize),

    /// A sequence has more steps than the configured maximum.
    #[error("too many sequence steps: {0} exceeds the budget")]
    TooManySequenceSteps(usize),

    /// A sequence window exceeds the configured maximum seconds.
    #[error("sequence window too large: {0}s exceeds the budget")]
    SequenceWindowTooLarge(u64),

    /// A JSON (de)serialization error (e.g. parsing the budget schema).
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// A filesystem I/O error (e.g. reading the budget schema).
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Convenience alias used throughout the predicates module.
pub type Result<T> = std::result::Result<T, RuleError>;
