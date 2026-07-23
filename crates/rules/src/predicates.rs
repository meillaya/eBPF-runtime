// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded, deterministic predicate evaluation for the native rule schema.
//!
//! This module evaluates a validated [`crate::Condition`] against an
//! [`Event`] under a [`RuleBudget`], producing a deterministic
//! [`EvaluationResult`] with a full match [`Explanation`]. It implements the
//! equality/order/set/prefix/bounded-regex predicates, typed null/validity
//! handling, reusable immutable lists, scoped exceptions, and AND/OR/NOT with
//! complexity/depth budgets (task 28). Temporal sequence correlation is task 29;
//! only the sequence *budget* guard lives here.
//!
//! # Contract
//!
//! - **No coercion**: incompatible runtime types are
//!   [`RuleError::IncompatibleTypes`], never silently coerced.
//! - **Unknown is not true**: an unknown or null field value is a non-match.
//! - **Immutable**: conditions, events, lists, and exceptions are only borrowed;
//!   shared definitions are never mutated.
//! - **Bounded**: depth, operation count, list/exception size, and regex
//!   size/complexity/time are all bounded by [`RuleBudget`]; no unbounded
//!   allocation or backtracking.
//! - **Deterministic**: the same input always yields the same result and
//!   explanation tree.
//!
//! The budget defaults are anchored in `bench/schemas/rule-budget.v1.json`
//! (see [`default_budget`] / [`load_budget_from_schema`]).

mod budget;
mod collection;
mod error;
mod eval;
mod event;
mod explain;
mod predicate;
mod regex_eval;

pub use budget::{default_budget, load_budget_from_schema, RuleBudget};
pub use error::{Result, RuleError};
pub use eval::PredicateEvaluator;
pub use event::Event;
pub use explain::{EvaluationResult, Explanation};
pub use predicate::parse_operator;
