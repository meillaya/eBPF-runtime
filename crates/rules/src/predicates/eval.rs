// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The bounded, deterministic predicate evaluator.
//!
//! [`PredicateEvaluator`] evaluates a [`Condition`] against an [`Event`] under
//! a [`RuleBudget`]. Guarantees:
//! - **Bounded**: nesting depth and operation count are checked against the
//!   budget; an over-budget condition is rejected before/outside evaluation.
//! - **Deterministic**: children are evaluated in document order and field
//!   storage is ordered, so the same input always yields the same
//!   [`EvaluationResult`] and [`Explanation`].
//! - **Honest**: an unknown or null field value is a non-match (`false`), never
//!   true; incompatible types are an error, never coerced (see
//!   [`PredicateEvaluator::evaluate_predicate`]).
//! - **Immutable**: the evaluator only ever borrows conditions, events, and
//!   lists; shared definitions are never mutated.

use crate::ast::{Condition, List, Operator, Value};

use super::budget::RuleBudget;
use super::error::{Result, RuleError};
use super::event::Event;
use super::explain::{EvaluationResult, Explanation};

/// A bounded, deterministic predicate evaluator.
#[derive(Debug, Clone, Copy)]
pub struct PredicateEvaluator {
    /// The resource budget every evaluation runs under.
    pub budget: RuleBudget,
}

impl PredicateEvaluator {
    /// Create an evaluator with the given budget.
    pub fn new(budget: RuleBudget) -> Self {
        Self { budget }
    }

    /// Evaluate a condition against an event, returning the match result and
    /// explanation tree.
    ///
    /// Validates nesting depth against `max_nested_expressions`, then evaluates
    /// deterministically while counting operations against
    /// `max_ops_per_evaluation`. List-name references in `in`/`not_in` values
    /// are resolved against `lists` (one level, bounded, never recursive).
    pub fn evaluate_condition(
        &self,
        condition: &Condition,
        event: &Event,
        lists: &[List],
    ) -> Result<EvaluationResult> {
        let depth = nesting_depth(condition);
        if depth > self.budget.max_nested_expressions {
            return Err(RuleError::NestingTooDeep(depth));
        }
        let mut ops = 0usize;
        self.eval_rec(condition, event, lists, &mut ops)
    }

    /// Recursive deterministic evaluation with a shared operation counter.
    fn eval_rec(
        &self,
        condition: &Condition,
        event: &Event,
        lists: &[List],
        ops: &mut usize,
    ) -> Result<EvaluationResult> {
        match condition {
            Condition::Field {
                field,
                operator,
                value,
            } => {
                *ops += 1;
                if *ops > self.budget.max_ops_per_evaluation {
                    return Err(RuleError::TooManyOps(*ops));
                }
                let resolved = self.resolve_list_value(operator, value, lists)?;
                // Unknown or null field value -> non-match, never true.
                let matched = match event.lookup(field) {
                    None => false,
                    Some(field_value) => self.evaluate_predicate(operator, field_value, &resolved)?,
                };
                Ok(EvaluationResult {
                    matched,
                    explanation: Explanation::leaf(field, *operator, resolved, matched),
                })
            }
            Condition::And(children) => {
                let mut explanations = Vec::new();
                let mut matched = true;
                for child in children {
                    let result = self.eval_rec(child, event, lists, ops)?;
                    matched = matched && result.matched;
                    explanations.push(result.explanation);
                }
                Ok(EvaluationResult {
                    matched,
                    explanation: Explanation::node("and", matched, explanations),
                })
            }
            Condition::Or(children) => {
                let mut explanations = Vec::new();
                let mut matched = false;
                for child in children {
                    let result = self.eval_rec(child, event, lists, ops)?;
                    matched = matched || result.matched;
                    explanations.push(result.explanation);
                }
                Ok(EvaluationResult {
                    matched,
                    explanation: Explanation::node("or", matched, explanations),
                })
            }
            Condition::Not(child) => {
                let result = self.eval_rec(child, event, lists, ops)?;
                let matched = !result.matched;
                Ok(EvaluationResult {
                    matched,
                    explanation: Explanation::node("not", matched, vec![result.explanation]),
                })
            }
        }
    }

    /// Resolve an `in`/`not_in` value that names a list to that list's items.
    ///
    /// Resolution is exactly one level: list items are literal strings and are
    /// never re-expanded, so a list that names another list (or itself) cannot
    /// recurse. The resolved list is bounded by `max_list_items`.
    fn resolve_list_value(&self, operator: &Operator, value: &Value, lists: &[List]) -> Result<Value> {
        if !matches!(operator, Operator::In | Operator::NotIn) {
            return Ok(value.clone());
        }
        if let Value::String(name) = value {
            if let Some(list) = lists.iter().find(|l| l.name == *name) {
                if list.items.len() > self.budget.max_list_items {
                    return Err(RuleError::TooManyListItems(list.items.len()));
                }
                return Ok(Value::Array(
                    list.items.iter().map(|i| Value::String(i.clone())).collect(),
                ));
            }
        }
        Ok(value.clone())
    }
}

/// Nesting depth of a condition: a leaf is 1; `not` is 1 + child; `and`/`or`
/// is 1 + the deepest child. Mirrors the validator's depth metric.
fn nesting_depth(condition: &Condition) -> usize {
    match condition {
        Condition::Field { .. } => 1,
        Condition::Not(child) => 1 + nesting_depth(child),
        Condition::And(children) | Condition::Or(children) => {
            1 + children.iter().map(nesting_depth).max().unwrap_or(0)
        }
    }
}
