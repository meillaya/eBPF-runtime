// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded evaluation of reusable lists, scoped exceptions, and sequence budgets.
//!
//! - [`PredicateEvaluator::evaluate_list`]: immutable membership in a reusable
//!   string list, bounded by `max_list_items`. The list is only ever borrowed;
//!   shared definitions are never mutated.
//! - [`PredicateEvaluator::evaluate_exception`]: a scoped exception is a single
//!   field match that suppresses a rule; its value array is bounded by
//!   `max_exception_items`. An exception over an unknown/null field never
//!   applies (non-match).
//! - [`PredicateEvaluator::validate_sequence`]: enforces the sequence step and
//!   window budgets. This is the budget guard only.

use crate::ast::{Exception, List, Sequence, Value};

use super::error::{Result, RuleError};
use super::eval::PredicateEvaluator;
use super::event::Event;

impl PredicateEvaluator {
    /// Evaluate immutable list membership: is `value` (a string) in `list`?
    ///
    /// The list is bounded by `max_list_items` and only ever borrowed (never
    /// mutated). A non-string `value` is incompatible (no coercion).
    pub fn evaluate_list(&self, list: &List, value: &Value) -> Result<bool> {
        if list.items.len() > self.budget.max_list_items {
            return Err(RuleError::TooManyListItems(list.items.len()));
        }
        let needle = value.as_str().ok_or_else(|| {
            RuleError::IncompatibleTypes("list membership requires a string value".to_string())
        })?;
        Ok(list.items.iter().any(|item| item == needle))
    }

    /// Evaluate a scoped exception against an event: does the exception match?
    ///
    /// A matching exception suppresses the rule. The exception's value array is
    /// bounded by `max_exception_items`. Over an unknown/null field the
    /// exception never applies (returns `false`), so an exception can never
    /// suppress a rule from unknown data.
    pub fn evaluate_exception(&self, exception: &Exception, event: &Event) -> Result<bool> {
        if let Value::Array(items) = &exception.value {
            if items.len() > self.budget.max_exception_items {
                return Err(RuleError::TooManyExceptionItems(items.len()));
            }
        }
        match event.lookup(&exception.field) {
            None => Ok(false),
            Some(field_value) => {
                self.evaluate_predicate(&exception.operator, field_value, &exception.value)
            }
        }
    }

    /// Validate a temporal sequence against the step/window budgets.
    ///
    /// This enforces the budget only. Ordered correlation lives in the
    /// sequence evaluator.
    pub fn validate_sequence(&self, sequence: &Sequence) -> Result<()> {
        if sequence.steps.len() > self.budget.max_sequence_steps {
            return Err(RuleError::TooManySequenceSteps(sequence.steps.len()));
        }
        let window = u64::from(sequence.window_seconds);
        if window > self.budget.max_sequence_window_seconds {
            return Err(RuleError::SequenceWindowTooLarge(window));
        }
        Ok(())
    }
}
