// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Single-predicate evaluation: the 14 comparison operators, with no coercion.
//!
//! [`PredicateEvaluator::evaluate_predicate`] dispatches one operator against a
//! resolved field value and condition value. Type rules are strict:
//! - equality/order operate on matching families; integers and floats compare
//!   numerically (both are numbers), any other cross-family comparison is
//!   [`RuleError::IncompatibleTypes`] — never coerced;
//! - `in`/`not_in` require an array operand; `contains` works on strings
//!   (substring) or arrays (element); `starts_with`/`ends_with`/`regex` require
//!   string operands;
//! - an unknown field value never reaches here (the caller resolves it to a
//!   non-match first), so a predicate only ever sees concrete values.

use std::cmp::Ordering;

use crate::ast::{Operator, Value};

use super::error::{Result, RuleError};
use super::eval::PredicateEvaluator;

impl PredicateEvaluator {
    /// Evaluate a single predicate. Returns `true` on match, `false` otherwise.
    ///
    /// Never coerces incompatible types (returns
    /// [`RuleError::IncompatibleTypes`]); never treats unknown as true (unknown
    /// is resolved to a non-match by the caller before this is invoked).
    pub fn evaluate_predicate(
        &self,
        operator: &Operator,
        field_value: &Value,
        condition_value: &Value,
    ) -> Result<bool> {
        match operator {
            Operator::Eq => values_eq(field_value, condition_value),
            Operator::Ne => Ok(!values_eq(field_value, condition_value)?),
            Operator::Gt => Ok(compare(field_value, condition_value)? == Ordering::Greater),
            Operator::Lt => Ok(compare(field_value, condition_value)? == Ordering::Less),
            Operator::Gte => Ok(matches!(
                compare(field_value, condition_value)?,
                Ordering::Greater | Ordering::Equal
            )),
            Operator::Lte => Ok(matches!(
                compare(field_value, condition_value)?,
                Ordering::Less | Ordering::Equal
            )),
            Operator::In => in_set(field_value, condition_value),
            Operator::NotIn => Ok(!in_set(field_value, condition_value)?),
            Operator::Contains => contains(field_value, condition_value),
            Operator::NotContains => Ok(!contains(field_value, condition_value)?),
            Operator::StartsWith => {
                str_binop(field_value, condition_value, |h, n| h.starts_with(n))
            }
            Operator::EndsWith => str_binop(field_value, condition_value, |h, n| h.ends_with(n)),
            Operator::Regex => {
                let (haystack, pattern) = regex_operands(field_value, condition_value)?;
                self.evaluate_regex(pattern, haystack)
            }
            Operator::NotRegex => {
                let (haystack, pattern) = regex_operands(field_value, condition_value)?;
                Ok(!self.evaluate_regex(pattern, haystack)?)
            }
        }
    }
}

/// Parse an operator from its wire name (snake_case). Unknown names are
/// [`RuleError::UnknownOperator`].
pub fn parse_operator(raw: &str) -> Result<Operator> {
    match raw {
        "eq" => Ok(Operator::Eq),
        "ne" => Ok(Operator::Ne),
        "gt" => Ok(Operator::Gt),
        "lt" => Ok(Operator::Lt),
        "gte" => Ok(Operator::Gte),
        "lte" => Ok(Operator::Lte),
        "in" => Ok(Operator::In),
        "not_in" => Ok(Operator::NotIn),
        "contains" => Ok(Operator::Contains),
        "not_contains" => Ok(Operator::NotContains),
        "starts_with" => Ok(Operator::StartsWith),
        "ends_with" => Ok(Operator::EndsWith),
        "regex" => Ok(Operator::Regex),
        "not_regex" => Ok(Operator::NotRegex),
        other => Err(RuleError::UnknownOperator(format!(
            "'{other}' is not a known operator"
        ))),
    }
}

/// Equality without coercion: matching families compare directly; integers and
/// floats compare numerically; any other cross-family pair is incompatible.
fn values_eq(a: &Value, b: &Value) -> Result<bool> {
    match (a, b) {
        (Value::String(x), Value::String(y)) => Ok(x == y),
        (Value::Boolean(x), Value::Boolean(y)) => Ok(x == y),
        (Value::Integer(x), Value::Integer(y)) => Ok(x == y),
        (Value::Float(x), Value::Float(y)) => Ok(x == y),
        (Value::Integer(x), Value::Float(y)) => Ok((*x as f64) == *y),
        (Value::Float(x), Value::Integer(y)) => Ok(*x == (*y as f64)),
        (Value::Array(x), Value::Array(y)) => Ok(x == y),
        _ => Err(RuleError::IncompatibleTypes(format!(
            "cannot compare {} with {} for equality",
            type_name(a),
            type_name(b)
        ))),
    }
}

/// Numeric ordering without coercion. NaN is unordered (incompatible).
fn compare(a: &Value, b: &Value) -> Result<Ordering> {
    let err = || RuleError::IncompatibleTypes("cannot order NaN".to_string());
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => Ok(x.cmp(y)),
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y).ok_or_else(err),
        (Value::Integer(x), Value::Float(y)) => (*x as f64).partial_cmp(y).ok_or_else(err),
        (Value::Float(x), Value::Integer(y)) => x.partial_cmp(&(*y as f64)).ok_or_else(err),
        _ => Err(RuleError::IncompatibleTypes(format!(
            "ordering requires numeric operands, got {} and {}",
            type_name(a),
            type_name(b)
        ))),
    }
}

/// Set membership: the condition value must be an array; every element must be
/// type-compatible with the field value (no coercion).
fn in_set(field_value: &Value, condition_value: &Value) -> Result<bool> {
    let items = match condition_value {
        Value::Array(items) => items,
        _ => {
            return Err(RuleError::IncompatibleTypes(
                "in/not_in requires an array operand".to_string(),
            ))
        }
    };
    for item in items {
        if values_eq(field_value, item)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Containment: substring for a string field, element membership for an array
/// field; any other field type is incompatible.
fn contains(field_value: &Value, condition_value: &Value) -> Result<bool> {
    match field_value {
        Value::String(haystack) => match condition_value {
            Value::String(needle) => Ok(haystack.contains(needle.as_str())),
            _ => Err(RuleError::IncompatibleTypes(
                "contains on a string field requires a string needle".to_string(),
            )),
        },
        Value::Array(items) => {
            for item in items {
                if values_eq(item, condition_value)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Err(RuleError::IncompatibleTypes(format!(
            "contains requires a string or array field, got {}",
            type_name(field_value)
        ))),
    }
}

/// A binary string predicate (`starts_with` / `ends_with`); both operands must
/// be strings.
fn str_binop(
    field_value: &Value,
    condition_value: &Value,
    op: fn(&str, &str) -> bool,
) -> Result<bool> {
    match (field_value, condition_value) {
        (Value::String(haystack), Value::String(needle)) => Ok(op(haystack, needle)),
        _ => Err(RuleError::IncompatibleTypes(
            "starts_with/ends_with require string operands".to_string(),
        )),
    }
}

/// Extract `(haystack, pattern)` for a regex predicate; both must be strings.
fn regex_operands<'a>(
    field_value: &'a Value,
    condition_value: &'a Value,
) -> Result<(&'a str, &'a str)> {
    match (field_value, condition_value) {
        (Value::String(haystack), Value::String(pattern)) => Ok((haystack, pattern)),
        _ => Err(RuleError::IncompatibleTypes(
            "regex/not_regex require string operands".to_string(),
        )),
    }
}

/// Human-readable type name for diagnostics.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Integer(_) => "integer",
        Value::Float(_) => "float",
        Value::Boolean(_) => "boolean",
        Value::Array(_) => "array",
    }
}
