// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Step predicate evaluation and event field extraction helpers.

use crate::ast::{Operator, Step, Value};
use crate::predicates::Event;

use crate::predicates::{Result, RuleError};

use super::{
    GroupKey, SequenceInstance, SequenceKey, SequenceMatch, StepState,
    CONTAINER_ID_FIELD, EVENT_ID_FIELD, PROCESS_GENERATION_FIELD, SOCKET_INODE_FIELD, TS_FIELD,
};

/// Extract the group key from an event. Priority order:
/// 1. `process.generation` (u64) — unique across PID reuse
/// 2. `container.id` (String)
/// 3. `socket.inode` (u64)
/// 4. Fallback: `Custom("default")`
///
/// NEVER uses PID alone. Process correlation uses the generation counter.
pub(crate) fn extract_group_key(event: &Event) -> GroupKey {
    if let Some(Value::Integer(gen)) = event.lookup(PROCESS_GENERATION_FIELD) {
        return GroupKey::ProcessGeneration(*gen as u64);
    }
    if let Some(Value::String(id)) = event.lookup(CONTAINER_ID_FIELD) {
        return GroupKey::Container(id.clone());
    }
    if let Some(Value::Integer(inode)) = event.lookup(SOCKET_INODE_FIELD) {
        return GroupKey::Socket(*inode as u64);
    }
    GroupKey::Custom("default".to_string())
}

/// Extract the monotonic timestamp from an event.
/// Uses the `ts` field (Integer, seconds). Returns 0 if absent.
/// NEVER uses wall clock.
pub(crate) fn extract_timestamp(event: &Event) -> u64 {
    match event.lookup(TS_FIELD) {
        Some(Value::Integer(ts)) if *ts >= 0 => *ts as u64,
        _ => 0,
    }
}

/// Extract the event identifier from an event.
/// Uses the `event.id` field (String). Returns None if absent.
pub(crate) fn extract_event_id(event: &Event) -> Option<String> {
    match event.lookup(EVENT_ID_FIELD) {
        Some(Value::String(id)) => Some(id.clone()),
        _ => None,
    }
}

/// Initialize step states for a sequence with `n` steps.
pub(crate) fn init_steps(n: usize) -> Vec<StepState> {
    (0..n)
        .map(|i| StepState {
            step_index: i,
            matched: false,
            matched_at: None,
            event_id: None,
        })
        .collect()
}

/// Check whether an event matches a sequence step.
pub(crate) fn step_matches(step: &Step, event: &Event) -> Result<bool> {
    match event.lookup(&step.field) {
        None => Ok(false),
        Some(field_value) => evaluate_step_predicate(&step.operator, field_value, &step.value),
    }
}

/// Evaluate a single step predicate (subset of operators valid for steps).
fn evaluate_step_predicate(
    operator: &Operator,
    field_value: &Value,
    condition_value: &Value,
) -> Result<bool> {
    match operator {
        Operator::Eq => values_eq(field_value, condition_value),
        Operator::Ne => Ok(!values_eq(field_value, condition_value)?),
        Operator::Contains => contains_value(field_value, condition_value),
        Operator::NotContains => Ok(!contains_value(field_value, condition_value)?),
        Operator::StartsWith => str_binop(field_value, condition_value, |h, n| h.starts_with(n)),
        Operator::EndsWith => str_binop(field_value, condition_value, |h, n| h.ends_with(n)),
        Operator::In => in_set(field_value, condition_value),
        Operator::NotIn => Ok(!in_set(field_value, condition_value)?),
        Operator::Gt => {
            Ok(compare_values(field_value, condition_value)? == std::cmp::Ordering::Greater)
        }
        Operator::Lt => {
            Ok(compare_values(field_value, condition_value)? == std::cmp::Ordering::Less)
        }
        Operator::Gte => Ok(matches!(
            compare_values(field_value, condition_value)?,
            std::cmp::Ordering::Greater | std::cmp::Ordering::Equal
        )),
        Operator::Lte => Ok(matches!(
            compare_values(field_value, condition_value)?,
            std::cmp::Ordering::Less | std::cmp::Ordering::Equal
        )),
        Operator::Regex | Operator::NotRegex => {
            // Regex in sequence steps: bounded, no backtracking.
            let (haystack, pattern) = match (field_value, condition_value) {
                (Value::String(h), Value::String(p)) => (h.as_str(), p.as_str()),
                _ => {
                    return Err(RuleError::IncompatibleTypes(
                        "regex requires string operands".to_string(),
                    ))
                }
            };
            let re = regex::Regex::new(pattern)
                .map_err(|e| RuleError::InvalidRegex(format!("'{pattern}': {e}")))?;
            let matched = re.is_match(haystack);
            Ok(if matches!(operator, Operator::NotRegex) {
                !matched
            } else {
                matched
            })
        }
    }
}

/// Equality without coercion.
fn values_eq(a: &Value, b: &Value) -> Result<bool> {
    match (a, b) {
        (Value::String(x), Value::String(y)) => Ok(x == y),
        (Value::Boolean(x), Value::Boolean(y)) => Ok(x == y),
        (Value::Integer(x), Value::Integer(y)) => Ok(x == y),
        (Value::Float(x), Value::Float(y)) => Ok(x == y),
        (Value::Integer(x), Value::Float(y)) => Ok((*x as f64) == *y),
        (Value::Float(x), Value::Integer(y)) => Ok(*x == (*y as f64)),
        _ => Err(RuleError::IncompatibleTypes(format!(
            "cannot compare {:?} with {:?} for equality",
            a, b
        ))),
    }
}

/// Numeric comparison without coercion.
fn compare_values(a: &Value, b: &Value) -> Result<std::cmp::Ordering> {
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => Ok(x.cmp(y)),
        (Value::Float(x), Value::Float(y)) => x
            .partial_cmp(y)
            .ok_or_else(|| RuleError::IncompatibleTypes("cannot order NaN".to_string())),
        (Value::Integer(x), Value::Float(y)) => (*x as f64)
            .partial_cmp(y)
            .ok_or_else(|| RuleError::IncompatibleTypes("cannot order NaN".to_string())),
        (Value::Float(x), Value::Integer(y)) => x
            .partial_cmp(&(*y as f64))
            .ok_or_else(|| RuleError::IncompatibleTypes("cannot order NaN".to_string())),
        _ => Err(RuleError::IncompatibleTypes(
            "ordering requires numeric operands".to_string(),
        )),
    }
}

/// Substring containment for strings.
fn contains_value(field_value: &Value, condition_value: &Value) -> Result<bool> {
    match (field_value, condition_value) {
        (Value::String(haystack), Value::String(needle)) => Ok(haystack.contains(needle.as_str())),
        _ => Err(RuleError::IncompatibleTypes(
            "contains requires string operands".to_string(),
        )),
    }
}

/// Binary string operation.
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

/// Set membership.
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

/// Build a [`SequenceMatch`] from a key and instance.
pub(crate) fn build_match(key: &SequenceKey, instance: &SequenceInstance) -> SequenceMatch {
    SequenceMatch {
        sequence_name: key.sequence_name.clone(),
        group_key: key.group_key.clone(),
        steps: instance.steps.clone(),
        completed: instance.completed,
        uncertain: instance.uncertain,
    }
}
