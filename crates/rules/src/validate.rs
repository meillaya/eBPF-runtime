// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Semantic validation: the rules the JSON Schema cannot express.
//!
//! Runs after structural validation. Enforces: schema/engine version
//! compatibility, unique rule ids, condition nesting depth, event-field catalog
//! membership, operator/field-type compatibility, value typing, bounded regex,
//! and the deny-only-on-kernel-observable-field rule. List/sequence name
//! uniqueness and list recursion live in [`crate::lists`].

use std::collections::HashSet;

use crate::ast::{Action, Condition, Operator, Rule, RuleSet, Value};
use crate::error::{Result, RuleError};
use crate::fields::{default_field_catalog, FieldCatalog, FieldType};
use crate::version::{is_engine_compatible, CURRENT_ENGINE_VERSION, SUPPORTED_SCHEMA_VERSION};

/// Maximum condition nesting depth (mirrors the rule-evaluation budget).
pub const MAX_CONDITION_DEPTH: usize = 16;

/// Validate an entire rule set semantically.
pub fn validate_ruleset(ruleset: &RuleSet) -> Result<()> {
    if ruleset.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(RuleError::SchemaVersionMismatch(ruleset.schema_version));
    }
    if !is_engine_compatible(&ruleset.engine_version) {
        return Err(RuleError::EngineVersionMismatch(format!(
            "engine_version '{}' is not compatible with engine {CURRENT_ENGINE_VERSION} (same major version and not newer required)",
            ruleset.engine_version
        )));
    }
    let catalog = default_field_catalog();
    check_unique_rule_ids(ruleset)?;
    for (i, rule) in ruleset.rules.iter().enumerate() {
        validate_rule(rule, &catalog, &format!("rules[{i}]"))?;
    }
    crate::lists::check_list_names_unique(ruleset)?;
    crate::lists::check_sequence_names_unique(ruleset)?;
    crate::lists::check_list_recursion(ruleset)?;
    Ok(())
}

fn check_unique_rule_ids(ruleset: &RuleSet) -> Result<()> {
    let mut seen = HashSet::new();
    for rule in &ruleset.rules {
        if !seen.insert(rule.id.as_str()) {
            return Err(RuleError::DuplicateRuleId(rule.id.clone()));
        }
    }
    Ok(())
}

fn validate_rule(rule: &Rule, catalog: &FieldCatalog, path: &str) -> Result<()> {
    let depth = condition_depth(&rule.condition);
    if depth > MAX_CONDITION_DEPTH {
        return Err(RuleError::SchemaValidationError(format!(
            "{path}.condition: nesting depth {depth} exceeds maximum {MAX_CONDITION_DEPTH}"
        )));
    }
    let deny = rule.action == Action::Deny;
    validate_condition(&rule.condition, catalog, deny, &format!("{path}.condition"))?;
    for (i, exc) in rule.exceptions.iter().enumerate() {
        validate_field_match(
            &exc.field,
            exc.operator,
            &exc.value,
            catalog,
            false,
            &format!("{path}.exceptions[{i}]"),
        )?;
    }
    for (i, seq) in rule.sequences.iter().enumerate() {
        for (j, step) in seq.steps.iter().enumerate() {
            validate_field_match(
                &step.field,
                step.operator,
                &step.value,
                catalog,
                false,
                &format!("{path}.sequences[{i}].steps[{j}]"),
            )?;
        }
    }
    Ok(())
}

fn validate_condition(
    cond: &Condition,
    catalog: &FieldCatalog,
    deny: bool,
    path: &str,
) -> Result<()> {
    match cond {
        Condition::Field {
            field,
            operator,
            value,
        } => validate_field_match(field, *operator, value, catalog, deny, path),
        Condition::And(children) => {
            for (i, child) in children.iter().enumerate() {
                validate_condition(child, catalog, deny, &format!("{path}.and[{i}]"))?;
            }
            Ok(())
        }
        Condition::Or(children) => {
            for (i, child) in children.iter().enumerate() {
                validate_condition(child, catalog, deny, &format!("{path}.or[{i}]"))?;
            }
            Ok(())
        }
        Condition::Not(child) => validate_condition(child, catalog, deny, &format!("{path}.not")),
    }
}

/// Validate one field/operator/value match against the catalog.
///
/// When `deny` is set, the field must additionally be kernel-observable: a deny
/// may never rest on enrichment-only / heuristic data.
fn validate_field_match(
    field: &str,
    operator: Operator,
    value: &Value,
    catalog: &FieldCatalog,
    deny: bool,
    path: &str,
) -> Result<()> {
    let def = catalog.get(field).ok_or_else(|| {
        RuleError::InvalidField(format!("{path}: '{field}' is not a known event field"))
    })?;
    if !operator_valid_for_type(operator, def.field_type) {
        return Err(RuleError::InvalidOperator(format!(
            "{path}: operator {operator:?} is not valid for field '{field}' of type {:?}",
            def.field_type
        )));
    }
    if !value_valid_for(operator, value, def.field_type) {
        return Err(RuleError::InvalidOperator(format!(
            "{path}: value type does not match field '{field}' for operator {operator:?}"
        )));
    }
    if matches!(operator, Operator::Regex | Operator::NotRegex) {
        let pattern = value.as_str().ok_or_else(|| {
            RuleError::InvalidOperator(format!("{path}: regex operator requires a string value"))
        })?;
        crate::regex_check::validate_regex(pattern, path)?;
    }
    if deny && !def.kernel_observable {
        return Err(RuleError::DenyOnHeuristicOnly(format!(
            "{path}: deny action references non-kernel-observable field '{field}'"
        )));
    }
    Ok(())
}

fn condition_depth(cond: &Condition) -> usize {
    match cond {
        Condition::Field { .. } => 1,
        Condition::Not(child) => 1 + condition_depth(child),
        Condition::And(children) | Condition::Or(children) => {
            1 + children.iter().map(condition_depth).max().unwrap_or(0)
        }
    }
}

/// Whether `operator` may be applied to a field of type `ft`.
pub fn operator_valid_for_type(operator: Operator, ft: FieldType) -> bool {
    use Operator as Op;
    match ft {
        FieldType::String => matches!(
            operator,
            Op::Eq
                | Op::Ne
                | Op::In
                | Op::NotIn
                | Op::Contains
                | Op::NotContains
                | Op::StartsWith
                | Op::EndsWith
                | Op::Regex
                | Op::NotRegex
        ),
        FieldType::Integer | FieldType::Float => {
            matches!(
                operator,
                Op::Eq | Op::Ne | Op::Gt | Op::Lt | Op::Gte | Op::Lte | Op::In | Op::NotIn
            )
        }
        FieldType::Boolean => matches!(operator, Op::Eq | Op::Ne),
        FieldType::Array => matches!(
            operator,
            Op::Contains | Op::NotContains | Op::In | Op::NotIn
        ),
    }
}

/// Whether `value`'s type matches `ft` for `operator` (no type coercion).
pub fn value_valid_for(operator: Operator, value: &Value, ft: FieldType) -> bool {
    match operator {
        Operator::In | Operator::NotIn => match value {
            Value::Array(items) => items.iter().all(|item| scalar_matches(item, ft)),
            _ => false,
        },
        _ => scalar_matches(value, ft),
    }
}

fn scalar_matches(value: &Value, ft: FieldType) -> bool {
    match ft {
        FieldType::String => matches!(value, Value::String(_)),
        FieldType::Integer => matches!(value, Value::Integer(_)),
        FieldType::Float => matches!(value, Value::Float(_) | Value::Integer(_)),
        FieldType::Boolean => matches!(value, Value::Boolean(_)),
        FieldType::Array => matches!(value, Value::String(_)),
    }
}
