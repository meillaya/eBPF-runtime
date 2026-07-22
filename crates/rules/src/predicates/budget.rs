// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The rule-evaluation resource budget.
//!
//! [`RuleBudget`] names every bound the predicate evaluator enforces. The
//! defaults match `bench/schemas/rule-budget.v1.json` (the single source of
//! truth for these constants); [`load_budget_from_schema`] reads the `default`
//! of each schema property so a deployment can re-tune the budget without
//! recompiling. No bound is hardcoded at a call site — every limit flows from
//! this struct.

use std::path::Path;

use super::error::Result;

/// The per-evaluation resource budget for bounded, deterministic evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleBudget {
    /// Maximum predicate operations (leaf evaluations) per evaluation.
    pub max_ops_per_evaluation: usize,
    /// Maximum AND/OR/NOT nesting depth.
    pub max_nested_expressions: usize,
    /// Maximum items in a reusable immutable list.
    pub max_list_items: usize,
    /// Maximum characters in a regex pattern.
    pub max_regex_chars: usize,
    /// Maximum wall-clock milliseconds for a single regex match.
    pub max_regex_time_ms: u64,
    /// Maximum items in a scoped exception value array.
    pub max_exception_items: usize,
    /// Maximum ordered steps in a temporal sequence.
    pub max_sequence_steps: usize,
    /// Maximum correlation window in seconds for a temporal sequence.
    pub max_sequence_window_seconds: u64,
}

/// The default budget, mirroring `bench/schemas/rule-budget.v1.json` defaults:
/// 1024 ops, 16 nested expressions, 64 list items, 256 regex chars, 10 ms regex
/// time, 64 exception items, 16 sequence steps, 3600 s sequence window.
pub fn default_budget() -> RuleBudget {
    RuleBudget {
        max_ops_per_evaluation: 1024,
        max_nested_expressions: 16,
        max_list_items: 64,
        max_regex_chars: 256,
        max_regex_time_ms: 10,
        max_exception_items: 64,
        max_sequence_steps: 16,
        max_sequence_window_seconds: 3600,
    }
}

/// Load a budget from a `rule-budget.v1.json` schema file by reading the
/// `default` of each property. Missing properties fall back to
/// [`default_budget`], so a partial schema still yields a complete budget.
pub fn load_budget_from_schema(path: &Path) -> Result<RuleBudget> {
    let raw = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&raw)?;
    let props = &json["properties"];
    let mut b = default_budget();
    b.max_ops_per_evaluation = read_usize(props, "max_ops_per_evaluation", b.max_ops_per_evaluation);
    b.max_nested_expressions = read_usize(props, "max_nested_expressions", b.max_nested_expressions);
    b.max_list_items = read_usize(props, "max_list_items", b.max_list_items);
    b.max_regex_chars = read_usize(props, "max_regex_chars", b.max_regex_chars);
    b.max_regex_time_ms = read_u64(props, "max_regex_time_ms", b.max_regex_time_ms);
    b.max_exception_items = read_usize(props, "max_exception_items", b.max_exception_items);
    b.max_sequence_steps = read_usize(props, "max_sequence_steps", b.max_sequence_steps);
    b.max_sequence_window_seconds =
        read_u64(props, "max_sequence_window_seconds", b.max_sequence_window_seconds);
    Ok(b)
}

/// Read `properties[key].default` as a `usize`, falling back when absent.
fn read_usize(props: &serde_json::Value, key: &str, fallback: usize) -> usize {
    props
        .get(key)
        .and_then(|p| p.get("default"))
        .and_then(serde_json::Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(fallback)
}

/// Read `properties[key].default` as a `u64`, falling back when absent.
fn read_u64(props: &serde_json::Value, key: &str, fallback: u64) -> u64 {
    props
        .get(key)
        .and_then(|p| p.get("default"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_budget_matches_schema_defaults() {
        let b = default_budget();
        assert_eq!(b.max_ops_per_evaluation, 1024);
        assert_eq!(b.max_nested_expressions, 16);
        assert_eq!(b.max_list_items, 64);
        assert_eq!(b.max_regex_chars, 256);
        assert_eq!(b.max_regex_time_ms, 10);
        assert_eq!(b.max_exception_items, 64);
        assert_eq!(b.max_sequence_steps, 16);
        assert_eq!(b.max_sequence_window_seconds, 3600);
    }
}
