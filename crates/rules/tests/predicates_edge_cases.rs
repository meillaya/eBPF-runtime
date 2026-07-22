// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Edge-case acceptance tests for bounded predicate evaluation.
//!
//! Covers empty/null/unicode/special inputs, deep and wide conditions,
//! recursive lists and runaway exceptions, overlapping/contradictory/
//! tautological/impossible conditions, and boundary/overflow/negative/float
//! values.

use rules::predicates::{default_budget, Event, PredicateEvaluator, RuleError};
use rules::{Condition, Exception, List, Operator, Sequence, Step, Value};

fn ev() -> PredicateEvaluator {
    PredicateEvaluator::new(default_budget())
}

fn field(field: &str, operator: Operator, value: Value) -> Condition {
    Condition::Field {
        field: field.to_string(),
        operator,
        value,
    }
}

fn s(value: &str) -> Value {
    Value::String(value.to_string())
}

fn i(value: i64) -> Value {
    Value::Integer(value)
}

fn step() -> Step {
    Step {
        field: "process.exec_path".to_string(),
        operator: Operator::Eq,
        value: s("/bin/sh"),
    }
}

#[test]
fn evaluate_empty_condition_succeeds() {
    // An empty AND is vacuously true and never errors.
    let result = ev()
        .evaluate_condition(&Condition::And(vec![]), &Event::new(), &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_empty_list_returns_false() {
    let list = List {
        name: "empty".to_string(),
        items: vec![],
    };
    assert!(!ev().evaluate_list(&list, &s("/etc")).unwrap());
}

#[test]
fn evaluate_empty_exception_returns_false() {
    let exception = Exception {
        field: "file.path".to_string(),
        operator: Operator::In,
        value: Value::Array(vec![]),
    };
    let event = Event::new().with_field("file.path", s("/etc"));
    assert!(!ev().evaluate_exception(&exception, &event).unwrap());
}

#[test]
fn evaluate_empty_regex_fails() {
    assert!(matches!(
        ev().evaluate_regex("", "anything"),
        Err(RuleError::InvalidRegex(_))
    ));
}

#[test]
fn evaluate_empty_value_succeeds() {
    let event = Event::new().with_field("file.path", s(""));
    let result = ev()
        .evaluate_condition(&field("file.path", Operator::Eq, s("")), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_null_value_returns_false() {
    // A field explicitly marked null is a non-match (typed null handling).
    let event = Event::new().with_null("file.path");
    assert!(event.is_null("file.path"));
    let result = ev()
        .evaluate_condition(&field("file.path", Operator::Eq, s("/etc")), &event, &[])
        .unwrap();
    assert!(!result.matched);
}

#[test]
fn evaluate_unicode_value_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc/日本語"));
    let result = ev()
        .evaluate_condition(&field("file.path", Operator::Eq, s("/etc/日本語")), &event, &[])
        .unwrap();
    assert!(result.matched);
    // Regex char bound counts characters, not bytes.
    assert!(ev().evaluate_regex("日本語", "/etc/日本語").unwrap());
}

#[test]
fn evaluate_special_characters_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc/pa$$w0rd!@#"));
    let result = ev()
        .evaluate_condition(&field("file.path", Operator::Contains, s("$$w0rd")), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_deeply_nested_condition_fails() {
    // depth 17 (leaf + 16 NOTs) exceeds the default 16-depth budget.
    let mut cond = field("file.path", Operator::Eq, s("/etc"));
    for _ in 0..16 {
        cond = Condition::Not(Box::new(cond));
    }
    let event = Event::new().with_field("file.path", s("/etc"));
    let result = ev().evaluate_condition(&cond, &event, &[]);
    assert!(matches!(result, Err(RuleError::NestingTooDeep(_))));
}

#[test]
fn evaluate_wide_condition_fails() {
    // 1025 sibling leaves exceed the default 1024-op budget.
    let leaves: Vec<Condition> = (0..1025)
        .map(|n| field("process.pid", Operator::Eq, i(n)))
        .collect();
    let cond = Condition::And(leaves);
    let event = Event::new().with_field("process.pid", i(1));
    let result = ev().evaluate_condition(&cond, &event, &[]);
    assert!(matches!(result, Err(RuleError::TooManyOps(_))));
}

#[test]
fn evaluate_recursive_list_fails() {
    // A self-referencing list is rejected before evaluation (parse-time guard),
    // so a recursive list can never reach the evaluator.
    let doc = "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: r\n    version: 1\n    severity: low\n    source: file\n    description: d\n    condition:\n      field: file.path\n      operator: eq\n      value: /x\n    action: alert\n    lists:\n      - name: a\n        items: [\"a\"]\n";
    assert!(matches!(
        rules::parse_ruleset(doc),
        Err(rules::RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn evaluate_circular_exception_fails() {
    // A runaway/circular exception value (more items than the budget) is
    // rejected, so an exception can never grow past max_exception_items.
    let items: Vec<Value> = (0..65).map(|n| Value::String(format!("v{n}"))).collect();
    let exception = Exception {
        field: "file.path".to_string(),
        operator: Operator::In,
        value: Value::Array(items),
    };
    let event = Event::new().with_field("file.path", s("v0"));
    let result = ev().evaluate_exception(&exception, &event);
    assert!(matches!(result, Err(RuleError::TooManyExceptionItems(_))));
}

#[test]
fn evaluate_overlapping_conditions_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc/passwd"));
    let cond = Condition::Or(vec![
        field("file.path", Operator::StartsWith, s("/etc")),
        field("file.path", Operator::Contains, s("passwd")),
    ]);
    let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert!(result.matched);
    assert_eq!(result.explanation.children.len(), 2);
    assert!(result.explanation.children.iter().all(|c| c.matched));
}

#[test]
fn evaluate_contradictory_conditions_returns_false() {
    let event = Event::new().with_field("file.path", s("/etc"));
    let cond = Condition::And(vec![
        field("file.path", Operator::Eq, s("/etc")),
        field("file.path", Operator::Eq, s("/var")),
    ]);
    let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert!(!result.matched);
}

#[test]
fn evaluate_tautological_condition_returns_true() {
    let event = Event::new().with_field("file.path", s("/etc"));
    let cond = Condition::Or(vec![
        field("file.path", Operator::Eq, s("/etc")),
        field("file.path", Operator::Ne, s("/etc")),
    ]);
    let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_impossible_condition_returns_false() {
    let event = Event::new().with_field("process.pid", i(75));
    let cond = Condition::And(vec![
        field("process.pid", Operator::Gt, i(100)),
        field("process.pid", Operator::Lt, i(50)),
    ]);
    let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert!(!result.matched);
}

#[test]
fn evaluate_boundary_values_succeeds() {
    assert!(ev()
        .evaluate_predicate(&Operator::Gt, &i(i64::MAX), &i(i64::MAX - 1))
        .unwrap());
    assert!(ev()
        .evaluate_predicate(&Operator::Lt, &i(i64::MIN), &i(i64::MIN + 1))
        .unwrap());
    assert!(ev()
        .evaluate_predicate(&Operator::Eq, &i(i64::MIN), &i(i64::MIN))
        .unwrap());
    // A regex pattern at exactly the char bound is accepted (not too large).
    let bound = default_budget().max_regex_chars;
    let pattern = "a".repeat(bound);
    let haystack = "a".repeat(bound);
    assert!(ev().evaluate_regex(&pattern, &haystack).unwrap());
}

#[test]
fn evaluate_overflow_values_fails() {
    // Each value is exactly one past a budget bound.
    let pattern = "a".repeat(default_budget().max_regex_chars + 1);
    assert!(matches!(
        ev().evaluate_regex(&pattern, "a"),
        Err(RuleError::RegexTooLarge(_))
    ));
    let list = List {
        name: "l".to_string(),
        items: (0..=default_budget().max_list_items)
            .map(|n| format!("v{n}"))
            .collect(),
    };
    assert!(matches!(
        ev().evaluate_list(&list, &s("v0")),
        Err(RuleError::TooManyListItems(_))
    ));
    let sequence = Sequence {
        name: "s".to_string(),
        steps: vec![step()],
        window_seconds: u32::MAX,
    };
    assert!(matches!(
        ev().validate_sequence(&sequence),
        Err(RuleError::SequenceWindowTooLarge(_))
    ));
}

#[test]
fn evaluate_negative_values_succeeds() {
    assert!(ev().evaluate_predicate(&Operator::Lt, &i(-5), &i(0)).unwrap());
    assert!(ev().evaluate_predicate(&Operator::Eq, &i(-5), &i(-5)).unwrap());
    assert!(ev().evaluate_predicate(&Operator::Gt, &i(-5), &i(-10)).unwrap());
}

#[test]
fn evaluate_float_values_succeeds() {
    assert!(ev()
        .evaluate_predicate(&Operator::Gt, &Value::Float(2.5), &Value::Float(1.5))
        .unwrap());
    assert!(ev()
        .evaluate_predicate(&Operator::Lt, &Value::Float(1.5), &Value::Float(2.5))
        .unwrap());
    // Integer and float are compatible numerics (not a coercion of incompatible
    // types): 2.0 == 2.
    assert!(ev()
        .evaluate_predicate(&Operator::Eq, &Value::Float(2.0), &i(2))
        .unwrap());
}
