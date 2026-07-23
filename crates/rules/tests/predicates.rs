// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side acceptance tests for bounded, deterministic predicate evaluation.
//!
//! Covers every predicate operator, AND/OR/NOT composition, list membership,
//! scoped exceptions, bounded regex, the complexity/depth budgets, determinism,
//! match-explanation correctness, immutability, and the property invariants
//! (deterministic results, unknown-never-true, no coercion, no mutation, no
//! unbounded regex).

use proptest::prelude::*;

use rules::predicates::{
    default_budget, parse_operator, Event, PredicateEvaluator, RuleBudget, RuleError,
};
use rules::{Condition, Exception, List, Operator, Sequence, Step, Value};

fn ev() -> PredicateEvaluator {
    PredicateEvaluator::new(default_budget())
}

fn ev_with(budget: RuleBudget) -> PredicateEvaluator {
    PredicateEvaluator::new(budget)
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

// ---------------------------------------------------------------------------
// Predicate operators
// ---------------------------------------------------------------------------

#[test]
fn evaluate_eq_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc"));
    let result = ev()
        .evaluate_condition(&field("file.path", Operator::Eq, s("/etc")), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_ne_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc"));
    let result = ev()
        .evaluate_condition(&field("file.path", Operator::Ne, s("/var")), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_gt_predicate_succeeds() {
    let event = Event::new().with_field("process.pid", i(200));
    let result = ev()
        .evaluate_condition(&field("process.pid", Operator::Gt, i(100)), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_lt_predicate_succeeds() {
    let event = Event::new().with_field("process.pid", i(50));
    let result = ev()
        .evaluate_condition(&field("process.pid", Operator::Lt, i(100)), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_gte_predicate_succeeds() {
    let event = Event::new().with_field("process.pid", i(100));
    let result = ev()
        .evaluate_condition(&field("process.pid", Operator::Gte, i(100)), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_lte_predicate_succeeds() {
    let event = Event::new().with_field("process.pid", i(100));
    let result = ev()
        .evaluate_condition(&field("process.pid", Operator::Lte, i(100)), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_in_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc"));
    let value = Value::Array(vec![s("/etc"), s("/var")]);
    let result = ev()
        .evaluate_condition(&field("file.path", Operator::In, value), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_not_in_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/tmp"));
    let value = Value::Array(vec![s("/etc"), s("/var")]);
    let result = ev()
        .evaluate_condition(&field("file.path", Operator::NotIn, value), &event, &[])
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_contains_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc/passwd"));
    let result = ev()
        .evaluate_condition(
            &field("file.path", Operator::Contains, s("/etc")),
            &event,
            &[],
        )
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_not_contains_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc/passwd"));
    let result = ev()
        .evaluate_condition(
            &field("file.path", Operator::NotContains, s("/var")),
            &event,
            &[],
        )
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_starts_with_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc/passwd"));
    let result = ev()
        .evaluate_condition(
            &field("file.path", Operator::StartsWith, s("/etc")),
            &event,
            &[],
        )
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_ends_with_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc/passwd"));
    let result = ev()
        .evaluate_condition(
            &field("file.path", Operator::EndsWith, s("passwd")),
            &event,
            &[],
        )
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_regex_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc/passwd"));
    let result = ev()
        .evaluate_condition(
            &field("file.path", Operator::Regex, s("^/etc/.*$")),
            &event,
            &[],
        )
        .unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_not_regex_predicate_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc/passwd"));
    let result = ev()
        .evaluate_condition(
            &field("file.path", Operator::NotRegex, s("^/var/.*$")),
            &event,
            &[],
        )
        .unwrap();
    assert!(result.matched);
}

// ---------------------------------------------------------------------------
// Condition composition
// ---------------------------------------------------------------------------

#[test]
fn evaluate_and_condition_succeeds() {
    let event = Event::new()
        .with_field("file.path", s("/etc/passwd"))
        .with_field("process.pid", i(200));
    let cond = Condition::And(vec![
        field("file.path", Operator::StartsWith, s("/etc")),
        field("process.pid", Operator::Gt, i(100)),
    ]);
    let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_or_condition_succeeds() {
    let event = Event::new()
        .with_field("file.path", s("/tmp/x"))
        .with_field("process.pid", i(200));
    let cond = Condition::Or(vec![
        field("file.path", Operator::Eq, s("/etc")),
        field("process.pid", Operator::Gt, i(100)),
    ]);
    let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_not_condition_succeeds() {
    let event = Event::new().with_field("file.path", s("/etc"));
    let cond = Condition::Not(Box::new(field("file.path", Operator::Eq, s("/var"))));
    let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert!(result.matched);
}

#[test]
fn evaluate_nested_condition_succeeds() {
    let event = Event::new()
        .with_field("file.path", s("/etc/passwd"))
        .with_field("process.exec_path", s("/usr/bin/cat"));
    let cond = Condition::And(vec![
        Condition::Or(vec![
            field("file.path", Operator::StartsWith, s("/etc")),
            field("file.path", Operator::StartsWith, s("/var")),
        ]),
        Condition::Not(Box::new(field(
            "process.exec_path",
            Operator::Eq,
            s("/usr/bin/dpkg"),
        ))),
    ]);
    let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert!(result.matched);
}

// ---------------------------------------------------------------------------
// Lists, exceptions, regex
// ---------------------------------------------------------------------------

#[test]
fn evaluate_list_membership_succeeds() {
    let list = List {
        name: "sensitive_paths".to_string(),
        items: vec!["/etc/shadow".to_string(), "/etc/passwd".to_string()],
    };
    assert!(ev().evaluate_list(&list, &s("/etc/passwd")).unwrap());
    assert!(!ev().evaluate_list(&list, &s("/tmp/x")).unwrap());
}

#[test]
fn evaluate_exception_succeeds() {
    let exception = Exception {
        field: "process.exec_path".to_string(),
        operator: Operator::Eq,
        value: s("/usr/bin/dpkg"),
    };
    let event = Event::new().with_field("process.exec_path", s("/usr/bin/dpkg"));
    assert!(ev().evaluate_exception(&exception, &event).unwrap());
    let other = Event::new().with_field("process.exec_path", s("/bin/sh"));
    assert!(!ev().evaluate_exception(&exception, &other).unwrap());
}

#[test]
fn evaluate_regex_match_succeeds() {
    assert!(ev().evaluate_regex("^proc[0-9]+$", "proc123").unwrap());
    assert!(!ev().evaluate_regex("^proc[0-9]+$", "process").unwrap());
}

// ---------------------------------------------------------------------------
// Type safety, unknown handling, operator validation
// ---------------------------------------------------------------------------

#[test]
fn evaluate_incompatible_types_fails() {
    let result = ev().evaluate_predicate(&Operator::Eq, &s("/etc"), &i(5));
    assert!(matches!(result, Err(RuleError::IncompatibleTypes(_))));
}

#[test]
fn evaluate_unknown_field_returns_false() {
    let event = Event::new(); // process.pid is unknown
    let result = ev()
        .evaluate_condition(&field("process.pid", Operator::Eq, i(1)), &event, &[])
        .unwrap();
    assert!(!result.matched);
}

#[test]
fn evaluate_unknown_operator_fails() {
    assert!(matches!(
        parse_operator("xor"),
        Err(RuleError::UnknownOperator(_))
    ));
    // every known operator name parses
    for name in [
        "eq",
        "ne",
        "gt",
        "lt",
        "gte",
        "lte",
        "in",
        "not_in",
        "contains",
        "not_contains",
        "starts_with",
        "ends_with",
        "regex",
        "not_regex",
    ] {
        assert!(parse_operator(name).is_ok(), "{name} should parse");
    }
}

// ---------------------------------------------------------------------------
// Bounded regex
// ---------------------------------------------------------------------------

#[test]
fn evaluate_invalid_regex_fails() {
    assert!(matches!(
        ev().evaluate_regex("[unclosed", "x"),
        Err(RuleError::InvalidRegex(_))
    ));
}

#[test]
fn evaluate_regex_too_large_fails() {
    let pattern = "a".repeat(300); // > 256-char bound
    assert!(matches!(
        ev().evaluate_regex(&pattern, "a"),
        Err(RuleError::RegexTooLarge(_))
    ));
}

#[test]
fn evaluate_regex_too_complex_fails() {
    let too_many_groups = "(a)".repeat(65); // > 64 capture groups
    assert!(matches!(
        ev().evaluate_regex(&too_many_groups, "a"),
        Err(RuleError::RegexTooComplex(_))
    ));
    let nested = "(a+)+b"; // catastrophic-backtracking shape
    assert!(matches!(
        ev().evaluate_regex(nested, "aaaaab"),
        Err(RuleError::RegexTooComplex(_))
    ));
}

#[test]
fn evaluate_regex_too_slow_fails() {
    // A zero-millisecond budget rejects any match that takes measurable time.
    let budget = RuleBudget {
        max_regex_time_ms: 0,
        ..default_budget()
    };
    let haystack = "a".repeat(8 * 1024 * 1024);
    let result = ev_with(budget).evaluate_regex("a*b", &haystack);
    assert!(matches!(result, Err(RuleError::RegexTooSlow(_))));
}

// ---------------------------------------------------------------------------
// Complexity / depth budgets
// ---------------------------------------------------------------------------

#[test]
fn evaluate_nesting_too_deep_fails() {
    let budget = RuleBudget {
        max_nested_expressions: 3,
        ..default_budget()
    };
    // depth 5: Not(Not(Not(Not(leaf))))
    let mut cond = field("file.path", Operator::Eq, s("/etc"));
    for _ in 0..4 {
        cond = Condition::Not(Box::new(cond));
    }
    let event = Event::new().with_field("file.path", s("/etc"));
    let result = ev_with(budget).evaluate_condition(&cond, &event, &[]);
    assert!(matches!(result, Err(RuleError::NestingTooDeep(_))));
}

#[test]
fn evaluate_too_many_ops_fails() {
    let budget = RuleBudget {
        max_ops_per_evaluation: 3,
        ..default_budget()
    };
    let cond = Condition::And(vec![
        field("process.pid", Operator::Eq, i(1)),
        field("process.pid", Operator::Eq, i(2)),
        field("process.pid", Operator::Eq, i(3)),
        field("process.pid", Operator::Eq, i(4)),
    ]);
    let event = Event::new().with_field("process.pid", i(1));
    let result = ev_with(budget).evaluate_condition(&cond, &event, &[]);
    assert!(matches!(result, Err(RuleError::TooManyOps(_))));
}

#[test]
fn evaluate_too_many_list_items_fails() {
    let budget = RuleBudget {
        max_list_items: 2,
        ..default_budget()
    };
    let list = List {
        name: "l".to_string(),
        items: vec!["a".to_string(), "b".to_string(), "c".to_string()],
    };
    let result = ev_with(budget).evaluate_list(&list, &s("a"));
    assert!(matches!(result, Err(RuleError::TooManyListItems(_))));
}

#[test]
fn evaluate_too_many_exception_items_fails() {
    let budget = RuleBudget {
        max_exception_items: 2,
        ..default_budget()
    };
    let exception = Exception {
        field: "file.path".to_string(),
        operator: Operator::In,
        value: Value::Array(vec![s("/a"), s("/b"), s("/c")]),
    };
    let event = Event::new().with_field("file.path", s("/a"));
    let result = ev_with(budget).evaluate_exception(&exception, &event);
    assert!(matches!(result, Err(RuleError::TooManyExceptionItems(_))));
}

#[test]
fn evaluate_too_many_sequence_steps_fails() {
    let budget = RuleBudget {
        max_sequence_steps: 2,
        ..default_budget()
    };
    let sequence = Sequence {
        name: "s".to_string(),
        steps: vec![step(), step(), step()],
        window_seconds: 60,
    };
    let result = ev_with(budget).validate_sequence(&sequence);
    assert!(matches!(result, Err(RuleError::TooManySequenceSteps(_))));
}

#[test]
fn evaluate_sequence_window_too_large_fails() {
    let budget = RuleBudget {
        max_sequence_window_seconds: 60,
        ..default_budget()
    };
    let sequence = Sequence {
        name: "s".to_string(),
        steps: vec![step()],
        window_seconds: 120,
    };
    let result = ev_with(budget).validate_sequence(&sequence);
    assert!(matches!(result, Err(RuleError::SequenceWindowTooLarge(_))));
}

// ---------------------------------------------------------------------------
// Determinism, explanation, immutability, boundedness
// ---------------------------------------------------------------------------

#[test]
fn evaluate_deterministic_results() {
    let event = Event::new()
        .with_field("file.path", s("/etc/passwd"))
        .with_field("process.pid", i(200));
    let cond = Condition::And(vec![
        field("file.path", Operator::StartsWith, s("/etc")),
        Condition::Or(vec![
            field("process.pid", Operator::Gt, i(100)),
            field("process.pid", Operator::Lt, i(10)),
        ]),
    ]);
    let r1 = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    let r2 = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert_eq!(r1.matched, r2.matched);
    assert_eq!(r1.explanation, r2.explanation);
}

#[test]
fn evaluate_match_explanation_tree_correctness() {
    let event = Event::new()
        .with_field("file.path", s("/etc/passwd"))
        .with_field("process.pid", i(200));
    let cond = Condition::And(vec![
        field("file.path", Operator::StartsWith, s("/etc")),
        field("process.pid", Operator::Gt, i(100)),
    ]);
    let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
    assert!(result.matched);
    // Root is the AND composite with two leaf children, in order.
    assert_eq!(result.explanation.field, "and");
    assert!(result.explanation.matched);
    assert_eq!(result.explanation.children.len(), 2);
    let leaf0 = &result.explanation.children[0];
    assert_eq!(leaf0.field, "file.path");
    assert_eq!(leaf0.operator, Operator::StartsWith);
    assert_eq!(leaf0.value, s("/etc"));
    assert!(leaf0.matched);
    assert!(leaf0.children.is_empty());
    let leaf1 = &result.explanation.children[1];
    assert_eq!(leaf1.field, "process.pid");
    assert_eq!(leaf1.operator, Operator::Gt);
    assert!(leaf1.matched);
}

#[test]
fn evaluate_list_immutability() {
    let list = List {
        name: "l".to_string(),
        items: vec!["/etc".to_string(), "/var".to_string()],
    };
    let before = list.clone();
    let _ = ev().evaluate_list(&list, &s("/etc")).unwrap();
    let _ = ev().evaluate_list(&list, &s("/missing")).unwrap();
    assert_eq!(list, before); // shared definition never mutated
}

#[test]
fn evaluate_bounded_regex_timing() {
    // A normal bounded pattern completes well within the 10ms default budget.
    let start = std::time::Instant::now();
    let matched = ev().evaluate_regex("^/etc/.*$", "/etc/passwd").unwrap();
    assert!(matched);
    assert!(start.elapsed() < std::time::Duration::from_millis(10));
}

#[test]
fn evaluate_no_unbounded_allocation() {
    // A 2000-leaf condition exceeds the 1024-op budget and is rejected, so the
    // evaluator never builds explanations for more than the budget allows.
    let leaves: Vec<Condition> = (0..2000)
        .map(|n| field("process.pid", Operator::Eq, i(n)))
        .collect();
    let cond = Condition::And(leaves);
    let event = Event::new().with_field("process.pid", i(1));
    assert!(matches!(
        ev().evaluate_condition(&cond, &event, &[]),
        Err(RuleError::TooManyOps(_))
    ));
    // Within budget, evaluation succeeds.
    let leaves: Vec<Condition> = (0..100)
        .map(|n| field("process.pid", Operator::Eq, i(n)))
        .collect();
    let cond = Condition::And(leaves);
    assert!(ev().evaluate_condition(&cond, &event, &[]).is_ok());
}

#[test]
fn evaluate_no_backtracking() {
    // Catastrophic-backtracking shapes are rejected before any match, so the
    // evaluator never backtracks (the engine is linear-time regardless).
    let result = ev().evaluate_regex("(a+)+b", &"a".repeat(64));
    assert!(matches!(result, Err(RuleError::RegexTooComplex(_))));
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

fn arb_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i64>().prop_map(Value::Integer),
        "[a-z]{0,6}".prop_map(Value::String),
        any::<bool>().prop_map(Value::Boolean),
    ]
}

fn arb_op() -> impl Strategy<Value = Operator> {
    proptest::sample::select(vec![
        Operator::Eq,
        Operator::Ne,
        Operator::Gt,
        Operator::Lt,
        Operator::Gte,
        Operator::Lte,
        Operator::In,
        Operator::NotIn,
        Operator::Contains,
        Operator::NotContains,
        Operator::StartsWith,
        Operator::EndsWith,
        Operator::Regex,
        Operator::NotRegex,
    ])
}

proptest! {
    #[test]
    fn property_test_deterministic_evaluation(fv in "[a-z]{0,6}", cv in "[a-z]{0,6}") {
        let event = Event::new().with_field("file.path", Value::String(fv));
        let cond = field("file.path", Operator::Eq, Value::String(cv));
        let r1 = ev().evaluate_condition(&cond, &event, &[]).unwrap();
        let r2 = ev().evaluate_condition(&cond, &event, &[]).unwrap();
        prop_assert_eq!(r1.matched, r2.matched);
        prop_assert_eq!(r1.explanation, r2.explanation);
    }

    #[test]
    fn property_test_unknown_never_true(op in arb_op(), value in arb_value()) {
        // Every field is unknown in an empty event; a leaf predicate over an
        // unknown field is always a non-match, for any operator/value.
        let event = Event::new();
        let cond = field("file.path", op, value);
        let result = ev().evaluate_condition(&cond, &event, &[]).unwrap();
        prop_assert!(!result.matched);
    }

    #[test]
    fn property_test_incompatible_types_never_coerced(text in "[a-z]{1,6}", n in any::<i64>()) {
        let field_value = Value::String(text);
        let condition_value = Value::Integer(n);
        for op in [
            Operator::Eq, Operator::Ne, Operator::Gt, Operator::Lt, Operator::Gte,
            Operator::Lte, Operator::Contains, Operator::StartsWith, Operator::EndsWith,
            Operator::Regex,
        ] {
            let result = ev().evaluate_predicate(&op, &field_value, &condition_value);
            prop_assert!(!matches!(result, Ok(true)), "op coerced incompatible types");
        }
    }

    #[test]
    fn property_test_list_never_mutated(
        items in proptest::collection::vec("[a-z]{1,4}", 0..10),
        needle in "[a-z]{1,4}",
    ) {
        let list = List { name: "l".to_string(), items: items.clone() };
        let _ = ev().evaluate_list(&list, &Value::String(needle));
        prop_assert_eq!(&list.items, &items);
    }

    #[test]
    fn property_test_regex_never_unbounded(extra in 1usize..50) {
        let pattern = "a".repeat(default_budget().max_regex_chars + extra);
        let result = ev().evaluate_regex(&pattern, "aaa");
        prop_assert!(matches!(result, Err(RuleError::RegexTooLarge(_))));
    }
}
