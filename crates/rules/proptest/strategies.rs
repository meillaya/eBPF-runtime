// proptest/strategies.rs: rules
//
// proptest strategies for the rules property tests (task: fuzz & property-test
// parser boundaries). Two families:
//   * `arb_condition` / `arb_event`: arbitrary (bounded-depth) conditions and
//     typed events for the predicate-evaluation DETERMINISM property. Field
//     names mix catalog-known and unknown names so the evaluator's typed
//     null/unknown handling and incompatible-type errors are exercised.
//   * `arb_valid_ruleset`: rule sets that are guaranteed to pass the semantic
//     validator (kernel-observable `file.path` `eq` string, `alert` action,
//     compatible engine version, unique ids) for the serialize/parse ROUNDTRIP
//     property.
//
// This file defines strategies only (no `#[test]`); the `proptest!` blocks live
// in `determinism.rs`. Both are wired into the integration test binary by
// `tests/proptest.rs` via `#[path]`.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use proptest::prelude::*;

use rules::predicates::Event;
use rules::{
    Action, Condition, Operator, Rule, RuleSet, Severity, Source, Value, CURRENT_ENGINE_VERSION,
};

/// All comparison operators (mirrors `rules::Operator`).
const OPERATORS: &[Operator] = &[
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
];

/// Field names: a mix of catalog-known and deliberately-unknown names so the
/// evaluator's unknown-field (non-match) path is exercised alongside matches.
const FIELD_NAMES: &[&str] = &[
    "process.pid",
    "process.exec_path",
    "file.path",
    "file.kind",
    "network.dst_port",
    "unknown.field",
    "enrichment.cluster",
];

/// Arbitrary typed match value (strings, ints, bools, small finite floats, and
/// shallow string arrays for the `in`/`not_in` operators).
pub fn arb_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        "[a-z/._]{0,12}".prop_map(Value::String),
        any::<i64>().prop_map(Value::Integer),
        any::<bool>().prop_map(Value::Boolean),
        (0i64..10_000).prop_map(|i| Value::Float(f64::from(i as i32))),
        prop::collection::vec("[a-z]{0,4}", 0..4)
            .prop_map(|v| Value::Array(v.into_iter().map(Value::String).collect())),
    ]
}

fn arb_field_name() -> impl Strategy<Value = String> {
    prop::sample::select(FIELD_NAMES).prop_map(str::to_string)
}

fn arb_operator() -> impl Strategy<Value = Operator> {
    prop::sample::select(OPERATORS)
}

fn arb_severity() -> impl Strategy<Value = Severity> {
    prop::sample::select(vec![
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ])
}

/// Arbitrary condition with bounded nesting (depth <= 4, well under the
/// anchored max_nesting_depth of 16) so the determinism property exercises
/// evaluation rather than always hitting the NestingTooDeep guard.
pub fn arb_condition() -> impl Strategy<Value = Condition> {
    let leaf =
        (arb_field_name(), arb_operator(), arb_value()).prop_map(|(field, operator, value)| {
            Condition::Field {
                field,
                operator,
                value,
            }
        });
    leaf.prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Condition::And),
            prop::collection::vec(inner.clone(), 0..4).prop_map(Condition::Or),
            inner.prop_map(|c| Condition::Not(Box::new(c))),
        ]
    })
}

/// Arbitrary typed event: a small set of present field values. Unknown fields
/// (referenced by a condition but absent here) resolve to non-match.
pub fn arb_event() -> impl Strategy<Value = Event> {
    prop::collection::vec((arb_field_name(), arb_value()), 0..6).prop_map(|pairs| {
        let mut event = Event::new();
        for (name, value) in pairs {
            event = event.with_field(name, value);
        }
        event
    })
}

/// A rule set guaranteed to pass the semantic validator: kernel-observable
/// `file.path` `eq` string condition, `alert` action, compatible engine
/// version, and unique rule ids (rewritten positionally to avoid duplicates).
pub fn arb_valid_ruleset() -> impl Strategy<Value = RuleSet> {
    let rule =
        ("[a-z]{1,8}", "[a-z/]{1,12}", arb_severity()).prop_map(|(id_suffix, path, severity)| {
            Rule {
                id: format!("rule-{id_suffix}"),
                version: 1,
                severity,
                tags: vec![],
                source: Source::File,
                description: format!("detect access to {path} ({id_suffix})"),
                condition: Condition::Field {
                    field: "file.path".into(),
                    operator: Operator::Eq,
                    value: Value::String(format!("/{path}")),
                },
                action: Action::Alert,
                exceptions: vec![],
                lists: vec![],
                sequences: vec![],
            }
        });
    prop::collection::vec(rule, 0..4).prop_map(|mut rules| {
        // Force unique, stable ids so re-parse never hits DuplicateRuleId.
        for (i, r) in rules.iter_mut().enumerate() {
            r.id = format!("rule-{i}");
        }
        RuleSet {
            schema_version: 1,
            engine_version: CURRENT_ENGINE_VERSION.to_string(),
            rules,
        }
    })
}

/// Arbitrary input string for parse-determinism: arbitrary bytes (including
/// newlines / non-YAML / hostile UTF-8) rendered lossily, so the parser's
/// YAML-injection and malformed-input paths are exercised.
pub fn arb_input_string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 0..256)
        .prop_map(|b| String::from_utf8_lossy(&b).into_owned())
}
