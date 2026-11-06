// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Edge-case tests for bounded temporal sequence correlation.

use rules::ast::{Operator, Sequence, Step, Value};
use rules::predicates::{default_budget, Event};
use rules::sequences::{SequenceEvaluator, SequenceMatch};

/// Helper: create an event with a monotonic timestamp and fields.
fn ev(ts: i64, fields: &[(&str, Value)]) -> Event {
    let mut event = Event::new().with_field("ts", Value::Integer(ts));
    for (name, value) in fields {
        event = event.with_field(*name, value.clone());
    }
    event
}

/// Helper: create a sequence.
fn seq(name: &str, window: u32, steps: Vec<Step>) -> Sequence {
    Sequence {
        name: name.to_string(),
        steps,
        window_seconds: window,
    }
}

/// Helper: create a step.
fn step(field: &str, op: Operator, value: Value) -> Step {
    Step {
        field: field.to_string(),
        operator: op,
        value,
    }
}

/// Helper: count completed non-uncertain matches.
fn completed_count(matches: &[SequenceMatch]) -> usize {
    matches
        .iter()
        .filter(|m| m.completed && !m.uncertain)
        .count()
}

// --- Edge case tests ---

#[test]
fn sequence_empty_steps_succeeds() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq("empty", 60, vec![]);
    let e = ev(100, &[("process.generation", Value::Integer(1))]);

    // Empty steps: the sequence has no steps to match, so it's trivially
    // "completed" (vacuous truth). The evaluator should handle this gracefully.
    let m = eval.process_event(&e, std::slice::from_ref(&s)).unwrap();
    // With zero steps, all steps are trivially matched -> completed.
    assert_eq!(m.len(), 1);
    assert!(m[0].completed, "empty steps should be trivially completed");
}

#[test]
fn sequence_single_step_succeeds() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "single",
        60,
        vec![step("syscall", Operator::Eq, Value::String("exec".into()))],
    );
    let e = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    let m = eval.process_event(&e, std::slice::from_ref(&s)).unwrap();
    assert_eq!(
        completed_count(&m),
        1,
        "single step should complete on match"
    );
}

#[test]
fn sequence_zero_window_seconds_fails() {
    let mut eval = SequenceEvaluator::new(default_budget());
    // window_seconds = 0: the budget's max_sequence_window_seconds is 3600,
    // so 0 is within budget. But a zero window means any event beyond t=started_at
    // is late. The first event starts the sequence at its ts; the window is 0,
    // so started_at + 0 = started_at. Any subsequent event with ts > started_at
    // is beyond the window.
    let s = seq(
        "zero-window",
        0,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    let e2 = ev(
        101,
        &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    let m2 = eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    // With window=0, e2 at t=101 > 100+0=100, so it's late -> uncertain.
    assert_eq!(
        completed_count(&m2),
        0,
        "zero window should not allow completion with time gap"
    );
    assert!(
        m2[0].uncertain,
        "zero window with time gap should be uncertain"
    );
}

#[test]
fn sequence_negative_window_seconds_fails() {
    // window_seconds is u32, so negative values are impossible at the type level.
    // This test verifies that the type system prevents negative windows.
    // We test that a very large window (u32::MAX) is rejected by the budget.
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "huge-window",
        u32::MAX,
        vec![step("syscall", Operator::Eq, Value::String("exec".into()))],
    );
    let e = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    let result = eval.process_event(&e, std::slice::from_ref(&s));
    assert!(
        result.is_err(),
        "window exceeding budget should be rejected"
    );
}

#[test]
fn sequence_too_many_steps_fails() {
    let mut eval = SequenceEvaluator::new(default_budget());
    // Budget allows max 16 steps. Create 17.
    let steps: Vec<Step> = (0..17)
        .map(|i| step("syscall", Operator::Eq, Value::String(format!("step{i}"))))
        .collect();
    let s = seq("too-many-steps", 60, steps);
    let e = ev(
        100,
        &[
            ("syscall", Value::String("step0".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    let result = eval.process_event(&e, std::slice::from_ref(&s));
    assert!(
        result.is_err(),
        "too many steps should be rejected by budget"
    );
}

#[test]
fn sequence_window_too_large_fails() {
    let mut eval = SequenceEvaluator::new(default_budget());
    // Budget allows max 3600s window. Use 3601.
    let s = seq(
        "too-large-window",
        3601,
        vec![step("syscall", Operator::Eq, Value::String("exec".into()))],
    );
    let e = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    let result = eval.process_event(&e, std::slice::from_ref(&s));
    assert!(
        result.is_err(),
        "window exceeding budget should be rejected"
    );
}

#[test]
fn sequence_empty_group_key_succeeds() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    // No group key fields -> falls back to Custom("default").
    let e1 = ev(100, &[("syscall", Value::String("exec".into()))]);
    let e2 = ev(101, &[("syscall", Value::String("connect".into()))]);

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    let m2 = eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    assert_eq!(
        completed_count(&m2),
        1,
        "empty group key should fall back to Custom(default)"
    );
}

#[test]
fn sequence_unicode_group_key_succeeds() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("container.id", Value::String("컨테이너-日本語-🔒".into())),
        ],
    );
    let e2 = ev(
        101,
        &[
            ("syscall", Value::String("connect".into())),
            ("container.id", Value::String("컨테이너-日本語-🔒".into())),
        ],
    );

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    let m2 = eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    assert_eq!(
        completed_count(&m2),
        1,
        "unicode group key should work correctly"
    );
}

#[test]
fn sequence_special_characters_group_key_succeeds() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            (
                "container.id",
                Value::String("container/with:special@chars!#$%".into()),
            ),
        ],
    );
    let e2 = ev(
        101,
        &[
            ("syscall", Value::String("connect".into())),
            (
                "container.id",
                Value::String("container/with:special@chars!#$%".into()),
            ),
        ],
    );

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    let m2 = eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    assert_eq!(
        completed_count(&m2),
        1,
        "special characters in group key should work"
    );
}

#[test]
fn sequence_overlapping_sequences_succeeds() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s1 = seq(
        "seq-a",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let s2 = seq(
        "seq-b",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("write".into())),
        ],
    );
    let e1 = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    let e2 = ev(
        101,
        &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    let e3 = ev(
        102,
        &[
            ("syscall", Value::String("write".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    eval.process_event(&e1, &[s1.clone(), s2.clone()]).unwrap();
    eval.process_event(&e2, &[s1.clone(), s2.clone()]).unwrap();
    let m3 = eval.process_event(&e3, &[s1.clone(), s2.clone()]).unwrap();

    // seq-a completed at e2, seq-b completes at e3.
    let completed_a = m3
        .iter()
        .filter(|m| m.sequence_name == "seq-a" && m.completed)
        .count();
    let completed_b = m3
        .iter()
        .filter(|m| m.sequence_name == "seq-b" && m.completed)
        .count();
    assert_eq!(completed_a, 1, "overlapping seq-a should be completed");
    assert_eq!(completed_b, 1, "overlapping seq-b should be completed");
}

#[test]
fn sequence_contradictory_sequences_returns_false() {
    let mut eval = SequenceEvaluator::new(default_budget());
    // A sequence that requires "exec" followed by "not-exec" (Ne "exec").
    // If the second event IS "exec", the Ne step won't match.
    let s = seq(
        "contradictory",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Ne, Value::String("exec".into())),
        ],
    );
    let e1 = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    // Second event is also "exec" -> Ne "exec" is false.
    let e2 = ev(
        101,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    let m2 = eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    assert_eq!(
        completed_count(&m2),
        0,
        "contradictory sequence should not complete"
    );
}

#[test]
fn sequence_tautological_sequence_returns_true() {
    let mut eval = SequenceEvaluator::new(default_budget());
    // A sequence where step 1 matches anything (Ne "impossible-value").
    let s = seq(
        "tautological",
        60,
        vec![step(
            "syscall",
            Operator::Ne,
            Value::String("impossible-value-xyz".into()),
        )],
    );
    let e = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    let m = eval.process_event(&e, std::slice::from_ref(&s)).unwrap();
    assert_eq!(
        completed_count(&m),
        1,
        "tautological sequence should always complete"
    );
}

#[test]
fn sequence_impossible_sequence_returns_false() {
    let mut eval = SequenceEvaluator::new(default_budget());
    // A sequence requiring a field value that never appears.
    let s = seq(
        "impossible",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("teleport".into())),
        ],
    );
    let e1 = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    let e2 = ev(
        101,
        &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    let m2 = eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    assert_eq!(
        completed_count(&m2),
        0,
        "impossible sequence should never complete"
    );
}

#[test]
fn sequence_boundary_values_succeeds() {
    let mut eval = SequenceEvaluator::new(default_budget());
    // Exactly at budget limits: 16 steps, 3600s window.
    let steps: Vec<Step> = (0..16)
        .map(|i| step("syscall", Operator::Eq, Value::String(format!("step{i}"))))
        .collect();
    let s = seq("boundary", 3600, steps);
    let e = ev(
        100,
        &[
            ("syscall", Value::String("step0".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    let result = eval.process_event(&e, std::slice::from_ref(&s));
    assert!(
        result.is_ok(),
        "boundary values (16 steps, 3600s) should be accepted"
    );
}

#[test]
fn sequence_overflow_values_fails() {
    let mut eval = SequenceEvaluator::new(default_budget());
    // Window that would overflow when added to a large timestamp.
    // u32::MAX seconds window exceeds the budget (3600).
    let s = seq(
        "overflow",
        u32::MAX,
        vec![step("syscall", Operator::Eq, Value::String("exec".into()))],
    );
    let e = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    let result = eval.process_event(&e, std::slice::from_ref(&s));
    assert!(
        result.is_err(),
        "overflow window should be rejected by budget"
    );
}

#[test]
fn sequence_negative_timestamp_fails() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "neg-ts",
        60,
        vec![step("syscall", Operator::Eq, Value::String("exec".into()))],
    );
    // Negative timestamp: the evaluator treats negative ts as 0 (clamped).
    let e = ev(
        -100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    // Should not panic; negative ts is clamped to 0.
    let result = eval.process_event(&e, std::slice::from_ref(&s));
    assert!(
        result.is_ok(),
        "negative timestamp should be handled gracefully (clamped to 0)"
    );
}

#[test]
fn sequence_out_of_order_timestamps_succeeds() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "ooo-ts",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    // exec at t=200, connect at t=100 (out of order timestamps).
    let e1 = ev(
        200,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    let e2 = ev(
        100,
        &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    let m2 = eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    // connect at t=100 < exec at t=200: out-of-order timestamps within the
    // sequence indicate a gap/uncertainty.
    // The step matches (connect matches step 1), but ts < prev ts -> uncertain.
    assert!(
        m2[0].uncertain || !m2[0].completed,
        "out-of-order timestamps should yield uncertain or incomplete"
    );
}

#[test]
fn sequence_duplicate_timestamps_succeeds() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "dup-ts",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    // Both events at the same timestamp.
    let e1 = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    let e2 = ev(
        100,
        &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    let m2 = eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    // Same timestamp is valid (not out-of-order, not a gap).
    assert_eq!(
        completed_count(&m2),
        1,
        "duplicate timestamps should allow completion"
    );
    assert!(!m2[0].uncertain);
}

#[test]
fn sequence_gap_in_timestamps_yields_incomplete() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "gap-ts",
        10, // 10 second window
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
            step("syscall", Operator::Eq, Value::String("write".into())),
        ],
    );
    // exec at t=100, connect at t=105, write at t=200 (gap beyond window).
    let e1 = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    let e2 = ev(
        105,
        &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    let e3 = ev(
        200,
        &[
            ("syscall", Value::String("write".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    let m3 = eval.process_event(&e3, std::slice::from_ref(&s)).unwrap();
    assert_eq!(
        completed_count(&m3),
        0,
        "gap beyond window should yield incomplete"
    );
    assert!(m3[0].uncertain, "gap should mark sequence as uncertain");
}

#[test]
fn sequence_late_timestamp_yields_incomplete() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "late-ts",
        5, // 5 second window
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    // Late: t=200 >> 100+5=105.
    let e2 = ev(
        200,
        &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    eval.process_event(&e1, std::slice::from_ref(&s)).unwrap();
    let m2 = eval.process_event(&e2, std::slice::from_ref(&s)).unwrap();
    assert_eq!(
        completed_count(&m2),
        0,
        "late timestamp should yield incomplete"
    );
    assert!(
        m2[0].uncertain,
        "late timestamp should mark sequence as uncertain"
    );
}
