// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::predicates::default_budget;

fn make_event(ts: i64, fields: &[(&str, Value)]) -> Event {
    let mut event = Event::new().with_field(TS_FIELD, Value::Integer(ts));
    for (name, value) in fields {
        event = event.with_field(*name, value.clone());
    }
    event
}

fn make_sequence(name: &str, window: u32, steps: Vec<Step>) -> Sequence {
    Sequence {
        name: name.to_string(),
        steps,
        window_seconds: window,
    }
}

fn step(field: &str, op: Operator, value: Value) -> Step {
    Step {
        field: field.to_string(),
        operator: op,
        value,
    }
}

#[test]
fn basic_in_order_sequence() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let seq = make_sequence(
        "test",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = make_event(
        100,
        &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );
    let e2 = make_event(
        101,
        &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ],
    );

    let m1 = eval.process_event(&e1, std::slice::from_ref(&seq)).unwrap();
    assert!(!m1[0].completed);

    let m2 = eval.process_event(&e2, std::slice::from_ref(&seq)).unwrap();
    assert!(m2[0].completed);
    assert!(!m2[0].uncertain);
}
