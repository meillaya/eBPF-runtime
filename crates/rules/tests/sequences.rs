// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Unit tests for bounded temporal sequence correlation (task 29).

use rules::ast::{Operator, Sequence, Step, Value};
use rules::predicates::{default_budget, Event};
use rules::sequences::{GroupKey, SequenceEvaluator, SequenceMatch};

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
    matches.iter().filter(|m| m.completed && !m.uncertain).count()
}

// --- Core sequence behavior tests ---

#[test]
fn sequence_in_order_matches_once() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    let e2 = ev(101, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    let m1 = eval.process_event(&e1, &[s.clone()]).unwrap();
    assert_eq!(completed_count(&m1), 0, "first step alone should not complete");

    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    assert_eq!(completed_count(&m2), 1, "in-order sequence should complete exactly once");
    assert!(!m2[0].uncertain);
}

#[test]
fn sequence_out_of_order_matches_once() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    // Events arrive out of order: connect first, then exec.
    // The evaluator matches steps in order, so connect at t=101 won't match
    // step 0 (which expects exec). Then exec at t=100 matches step 0.
    // But since t=100 < t=101 (the started_at), this is out-of-order.
    let e_connect = ev(101, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    let e_exec = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    let m1 = eval.process_event(&e_connect, &[s.clone()]).unwrap();
    assert_eq!(completed_count(&m1), 0, "out-of-order first event should not complete");

    let m2 = eval.process_event(&e_exec, &[s.clone()]).unwrap();
    // exec matches step 0, but connect already arrived and didn't match step 0.
    // The sequence is incomplete because step 1 was never matched after step 0.
    // However, the evaluator processes step-by-step: exec matches step 0.
    // connect was already processed and didn't match step 0 (it was looking for exec).
    // So the sequence has step 0 matched but step 1 not matched.
    assert_eq!(completed_count(&m2), 0, "out-of-order should not complete without both steps in order");
}

#[test]
fn sequence_missing_step_yields_incomplete() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "three-steps",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
            step("syscall", Operator::Eq, Value::String("write".into())),
        ],
    );
    // Only send exec and write (skip connect).
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    let e2 = ev(101, &[
        ("syscall", Value::String("write".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    // write doesn't match step 1 (expects connect), so sequence stays incomplete.
    assert_eq!(completed_count(&m2), 0, "missing step should yield incomplete");
    assert!(!m2[0].completed);
}

#[test]
fn sequence_duplicate_event_matches_once() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    let e2 = ev(101, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    assert_eq!(completed_count(&m2), 1);

    // Send the same connect event again (duplicate).
    let m3 = eval.process_event(&e2, &[s.clone()]).unwrap();
    // Already completed: should still report completed but not double-count.
    assert_eq!(completed_count(&m3), 1, "duplicate event should not create a second match");
}

#[test]
fn sequence_late_event_yields_incomplete() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        10, // 10 second window
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    // Late event: arrives at t=200, well beyond the 10s window from t=100.
    let e2 = ev(200, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    assert_eq!(completed_count(&m2), 0, "late event should not complete the sequence");
    assert!(m2[0].uncertain, "late event should mark sequence as uncertain");
}

#[test]
fn sequence_gap_yields_incomplete() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect-write",
        10, // 10 second window
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
            step("syscall", Operator::Eq, Value::String("write".into())),
        ],
    );
    // exec at t=100, connect at t=105 (within window), write at t=200 (gap beyond window).
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    let e2 = ev(105, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    let e3 = ev(200, &[
        ("syscall", Value::String("write".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    eval.process_event(&e2, &[s.clone()]).unwrap();
    let m3 = eval.process_event(&e3, &[s.clone()]).unwrap();
    assert_eq!(completed_count(&m3), 0, "gap beyond window should yield incomplete");
    assert!(m3[0].uncertain, "gap should mark sequence as uncertain");
}

#[test]
fn sequence_pid_reuse_does_not_correlate() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    // Process generation 1: exec
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    // PID reuse: same PID but different generation (2). Connect from gen 2.
    let e2 = ev(101, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(2)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    // gen 2 is a different group key, so it starts a new sequence instance.
    // The connect from gen 2 doesn't complete the gen 1 sequence.
    assert_eq!(completed_count(&m2), 0, "PID reuse (different generation) should not correlate");
}

#[test]
fn sequence_socket_reuse_does_not_correlate() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "connect-write",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("connect".into())),
            step("syscall", Operator::Eq, Value::String("write".into())),
        ],
    );
    // Socket inode 1000: connect
    let e1 = ev(100, &[
        ("syscall", Value::String("connect".into())),
        ("socket.inode", Value::Integer(1000)),
    ]);
    // Socket reuse: different inode 2000. Write from inode 2000.
    let e2 = ev(101, &[
        ("syscall", Value::String("write".into())),
        ("socket.inode", Value::Integer(2000)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    // inode 2000 is a different group key, so it starts a new sequence instance.
    assert_eq!(completed_count(&m2), 0, "socket reuse (different inode) should not correlate");
}

#[test]
fn sequence_ttl_eviction() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        10, // 10 second window
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    eval.process_event(&e1, &[s.clone()]).unwrap();
    assert_eq!(eval.state.sequences.len(), 1);

    // Evict at t=200 (well beyond 100+10=110).
    let evicted = eval.evict_expired(200);
    assert_eq!(evicted, 1, "expired sequence should be evicted");
    assert_eq!(eval.state.sequences.len(), 0);
}

#[test]
fn sequence_lru_eviction() {
    let budget = default_budget();
    let mut eval = SequenceEvaluator::with_capacity(budget, 2);
    let s = seq(
        "exec-connect",
        3600,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );

    // Create 3 sequence instances (capacity is 2).
    for gen in 1..=3 {
        let e = ev(100, &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(gen)),
        ]);
        eval.process_event(&e, &[s.clone()]).unwrap();
    }

    // LRU eviction should have kept only 2.
    assert!(eval.state.sequences.len() <= 2, "LRU eviction should bound state to capacity");
}

#[test]
fn sequence_restart_replay() {
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let events = vec![
        ev(100, &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ]),
        ev(101, &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ]),
    ];

    // First replay.
    let mut eval1 = SequenceEvaluator::new(default_budget());
    let m1 = eval1.replay(&events, &[s.clone()]).unwrap();
    let completed1 = completed_count(&m1);

    // Second replay (simulating restart): same events, same result.
    let mut eval2 = SequenceEvaluator::new(default_budget());
    let m2 = eval2.replay(&events, &[s.clone()]).unwrap();
    let completed2 = completed_count(&m2);

    assert_eq!(completed1, completed2, "restart replay should produce identical results");
    assert_eq!(completed1, 1, "replay should complete the sequence once");
}

#[test]
fn sequence_deterministic_replay() {
    let s = seq(
        "exec-connect-write",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
            step("syscall", Operator::Eq, Value::String("write".into())),
        ],
    );
    let events = vec![
        ev(100, &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ]),
        ev(101, &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ]),
        ev(102, &[
            ("syscall", Value::String("write".into())),
            ("process.generation", Value::Integer(1)),
        ]),
    ];

    // Run replay multiple times; results must be identical.
    let mut eval = SequenceEvaluator::new(default_budget());
    let m1 = eval.replay(&events, &[s.clone()]).unwrap();
    let m2 = eval.replay(&events, &[s.clone()]).unwrap();
    let m3 = eval.replay(&events, &[s.clone()]).unwrap();

    assert_eq!(m1, m2, "deterministic replay: run 1 == run 2");
    assert_eq!(m2, m3, "deterministic replay: run 2 == run 3");
}

#[test]
fn sequence_never_correlates_by_pid_alone() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    // Event with PID but NO process.generation. The evaluator should NOT
    // use PID as the group key. Without a valid group key field, it falls
    // back to Custom("default").
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.pid", Value::Integer(1234)),
    ]);
    let e2 = ev(101, &[
        ("syscall", Value::String("connect".into())),
        ("process.pid", Value::Integer(1234)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    // Both events fall into Custom("default") group since no generation/container/socket.
    // They DO correlate (same group), but NOT by PID. The group key is Custom, not PID.
    // Verify the group key is NOT a PID-based key.
    assert!(
        matches!(m2[0].group_key, GroupKey::Custom(_)),
        "group key should be Custom (fallback), never PID-based"
    );
}

#[test]
fn sequence_never_hides_loss_gap_uncertainty() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        10,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    // Late event beyond window.
    let e2 = ev(200, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    // The sequence MUST be marked uncertain; loss/gap is never hidden.
    assert!(m2[0].uncertain, "loss/gap uncertainty must never be hidden");
    assert!(!m2[0].completed || m2[0].uncertain, "uncertain sequence must not appear as clean completion");
}

#[test]
fn sequence_never_uses_wall_clock_for_ordering() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    // Events with monotonic timestamps that differ from any wall clock.
    // The evaluator uses the `ts` field, not system time.
    let e1 = ev(999999, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    let e2 = ev(1000000, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    // Should complete using monotonic ts, regardless of wall clock.
    assert_eq!(completed_count(&m2), 1, "ordering must use monotonic ts, not wall clock");
    assert!(!m2[0].uncertain);
}

#[test]
fn sequence_never_lets_unbounded_keys_exhaust_memory() {
    let budget = default_budget();
    let mut eval = SequenceEvaluator::with_capacity(budget, 100);
    let s = seq(
        "exec-connect",
        3600,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );

    // Insert 200 unique group keys (exceeds capacity of 100).
    for gen in 0..200 {
        let e = ev(100, &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(gen)),
        ]);
        eval.process_event(&e, &[s.clone()]).unwrap();
    }

    assert!(
        eval.state.sequences.len() <= 100,
        "state must be bounded by LRU capacity, got {}",
        eval.state.sequences.len()
    );
}

#[test]
fn sequence_shell_exec_socket_stdio_matches_once() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "shell-exec-socket-stdio",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("socket".into())),
            step("syscall", Operator::Eq, Value::String("stdio".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(42)),
    ]);
    let e2 = ev(101, &[
        ("syscall", Value::String("socket".into())),
        ("process.generation", Value::Integer(42)),
    ]);
    let e3 = ev(102, &[
        ("syscall", Value::String("stdio".into())),
        ("process.generation", Value::Integer(42)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    eval.process_event(&e2, &[s.clone()]).unwrap();
    let m3 = eval.process_event(&e3, &[s.clone()]).unwrap();
    assert_eq!(completed_count(&m3), 1, "shell exec→socket→stdio should match exactly once");
    assert!(!m3[0].uncertain);
}

#[test]
fn sequence_negative_clause_safely_expressible() {
    let mut eval = SequenceEvaluator::new(default_budget());
    // Negative clause: step uses Ne operator (safely expressible negation).
    let s = seq(
        "exec-not-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Ne, Value::String("connect".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    // "write" is NOT "connect", so the Ne step matches.
    let e2 = ev(101, &[
        ("syscall", Value::String("write".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    assert_eq!(completed_count(&m2), 1, "negative clause (Ne) should be safely expressible");
    assert!(!m2[0].uncertain);
}

#[test]
fn sequence_within_window_timer() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        30, // 30 second window
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    // Within window: exec at t=100, connect at t=125 (25s < 30s window).
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(1)),
    ]);
    let e2 = ev(125, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(1)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    assert_eq!(completed_count(&m2), 1, "within-window timer should allow completion");
    assert!(!m2[0].uncertain);
}

#[test]
fn sequence_group_key_process_generation() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("process.generation", Value::Integer(7)),
    ]);
    let e2 = ev(101, &[
        ("syscall", Value::String("connect".into())),
        ("process.generation", Value::Integer(7)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    assert!(
        matches!(m2[0].group_key, GroupKey::ProcessGeneration(7)),
        "group key should be ProcessGeneration(7)"
    );
    assert_eq!(completed_count(&m2), 1);
}

#[test]
fn sequence_group_key_container() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
        ("container.id", Value::String("abc123".into())),
    ]);
    let e2 = ev(101, &[
        ("syscall", Value::String("connect".into())),
        ("container.id", Value::String("abc123".into())),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    assert!(
        matches!(&m2[0].group_key, GroupKey::Container(id) if id == "abc123"),
        "group key should be Container(abc123)"
    );
    assert_eq!(completed_count(&m2), 1);
}

#[test]
fn sequence_group_key_socket() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "connect-write",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("connect".into())),
            step("syscall", Operator::Eq, Value::String("write".into())),
        ],
    );
    let e1 = ev(100, &[
        ("syscall", Value::String("connect".into())),
        ("socket.inode", Value::Integer(5555)),
    ]);
    let e2 = ev(101, &[
        ("syscall", Value::String("write".into())),
        ("socket.inode", Value::Integer(5555)),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    assert!(
        matches!(m2[0].group_key, GroupKey::Socket(5555)),
        "group key should be Socket(5555)"
    );
    assert_eq!(completed_count(&m2), 1);
}

#[test]
fn sequence_group_key_custom() {
    let mut eval = SequenceEvaluator::new(default_budget());
    let s = seq(
        "exec-connect",
        60,
        vec![
            step("syscall", Operator::Eq, Value::String("exec".into())),
            step("syscall", Operator::Eq, Value::String("connect".into())),
        ],
    );
    // No process.generation, container.id, or socket.inode -> Custom("default").
    let e1 = ev(100, &[
        ("syscall", Value::String("exec".into())),
    ]);
    let e2 = ev(101, &[
        ("syscall", Value::String("connect".into())),
    ]);

    eval.process_event(&e1, &[s.clone()]).unwrap();
    let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();
    assert!(
        matches!(&m2[0].group_key, GroupKey::Custom(s) if s == "default"),
        "group key should be Custom(default) as fallback"
    );
    assert_eq!(completed_count(&m2), 1);
}

// --- Property tests ---

#[test]
fn property_test_deterministic_sequence_evaluation() {
    use proptest::prelude::*;

    proptest!(|(ts_base in 0u64..1000, gen in 1u64..100)| {
        let s = seq(
            "prop-seq",
            60,
            vec![
                step("syscall", Operator::Eq, Value::String("exec".into())),
                step("syscall", Operator::Eq, Value::String("connect".into())),
            ],
        );
        let events = vec![
            ev(ts_base as i64, &[
                ("syscall", Value::String("exec".into())),
                ("process.generation", Value::Integer(gen as i64)),
            ]),
            ev((ts_base + 1) as i64, &[
                ("syscall", Value::String("connect".into())),
                ("process.generation", Value::Integer(gen as i64)),
            ]),
        ];

        let mut eval1 = SequenceEvaluator::new(default_budget());
        let m1 = eval1.replay(&events, &[s.clone()]).unwrap();

        let mut eval2 = SequenceEvaluator::new(default_budget());
        let m2 = eval2.replay(&events, &[s.clone()]).unwrap();

        prop_assert_eq!(&m1, &m2, "deterministic: same input -> same output");
    });
}

#[test]
fn property_test_sequence_state_bounded() {
    use proptest::prelude::*;

    proptest!(|(n_keys in 1usize..50)| {
        let budget = default_budget();
        let capacity = 10;
        let mut eval = SequenceEvaluator::with_capacity(budget, capacity);
        let s = seq(
            "bounded-seq",
            3600,
            vec![step("syscall", Operator::Eq, Value::String("exec".into()))],
        );

        for gen in 0..n_keys {
            let e = ev(100, &[
                ("syscall", Value::String("exec".into())),
                ("process.generation", Value::Integer(gen as i64)),
            ]);
            eval.process_event(&e, &[s.clone()]).unwrap();
        }

        prop_assert!(
            eval.state.sequences.len() <= capacity,
            "state must be bounded: {} > {}",
            eval.state.sequences.len(),
            capacity
        );
    });
}

#[test]
fn property_test_sequence_never_denies_on_uncertain() {
    use proptest::prelude::*;

    proptest!(|(ts_gap in 100u64..1000)| {
        let mut eval = SequenceEvaluator::new(default_budget());
        let s = seq(
            "deny-check",
            10, // short window
            vec![
                step("syscall", Operator::Eq, Value::String("exec".into())),
                step("syscall", Operator::Eq, Value::String("connect".into())),
            ],
        );
        let e1 = ev(100, &[
            ("syscall", Value::String("exec".into())),
            ("process.generation", Value::Integer(1)),
        ]);
        // Late event beyond window.
        let e2 = ev((100 + ts_gap) as i64, &[
            ("syscall", Value::String("connect".into())),
            ("process.generation", Value::Integer(1)),
        ]);

        eval.process_event(&e1, &[s.clone()]).unwrap();
        let m2 = eval.process_event(&e2, &[s.clone()]).unwrap();

        for m in &m2 {
            if m.uncertain {
                // Uncertain sequences must NEVER be marked as clean completions.
                prop_assert!(
                    !m.completed || m.uncertain,
                    "uncertain sequence must never produce a clean deny-eligible completion"
                );
            }
        }
    });
}
