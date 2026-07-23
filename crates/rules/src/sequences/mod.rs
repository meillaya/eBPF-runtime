// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded temporal sequence correlation with deterministic replay.
//!
//! [`SequenceEvaluator`] correlates ordered event sequences within bounded
//! time windows, using monotonic timestamps for local ordering. State is
//! bounded by an LRU cache with configurable capacity and TTL-based eviction.
//!
//! # Contract
//!
//! - **Never correlates by PID alone**: the group key is one of process
//!   generation, container, socket, or custom — never a bare PID.
//! - **Never hides loss/gap uncertainty**: if a step is missing or late, the
//!   sequence is marked as incomplete and uncertain; uncertain sequences never
//!   produce a deny.
//! - **Never uses wall clock for local ordering**: all ordering uses the
//!   monotonic `ts` field from events.
//! - **Never lets unbounded tenants/keys exhaust memory**: state is bounded by
//!   an LRU cache with a configurable capacity; expired sequences are evicted
//!   by TTL.
//! - **Deterministic replay**: processing the same events in the same order
//!   always yields the same matches.

mod evaluator;
pub(crate) mod predicates;

pub use evaluator::SequenceEvaluator;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The monotonic timestamp field name used for ordering.
pub(crate) const TS_FIELD: &str = "ts";
/// The event identifier field name.
pub(crate) const EVENT_ID_FIELD: &str = "event.id";
/// The process generation field (never PID alone).
pub(crate) const PROCESS_GENERATION_FIELD: &str = "process.generation";
/// The container identifier field.
pub(crate) const CONTAINER_ID_FIELD: &str = "container.id";
/// The socket inode field.
pub(crate) const SOCKET_INODE_FIELD: &str = "socket.inode";
/// Default LRU capacity when not explicitly configured.
pub(crate) const DEFAULT_CAPACITY: usize = 10_000;

/// The bounded correlation state: a map from sequence keys to instances.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SequenceState {
    /// Active sequence instances, keyed by (sequence_name, group_key).
    pub sequences: BTreeMap<SequenceKey, SequenceInstance>,
}

/// The key identifying a unique sequence instance.
///
/// Combines the sequence definition name with a group key that partitions
/// correlation state. The group key is NEVER a bare PID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SequenceKey {
    /// The sequence definition name.
    pub sequence_name: String,
    /// The correlation group key (never PID alone).
    pub group_key: GroupKey,
}

/// The correlation group key. Determines how events are partitioned into
/// independent sequence instances.
///
/// NEVER a bare PID: process correlation uses the generation counter (which
/// is unique across PID reuse), not the PID itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GroupKey {
    /// Process generation counter (unique across PID reuse).
    ProcessGeneration(u64),
    /// Container identifier.
    Container(String),
    /// Socket inode (with generation for reuse safety).
    Socket(u64),
    /// Custom group key for application-defined partitioning.
    Custom(String),
}

/// A single in-progress or completed sequence instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SequenceInstance {
    /// The ordered step states.
    pub steps: Vec<StepState>,
    /// Monotonic timestamp when the sequence started (first step matched).
    pub started_at: u64,
    /// The correlation window in seconds.
    pub window_seconds: u64,
    /// Whether all steps have matched in order.
    pub completed: bool,
    /// Whether the sequence is uncertain (missing/late/gap).
    pub uncertain: bool,
    /// Last access counter value (for LRU eviction).
    pub last_accessed: u64,
}

/// The state of a single step within a sequence instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepState {
    /// The zero-based step index.
    pub step_index: usize,
    /// Whether this step has been matched.
    pub matched: bool,
    /// The monotonic timestamp when this step matched (if matched).
    pub matched_at: Option<u64>,
    /// The event identifier that matched this step (if matched).
    pub event_id: Option<String>,
}

/// A completed or uncertain sequence match result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SequenceMatch {
    /// The sequence definition name.
    pub sequence_name: String,
    /// The correlation group key.
    pub group_key: GroupKey,
    /// The final step states.
    pub steps: Vec<StepState>,
    /// Whether all steps matched in order within the window.
    pub completed: bool,
    /// Whether the sequence is uncertain (missing/late/gap events).
    /// Uncertain sequences NEVER produce a deny action.
    pub uncertain: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Operator, Sequence, Step, Value};
    use crate::predicates::{default_budget, Event};

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
}
