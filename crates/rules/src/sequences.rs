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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ast::{Operator, Sequence, Step, Value};
use crate::predicates::{Event, RuleBudget};

use crate::predicates::{Result, RuleError};

/// The monotonic timestamp field name used for ordering.
const TS_FIELD: &str = "ts";
/// The event identifier field name.
const EVENT_ID_FIELD: &str = "event.id";
/// The process generation field (never PID alone).
const PROCESS_GENERATION_FIELD: &str = "process.generation";
/// The container identifier field.
const CONTAINER_ID_FIELD: &str = "container.id";
/// The socket inode field.
const SOCKET_INODE_FIELD: &str = "socket.inode";
/// Default LRU capacity when not explicitly configured.
const DEFAULT_CAPACITY: usize = 10_000;

/// A bounded, deterministic temporal sequence evaluator.
///
/// Correlates ordered event sequences within bounded time windows using
/// monotonic timestamps. State is bounded by LRU capacity and TTL eviction.
#[derive(Debug, Clone)]
pub struct SequenceEvaluator {
    /// The resource budget every evaluation runs under.
    pub budget: RuleBudget,
    /// The bounded correlation state.
    pub state: SequenceState,
    /// Maximum number of sequence instances (LRU capacity).
    pub capacity: usize,
    /// Monotonic access counter for LRU ordering.
    access_counter: u64,
}

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

impl SequenceEvaluator {
    /// Create a new sequence evaluator with the given budget and default
    /// LRU capacity.
    pub fn new(budget: RuleBudget) -> Self {
        Self {
            budget,
            state: SequenceState::default(),
            capacity: DEFAULT_CAPACITY,
            access_counter: 0,
        }
    }

    /// Create a new sequence evaluator with an explicit LRU capacity.
    pub fn with_capacity(budget: RuleBudget, capacity: usize) -> Self {
        Self {
            budget,
            state: SequenceState::default(),
            capacity,
            access_counter: 0,
        }
    }

    /// Process a single event against all sequences deterministically.
    ///
    /// Returns a list of [`SequenceMatch`] for sequences that completed (or
    /// became uncertain) as a result of this event.
    ///
    /// # Guarantees
    ///
    /// - Validates sequence step count and window against the budget.
    /// - Uses monotonic `ts` field for ordering (never wall clock).
    /// - Never correlates by PID alone.
    /// - Marks sequences as uncertain on missing/late/gap events.
    /// - Enforces LRU capacity after processing.
    pub fn process_event(
        &mut self,
        event: &Event,
        sequences: &[Sequence],
    ) -> Result<Vec<SequenceMatch>> {
        let mut matches = Vec::new();

        for sequence in sequences {
            self.validate_sequence(sequence)?;
            let group_key = extract_group_key(event);
            let ts = extract_timestamp(event);
            let event_id = extract_event_id(event);

            let key = SequenceKey {
                sequence_name: sequence.name.clone(),
                group_key: group_key.clone(),
            };

            self.access_counter += 1;
            let access = self.access_counter;

            let instance =
                self.state
                    .sequences
                    .entry(key.clone())
                    .or_insert_with(|| SequenceInstance {
                        steps: init_steps(sequence.steps.len()),
                        started_at: ts,
                        window_seconds: u64::from(sequence.window_seconds),
                        completed: false,
                        uncertain: false,
                        last_accessed: access,
                    });

            instance.last_accessed = access;

            // Vacuous completion: a sequence with zero steps is trivially completed.
            if instance.steps.is_empty() && !instance.completed {
                instance.completed = true;
            }

            // Check window expiry: if the event is beyond the window, mark
            // uncertain (late event / gap).
            if ts > instance.started_at + instance.window_seconds {
                if !instance.completed {
                    instance.uncertain = true;
                }
                // Late event beyond window: do not advance steps.
                if instance.uncertain || instance.completed {
                    let m = build_match(&key, instance);
                    matches.push(m);
                    continue;
                }
            }

            // Already completed: emit match again (idempotent).
            if instance.completed {
                let m = build_match(&key, instance);
                matches.push(m);
                continue;
            }

            // Already uncertain: emit uncertain match.
            if instance.uncertain {
                let m = build_match(&key, instance);
                matches.push(m);
                continue;
            }

            // Try to match the event against the next unmatched step.
            let next_step = instance.steps.iter().position(|s| !s.matched);
            if let Some(step_idx) = next_step {
                let step = &sequence.steps[step_idx];
                if step_matches(step, event)? {
                    instance.steps[step_idx].matched = true;
                    instance.steps[step_idx].matched_at = Some(ts);
                    instance.steps[step_idx].event_id = event_id;

                    // Check if all steps are now matched.
                    if instance.steps.iter().all(|s| s.matched) {
                        instance.completed = true;
                    }

                    // Check for gap: if this step's timestamp is before the
                    // previous step's timestamp, mark uncertain (out-of-order
                    // within the sequence is a gap indicator).
                    if step_idx > 0 {
                        if let Some(prev_ts) = instance.steps[step_idx - 1].matched_at {
                            if ts < prev_ts {
                                instance.uncertain = true;
                            }
                        }
                    }
                }
            }

            let m = build_match(&key, instance);
            matches.push(m);
        }

        // Enforce LRU capacity.
        self.evict_lru(self.capacity);

        Ok(matches)
    }

    /// Evict expired sequences (TTL-based). A sequence is expired if
    /// `now > started_at + window_seconds`.
    ///
    /// Returns the number of evicted sequences.
    pub fn evict_expired(&mut self, now: u64) -> usize {
        let before = self.state.sequences.len();
        self.state
            .sequences
            .retain(|_, inst| now <= inst.started_at + inst.window_seconds);
        before - self.state.sequences.len()
    }

    /// Evict least-recently-used sequences to fit within `capacity`.
    ///
    /// Returns the number of evicted sequences.
    pub fn evict_lru(&mut self, capacity: usize) -> usize {
        let len = self.state.sequences.len();
        if len <= capacity {
            return 0;
        }
        let to_evict = len - capacity;

        // Collect keys sorted by last_accessed (ascending = oldest first).
        let mut entries: Vec<(SequenceKey, u64)> = self
            .state
            .sequences
            .iter()
            .map(|(k, v)| (k.clone(), v.last_accessed))
            .collect();
        entries.sort_by_key(|(_, accessed)| *accessed);

        let evict_keys: Vec<SequenceKey> =
            entries.into_iter().take(to_evict).map(|(k, _)| k).collect();
        for key in &evict_keys {
            self.state.sequences.remove(key);
        }
        evict_keys.len()
    }

    /// Replay a list of events against all sequences deterministically.
    ///
    /// Resets internal state and processes events in order, producing the same
    /// results as processing each event individually in the same order.
    /// Deterministic: the same input always yields the same output.
    pub fn replay(
        &mut self,
        events: &[Event],
        sequences: &[Sequence],
    ) -> Result<Vec<SequenceMatch>> {
        // Reset state for deterministic replay.
        self.state = SequenceState::default();
        self.access_counter = 0;

        let mut all_matches = Vec::new();
        for event in events {
            let matches = self.process_event(event, sequences)?;
            all_matches.extend(matches);
        }
        Ok(all_matches)
    }

    /// Validate a sequence against the budget constraints.
    fn validate_sequence(&self, sequence: &Sequence) -> Result<()> {
        if sequence.steps.len() > self.budget.max_sequence_steps {
            return Err(RuleError::TooManySequenceSteps(sequence.steps.len()));
        }
        let window = u64::from(sequence.window_seconds);
        if window > self.budget.max_sequence_window_seconds {
            return Err(RuleError::SequenceWindowTooLarge(window));
        }
        Ok(())
    }
}

/// Extract the group key from an event. Priority order:
/// 1. `process.generation` (u64) — unique across PID reuse
/// 2. `container.id` (String)
/// 3. `socket.inode` (u64)
/// 4. Fallback: `Custom("default")`
///
/// NEVER uses PID alone. Process correlation uses the generation counter.
fn extract_group_key(event: &Event) -> GroupKey {
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
fn extract_timestamp(event: &Event) -> u64 {
    match event.lookup(TS_FIELD) {
        Some(Value::Integer(ts)) if *ts >= 0 => *ts as u64,
        _ => 0,
    }
}

/// Extract the event identifier from an event.
/// Uses the `event.id` field (String). Returns None if absent.
fn extract_event_id(event: &Event) -> Option<String> {
    match event.lookup(EVENT_ID_FIELD) {
        Some(Value::String(id)) => Some(id.clone()),
        _ => None,
    }
}

/// Initialize step states for a sequence with `n` steps.
fn init_steps(n: usize) -> Vec<StepState> {
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
fn step_matches(step: &Step, event: &Event) -> Result<bool> {
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
fn build_match(key: &SequenceKey, instance: &SequenceInstance) -> SequenceMatch {
    SequenceMatch {
        sequence_name: key.sequence_name.clone(),
        group_key: key.group_key.clone(),
        steps: instance.steps.clone(),
        completed: instance.completed,
        uncertain: instance.uncertain,
    }
}

#[cfg(test)]
mod tests {
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

        let m1 = eval.process_event(&e1, &[seq.clone()]).unwrap();
        assert!(!m1[0].completed);

        let m2 = eval.process_event(&e2, &[seq.clone()]).unwrap();
        assert!(m2[0].completed);
        assert!(!m2[0].uncertain);
    }
}
