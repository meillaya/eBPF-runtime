// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Sequence evaluator: process events, evict expired/LRU, replay.

use crate::ast::Sequence;
use crate::predicates::{Event, RuleBudget};

use crate::predicates::{Result, RuleError};

use super::predicates::{build_match, extract_event_id, extract_group_key, extract_timestamp, init_steps, step_matches};
use super::{
    SequenceInstance, SequenceKey, SequenceMatch, SequenceState, DEFAULT_CAPACITY,
};

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
    pub(crate) access_counter: u64,
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
