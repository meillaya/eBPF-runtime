// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded regex matching for predicates.
//!
//! [`PredicateEvaluator::evaluate_regex`] enforces every regex bound from the
//! [`super::RuleBudget`] before and during a match:
//! - pattern length <= `max_regex_chars` characters ([`RuleError::RegexTooLarge`]);
//! - pattern is non-empty and compiles ([`RuleError::InvalidRegex`]);
//! - <= 64 capture groups and no unbounded/nested quantifiers
//!   ([`RuleError::RegexTooComplex`]): the catastrophic-backtracking guard;
//! - match wall-clock time <= `max_regex_time_ms` ([`RuleError::RegexTooSlow`]).
//!
//! The `regex` crate is linear-time (it never backtracks), so allocation and
//! time are bounded by the pattern and haystack sizes; the timing check is a
//! defensive bound on top of that guarantee.

use std::time::{Duration, Instant};

use crate::regex_check::{has_unbounded_nesting, MAX_CAPTURE_GROUPS};

use super::error::{Result, RuleError};
use super::eval::PredicateEvaluator;

impl PredicateEvaluator {
    /// Evaluate a bounded regex match of `pattern` against `value`.
    ///
    /// Never performs unbounded allocation or backtracking: the engine is
    /// linear-time, the pattern is character-bounded and complexity-checked,
    /// and the match is wall-clock-bounded by `max_regex_time_ms`.
    pub fn evaluate_regex(&self, pattern: &str, value: &str) -> Result<bool> {
        if pattern.is_empty() {
            return Err(RuleError::InvalidRegex("empty regex pattern".to_string()));
        }
        let chars = pattern.chars().count();
        if chars > self.budget.max_regex_chars {
            return Err(RuleError::RegexTooLarge(format!(
                "regex pattern is {chars} characters, exceeds the {}-character bound",
                self.budget.max_regex_chars
            )));
        }
        let re = regex::Regex::new(pattern)
            .map_err(|e| RuleError::InvalidRegex(format!("'{pattern}': {e}")))?;
        let groups = re.captures_len().saturating_sub(1);
        if groups > MAX_CAPTURE_GROUPS {
            return Err(RuleError::RegexTooComplex(format!(
                "regex has {groups} capture groups, exceeds the {MAX_CAPTURE_GROUPS}-group bound"
            )));
        }
        if has_unbounded_nesting(pattern) {
            return Err(RuleError::RegexTooComplex(
                "regex contains unbounded/nested quantifiers (catastrophic-backtracking risk)"
                    .to_string(),
            ));
        }
        let start = Instant::now();
        let matched = re.is_match(value);
        let elapsed = start.elapsed();
        let limit = Duration::from_millis(self.budget.max_regex_time_ms);
        if elapsed > limit {
            return Err(RuleError::RegexTooSlow(format!(
                "regex match took {elapsed:?}, exceeds the {limit:?} bound"
            )));
        }
        Ok(matched)
    }
}
