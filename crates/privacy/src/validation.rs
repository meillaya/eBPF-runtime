// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Startup validation for the redaction policy.

use std::time::Instant;

use super::policy::*;
use super::{
    ARGV_MAX_BYTES_LIMIT, MAX_CAPTURE_GROUPS, MAX_NFA_STATES, MAX_REGEX_BYTES,
    REGEX_COMPILE_TIME_LIMIT, REGEX_MATCH_TIME_LIMIT,
};

/// A policy validation failure. Reported at startup; the agent must refuse to
/// start with an invalid policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyValidationError {
    #[error("argv_max_bytes must be greater than zero")]
    ArgvMaxBytesZero,
    #[error("argv_max_bytes {0} exceeds the {limit} byte limit", limit = ARGV_MAX_BYTES_LIMIT)]
    ArgvMaxBytesTooLarge(usize),
    #[error("regex failed to compile: {0}")]
    RegexCompileError(String),
    #[error("regex rejected as catastrophic / too slow: {0}")]
    RegexTooSlow(String),
    #[error("regex pattern exceeds the {limit} byte size limit: {0}", limit = MAX_REGEX_BYTES)]
    RegexTooLarge(String),
    #[error("regex pattern is too complex (capture groups / automaton states): {0}")]
    RegexTooComplex(String),
    #[error("policy declares no redaction patterns; a privacy policy must redact something")]
    EmptyPatternList,
}

/// Validate a redaction policy at startup.
pub fn validate_policy(policy: &RedactionPolicy) -> Result<(), PolicyValidationError> {
    if policy.argv_max_bytes == 0 {
        return Err(PolicyValidationError::ArgvMaxBytesZero);
    }
    if policy.argv_max_bytes > ARGV_MAX_BYTES_LIMIT {
        return Err(PolicyValidationError::ArgvMaxBytesTooLarge(
            policy.argv_max_bytes,
        ));
    }
    for pat in &policy.path_patterns {
        if let PathPattern::Regex(p) = pat {
            validate_regex(p)?;
        }
    }
    for pat in &policy.argument_patterns {
        if let ArgumentPattern::Regex(p) = pat {
            validate_regex(p)?;
        }
    }
    for SecretPattern::Regex(p) in &policy.secret_patterns {
        validate_regex(p)?;
    }
    Ok(())
}

/// Validate that the policy is both well-formed and non-trivial.
pub fn validate_policy_strict(policy: &RedactionPolicy) -> Result<(), PolicyValidationError> {
    validate_policy(policy)?;
    if policy.path_patterns.is_empty()
        && policy.argument_patterns.is_empty()
        && policy.secret_patterns.is_empty()
    {
        return Err(PolicyValidationError::EmptyPatternList);
    }
    Ok(())
}

fn validate_regex(pattern: &str) -> Result<(), PolicyValidationError> {
    if pattern.len() > MAX_REGEX_BYTES {
        return Err(PolicyValidationError::RegexTooLarge(pattern.to_string()));
    }
    if has_nested_quantifier(pattern) {
        return Err(PolicyValidationError::RegexTooSlow(format!(
            "catastrophic regex (nested quantifier): {pattern}"
        )));
    }
    let start = Instant::now();
    let re = regex::Regex::new(pattern)
        .map_err(|e| PolicyValidationError::RegexCompileError(format!("{pattern}: {e}")))?;
    if start.elapsed() > REGEX_COMPILE_TIME_LIMIT {
        return Err(PolicyValidationError::RegexTooSlow(format!(
            "regex compile exceeded {:?}: {pattern}",
            REGEX_COMPILE_TIME_LIMIT
        )));
    }
    if re.captures_len().saturating_sub(1) > MAX_CAPTURE_GROUPS {
        return Err(PolicyValidationError::RegexTooComplex(pattern.to_string()));
    }
    if let Ok(nfa) = regex_automata::nfa::thompson::NFA::compiler().build(pattern) {
        if nfa.states().len() > MAX_NFA_STATES {
            return Err(PolicyValidationError::RegexTooComplex(pattern.to_string()));
        }
    }
    let probe = "a".repeat(1024);
    let start = Instant::now();
    let _ = re.is_match(&probe);
    if start.elapsed() > REGEX_MATCH_TIME_LIMIT {
        return Err(PolicyValidationError::RegexTooSlow(format!(
            "regex match exceeded {:?} on a 1 KiB probe: {pattern}",
            REGEX_MATCH_TIME_LIMIT
        )));
    }
    Ok(())
}

/// Bounded single-pass scan for the nested-quantifier catastrophic-backtracking
/// signature.
pub(crate) fn has_nested_quantifier(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let n = chars.len();
    let mut group_has_unbounded: Vec<bool> = Vec::new();
    let mut in_class = false;
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if c == '\\' {
            i += 2;
            continue;
        }
        if in_class {
            if c == ']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match c {
            '[' => {
                in_class = true;
                i += 1;
            }
            '(' => {
                group_has_unbounded.push(false);
                if i + 1 < n && chars[i + 1] == '?' {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            ')' => {
                let inner = group_has_unbounded.pop().unwrap_or(false);
                let followed_by_quant =
                    matches!(chars.get(i + 1), Some('*') | Some('+') | Some('{'));
                if inner && followed_by_quant {
                    return true;
                }
                if inner || followed_by_quant {
                    if let Some(top) = group_has_unbounded.last_mut() {
                        *top = true;
                    }
                }
                if followed_by_quant {
                    i += 2;
                    if matches!(chars.get(i), Some('?') | Some('+')) {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            '*' | '+' => {
                if let Some(top) = group_has_unbounded.last_mut() {
                    *top = true;
                }
                i += 1;
                if matches!(chars.get(i), Some('?') | Some('+')) {
                    i += 1;
                }
            }
            '{' => {
                if let Some(top) = group_has_unbounded.last_mut() {
                    *top = true;
                }
                while i < n && chars[i] != '}' {
                    i += 1;
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    false
}
