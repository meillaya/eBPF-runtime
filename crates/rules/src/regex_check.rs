// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded regex validation for the native rule schema.
//!
//! Rules may use regex matching, but never *arbitrary* regex: every pattern is
//! bounded so a rule author cannot smuggle in an unbounded or
//! catastrophic-backtracking expression. Bounds enforced here:
//! - pattern length <= [`MAX_REGEX_BYTES`] bytes;
//! - pattern must compile (both the `regex` crate and the `regex-automata`
//!   engine that evaluates rules);
//! - <= [`MAX_CAPTURE_GROUPS`] user capture groups;
//! - no unbounded/nested quantifiers (e.g. `(a+)+`).

use crate::error::{Result, RuleError};

/// Maximum regex pattern length in bytes.
pub const MAX_REGEX_BYTES: usize = 1024;

/// Maximum number of user capture groups in a regex.
pub const MAX_CAPTURE_GROUPS: usize = 64;

/// Validate a regex pattern, returning a path-aware diagnostic on any breach.
///
/// Checks run cheapest-first: byte bound, then compilation, then capture-group
/// count, then unbounded-nesting, then a cross-check that the `regex-automata`
/// evaluation engine can also build the pattern.
pub fn validate_regex(pattern: &str, path: &str) -> Result<()> {
    if pattern.len() > MAX_REGEX_BYTES {
        return Err(RuleError::RegexTooLarge(format!(
            "{path}: regex pattern is {} bytes, exceeds the {MAX_REGEX_BYTES}-byte bound",
            pattern.len()
        )));
    }
    let re =
        regex::Regex::new(pattern).map_err(|e| RuleError::InvalidRegex(format!("{path}: {e}")))?;
    let groups = re.captures_len().saturating_sub(1);
    if groups > MAX_CAPTURE_GROUPS {
        return Err(RuleError::RegexTooComplex(format!(
            "{path}: regex has {groups} capture groups, exceeds the {MAX_CAPTURE_GROUPS}-group bound"
        )));
    }
    if has_unbounded_nesting(pattern) {
        return Err(RuleError::RegexTooComplex(format!(
            "{path}: regex contains unbounded/nested quantifiers (catastrophic-backtracking risk)"
        )));
    }
    regex_automata::meta::Regex::new(pattern).map_err(|e| {
        RuleError::InvalidRegex(format!("{path}: evaluation engine rejected pattern: {e}"))
    })?;
    Ok(())
}

/// Detect an unbounded quantifier applied to a group that itself contains a
/// quantifier (the classic catastrophic-backtracking shape, e.g. `(a+)+`,
/// `(a*)*`, `((a)+)+`, `(?:a+)+`, `(a+){2,}`).
///
/// Conservative: returns `true` only for clearly nested-unbounded shapes, so
/// ordinary bounded patterns (`.*`, `^/etc/.*$`, `[a-z]+`, `^proc[0-9]+$`)
/// never false-positive. The `regex` crate is linear-time anyway; this is a
/// defensive authoring-time rejection of obviously unbounded expressions.
pub fn has_unbounded_nesting(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut in_class = false;
    let mut escape = false;
    // group_has_quant[d] = a quantifier was seen inside the group at depth d.
    let mut group_has_quant: Vec<bool> = vec![false];
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if escape {
            escape = false;
            i += 1;
            continue;
        }
        if c == b'\\' {
            escape = true;
            i += 1;
            continue;
        }
        if in_class {
            if c == b']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'[' => in_class = true,
            b'(' => group_has_quant.push(false),
            b')' => {
                let inner_had_quant = group_has_quant.pop().unwrap_or(false);
                let unbounded = is_unbounded_quant_at(bytes, i + 1);
                if unbounded && inner_had_quant {
                    return true;
                }
                if unbounded || matches!(bytes.get(i + 1), Some(b'?')) {
                    if let Some(slot) = group_has_quant.last_mut() {
                        *slot = true;
                    }
                }
            }
            b'*' | b'+' => {
                if let Some(slot) = group_has_quant.last_mut() {
                    *slot = true;
                }
            }
            b'{' => {
                if is_unbounded_brace(bytes, i) {
                    if let Some(slot) = group_has_quant.last_mut() {
                        *slot = true;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Whether the byte at `pos` begins an unbounded quantifier (`*`, `+`, `{n,}`).
fn is_unbounded_quant_at(bytes: &[u8], pos: usize) -> bool {
    match bytes.get(pos) {
        Some(b'*') | Some(b'+') => true,
        Some(b'{') => is_unbounded_brace(bytes, pos),
        _ => false,
    }
}

/// Whether the `{...}` starting at `i` is an unbounded repetition `{n,}`.
///
/// `{2,}` -> true; `{2,5}` -> false; `{2}` -> false; malformed -> false.
fn is_unbounded_brace(bytes: &[u8], i: usize) -> bool {
    let mut j = i + 1;
    let mut saw_comma = false;
    let mut digit_after_comma = false;
    while j < bytes.len() {
        match bytes[j] {
            b'}' => return saw_comma && !digit_after_comma,
            b',' => {
                saw_comma = true;
                digit_after_comma = false;
            }
            b'0'..=b'9' => {
                if saw_comma {
                    digit_after_comma = true;
                }
            }
            _ => return false,
        }
        j += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_patterns_are_not_unbounded() {
        for p in [
            ".*",
            "^/etc/.*$",
            "[a-z]+",
            "^proc[0-9]+$",
            ".*\\.secret$",
            "(a+)?",
            "a{2,5}",
        ] {
            assert!(!has_unbounded_nesting(p), "false positive on {p}");
        }
    }

    #[test]
    fn nested_unbounded_patterns_are_detected() {
        for p in ["(a+)+", "(a*)*", "(a+)*", "((a)+)+", "(?:a+)+", "(a+){2,}"] {
            assert!(has_unbounded_nesting(p), "missed {p}");
        }
    }

    #[test]
    fn oversize_pattern_is_too_large() {
        let p = "é".repeat(600); // 600 chars, 1200 bytes
        assert!(matches!(
            validate_regex(&p, "x"),
            Err(RuleError::RegexTooLarge(_))
        ));
    }

    #[test]
    fn too_many_groups_is_too_complex() {
        let p = "(a)".repeat(65);
        assert!(matches!(
            validate_regex(&p, "x"),
            Err(RuleError::RegexTooComplex(_))
        ));
    }

    #[test]
    fn invalid_pattern_is_invalid() {
        assert!(matches!(
            validate_regex("[unclosed", "x"),
            Err(RuleError::InvalidRegex(_))
        ));
    }

    #[test]
    fn unbounded_nesting_is_too_complex() {
        assert!(matches!(
            validate_regex("(a+)+b", "x"),
            Err(RuleError::RegexTooComplex(_))
        ));
    }
}
