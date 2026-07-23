// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::validation::has_nested_quantifier;

#[test]
fn nested_quantifier_scanner_flags_classic_catastrophic_patterns() {
    assert!(has_nested_quantifier("(a+)+$"));
    assert!(has_nested_quantifier("(a*)*"));
    assert!(has_nested_quantifier("(a+)*"));
    assert!(has_nested_quantifier("(?:a+)+"));
    assert!(has_nested_quantifier("((a+)b)+"));
}

#[test]
fn nested_quantifier_scanner_accepts_bounded_patterns() {
    assert!(!has_nested_quantifier("(abc)+"));
    assert!(!has_nested_quantifier("[a-z]+"));
    assert!(!has_nested_quantifier("(?i)abc"));
    assert!(!has_nested_quantifier("AKIA[0-9A-Z]{16}"));
    assert!(!has_nested_quantifier("^/etc/(passwd|shadow)$"));
}

#[test]
fn default_policy_is_well_formed_and_env_disabled() {
    let policy = RedactionPolicy::default();
    assert_eq!(policy.argv_max_bytes, ARGV_MAX_BYTES_DEFAULT);
    assert!(!policy.env_enabled);
    assert!(!policy.dns_field_allowlist.rdata);
    assert!(validate_policy(&policy).is_ok());
}
