// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Edge-case acceptance tests for the native rule schema parser/validator.

use rules::{canonical_digest, parse_ruleset, serialize_ruleset, RuleError};

fn valid_doc() -> String {
    "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: test-rule\n    version: 1\n    severity: high\n    tags: [file, test]\n    source: file\n    description: test rule\n    condition:\n      field: file.path\n      operator: eq\n      value: /etc\n    action: alert\n".into()
}

fn rep(old: &str, new: &str) -> String {
    valid_doc().replace(old, new)
}

fn empty_rules_doc() -> String {
    "schema_version: 1\nengine_version: \"1.0.0\"\nrules: []\n".into()
}

fn raw_condition_doc(cond_inline: &str) -> String {
    format!("schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: r\n    version: 1\n    severity: low\n    source: file\n    description: d\n    condition: {cond_inline}\n    action: alert\n")
}

fn version_doc(v: &str) -> String {
    format!("schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: r\n    version: {v}\n    severity: low\n    source: file\n    description: d\n    condition:\n      field: file.path\n      operator: eq\n      value: /x\n    action: alert\n")
}

fn window_doc(w: &str) -> String {
    format!("schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: r\n    version: 1\n    severity: low\n    source: file\n    description: d\n    condition:\n      field: file.path\n      operator: eq\n      value: /x\n    action: alert\n    sequences:\n      - name: s\n        window_seconds: {w}\n        steps:\n          - field: process.exec_path\n            operator: eq\n            value: /bin/sh\n")
}

fn doc_with_cond(cond: &str) -> String {
    format!("schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: r\n    version: 1\n    severity: low\n    source: file\n    description: d\n    condition:\n{cond}    action: alert\n")
}

fn nested_not(depth: usize) -> String {
    let mut s = String::new();
    for i in 0..depth {
        let indent = "  ".repeat(3 + i);
        s.push_str(&format!("{indent}not:\n"));
    }
    let indent = "  ".repeat(3 + depth);
    s.push_str(&format!(
        "{indent}field: file.path\n{indent}operator: eq\n{indent}value: /x\n"
    ));
    s
}

#[test]
fn parse_empty_ruleset_succeeds() {
    let rs = parse_ruleset(&empty_rules_doc()).unwrap();
    assert!(rs.rules.is_empty());
}

#[test]
fn parse_ruleset_with_no_rules_succeeds() {
    assert_eq!(parse_ruleset(&empty_rules_doc()).unwrap().rules.len(), 0);
}

#[test]
fn parse_ruleset_with_no_lists_succeeds() {
    assert!(parse_ruleset(&valid_doc()).unwrap().rules[0]
        .lists
        .is_empty());
}

#[test]
fn parse_ruleset_with_no_exceptions_succeeds() {
    assert!(parse_ruleset(&valid_doc()).unwrap().rules[0]
        .exceptions
        .is_empty());
}

#[test]
fn parse_ruleset_with_no_sequences_succeeds() {
    assert!(parse_ruleset(&valid_doc()).unwrap().rules[0]
        .sequences
        .is_empty());
}

#[test]
fn parse_ruleset_with_empty_tags_succeeds() {
    assert!(parse_ruleset(&rep("tags: [file, test]", "tags: []"))
        .unwrap()
        .rules[0]
        .tags
        .is_empty());
}

#[test]
fn parse_ruleset_with_empty_description_fails() {
    assert!(matches!(
        parse_ruleset(&rep("description: test rule", "description: \"\"")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_ruleset_with_empty_condition_fails() {
    assert!(matches!(
        parse_ruleset(&raw_condition_doc("{}")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_ruleset_with_empty_list_fails() {
    let doc = rep(
        "action: alert",
        "action: alert\n    lists:\n      - name: a\n        items: []",
    );
    assert!(matches!(
        parse_ruleset(&doc),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_ruleset_with_empty_sequence_fails() {
    let doc = rep("action: alert", "action: alert\n    sequences:\n      - name: s\n        window_seconds: 5\n        steps: []");
    assert!(matches!(
        parse_ruleset(&doc),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_ruleset_with_zero_window_seconds_fails() {
    assert!(matches!(
        parse_ruleset(&window_doc("0")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_ruleset_with_negative_window_seconds_fails() {
    assert!(matches!(
        parse_ruleset(&window_doc("-1")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_ruleset_with_zero_rule_version_fails() {
    assert!(matches!(
        parse_ruleset(&version_doc("0")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_ruleset_with_negative_rule_version_fails() {
    assert!(matches!(
        parse_ruleset(&version_doc("-1")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn serialize_ruleset_with_special_characters_succeeds() {
    let doc = "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: special-rule\n    version: 1\n    severity: medium\n    tags: [\"a&b\", \"c;d\"]\n    source: file\n    description: \"detect: writes; to /etc & /var (v1.0) [critical] {x}\"\n    condition:\n      field: file.path\n      operator: contains\n      value: \"/etc/passwd & shadow; (test) [v1.0]\"\n    action: alert\n";
    let rs = parse_ruleset(doc).unwrap();
    let yaml = serialize_ruleset(&rs).unwrap();
    assert_eq!(parse_ruleset(&yaml).unwrap(), rs);
}

#[test]
fn canonical_digest_with_special_characters_is_stable() {
    let doc = "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: special-rule\n    version: 1\n    severity: medium\n    source: file\n    description: \"a & b ; c (d) [e] {f}\"\n    condition:\n      field: file.path\n      operator: contains\n      value: \"/etc & /var\"\n    action: alert\n";
    let rs = parse_ruleset(doc).unwrap();
    assert_eq!(
        canonical_digest(&rs).unwrap(),
        canonical_digest(&rs).unwrap()
    );
}

#[test]
fn parse_ruleset_with_unicode_succeeds() {
    let doc = "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: unicode-rule\n    version: 1\n    severity: low\n    tags: [\"ファイル\"]\n    source: file\n    description: \"détection 日本語 🚀 écriture\"\n    condition:\n      field: file.path\n      operator: contains\n      value: \"/etc/日本語\"\n    action: alert\n";
    assert!(parse_ruleset(doc).is_ok());
}

#[test]
fn canonical_digest_with_unicode_is_stable() {
    let doc = "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: unicode-rule\n    version: 1\n    severity: low\n    source: file\n    description: \"日本語 🚀\"\n    condition:\n      field: file.path\n      operator: contains\n      value: \"/etc/日本語\"\n    action: alert\n";
    let rs = parse_ruleset(doc).unwrap();
    assert_eq!(
        canonical_digest(&rs).unwrap(),
        canonical_digest(&rs).unwrap()
    );
}

#[test]
fn parse_ruleset_with_nested_conditions_succeeds() {
    assert!(parse_ruleset(&doc_with_cond(&nested_not(4))).is_ok());
}

#[test]
fn parse_ruleset_with_deeply_nested_conditions_fails() {
    assert!(matches!(
        parse_ruleset(&doc_with_cond(&nested_not(20))),
        Err(RuleError::SchemaValidationError(_))
    ));
}
