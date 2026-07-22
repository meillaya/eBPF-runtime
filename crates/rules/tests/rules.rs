// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side acceptance tests for the native rule schema parser/validator.

use rules::{canonical_digest, default_field_catalog, parse_ruleset, serialize_ruleset, RuleError};

fn valid_doc() -> String {
    "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: test-rule\n    version: 1\n    severity: high\n    tags: [file, test]\n    source: file\n    description: test rule\n    condition:\n      field: file.path\n      operator: eq\n      value: /etc\n    action: alert\n".into()
}

fn rep(old: &str, new: &str) -> String {
    valid_doc().replace(old, new)
}

fn leaf(field: &str, op: &str, val: &str) -> String {
    format!("      field: {field}\n      operator: {op}\n      value: {val}\n")
}

fn doc_ca(cond_block: &str, action: &str) -> String {
    format!("schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: test-rule\n    version: 1\n    severity: high\n    source: file\n    description: test rule\n    condition:\n{cond_block}    action: {action}\n")
}

fn regex_doc(pattern_yaml: &str) -> String {
    doc_ca(&leaf("file.path", "regex", pattern_yaml), "alert")
}

fn deny_doc(field: &str) -> String {
    doc_ca(&leaf(field, "eq", "\"x\""), "deny")
}

#[test]
fn parse_valid_ruleset_succeeds() {
    let rs = parse_ruleset(&valid_doc()).unwrap();
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(rs.rules[0].id, "test-rule");
}

#[test]
fn parse_valid_ruleset_with_lists_succeeds() {
    let doc = rep(
        "action: alert",
        "action: alert\n    lists:\n      - name: sensitive_paths\n        items: [/etc, /var]",
    );
    let rs = parse_ruleset(&doc).unwrap();
    assert_eq!(rs.rules[0].lists[0].name, "sensitive_paths");
}

#[test]
fn parse_valid_ruleset_with_exceptions_succeeds() {
    let doc = rep("action: alert", "action: alert\n    exceptions:\n      - field: process.exec_path\n        operator: eq\n        value: /usr/bin/dpkg");
    let rs = parse_ruleset(&doc).unwrap();
    assert_eq!(rs.rules[0].exceptions.len(), 1);
}

#[test]
fn parse_valid_ruleset_with_sequences_succeeds() {
    let doc = rep("action: alert", "action: alert\n    sequences:\n      - name: exec_then_connect\n        window_seconds: 60\n        steps:\n          - field: process.exec_path\n            operator: eq\n            value: /bin/sh");
    let rs = parse_ruleset(&doc).unwrap();
    assert_eq!(rs.rules[0].sequences[0].window_seconds, 60);
}

#[test]
fn parse_valid_ruleset_with_and_condition_succeeds() {
    let cond = "      and:\n        - field: file.path\n          operator: contains\n          value: /etc\n        - field: process.pid\n          operator: gt\n          value: 100\n";
    assert!(parse_ruleset(&doc_ca(cond, "alert")).is_ok());
}

#[test]
fn parse_valid_ruleset_with_or_condition_succeeds() {
    let cond = "      or:\n        - field: file.path\n          operator: eq\n          value: /etc\n        - field: file.path\n          operator: eq\n          value: /var\n";
    assert!(parse_ruleset(&doc_ca(cond, "alert")).is_ok());
}

#[test]
fn parse_valid_ruleset_with_not_condition_succeeds() {
    let cond = "      not:\n        field: file.path\n        operator: eq\n        value: /tmp\n";
    assert!(parse_ruleset(&doc_ca(cond, "alert")).is_ok());
}

#[test]
fn parse_valid_ruleset_with_all_operators_succeeds() {
    for (op, val) in [
        ("eq", "\"/etc\""),
        ("ne", "\"/etc\""),
        ("contains", "\"/etc\""),
        ("not_contains", "\"/etc\""),
        ("starts_with", "\"/etc\""),
        ("ends_with", "\".conf\""),
        ("regex", "\"^/etc/.*$\""),
        ("not_regex", "\"^/tmp/.*$\""),
    ] {
        assert!(
            parse_ruleset(&doc_ca(&leaf("file.path", op, val), "alert")).is_ok(),
            "op {op}"
        );
    }
    for (op, val) in [
        ("gt", "100"),
        ("lt", "100"),
        ("gte", "100"),
        ("lte", "100"),
        ("in", "[1, 2]"),
        ("not_in", "[1, 2]"),
    ] {
        assert!(
            parse_ruleset(&doc_ca(&leaf("process.pid", op, val), "alert")).is_ok(),
            "op {op}"
        );
    }
}

#[test]
fn parse_valid_ruleset_with_all_severities_succeeds() {
    for sev in ["critical", "high", "medium", "low", "info"] {
        assert!(
            parse_ruleset(&rep("severity: high", &format!("severity: {sev}"))).is_ok(),
            "sev {sev}"
        );
    }
}

#[test]
fn parse_valid_ruleset_with_all_sources_succeeds() {
    for (src, field, val) in [
        ("process", "process.exec_path", "\"x\""),
        ("file", "file.path", "\"x\""),
        ("network", "network.dst_ip", "\"x\""),
        ("dns", "dns.qname", "\"x\""),
        ("syscall", "syscall.nr", "1"),
        ("identity", "identity.cgroup_id", "1"),
    ] {
        let doc = doc_ca(&leaf(field, "eq", val), "alert")
            .replace("source: file", &format!("source: {src}"));
        assert!(parse_ruleset(&doc).is_ok(), "src {src}");
    }
}

#[test]
fn parse_valid_ruleset_with_all_actions_succeeds() {
    assert!(parse_ruleset(&doc_ca(&leaf("file.path", "eq", "\"/etc\""), "alert")).is_ok());
    assert!(parse_ruleset(&doc_ca(&leaf("file.path", "eq", "\"/etc\""), "audit")).is_ok());
    assert!(parse_ruleset(&doc_ca(&leaf("file.path", "eq", "\"/etc\""), "deny")).is_ok());
}

#[test]
fn parse_invalid_schema_version_fails() {
    assert!(matches!(
        parse_ruleset(&rep("schema_version: 1", "schema_version: 2")),
        Err(RuleError::SchemaVersionMismatch(2))
    ));
}

#[test]
fn parse_invalid_engine_version_fails() {
    assert!(matches!(
        parse_ruleset(&rep(
            "engine_version: \"1.0.0\"",
            "engine_version: \"2.0.0\""
        )),
        Err(RuleError::EngineVersionMismatch(_))
    ));
}

#[test]
fn parse_duplicate_rule_id_fails() {
    let two = "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: same\n    version: 1\n    severity: low\n    source: file\n    description: a\n    condition:\n      field: file.path\n      operator: eq\n      value: /x\n    action: alert\n  - id: same\n    version: 1\n    severity: low\n    source: file\n    description: b\n    condition:\n      field: file.path\n      operator: eq\n      value: /y\n    action: alert\n";
    assert!(matches!(
        parse_ruleset(two),
        Err(RuleError::DuplicateRuleId(_))
    ));
}

#[test]
fn parse_duplicate_list_name_fails() {
    let doc = rep("action: alert", "action: alert\n    lists:\n      - name: dup\n        items: [/a]\n      - name: dup\n        items: [/b]");
    assert!(matches!(
        parse_ruleset(&doc),
        Err(RuleError::DuplicateListName(_))
    ));
}

#[test]
fn parse_duplicate_sequence_name_fails() {
    let step = "        steps:\n          - field: process.exec_path\n            operator: eq\n            value: /bin/sh";
    let doc = rep("action: alert", &format!("action: alert\n    sequences:\n      - name: dup\n        window_seconds: 5\n{step}\n      - name: dup\n        window_seconds: 5\n{step}"));
    assert!(matches!(
        parse_ruleset(&doc),
        Err(RuleError::DuplicateSequenceName(_))
    ));
}

#[test]
fn parse_invalid_field_fails() {
    assert!(matches!(
        parse_ruleset(&rep("field: file.path", "field: file.nonexistent")),
        Err(RuleError::InvalidField(_))
    ));
}

#[test]
fn parse_invalid_operator_fails() {
    assert!(matches!(
        parse_ruleset(&rep("operator: eq", "operator: gt")),
        Err(RuleError::InvalidOperator(_))
    ));
}

#[test]
fn parse_invalid_regex_fails() {
    assert!(matches!(
        parse_ruleset(&regex_doc("\"[unclosed\"")),
        Err(RuleError::InvalidRegex(_))
    ));
}

#[test]
fn parse_regex_too_large_fails() {
    let pattern = format!("\"{}\"", "é".repeat(600)); // 600 chars, 1200 bytes
    assert!(matches!(
        parse_ruleset(&regex_doc(&pattern)),
        Err(RuleError::RegexTooLarge(_))
    ));
}

#[test]
fn parse_regex_too_complex_fails() {
    let pattern = format!("\"{}\"", "(a)".repeat(65)); // 65 capture groups
    assert!(matches!(
        parse_ruleset(&regex_doc(&pattern)),
        Err(RuleError::RegexTooComplex(_))
    ));
}

#[test]
fn parse_deny_on_heuristic_only_fails() {
    assert!(matches!(
        parse_ruleset(&deny_doc("enrichment.container_id")),
        Err(RuleError::DenyOnHeuristicOnly(_))
    ));
}

#[test]
fn parse_unknown_field_fails() {
    assert!(matches!(
        parse_ruleset(&rep("action: alert", "action: alert\n    bogus: 1")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_unknown_operator_fails() {
    assert!(matches!(
        parse_ruleset(&rep("operator: eq", "operator: matches")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_unknown_action_fails() {
    assert!(matches!(
        parse_ruleset(&rep("action: alert", "action: block")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_unknown_severity_fails() {
    assert!(matches!(
        parse_ruleset(&rep("severity: high", "severity: urgent")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_unknown_source_fails() {
    assert!(matches!(
        parse_ruleset(&rep("source: file", "source: kernel")),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn serialize_ruleset_is_deterministic() {
    let rs = parse_ruleset(&valid_doc()).unwrap();
    assert_eq!(
        serialize_ruleset(&rs).unwrap(),
        serialize_ruleset(&rs).unwrap()
    );
}

#[test]
fn canonical_digest_is_stable() {
    let rs = parse_ruleset(&valid_doc()).unwrap();
    assert_eq!(
        canonical_digest(&rs).unwrap(),
        canonical_digest(&rs).unwrap()
    );
}

#[test]
fn canonical_digest_is_deterministic() {
    let a = parse_ruleset(&valid_doc()).unwrap();
    let b = parse_ruleset(&valid_doc()).unwrap();
    assert_eq!(canonical_digest(&a).unwrap(), canonical_digest(&b).unwrap());
}

#[test]
fn field_catalog_includes_all_event_fields() {
    let cat = default_field_catalog();
    for f in [
        "process.exec_path",
        "process.argv",
        "process.pid",
        "process.tgid",
        "process.uid",
        "process.gid",
        "file.path",
        "file.kind",
        "network.dst_ip",
        "network.dst_port",
        "network.family",
        "dns.qname",
        "dns.qtype",
        "syscall.nr",
        "syscall.latency_ns",
        "identity.cgroup_id",
        "identity.ns_pid",
        "identity.ns_mnt",
        "identity.ns_net",
        "identity.ns_user",
        "enrichment.container_id",
        "enrichment.pod_uid",
        "enrichment.pod_name",
        "enrichment.namespace",
    ] {
        assert!(cat.contains(f), "missing field {f}");
    }
}

#[test]
fn field_catalog_marks_enrichment_fields_as_not_kernel_observable() {
    let cat = default_field_catalog();
    for f in &cat.fields {
        if f.name.starts_with("enrichment.") {
            assert!(
                !f.kernel_observable,
                "{} should not be kernel-observable",
                f.name
            );
        } else {
            assert!(
                f.kernel_observable,
                "{} should be kernel-observable",
                f.name
            );
        }
    }
}

#[test]
fn parse_ruleset_with_enrichment_field_in_deny_fails() {
    assert!(matches!(
        parse_ruleset(&deny_doc("enrichment.pod_name")),
        Err(RuleError::DenyOnHeuristicOnly(_))
    ));
}

#[test]
fn parse_ruleset_with_kernel_observable_field_in_deny_succeeds() {
    assert!(parse_ruleset(&deny_doc("file.path")).is_ok());
}

#[test]
fn parse_ruleset_with_recursive_list_fails() {
    let doc = rep(
        "action: alert",
        "action: alert\n    lists:\n      - name: a\n        items: [a]",
    );
    assert!(matches!(
        parse_ruleset(&doc),
        Err(RuleError::SchemaValidationError(_))
    ));
}

#[test]
fn parse_ruleset_with_unbounded_regex_fails() {
    assert!(matches!(
        parse_ruleset(&regex_doc("\"(a+)+b\"")),
        Err(RuleError::RegexTooComplex(_))
    ));
}

#[test]
fn parse_ruleset_with_stale_engine_version_fails() {
    assert!(matches!(
        parse_ruleset(&rep(
            "engine_version: \"1.0.0\"",
            "engine_version: \"0.9.0\""
        )),
        Err(RuleError::EngineVersionMismatch(_))
    ));
}

#[test]
fn parse_ruleset_with_unsafe_deny_fails() {
    assert!(matches!(
        parse_ruleset(&deny_doc("enrichment.namespace")),
        Err(RuleError::DenyOnHeuristicOnly(_))
    ));
}
