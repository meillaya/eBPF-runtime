// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side acceptance tests for the privacy / redaction layer (plan task 23).
//!
//! These tests prove:
//! * argv truncation at the 4 KiB bound with the truncation flag set;
//! * environment disabled by default (and preserved when enabled);
//! * exact / prefix / regex path and argument redaction;
//! * secret-pattern masking (API key, bearer token, AWS key);
//! * DNS field allowlist with rdata masked by default;
//! * every sink receives the identical redacted object and seeded tokens are
//!   absent from SQLite, Kafka, REST, WebSocket, and log outputs;
//! * regex time / size / complexity limits and catastrophic-regex rejection at
//!   startup;
//! * sink-bypass rejection, no raw logging, and no packet-payload persistence.

use std::fmt;
use std::sync::{Arc, Mutex};

use agent_core::{Kind, NormalizedEvent, RawEvent};
use privacy::sinks::{
    write_normalized_to_sinks, write_to_all_sinks, KafkaSinkAdapter, LogSinkAdapter, MultiSink,
    RestSinkAdapter, SinkAdapter, SqliteSinkAdapter, WebSocketSinkAdapter,
};
use privacy::{
    apply_redaction, apply_redaction_to_record, validate_policy, ArgumentPattern, DecodedDns,
    DecodedRecord, EventIdentity, PathPattern, RedactedEvent, RedactionPolicy, SecretPattern,
    TruncationFlags, ARGV_MAX_BYTES_DEFAULT,
};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Record};
use tracing::{Event as TracingEvent, Id, Metadata, Subscriber};

// ---------------------------------------------------------------------------
// Seeded tokens used across the absence assertions
// ---------------------------------------------------------------------------
const API_KEY: &str = "sk_live_SUPERSECRETKEY1234567890";
const BEARER_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.SECRETBEARERPAYLOAD.signature";
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET_PATH_FRAGMENT: &str = "SUPERSECRETPATH";
const SECRET_DNS_FRAGMENT: &str = "SECRETDNSRDATA999";
const SECRET_LOG_FRAGMENT: &str = "SECRETTOKEN1234567890";
const RAW_PACKET_FRAGMENT: &str = "RAWPACKETPAYLOAD999";
const RAW_LOG_SECRET: &str = "RAWSECRET_XYZ_9876543210";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Build a normalized event whose raw payload carries the decoded record. The
/// kind is inferred from the record (DNS when a DNS view is present).
fn event_with_record(kind: Kind, record: &DecodedRecord) -> NormalizedEvent {
    let wire = agent_core::synthetic_record(1);
    let mut event = agent_core::normalize_bytes(&wire).expect("synthetic record normalizes");
    event.kind = kind;
    event.raw = RawEvent {
        payload: serde_json::to_vec(record)
            .expect("decoded record serializes")
            .into_boxed_slice(),
    };
    event
}

fn dns_record(rdata: Vec<&str>) -> DecodedRecord {
    DecodedRecord {
        dns: Some(DecodedDns {
            qname: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            an_count: 1,
            rdata: rdata.into_iter().map(String::from).collect(),
        }),
        ..Default::default()
    }
}

/// A multi-sink with all five sink adapters (SQLite, Kafka, REST, WebSocket,
/// log).
fn all_sinks() -> MultiSink {
    let mut multi = MultiSink::new();
    multi.add(Box::new(SqliteSinkAdapter::new()));
    multi.add(Box::new(KafkaSinkAdapter::new()));
    multi.add(Box::new(RestSinkAdapter::new(
        "https://collector.local/v1/events",
    )));
    multi.add(Box::new(WebSocketSinkAdapter::new()));
    multi.add(Box::new(LogSinkAdapter::new()));
    multi
}

/// True iff any recorded sink output contains the given token.
fn any_sink_contains(multi: &MultiSink, token: &str) -> bool {
    multi
        .recorded()
        .iter()
        .flat_map(|(_, records)| records.iter())
        .any(|bytes| String::from_utf8_lossy(bytes).contains(token))
}

fn argv_lossy(event: &RedactedEvent) -> String {
    event
        .argv_bytes
        .as_ref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// argv / env
// ---------------------------------------------------------------------------

#[test]
fn argv_truncation_at_4096_bytes_sets_truncation_flag() {
    let record = DecodedRecord {
        argv: vec!["a".repeat(5000)],
        ..Default::default()
    };
    let policy = RedactionPolicy::default();
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    let argv = redacted.argv_bytes.as_ref().expect("argv present");
    assert_eq!(argv.len(), ARGV_MAX_BYTES_DEFAULT);
    assert!(redacted.truncation_flags.argv_truncated);
}

#[test]
fn env_disabled_by_default_clears_env_field() {
    let record = DecodedRecord {
        env: vec!["PATH=/usr/bin".to_string(), "HOME=/root".to_string()],
        ..Default::default()
    };
    let policy = RedactionPolicy::default();
    assert!(!policy.env_enabled);
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    assert!(redacted.env.is_none());
}

#[test]
fn env_enabled_preserves_env_field() {
    let record = DecodedRecord {
        env: vec!["FOO=bar".to_string()],
        ..Default::default()
    };
    let policy = RedactionPolicy {
        env_enabled: true,
        ..Default::default()
    };
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.env.as_deref(), Some(&b"FOO=bar"[..]));
}

// ---------------------------------------------------------------------------
// path redaction
// ---------------------------------------------------------------------------

#[test]
fn path_exact_pattern_redacts_matching_path() {
    let record = DecodedRecord {
        path: "/etc/shadow".to_string(),
        ..Default::default()
    };
    let policy = RedactionPolicy {
        path_patterns: vec![PathPattern::Exact("/etc/shadow".to_string())],
        ..Default::default()
    };
    let event = event_with_record(Kind::FileOpen, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.path.as_deref(), Some("[REDACTED]"));
    assert!(redacted.truncation_flags.path_truncated);
}

#[test]
fn path_prefix_pattern_redacts_matching_prefix() {
    let record = DecodedRecord {
        path: "/secret/data.txt".to_string(),
        ..Default::default()
    };
    let policy = RedactionPolicy {
        path_patterns: vec![PathPattern::Prefix("/secret/".to_string())],
        ..Default::default()
    };
    let event = event_with_record(Kind::FileOpen, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.path.as_deref(), Some("[REDACTED]"));
}

#[test]
fn path_regex_pattern_redacts_matching_regex() {
    let record = DecodedRecord {
        path: "/tmp/api.key".to_string(),
        ..Default::default()
    };
    let policy = RedactionPolicy {
        path_patterns: vec![PathPattern::Regex(r"^/tmp/.*\.key$".to_string())],
        ..Default::default()
    };
    validate_policy(&policy).expect("regex policy is valid");
    let event = event_with_record(Kind::FileOpen, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.path.as_deref(), Some("[REDACTED]"));
}

// ---------------------------------------------------------------------------
// argument redaction
// ---------------------------------------------------------------------------

#[test]
fn argument_exact_pattern_redacts_matching_argument() {
    let record = DecodedRecord {
        arguments: vec!["--password".to_string(), "hunter2".to_string()],
        ..Default::default()
    };
    let policy = RedactionPolicy {
        argument_patterns: vec![ArgumentPattern::Exact("--password".to_string())],
        ..Default::default()
    };
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.arguments[0], "[REDACTED]");
    assert_eq!(redacted.arguments[1], "hunter2");
}

#[test]
fn argument_prefix_pattern_redacts_matching_prefix() {
    let record = DecodedRecord {
        arguments: vec!["--token=abc123".to_string()],
        ..Default::default()
    };
    let policy = RedactionPolicy {
        argument_patterns: vec![ArgumentPattern::Prefix("--token=".to_string())],
        ..Default::default()
    };
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.arguments[0], "[REDACTED]");
}

#[test]
fn argument_regex_pattern_redacts_matching_regex() {
    let record = DecodedRecord {
        arguments: vec!["--secret-key".to_string()],
        ..Default::default()
    };
    let policy = RedactionPolicy {
        argument_patterns: vec![ArgumentPattern::Regex(r"^--secret-.*".to_string())],
        ..Default::default()
    };
    validate_policy(&policy).expect("regex policy is valid");
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.arguments[0], "[REDACTED]");
}

// ---------------------------------------------------------------------------
// secret masking
// ---------------------------------------------------------------------------

#[test]
fn secret_pattern_masks_api_key() {
    let record = DecodedRecord {
        argv: vec![format!("--key={API_KEY}")],
        ..Default::default()
    };
    let policy = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex(
            r"sk_(live|test)_[0-9A-Za-z]{16,}".to_string(),
        )],
        ..Default::default()
    };
    validate_policy(&policy).expect("regex policy is valid");
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    let argv = argv_lossy(&redacted);
    assert!(argv.contains("[MASKED]"), "argv was: {argv}");
    assert!(!argv.contains(API_KEY), "argv leaked the API key: {argv}");
}

#[test]
fn secret_pattern_masks_bearer_token() {
    let record = DecodedRecord {
        message: format!("Authorization: Bearer {BEARER_TOKEN}"),
        ..Default::default()
    };
    let policy = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex(
            r"(?i)bearer\s+[0-9A-Za-z._\-]{16,}".to_string(),
        )],
        ..Default::default()
    };
    validate_policy(&policy).expect("regex policy is valid");
    let event = event_with_record(Kind::NetworkConnect, &record);
    let redacted = apply_redaction(&event, &policy);
    let message = redacted.message.clone().unwrap_or_default();
    assert!(message.contains("[MASKED]"), "message was: {message}");
    assert!(
        !message.contains(BEARER_TOKEN),
        "message leaked the bearer token: {message}"
    );
}

#[test]
fn secret_pattern_masks_aws_key() {
    let record = DecodedRecord {
        argv: vec![AWS_KEY.to_string()],
        ..Default::default()
    };
    let policy = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex(r"AKIA[0-9A-Z]{16}".to_string())],
        ..Default::default()
    };
    validate_policy(&policy).expect("regex policy is valid");
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    let argv = argv_lossy(&redacted);
    assert!(argv.contains("[MASKED]"), "argv was: {argv}");
    assert!(!argv.contains(AWS_KEY), "argv leaked the AWS key: {argv}");
}

// ---------------------------------------------------------------------------
// DNS field allowlist
// ---------------------------------------------------------------------------

#[test]
fn dns_field_allowlist_masks_rdata_by_default() {
    let record = dns_record(vec!["93.184.216.34"]);
    let policy = RedactionPolicy::default();
    assert!(!policy.dns_field_allowlist.rdata);
    let event = event_with_record(Kind::DnsPacket, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.dns_rdata.as_deref(), Some(&b"[MASKED]"[..]));
    assert!(redacted.truncation_flags.dns_truncated);
}

#[test]
fn dns_field_allowlist_preserves_qname_qtype_qclass_an_count() {
    let record = dns_record(vec!["93.184.216.34"]);
    let policy = RedactionPolicy::default();
    let event = event_with_record(Kind::DnsPacket, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.dns_qname.as_deref(), Some("example.com"));
    assert_eq!(redacted.dns_qtype, Some(1));
    assert_eq!(redacted.dns_qclass, Some(1));
    assert_eq!(redacted.dns_an_count, Some(1));
}

#[test]
fn dns_field_allowlist_preserves_rdata_when_enabled() {
    let record = dns_record(vec!["93.184.216.34"]);
    let mut policy = RedactionPolicy::default();
    policy.dns_field_allowlist.rdata = true;
    let event = event_with_record(Kind::DnsPacket, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.dns_rdata.as_deref(), Some(&b"93.184.216.34"[..]));
    assert!(!redacted.truncation_flags.dns_truncated);
}

// ---------------------------------------------------------------------------
// sinks: same redacted object + seeded-token absence
// ---------------------------------------------------------------------------

#[test]
fn all_sinks_receive_same_redacted_event() {
    let record = DecodedRecord {
        argv: vec![
            "/usr/bin/curl".to_string(),
            "https://example.com".to_string(),
        ],
        path: "/usr/bin/curl".to_string(),
        message: "exec curl".to_string(),
        ..Default::default()
    };
    let policy = RedactionPolicy::with_default_secrets();
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    let canonical = redacted.to_json_bytes().expect("serializes");

    let mut sqlite = SqliteSinkAdapter::new();
    let mut kafka = KafkaSinkAdapter::new();
    let mut rest = RestSinkAdapter::new("https://collector.local/v1/events");
    let mut ws = WebSocketSinkAdapter::new();
    let mut log = LogSinkAdapter::new();
    for sink in [
        &mut sqlite as &mut dyn SinkAdapter,
        &mut kafka as &mut dyn SinkAdapter,
        &mut rest as &mut dyn SinkAdapter,
        &mut ws as &mut dyn SinkAdapter,
        &mut log as &mut dyn SinkAdapter,
    ] {
        sink.write_redacted(&redacted).expect("write succeeds");
        assert_eq!(
            sink.recorded_bytes(),
            vec![canonical.clone()],
            "sink {} did not receive the canonical redacted object",
            sink.name()
        );
    }
}

#[test]
fn seeded_token_in_argv_is_absent_from_all_sinks() {
    let record = DecodedRecord {
        argv: vec![format!("--key={API_KEY}")],
        ..Default::default()
    };
    let policy = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex(
            r"sk_(live|test)_[0-9A-Za-z]{16,}".to_string(),
        )],
        ..Default::default()
    };
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    let mut multi = all_sinks();
    write_to_all_sinks(&redacted, &mut multi).expect("all sinks accept the redacted event");
    assert!(!any_sink_contains(&multi, API_KEY));
    assert!(any_sink_contains(&multi, "[MASKED]"));
}

#[test]
fn seeded_token_in_path_is_absent_from_all_sinks() {
    let record = DecodedRecord {
        path: format!("/secret/{SECRET_PATH_FRAGMENT}"),
        ..Default::default()
    };
    let policy = RedactionPolicy {
        path_patterns: vec![PathPattern::Prefix("/secret/".to_string())],
        ..Default::default()
    };
    let event = event_with_record(Kind::FileOpen, &record);
    let redacted = apply_redaction(&event, &policy);
    let mut multi = all_sinks();
    write_to_all_sinks(&redacted, &mut multi).expect("all sinks accept the redacted event");
    assert!(!any_sink_contains(&multi, SECRET_PATH_FRAGMENT));
    assert!(any_sink_contains(&multi, "[REDACTED]"));
}

#[test]
fn seeded_token_in_dns_is_absent_from_all_sinks() {
    let record = dns_record(vec![SECRET_DNS_FRAGMENT]);
    let policy = RedactionPolicy::default();
    let event = event_with_record(Kind::DnsPacket, &record);
    let redacted = apply_redaction(&event, &policy);
    let mut multi = all_sinks();
    write_to_all_sinks(&redacted, &mut multi).expect("all sinks accept the redacted event");
    assert!(!any_sink_contains(&multi, SECRET_DNS_FRAGMENT));
    assert!(any_sink_contains(&multi, "[MASKED]"));
}

#[test]
fn seeded_token_in_log_is_absent_from_all_sinks() {
    let record = DecodedRecord {
        message: format!("token={SECRET_LOG_FRAGMENT}"),
        ..Default::default()
    };
    let policy = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex(r"(?i)token[=:]\s*\S{8,}".to_string())],
        ..Default::default()
    };
    let event = event_with_record(Kind::NetworkConnect, &record);
    let redacted = apply_redaction(&event, &policy);
    let mut multi = all_sinks();
    write_to_all_sinks(&redacted, &mut multi).expect("all sinks accept the redacted event");
    assert!(!any_sink_contains(&multi, SECRET_LOG_FRAGMENT));
    // The log sink specifically must not carry the token.
    let log_records = multi
        .recorded()
        .into_iter()
        .find(|(name, _)| *name == "log")
        .expect("log sink present")
        .1;
    assert!(!log_records.is_empty());
    for bytes in &log_records {
        assert!(!String::from_utf8_lossy(bytes).contains(SECRET_LOG_FRAGMENT));
    }
}

// ---------------------------------------------------------------------------
// startup validation: regex time / size / complexity limits
// ---------------------------------------------------------------------------

#[test]
fn regex_time_limit_enforced_at_startup() {
    // A catastrophic nested-quantifier regex is rejected via the RegexTooSlow
    // path before startup — this is the time-limit defense (the nested
    // quantifier scan is the first line of defense; the compile/match timing
    // checks in validate_regex are the runtime safety net).
    let policy = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex("(a+)+$".to_string())],
        ..Default::default()
    };
    let err = validate_policy(&policy).expect_err("catastrophic regex must be rejected");
    assert!(
        matches!(err, privacy::PolicyValidationError::RegexTooSlow(_)),
        "expected RegexTooSlow, got {err:?}"
    );
    // A benign regex passes within the time limits.
    let ok = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex(r"AKIA[0-9A-Z]{16}".to_string())],
        ..Default::default()
    };
    assert!(validate_policy(&ok).is_ok());
}

#[test]
fn regex_size_limit_enforced_at_startup() {
    let huge = format!("^{}$", "a".repeat(2000));
    let policy = RedactionPolicy {
        path_patterns: vec![PathPattern::Regex(huge)],
        ..Default::default()
    };
    let err = validate_policy(&policy).expect_err("oversized regex must be rejected");
    assert!(
        matches!(err, privacy::PolicyValidationError::RegexTooLarge(_)),
        "expected RegexTooLarge, got {err:?}"
    );
}

#[test]
fn regex_complexity_limit_enforced_at_startup() {
    // 70 capture groups exceeds the 64-group complexity limit.
    let complex = "a"
        .repeat(70)
        .chars()
        .map(|c| format!("({c})"))
        .collect::<String>();
    let policy = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex(complex)],
        ..Default::default()
    };
    let err = validate_policy(&policy).expect_err("over-complex regex must be rejected");
    assert!(
        matches!(err, privacy::PolicyValidationError::RegexTooComplex(_)),
        "expected RegexTooComplex, got {err:?}"
    );
}

#[test]
fn malicious_regex_rejected_before_startup() {
    // The classic catastrophic-backtracking regex from the failure QA scenario.
    let policy = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex("(a+)+$".to_string())],
        ..Default::default()
    };
    let err = validate_policy(&policy).expect_err("(a+)+$ must be rejected before startup");
    let msg = err.to_string();
    assert!(
        msg.contains("(a+)+$"),
        "diagnostic must name the regex: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("catastrophic"),
        "diagnostic must flag it as catastrophic: {msg}"
    );
}

// ---------------------------------------------------------------------------
// no bypass / no raw logging / no payload persistence
// ---------------------------------------------------------------------------

#[test]
fn sink_bypass_attempt_rejected() {
    let record = DecodedRecord {
        argv: vec![API_KEY.to_string()],
        ..Default::default()
    };
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let mut multi = all_sinks();
    let result = write_normalized_to_sinks(&event, &mut multi);
    assert!(
        matches!(result, Err(privacy::sinks::SinkError::BypassRejected(_))),
        "raw write must be rejected, got {result:?}"
    );
    // No sink received anything via the rejected bypass path.
    for (_, records) in multi.recorded() {
        assert!(records.is_empty());
    }
}

#[test]
fn raw_pre_redaction_record_never_logged() {
    // The raw payload carries a secret; apply_redaction must never log it.
    let record = DecodedRecord {
        message: RAW_LOG_SECRET.to_string(),
        argv: vec![RAW_LOG_SECRET.to_string()],
        ..Default::default()
    };
    let policy = RedactionPolicy {
        secret_patterns: vec![SecretPattern::Regex(
            r"RAWSECRET_[A-Z0-9_]{10,}".to_string(),
        )],
        ..Default::default()
    };
    let event = event_with_record(Kind::ProcessExecResult, &record);

    let capture = Capture::default();
    let subscriber = CaptureSubscriber(capture.clone());
    tracing::subscriber::with_default(subscriber, || {
        // Callsite Interest is cached process-wide; other tests register this
        // debug! callsite under the no-op subscriber (Interest::never). Rebuild
        // the cache against this subscriber (retrying to win the parallel-test
        // race) so the redaction event is actually dispatched here.
        for _ in 0..32 {
            tracing::callsite::rebuild_interest_cache();
            let _ = apply_redaction(&event, &policy);
            if !capture.joined().is_empty() {
                break;
            }
        }
    });

    let logged = capture.joined();
    // The debug event fired (redaction metadata was logged) ...
    assert!(
        !logged.is_empty(),
        "expected a redaction debug event to be captured"
    );
    // ... but it never contains the raw pre-redaction secret.
    assert!(
        !logged.contains(RAW_LOG_SECRET),
        "raw pre-redaction secret was logged: {logged}"
    );
}

#[test]
fn packet_payload_never_persisted() {
    // DNS rdata (packet payload) must never reach a sink.
    let record = dns_record(vec![RAW_PACKET_FRAGMENT]);
    let policy = RedactionPolicy::default();
    let event = event_with_record(Kind::DnsPacket, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.dns_rdata.as_deref(), Some(&b"[MASKED]"[..]));

    let mut multi = all_sinks();
    write_to_all_sinks(&redacted, &mut multi).expect("all sinks accept the redacted event");
    assert!(!any_sink_contains(&multi, RAW_PACKET_FRAGMENT));

    // The serialized redacted event has no "raw" payload field at all.
    let json = redacted.to_json();
    assert!(
        json.get("raw").is_none(),
        "redacted event must not carry a raw field"
    );
    let serialized = serde_json::to_string(&json).expect("serializes");
    assert!(!serialized.contains(RAW_PACKET_FRAGMENT));
}

#[test]
fn redacted_event_shape_is_stable_across_sinks() {
    let record = DecodedRecord {
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo hi".to_string(),
        ],
        path: "/bin/sh".to_string(),
        arguments: vec!["-c".to_string()],
        dns: Some(DecodedDns {
            qname: "svc.local".to_string(),
            qtype: 28,
            qclass: 1,
            an_count: 2,
            rdata: vec!["fe80::1".to_string()],
        }),
        message: "exec sh".to_string(),
        ..Default::default()
    };
    let policy = RedactionPolicy::with_default_secrets();
    let event = event_with_record(Kind::DnsPacket, &record);
    let redacted = apply_redaction(&event, &policy);

    let mut multi = all_sinks();
    write_to_all_sinks(&redacted, &mut multi).expect("all sinks accept the redacted event");
    let recorded = multi.recorded();
    assert_eq!(recorded.len(), 5, "five sinks configured");
    let first = &recorded[0].1;
    assert_eq!(first.len(), 1, "each sink received exactly one record");
    for (name, records) in &recorded {
        assert_eq!(records.len(), 1, "sink {name} received exactly one record");
        assert_eq!(records, first, "sink {name} received a different shape");
    }
}

// ---------------------------------------------------------------------------
// property tests
// ---------------------------------------------------------------------------

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn seeded_argv_token_is_always_absent_and_argv_bounded(
            extra in proptest::collection::vec("[a-zA-Z0-9]{1,16}", 0..6),
            pad in 0usize..6000,
        ) {
            let mut argv = extra;
            argv.push(format!("--key={API_KEY}"));
            argv.push("x".repeat(pad));
            let record = DecodedRecord { argv, ..Default::default() };
            let policy = RedactionPolicy {
                secret_patterns: vec![SecretPattern::Regex(
                    r"sk_(live|test)_[0-9A-Za-z]{16,}".to_string(),
                )],
                ..Default::default()
            };
            let event = event_with_record(Kind::ProcessExecResult, &record);
            let redacted = apply_redaction(&event, &policy);
            let argv_str = argv_lossy(&redacted);
            prop_assert!(!argv_str.contains(API_KEY));
            prop_assert!(redacted.argv_bytes.as_ref().unwrap().len() <= ARGV_MAX_BYTES_DEFAULT);
        }

        #[test]
        fn all_sinks_receive_identical_bytes_for_arbitrary_records(
            path in "/[a-z]{0,12}",
            message in "[a-zA-Z0-9 ]{0,32}",
        ) {
            let record = DecodedRecord {
                argv: vec!["prog".to_string()],
                path,
                message,
                ..Default::default()
            };
            let policy = RedactionPolicy::with_default_secrets();
            let event = event_with_record(Kind::ProcessExecResult, &record);
            let redacted = apply_redaction(&event, &policy);
            let mut multi = all_sinks();
            write_to_all_sinks(&redacted, &mut multi).unwrap();
            let recorded = multi.recorded();
            let first = recorded[0].1.clone();
            for (_, records) in &recorded {
                prop_assert_eq!(records, &first);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Capturing tracing subscriber (proves apply_redaction never logs raw input)
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

impl Capture {
    fn joined(&self) -> String {
        self.0.lock().expect("capture lock").join("\n")
    }
}

impl Visit for Capture {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .lock()
            .expect("capture lock")
            .push(format!("{}={value:?}", field.name()));
    }
}

struct CaptureSubscriber(Capture);

impl Subscriber for CaptureSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }
    fn register_callsite(
        &self,
        _metadata: &'static Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn event(&self, event: &TracingEvent<'_>) {
        let mut visitor = self.0.clone();
        event.record(&mut visitor);
    }
    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

// Referenced to keep the import used across cfg variations.
#[allow(dead_code)]
fn _identity_helper(event: &NormalizedEvent, policy: &RedactionPolicy) -> RedactedEvent {
    let record = privacy::decode_record(event);
    let identity = EventIdentity::from_event(event);
    apply_redaction_to_record(&record, &identity, policy)
}

#[allow(dead_code)]
fn _flags_default() -> TruncationFlags {
    TruncationFlags::default()
}
