// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Edge-case acceptance tests for the privacy / redaction layer (plan task 23).

use agent_core::{Kind, NormalizedEvent, RawEvent};
use privacy::sinks::{
    write_to_all_sinks, KafkaSinkAdapter, MultiSink, SinkAdapter, SinkError, SqliteSinkAdapter,
};
use privacy::{
    apply_redaction, apply_redaction_to_record, ArgumentPattern, DecodedDns, DecodedRecord,
    EventIdentity, PathPattern, RedactedEvent, RedactionPolicy, SecretPattern,
};

const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const SK_LIVE: &str = "sk_live_ABCDEFGHIJ1234567890";

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

fn argv_lossy(event: &RedactedEvent) -> String {
    event
        .argv_bytes
        .as_ref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

#[test]
fn empty_argv_is_preserved_as_empty_not_truncated() {
    let record = DecodedRecord {
        argv: Vec::new(),
        ..Default::default()
    };
    let policy = RedactionPolicy::default();
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.argv_bytes.as_deref(), Some(&[][..]));
    assert!(!redacted.truncation_flags.argv_truncated);
}

#[test]
fn empty_path_is_preserved_as_empty_not_redacted() {
    let record = DecodedRecord {
        path: String::new(),
        ..Default::default()
    };
    let policy = RedactionPolicy::default();
    let event = event_with_record(Kind::FileOpen, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.path.as_deref(), Some(""));
    assert!(!redacted.truncation_flags.path_truncated);
}

#[test]
fn dns_event_with_no_rdata_is_preserved() {
    let record = DecodedRecord {
        dns: Some(DecodedDns {
            qname: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            an_count: 0,
            rdata: Vec::new(),
        }),
        ..Default::default()
    };
    let policy = RedactionPolicy::default();
    let event = event_with_record(Kind::DnsPacket, &record);
    let redacted = apply_redaction(&event, &policy);
    // Empty rdata is preserved as empty, not fabricated into [MASKED].
    assert_eq!(redacted.dns_rdata.as_deref(), Some(&[][..]));
    assert!(!redacted.truncation_flags.dns_truncated);
}

#[test]
fn dns_event_with_rdata_is_masked_by_default() {
    let record = DecodedRecord {
        dns: Some(DecodedDns {
            qname: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            an_count: 1,
            rdata: vec!["1.2.3.4".to_string()],
        }),
        ..Default::default()
    };
    let policy = RedactionPolicy::default();
    let event = event_with_record(Kind::DnsPacket, &record);
    let redacted = apply_redaction(&event, &policy);
    assert_eq!(redacted.dns_rdata.as_deref(), Some(&b"[MASKED]"[..]));
    assert!(redacted.truncation_flags.dns_truncated);
}

#[test]
fn multiple_secret_patterns_applied_in_order() {
    let record = DecodedRecord {
        message: format!("key={AWS_KEY} and {SK_LIVE}"),
        ..Default::default()
    };
    let policy = RedactionPolicy {
        secret_patterns: vec![
            SecretPattern::Regex(r"AKIA[0-9A-Z]{16}".to_string()),
            SecretPattern::Regex(r"sk_(live|test)_[0-9A-Za-z]{16,}".to_string()),
        ],
        ..Default::default()
    };
    let event = event_with_record(Kind::NetworkConnect, &record);
    let redacted = apply_redaction(&event, &policy);
    let message = redacted.message.clone().unwrap_or_default();
    assert_eq!(
        message.matches("[MASKED]").count(),
        2,
        "both secrets must be masked: {message}"
    );
    assert!(!message.contains(AWS_KEY));
    assert!(!message.contains(SK_LIVE));
}

#[test]
fn overlapping_path_and_argument_patterns_applied_independently() {
    let record = DecodedRecord {
        path: "/secret/file".to_string(),
        arguments: vec!["--secret-arg".to_string(), "safe".to_string()],
        ..Default::default()
    };
    let policy = RedactionPolicy {
        path_patterns: vec![PathPattern::Prefix("/secret/".to_string())],
        argument_patterns: vec![ArgumentPattern::Prefix("--secret-".to_string())],
        ..Default::default()
    };
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);
    // Path redaction and argument redaction act on their own fields only.
    assert_eq!(redacted.path.as_deref(), Some("[REDACTED]"));
    assert_eq!(redacted.arguments[0], "[REDACTED]");
    assert_eq!(redacted.arguments[1], "safe");
}

#[test]
fn truncation_flags_set_correctly_for_all_truncated_fields() {
    let record = DecodedRecord {
        argv: vec!["a".repeat(5000)],
        path: "/secret/blob".to_string(),
        dns: Some(DecodedDns {
            qname: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            an_count: 1,
            rdata: vec!["9.9.9.9".to_string()],
        }),
        ..Default::default()
    };
    let policy = RedactionPolicy {
        path_patterns: vec![PathPattern::Prefix("/secret/".to_string())],
        ..Default::default()
    };
    let event = event_with_record(Kind::DnsPacket, &record);
    let redacted = apply_redaction(&event, &policy);
    assert!(redacted.truncation_flags.argv_truncated, "argv flag");
    assert!(redacted.truncation_flags.path_truncated, "path flag");
    assert!(redacted.truncation_flags.dns_truncated, "dns flag");
}

#[test]
fn redaction_is_idempotent() {
    let record = DecodedRecord {
        argv: vec![AWS_KEY.to_string()],
        path: "/secret/x".to_string(),
        arguments: vec!["--token=abc".to_string()],
        dns: Some(DecodedDns {
            qname: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            an_count: 1,
            rdata: vec!["9.9.9.9".to_string()],
        }),
        message: "plain message".to_string(),
        ..Default::default()
    };
    let policy = RedactionPolicy {
        path_patterns: vec![PathPattern::Prefix("/secret/".to_string())],
        argument_patterns: vec![ArgumentPattern::Prefix("--token=".to_string())],
        secret_patterns: vec![
            SecretPattern::Regex(r"AKIA[0-9A-Z]{16}".to_string()),
            SecretPattern::Regex(r"sk_(live|test)_[0-9A-Za-z]{16,}".to_string()),
        ],
        ..Default::default()
    };
    let event = event_with_record(Kind::DnsPacket, &record);
    let identity = EventIdentity::from_event(&event);

    let r1 = apply_redaction(&event, &policy);
    let once = r1.to_decoded_record();
    let r2 = apply_redaction_to_record(&once, &identity, &policy);
    let twice = r2.to_decoded_record();

    // Re-redacting an already-redacted record is a fixed point on the redacted
    // data: no raw material is re-introduced and the projections are stable.
    assert_eq!(
        once, twice,
        "redaction must be idempotent on the redacted data"
    );
    assert!(!argv_lossy(&r2).contains(AWS_KEY));
    assert_eq!(r2.path.as_deref(), Some("[REDACTED]"));
}

#[test]
fn redaction_is_deterministic() {
    let record = DecodedRecord {
        argv: vec![
            "/usr/bin/curl".to_string(),
            "https://example.com".to_string(),
        ],
        path: "/usr/bin/curl".to_string(),
        arguments: vec!["--silent".to_string()],
        dns: Some(DecodedDns {
            qname: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
            an_count: 1,
            rdata: vec!["93.184.216.34".to_string()],
        }),
        message: "exec curl https://example.com".to_string(),
        ..Default::default()
    };
    let policy = RedactionPolicy::with_default_secrets();
    let event = event_with_record(Kind::DnsPacket, &record);
    let r1 = apply_redaction(&event, &policy);
    let r2 = apply_redaction(&event, &policy);
    assert_eq!(r1, r2, "redaction of the same input must be deterministic");
    assert_eq!(r1.to_json(), r2.to_json());
}

/// A sink that always fails, used to prove error propagation does not stop
/// fan-out to the other sinks.
struct FailingSink;

impl SinkAdapter for FailingSink {
    fn write_redacted(&mut self, _event: &RedactedEvent) -> Result<(), SinkError> {
        Err(SinkError::SinkFailed("simulated sink outage".to_string()))
    }
    fn name(&self) -> &'static str {
        "failing"
    }
    fn recorded_bytes(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

#[test]
fn sink_error_propagates_but_other_sinks_still_receive_event() {
    let record = DecodedRecord {
        argv: vec!["/bin/true".to_string()],
        ..Default::default()
    };
    let policy = RedactionPolicy::default();
    let event = event_with_record(Kind::ProcessExecResult, &record);
    let redacted = apply_redaction(&event, &policy);

    let mut multi = MultiSink::new();
    multi.add(Box::new(SqliteSinkAdapter::new()));
    multi.add(Box::new(FailingSink));
    multi.add(Box::new(KafkaSinkAdapter::new()));

    let result = write_to_all_sinks(&redacted, &mut multi);
    assert!(
        matches!(result, Err(SinkError::SinkFailed(_))),
        "the failing sink's error must propagate, got {result:?}"
    );

    let recorded = multi.recorded();
    let sqlite = recorded
        .iter()
        .find(|(n, _)| *n == "sqlite")
        .expect("sqlite")
        .1
        .clone();
    let kafka = recorded
        .iter()
        .find(|(n, _)| *n == "kafka")
        .expect("kafka")
        .1
        .clone();
    let failing = recorded
        .iter()
        .find(|(n, _)| *n == "failing")
        .expect("failing")
        .1
        .clone();
    assert_eq!(sqlite.len(), 1, "sqlite still received the event");
    assert_eq!(kafka.len(), 1, "kafka still received the event");
    assert_eq!(failing.len(), 0, "failing sink recorded nothing");
    assert_eq!(
        sqlite, kafka,
        "both healthy sinks received the identical object"
    );
}
