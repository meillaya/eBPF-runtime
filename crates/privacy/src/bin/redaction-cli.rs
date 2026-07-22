// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `redaction-cli` — host-side smoke test for the privacy policy.
//!
//! ```text
//! redaction-cli apply <input.json> --policy <policy.json>
//!     Read a JSON-encoded decoded event and a JSON-encoded policy, validate
//!     the policy, apply redaction, and write the redacted event JSON to
//!     stdout. Exits 0 on success, 1 on an invalid policy or bad input.
//!
//! redaction-cli validate-policy <policy.json>
//!     Validate a JSON-encoded policy. Exits 0 if valid, 1 (with a diagnostic
//!     on stderr) if invalid.
//! ```
//!
//! The `<input.json>` is a [`privacy::DecodedRecord`] — the privacy layer's
//! bounded decoded view of an event's redactable fields. The CLI builds a
//! normalized event whose raw payload carries that record, runs the mandatory
//! [`privacy::apply_redaction`] stage, and prints the resulting
//! [`privacy::RedactedEvent`] as JSON.

use std::process::ExitCode;

use agent_core::{Kind, NormalizedEvent, RawEvent};
use privacy::{apply_redaction, decode_record, validate_policy, DecodedRecord, RedactionPolicy};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("apply") => cmd_apply(&args[2..]),
        Some("validate-policy") => cmd_validate_policy(&args[2..]),
        _ => {
            eprintln!(
                "usage: redaction-cli apply <input.json> --policy <policy.json>\n       \
                 redaction-cli validate-policy <policy.json>"
            );
            ExitCode::from(2)
        }
    }
}

fn cmd_apply(args: &[String]) -> ExitCode {
    let input_path = match args.first() {
        Some(p) => p.clone(),
        None => {
            eprintln!("error: apply requires <input.json>");
            return ExitCode::from(2);
        }
    };
    let policy_path = match flag_value(args, "--policy") {
        Some(p) => p,
        None => {
            eprintln!("error: apply requires --policy <policy.json>");
            return ExitCode::from(2);
        }
    };

    let record = match read_json::<DecodedRecord>(&input_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to read input event {input_path}: {e}");
            return ExitCode::from(1);
        }
    };
    let policy = match read_json::<RedactionPolicy>(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to read policy {policy_path}: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = validate_policy(&policy) {
        eprintln!("error: invalid policy: {e}");
        return ExitCode::from(1);
    }

    let event = build_event(&record);
    // Sanity: the decoded view round-trips from the event we built.
    let _ = decode_record(&event);
    let redacted = apply_redaction(&event, &policy);
    match serde_json::to_string_pretty(&redacted.to_json()) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to serialize redacted event: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_validate_policy(args: &[String]) -> ExitCode {
    let policy_path = match args.first() {
        Some(p) => p.clone(),
        None => {
            eprintln!("error: validate-policy requires <policy.json>");
            return ExitCode::from(2);
        }
    };
    let policy = match read_json::<RedactionPolicy>(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to read policy {policy_path}: {e}");
            return ExitCode::from(1);
        }
    };
    match validate_policy(&policy) {
        Ok(()) => {
            println!("policy OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: invalid policy: {e}");
            ExitCode::from(1)
        }
    }
}

/// Build a normalized event whose raw payload carries the decoded record. The
/// kind is inferred from the record (DNS when a DNS view is present, otherwise
/// a process exec result). Identity fields come from a synthetic record.
fn build_event(record: &DecodedRecord) -> NormalizedEvent {
    let wire = agent_core::synthetic_record(1);
    let mut event = agent_core::normalize_bytes(&wire).expect("synthetic record normalizes");
    event.kind = if record.dns.is_some() {
        Kind::DnsPacket
    } else {
        Kind::ProcessExecResult
    };
    event.raw = RawEvent {
        payload: serde_json::to_vec(record)
            .expect("decoded record serializes")
            .into_boxed_slice(),
    };
    event
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
