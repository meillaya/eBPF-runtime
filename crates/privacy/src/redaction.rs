// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The mandatory redaction / data-minimization stage.

use agent_core::NormalizedEvent;

use super::policy::*;
use super::redacted_event::RedactedEvent;
use super::types::*;
use super::{MASKED, REDACTED};

/// The mandatory normalization stage. Decodes the bounded [`DecodedRecord`]
/// from the event, applies every redaction / minimization rule in `policy`, and
/// returns a [`RedactedEvent`] that is guaranteed to carry no raw pre-redaction
/// data.
pub fn apply_redaction(event: &NormalizedEvent, policy: &RedactionPolicy) -> RedactedEvent {
    let record = decode_record(event);
    let identity = EventIdentity::from_event(event);
    let redacted = apply_redaction_to_record(&record, &identity, policy);
    tracing::debug!(
        event_id = %super::redacted_event::hex(&redacted.event_id.0),
        argv_truncated = redacted.truncation_flags.argv_truncated,
        path_truncated = redacted.truncation_flags.path_truncated,
        dns_truncated = redacted.truncation_flags.dns_truncated,
        env_present = redacted.env.is_some(),
        "applied redaction policy"
    );
    redacted
}

/// Apply the redaction policy to an already-decoded record and identity.
pub fn apply_redaction_to_record(
    record: &DecodedRecord,
    identity: &EventIdentity,
    policy: &RedactionPolicy,
) -> RedactedEvent {
    let compiled = compile_patterns(policy);
    let mut flags = TruncationFlags::default();

    let masked_argv: Vec<String> = record
        .argv
        .iter()
        .map(|t| mask_secrets(t, &compiled.secret_regex))
        .collect();
    let argv_joined = join_nul(&masked_argv);
    let (argv_bytes, argv_trunc) = truncate_bytes(&argv_joined, policy.argv_max_bytes);
    if argv_trunc && policy.truncation_flags.argv_truncated {
        flags.argv_truncated = true;
    }

    let env = if policy.env_enabled {
        let masked_env: Vec<String> = record
            .env
            .iter()
            .map(|t| mask_secrets(t, &compiled.secret_regex))
            .collect();
        Some(join_nul(&masked_env))
    } else {
        None
    };

    let (path, path_redacted) = if matches_path(&record.path, policy, &compiled) {
        (REDACTED.to_string(), true)
    } else {
        (mask_secrets(&record.path, &compiled.secret_regex), false)
    };
    if path_redacted && policy.truncation_flags.path_truncated {
        flags.path_truncated = true;
    }

    let arguments: Vec<String> = record
        .arguments
        .iter()
        .map(|a| {
            if matches_argument(a, policy, &compiled) {
                REDACTED.to_string()
            } else {
                mask_secrets(a, &compiled.secret_regex)
            }
        })
        .collect();

    let (dns_qname, dns_qtype, dns_qclass, dns_an_count, dns_rdata, dns_trunc) = match &record.dns {
        Some(dns) => {
            let qname = policy
                .dns_field_allowlist
                .qname
                .then(|| mask_secrets(&dns.qname, &compiled.secret_regex));
            let qtype = policy.dns_field_allowlist.qtype.then_some(dns.qtype);
            let qclass = policy.dns_field_allowlist.qclass.then_some(dns.qclass);
            let an_count = policy.dns_field_allowlist.an_count.then_some(dns.an_count);
            let rdata_joined = join_nul(&dns.rdata);
            let (rdata, truncated) = if rdata_joined.is_empty() {
                (Some(Vec::new()), false)
            } else if policy.dns_field_allowlist.rdata {
                (
                    Some(mask_secrets(&lossy(&rdata_joined), &compiled.secret_regex).into_bytes()),
                    false,
                )
            } else {
                (Some(MASKED.as_bytes().to_vec()), true)
            };
            (qname, qtype, qclass, an_count, rdata, truncated)
        }
        None => (None, None, None, None, None, false),
    };
    if dns_trunc && policy.truncation_flags.dns_truncated {
        flags.dns_truncated = true;
    }

    let message = mask_secrets(&record.message, &compiled.secret_regex);

    RedactedEvent {
        kind: identity.kind,
        event_id: identity.event_id,
        sequence: identity.sequence,
        monotonic_ns: identity.monotonic_ns,
        wall_clock: identity.wall_clock.clone(),
        pid_tgid: identity.pid_tgid,
        task_start_ns: identity.task_start_ns,
        cgroup_id: identity.cgroup_id,
        boot_id: identity.boot_id,
        namespaces: identity.namespaces.clone(),
        identity: identity.identity.clone(),
        priority: identity.priority,
        attribution_scope: identity.attribution_scope.clone(),
        argv_bytes: Some(argv_bytes),
        env,
        path: Some(path),
        arguments,
        dns_qname,
        dns_qtype,
        dns_qclass,
        dns_an_count,
        dns_rdata,
        message: Some(message),
        truncation_flags: flags,
    }
}

/// Label an enrichment attribution scope for export.
pub fn scope_label(scope: &enrichment::AttributionScope) -> String {
    scope.to_string()
}

// ---------------------------------------------------------------------------
// Redaction helpers
// ---------------------------------------------------------------------------

pub(crate) struct CompiledPatterns {
    pub(crate) path_regex: Vec<regex::Regex>,
    pub(crate) arg_regex: Vec<regex::Regex>,
    pub(crate) secret_regex: Vec<regex::Regex>,
}

pub(crate) fn compile_patterns(policy: &RedactionPolicy) -> CompiledPatterns {
    fn compile<'a>(patterns: impl Iterator<Item = &'a String>) -> Vec<regex::Regex> {
        patterns.filter_map(|p| regex::Regex::new(p).ok()).collect()
    }
    CompiledPatterns {
        path_regex: compile(policy.path_patterns.iter().filter_map(|p| match p {
            PathPattern::Regex(s) => Some(s),
            _ => None,
        })),
        arg_regex: compile(policy.argument_patterns.iter().filter_map(|p| match p {
            ArgumentPattern::Regex(s) => Some(s),
            _ => None,
        })),
        secret_regex: compile(
            policy
                .secret_patterns
                .iter()
                .map(|SecretPattern::Regex(s)| s),
        ),
    }
}

pub(crate) fn mask_secrets(input: &str, secret_regex: &[regex::Regex]) -> String {
    let mut out = input.to_string();
    for re in secret_regex {
        out = re.replace_all(&out, MASKED).into_owned();
    }
    out
}

pub(crate) fn matches_path(
    path: &str,
    policy: &RedactionPolicy,
    compiled: &CompiledPatterns,
) -> bool {
    for pat in &policy.path_patterns {
        match pat {
            PathPattern::Exact(e) => {
                if path == e {
                    return true;
                }
            }
            PathPattern::Prefix(p) => {
                if path.starts_with(p) {
                    return true;
                }
            }
            PathPattern::Regex(_) => {}
        }
    }
    compiled.path_regex.iter().any(|re| re.is_match(path))
}

pub(crate) fn matches_argument(
    arg: &str,
    policy: &RedactionPolicy,
    compiled: &CompiledPatterns,
) -> bool {
    for pat in &policy.argument_patterns {
        match pat {
            ArgumentPattern::Exact(e) => {
                if arg == e {
                    return true;
                }
            }
            ArgumentPattern::Prefix(p) => {
                if arg.starts_with(p) {
                    return true;
                }
            }
            ArgumentPattern::Regex(_) => {}
        }
    }
    compiled.arg_regex.iter().any(|re| re.is_match(arg))
}

pub(crate) fn join_nul(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push(0);
        }
        out.extend_from_slice(s.as_bytes());
    }
    out
}

pub(crate) fn truncate_bytes(bytes: &[u8], max: usize) -> (Vec<u8>, bool) {
    if bytes.len() > max {
        (bytes[..max].to_vec(), true)
    } else {
        (bytes.to_vec(), false)
    }
}

pub(crate) fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
