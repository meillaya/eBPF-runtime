// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed privacy policy and the mandatory redaction / data-minimization stage
//! applied before **every** persistence and export boundary.
//!
//! # The privacy boundary
//!
//! The agent ingests raw kernel records ([`agent_core::NormalizedEvent`]) whose
//! `raw.payload` bytes still contain pre-redaction material (argv, environment,
//! paths, DNS rdata, packet fragments). Nothing downstream of this crate is
//! allowed to see those bytes. The single mandatory normalization stage is
//! [`apply_redaction`]:
//!
//! ```text
//! NormalizedEvent --decode_record--> DecodedRecord --apply_redaction--> RedactedEvent --> sinks
//!        (raw payload lives here)                      (raw payload is DROPPED here)
//! ```
//!
//! A [`RedactedEvent`] deliberately does **not** carry the `NormalizedEvent`'s
//! `raw` field. The only data it can ever expose is the redacted projection of
//! the bounded [`DecodedRecord`]. That structural choice is the guarantee that
//! "no sink can bypass the policy": the sink layer ([`sinks`]) only accepts a
//! `&RedactedEvent`, and there is no API that hands a sink a `NormalizedEvent`
//! or raw bytes (see [`sinks::write_normalized_to_sinks`], which always rejects).
//!
//! # Guardrails enforced here (plan task 23)
//!
//! * 4 KiB max argv record ([`ARGV_MAX_BYTES_DEFAULT`]); environment capture is
//!   disabled by default ([`RedactionPolicy::env_enabled`] defaults to `false`).
//! * Exact / prefix / regex path and argument redaction with bounded execution.
//! * Secret-pattern masking (API keys, bearer tokens, AWS keys, passwords, …).
//! * DNS field allowlist; rdata is masked by default and packet payloads are
//!   never persisted.
//! * Truncation / redaction flags on every field that is shortened or removed.
//! * Startup validation ([`validate_policy`]) rejects catastrophic regexes
//!   (nested-quantifier scan + bounded NFA state count + compile/match time
//!   limits + size + capture-group complexity) before the agent ever starts.
//!
//! `apply_redaction` never logs the raw pre-redaction record: the only
//! `tracing` emission references the redacted event id and redaction counts.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod sinks;

use std::time::{Duration, Instant};

use agent_core::{
    BootId, CgroupId, EventId, EventPriority, Identity, Kind, MonotonicNs, NamespaceBundle,
    NormalizedEvent, PidTgid, Sequence, TaskStartNs, WallClock,
};
use serde::{Deserialize, Serialize};

/// 4 KiB — the maximum argv record size. argv beyond this is truncated and the
/// `argv_truncated` flag is set. Pinned by plan task 23.
pub const ARGV_MAX_BYTES_DEFAULT: usize = 4096;
/// Hard upper bound on a configurable argv record (64 KiB). A policy asking for
/// more is rejected at startup.
pub const ARGV_MAX_BYTES_LIMIT: usize = 65536;
/// Maximum byte length of a single regex pattern. Larger patterns are rejected.
pub const MAX_REGEX_BYTES: usize = 1024;
/// Maximum number of user capture groups a regex may declare.
pub const MAX_CAPTURE_GROUPS: usize = 64;
/// Maximum number of Thompson-NFA states a regex may compile to. This is the
/// `regex-automata`-backed complexity bound: a pattern that explodes the
/// automaton is rejected even if it is not a syntactically nested quantifier.
pub const MAX_NFA_STATES: usize = 8192;
/// A regex that takes longer than this to compile is rejected (catastrophic).
pub const REGEX_COMPILE_TIME_LIMIT: Duration = Duration::from_millis(100);
/// A regex that takes longer than this to match a 1 KiB probe string is
/// rejected (catastrophic). This is the runtime safety net.
pub const REGEX_MATCH_TIME_LIMIT: Duration = Duration::from_millis(10);
/// Replacement for a path / argument removed by a redaction pattern.
pub const REDACTED: &str = "[REDACTED]";
/// Replacement for a secret removed by a secret pattern (and for masked DNS
/// rdata).
pub const MASKED: &str = "[MASKED]";

// ---------------------------------------------------------------------------
// Redaction patterns
// ---------------------------------------------------------------------------

/// A path redaction pattern. `Exact` matches a whole path, `Prefix` matches a
/// leading prefix, `Regex` matches a bounded regular expression. A matching
/// path is replaced wholesale by [`REDACTED`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathPattern {
    Exact(String),
    Prefix(String),
    Regex(String),
}

/// An argument redaction pattern. Semantics mirror [`PathPattern`]; a matching
/// argument token is replaced wholesale by [`REDACTED`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgumentPattern {
    Exact(String),
    Prefix(String),
    Regex(String),
}

/// A secret-masking pattern. Only regex matching is meaningful for secrets
/// (they appear as substrings of larger tokens). A match is replaced inline by
/// [`MASKED`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretPattern {
    Regex(String),
}

/// Which DNS fields are permitted to pass the privacy boundary. `rdata` is
/// masked by default because it can carry packet payload (including TXT/CNAME
/// data and tunnelled content); the question/answer metadata is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsFieldAllowlist {
    pub qname: bool,
    pub qtype: bool,
    pub qclass: bool,
    pub an_count: bool,
    pub rdata: bool,
}

impl Default for DnsFieldAllowlist {
    fn default() -> Self {
        Self {
            qname: true,
            qtype: true,
            qclass: true,
            an_count: true,
            // rdata is masked by default — packet payloads are never persisted.
            rdata: false,
        }
    }
}

/// Truncation / redaction flags.
///
/// In a [`RedactionPolicy`] this is the *configuration*: which flags the policy
/// permits to be set when a field exceeds its bound (default: all enabled). In
/// a [`RedactedEvent`] this is the *output*: which fields were actually
/// truncated or redacted (default: none).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncationFlags {
    pub argv_truncated: bool,
    pub path_truncated: bool,
    pub dns_truncated: bool,
}

impl Default for TruncationFlags {
    fn default() -> Self {
        // Output default: nothing truncated yet.
        Self {
            argv_truncated: false,
            path_truncated: false,
            dns_truncated: false,
        }
    }
}

impl TruncationFlags {
    /// The policy configuration that enables every truncation flag.
    pub const fn all_enabled() -> Self {
        Self {
            argv_truncated: true,
            path_truncated: true,
            dns_truncated: true,
        }
    }
}

/// The canonical privacy policy. One instance governs every sink; there is no
/// per-sink override (a sink cannot bypass the policy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionPolicy {
    /// Maximum argv record size in bytes (default 4096; must be in
    /// `1..=ARGV_MAX_BYTES_LIMIT`).
    pub argv_max_bytes: usize,
    /// Whether environment capture is enabled. Disabled by default.
    pub env_enabled: bool,
    /// Path redaction patterns (exact / prefix / regex).
    pub path_patterns: Vec<PathPattern>,
    /// Argument redaction patterns (exact / prefix / regex).
    pub argument_patterns: Vec<ArgumentPattern>,
    /// Secret-masking regex patterns.
    pub secret_patterns: Vec<SecretPattern>,
    /// DNS field allowlist (rdata masked by default).
    pub dns_field_allowlist: DnsFieldAllowlist,
    /// Which truncation flags the policy permits to be set.
    pub truncation_flags: TruncationFlags,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            argv_max_bytes: ARGV_MAX_BYTES_DEFAULT,
            env_enabled: false,
            path_patterns: Vec::new(),
            argument_patterns: Vec::new(),
            secret_patterns: Vec::new(),
            dns_field_allowlist: DnsFieldAllowlist::default(),
            truncation_flags: TruncationFlags::all_enabled(),
        }
    }
}

impl RedactionPolicy {
    /// A policy with the default 4 KiB argv bound, environment disabled, the
    /// default DNS allowlist, and a sensible built-in secret-pattern set.
    pub fn with_default_secrets() -> Self {
        Self {
            secret_patterns: default_secret_patterns(),
            ..Self::default()
        }
    }
}

/// The built-in secret-pattern set: AWS access key ids, generic API keys,
/// bearer tokens, and `password=`/`token=` style assignments.
pub fn default_secret_patterns() -> Vec<SecretPattern> {
    vec![
        // AWS access key id (AKIA… 16 uppercase alphanumerics).
        SecretPattern::Regex(r"AKIA[0-9A-Z]{16}".to_string()),
        // Stripe-style live/test secret keys.
        SecretPattern::Regex(r"sk_(live|test)_[0-9A-Za-z]{16,}".to_string()),
        // Generic api_key=… / api-key: … assignments.
        SecretPattern::Regex(r"(?i)api[_-]?key[=:]\s*[0-9A-Za-z._\-]{16,}".to_string()),
        // Authorization: Bearer <token>.
        SecretPattern::Regex(r"(?i)bearer\s+[0-9A-Za-z._\-]{16,}".to_string()),
        // password=… / token=… assignments.
        SecretPattern::Regex(r"(?i)(password|passwd|token)[=:]\s*\S{8,}".to_string()),
    ]
}

// ---------------------------------------------------------------------------
// Decoded record — the bounded view the privacy layer consumes
// ---------------------------------------------------------------------------

/// DNS question/answer fields as the privacy layer sees them. `rdata` is a list
/// of record-data strings; it is masked unless explicitly allowlisted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedDns {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub an_count: u16,
    pub rdata: Vec<String>,
}

/// The bounded decoded view of an event's redactable fields.
///
/// In production the agent-core per-sensor decoders populate this view; the
/// privacy layer consumes it (never the raw bytes). For host-side fixtures and
/// the [`redaction-cli`](crate) the record is encoded as JSON inside the
/// normalized event's `raw.payload`, and [`decode_record`] parses it back. A
/// payload that does not decode yields an empty record — the layer fails
/// closed, exporting nothing redactable rather than leaking raw material.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedRecord {
    /// exec argv tokens.
    pub argv: Vec<String>,
    /// exec environment tokens (only exported when `env_enabled`).
    pub env: Vec<String>,
    /// file / exec path.
    pub path: String,
    /// generic argument tokens (e.g. syscall / cli arguments).
    pub arguments: Vec<String>,
    /// DNS question/answer fields, when the event is a DNS packet.
    pub dns: Option<DecodedDns>,
    /// generic log / line text subject to secret masking.
    pub message: String,
}

/// Decode the bounded [`DecodedRecord`] view from a normalized event's raw
/// payload. Fail-closed: any payload that is not a valid encoded record yields
/// an empty record (no redactable data exported).
pub fn decode_record(event: &NormalizedEvent) -> DecodedRecord {
    serde_json::from_slice(&event.raw.payload).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Redacted event — the only shape that may cross a sink boundary
// ---------------------------------------------------------------------------

/// The non-secret identity/metadata of an event, projected from a
/// [`NormalizedEvent`]. Carried verbatim onto the [`RedactedEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIdentity {
    pub kind: Kind,
    pub event_id: EventId,
    pub sequence: Sequence,
    pub monotonic_ns: MonotonicNs,
    pub wall_clock: WallClock,
    pub pid_tgid: PidTgid,
    pub task_start_ns: TaskStartNs,
    pub cgroup_id: CgroupId,
    pub boot_id: BootId,
    pub namespaces: NamespaceBundle,
    pub identity: Identity,
    pub priority: EventPriority,
    /// Enrichment attribution scope label (set by the enrichment-aware path;
    /// always safe to export — it is a scope, never raw identity).
    pub attribution_scope: Option<String>,
}

impl EventIdentity {
    /// Project the identity/metadata from a normalized event. The raw payload
    /// is intentionally not referenced here.
    pub fn from_event(event: &NormalizedEvent) -> Self {
        Self {
            kind: event.kind,
            event_id: event.event_id,
            sequence: event.sequence,
            monotonic_ns: event.monotonic_ns,
            wall_clock: event.wall_clock.clone(),
            pid_tgid: event.pid_tgid,
            task_start_ns: event.task_start_ns,
            cgroup_id: event.cgroup_id,
            boot_id: event.boot_id,
            namespaces: event.namespaces.clone(),
            identity: event.identity.clone(),
            priority: event.priority,
            attribution_scope: None,
        }
    }
}

/// The redacted event shape — the **only** object any sink may receive.
///
/// It carries the same identity/metadata fields as [`NormalizedEvent`] plus the
/// redacted projections of the redactable fields. It deliberately has **no**
/// `raw` field: the pre-redaction payload cannot cross the boundary because it
/// is not present on this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedEvent {
    // identity / metadata (non-secret-bearing) projected from NormalizedEvent
    pub kind: Kind,
    pub event_id: EventId,
    pub sequence: Sequence,
    pub monotonic_ns: MonotonicNs,
    pub wall_clock: WallClock,
    pub pid_tgid: PidTgid,
    pub task_start_ns: TaskStartNs,
    pub cgroup_id: CgroupId,
    pub boot_id: BootId,
    pub namespaces: NamespaceBundle,
    pub identity: Identity,
    pub priority: EventPriority,
    pub attribution_scope: Option<String>,
    // redacted payload projections (the ONLY place redactable data may live)
    /// argv joined by NUL, secret-masked, truncated to `argv_max_bytes`.
    pub argv_bytes: Option<Vec<u8>>,
    /// environment joined by NUL, or `None` when `env_enabled` is false.
    pub env: Option<Vec<u8>>,
    /// file / exec path, redacted to [`REDACTED`] on a pattern match.
    pub path: Option<String>,
    /// argument tokens, each redacted / masked independently.
    pub arguments: Vec<String>,
    pub dns_qname: Option<String>,
    pub dns_qtype: Option<u16>,
    pub dns_qclass: Option<u16>,
    pub dns_an_count: Option<u16>,
    /// DNS rdata, masked to [`MASKED`] unless `rdata` is allowlisted.
    pub dns_rdata: Option<Vec<u8>>,
    /// generic log / line text, secret-masked.
    pub message: Option<String>,
    /// which fields were truncated / redacted.
    pub truncation_flags: TruncationFlags,
}

impl RedactedEvent {
    /// Serialize the redacted event to a stable JSON value. This is the wire
    /// form every sink writes. Only redacted projections are present; the raw
    /// payload is structurally absent.
    pub fn to_json(&self) -> serde_json::Value {
        let mut ns = serde_json::Map::new();
        ns.insert("pid".into(), opt_u64(self.namespaces.pid));
        ns.insert("mnt".into(), opt_u64(self.namespaces.mnt));
        ns.insert("net".into(), opt_u64(self.namespaces.net));
        ns.insert("user".into(), opt_u64(self.namespaces.user));
        ns.insert("uts".into(), opt_u64(self.namespaces.uts));
        ns.insert("ipc".into(), opt_u64(self.namespaces.ipc));
        ns.insert("cgroup".into(), opt_u64(self.namespaces.cgroup));
        ns.insert("time".into(), opt_u64(self.namespaces.time));

        let mut id = serde_json::Map::new();
        id.insert(
            "real_uid".into(),
            opt_u64(self.identity.real_uid.map(u64::from)),
        );
        id.insert(
            "effective_uid".into(),
            opt_u64(self.identity.effective_uid.map(u64::from)),
        );
        id.insert(
            "saved_uid".into(),
            opt_u64(self.identity.saved_uid.map(u64::from)),
        );
        id.insert(
            "real_gid".into(),
            opt_u64(self.identity.real_gid.map(u64::from)),
        );
        id.insert(
            "effective_gid".into(),
            opt_u64(self.identity.effective_gid.map(u64::from)),
        );
        id.insert(
            "saved_gid".into(),
            opt_u64(self.identity.saved_gid.map(u64::from)),
        );
        id.insert(
            "loginuid".into(),
            opt_u64(self.identity.loginuid.map(u64::from)),
        );

        let mut flags = serde_json::Map::new();
        flags.insert(
            "argv_truncated".into(),
            self.truncation_flags.argv_truncated.into(),
        );
        flags.insert(
            "path_truncated".into(),
            self.truncation_flags.path_truncated.into(),
        );
        flags.insert(
            "dns_truncated".into(),
            self.truncation_flags.dns_truncated.into(),
        );

        let mut map = serde_json::Map::new();
        map.insert("kind".into(), format!("{:?}", self.kind).into());
        map.insert("event_id".into(), hex(&self.event_id.0).into());
        map.insert("sequence".into(), self.sequence.0.into());
        map.insert("monotonic_ns".into(), self.monotonic_ns.0.into());
        map.insert("wall_clock".into(), self.wall_clock.0.clone().into());
        map.insert("pid_tgid".into(), self.pid_tgid.0.into());
        map.insert("task_start_ns".into(), self.task_start_ns.0.into());
        map.insert("cgroup_id".into(), self.cgroup_id.0.into());
        map.insert("boot_id".into(), hex(&self.boot_id.0).into());
        map.insert("namespaces".into(), serde_json::Value::Object(ns));
        map.insert("identity".into(), serde_json::Value::Object(id));
        map.insert("priority".into(), format!("{:?}", self.priority).into());
        map.insert(
            "attribution_scope".into(),
            self.attribution_scope
                .clone()
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "argv".into(),
            self.argv_bytes
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned().into())
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "env".into(),
            self.env
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned().into())
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "path".into(),
            self.path
                .clone()
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "arguments".into(),
            serde_json::Value::Array(self.arguments.iter().map(|a| a.clone().into()).collect()),
        );
        map.insert(
            "dns_qname".into(),
            self.dns_qname
                .clone()
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert("dns_qtype".into(), opt_u64(self.dns_qtype.map(u64::from)));
        map.insert("dns_qclass".into(), opt_u64(self.dns_qclass.map(u64::from)));
        map.insert(
            "dns_an_count".into(),
            opt_u64(self.dns_an_count.map(u64::from)),
        );
        map.insert(
            "dns_rdata".into(),
            self.dns_rdata
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned().into())
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "message".into(),
            self.message
                .clone()
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert("truncation_flags".into(), serde_json::Value::Object(flags));
        serde_json::Value::Object(map)
    }

    /// Serialize to compact JSON bytes (the form sinks persist / transmit).
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.to_json())
    }

    /// Project this redacted event back to a [`DecodedRecord`]. Used to prove
    /// redaction is idempotent: re-redacting an already-redacted record yields
    /// the same record.
    pub fn to_decoded_record(&self) -> DecodedRecord {
        let split = |bytes: &Option<Vec<u8>>| -> Vec<String> {
            bytes
                .as_ref()
                .map(|b| {
                    if b.is_empty() {
                        Vec::new()
                    } else {
                        b.split(|c| *c == 0)
                            .map(|part| String::from_utf8_lossy(part).into_owned())
                            .collect()
                    }
                })
                .unwrap_or_default()
        };
        let dns = match (
            &self.dns_qname,
            self.dns_qtype,
            self.dns_qclass,
            self.dns_an_count,
            &self.dns_rdata,
        ) {
            (None, None, None, None, None) => None,
            (qname, qtype, qclass, an_count, rdata) => Some(DecodedDns {
                qname: qname.clone().unwrap_or_default(),
                qtype: qtype.unwrap_or(0),
                qclass: qclass.unwrap_or(0),
                an_count: an_count.unwrap_or(0),
                rdata: rdata
                    .as_ref()
                    .map(|b| {
                        if b.is_empty() {
                            Vec::new()
                        } else {
                            vec![String::from_utf8_lossy(b).into_owned()]
                        }
                    })
                    .unwrap_or_default(),
            }),
        };
        DecodedRecord {
            argv: split(&self.argv_bytes),
            env: split(&self.env),
            path: self.path.clone().unwrap_or_default(),
            arguments: self.arguments.clone(),
            dns,
            message: self.message.clone().unwrap_or_default(),
        }
    }
}

fn opt_u64(v: Option<u64>) -> serde_json::Value {
    v.map(Into::into).unwrap_or(serde_json::Value::Null)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// The mandatory normalization stage
// ---------------------------------------------------------------------------

/// The mandatory normalization stage. Decodes the bounded [`DecodedRecord`]
/// from the event, applies every redaction / minimization rule in `policy`, and
/// returns a [`RedactedEvent`] that is guaranteed to carry no raw pre-redaction
/// data. This is the only path from a [`NormalizedEvent`] to any sink.
///
/// This function never logs the raw input. The single `tracing` emission
/// references only the redacted event id and redaction counts.
pub fn apply_redaction(event: &NormalizedEvent, policy: &RedactionPolicy) -> RedactedEvent {
    let record = decode_record(event);
    let identity = EventIdentity::from_event(event);
    let redacted = apply_redaction_to_record(&record, &identity, policy);
    // Debug-only, redacted output. The raw payload is never referenced here.
    tracing::debug!(
        event_id = %hex(&redacted.event_id.0),
        argv_truncated = redacted.truncation_flags.argv_truncated,
        path_truncated = redacted.truncation_flags.path_truncated,
        dns_truncated = redacted.truncation_flags.dns_truncated,
        env_present = redacted.env.is_some(),
        "applied redaction policy"
    );
    redacted
}

/// Apply the redaction policy to an already-decoded record and identity. This
/// is the pure core of [`apply_redaction`], exposed so redaction can be shown
/// idempotent and deterministic.
pub fn apply_redaction_to_record(
    record: &DecodedRecord,
    identity: &EventIdentity,
    policy: &RedactionPolicy,
) -> RedactedEvent {
    let compiled = compile_patterns(policy);
    let mut flags = TruncationFlags::default();

    // argv: secret-mask each token, join with NUL, truncate to argv_max_bytes.
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

    // env: cleared entirely unless env_enabled.
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

    // path: redaction patterns replace wholesale, then secret-mask.
    let (path, path_redacted) = if matches_path(&record.path, policy, &compiled) {
        (REDACTED.to_string(), true)
    } else {
        (mask_secrets(&record.path, &compiled.secret_regex), false)
    };
    if path_redacted && policy.truncation_flags.path_truncated {
        flags.path_truncated = true;
    }

    // arguments: each token redacted / masked independently.
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

    // dns: field allowlist + rdata masking. Packet payload is never persisted.
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
                // No rdata present: preserve as empty, do not fabricate [MASKED].
                (Some(Vec::new()), false)
            } else if policy.dns_field_allowlist.rdata {
                (
                    Some(mask_secrets(&lossy(&rdata_joined), &compiled.secret_regex).into_bytes()),
                    false,
                )
            } else {
                // rdata masked by default — packet payload never persisted.
                (Some(MASKED.as_bytes().to_vec()), true)
            };
            (qname, qtype, qclass, an_count, rdata, truncated)
        }
        None => (None, None, None, None, None, false),
    };
    if dns_trunc && policy.truncation_flags.dns_truncated {
        flags.dns_truncated = true;
    }

    // message: secret-mask the generic log/line text.
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

/// Label an enrichment attribution scope for export. The scope is always safe
/// to export (it is a scope label, never raw kernel identity); this helper
/// exists so the sink layer can attach enrichment metadata uniformly.
pub fn scope_label(scope: &enrichment::AttributionScope) -> String {
    scope.to_string()
}

// ---------------------------------------------------------------------------
// Redaction helpers
// ---------------------------------------------------------------------------

struct CompiledPatterns {
    path_regex: Vec<regex::Regex>,
    arg_regex: Vec<regex::Regex>,
    secret_regex: Vec<regex::Regex>,
}

fn compile_patterns(policy: &RedactionPolicy) -> CompiledPatterns {
    fn compile<'a>(patterns: impl Iterator<Item = &'a String>) -> Vec<regex::Regex> {
        // Fail-closed: an invalid regex is skipped here (it would have been
        // rejected at startup by validate_policy; skipping means it cannot
        // accidentally let data through unmasked-by-this-pattern, and the
        // remaining patterns still apply).
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

fn mask_secrets(input: &str, secret_regex: &[regex::Regex]) -> String {
    let mut out = input.to_string();
    for re in secret_regex {
        out = re.replace_all(&out, MASKED).into_owned();
    }
    out
}

fn matches_path(path: &str, policy: &RedactionPolicy, compiled: &CompiledPatterns) -> bool {
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

fn matches_argument(arg: &str, policy: &RedactionPolicy, compiled: &CompiledPatterns) -> bool {
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

fn join_nul(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push(0);
        }
        out.extend_from_slice(s.as_bytes());
    }
    out
}

fn truncate_bytes(bytes: &[u8], max: usize) -> (Vec<u8>, bool) {
    if bytes.len() > max {
        (bytes[..max].to_vec(), true)
    } else {
        (bytes.to_vec(), false)
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Startup validation
// ---------------------------------------------------------------------------

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

/// Validate a redaction policy at startup. Rejects:
/// * `argv_max_bytes == 0` or `> ARGV_MAX_BYTES_LIMIT`,
/// * any regex pattern larger than [`MAX_REGEX_BYTES`],
/// * any regex that fails to compile,
/// * any regex with more than [`MAX_CAPTURE_GROUPS`] capture groups,
/// * any regex whose Thompson NFA exceeds [`MAX_NFA_STATES`] states,
/// * any regex exhibiting the nested-quantifier catastrophic-backtracking
///   signature (e.g. `(a+)+$`),
/// * any regex that takes longer than [`REGEX_COMPILE_TIME_LIMIT`] to compile
///   or [`REGEX_MATCH_TIME_LIMIT`] to match a 1 KiB probe string.
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

/// Validate that the policy is both well-formed and non-trivial (at least one
/// redaction pattern is configured). Useful for deployments that must never run
/// with a no-op policy.
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
    // Size limit (cheap, checked first).
    if pattern.len() > MAX_REGEX_BYTES {
        return Err(PolicyValidationError::RegexTooLarge(pattern.to_string()));
    }
    // Catastrophic nested-quantifier signature, e.g. (a+)+$ — rejected before
    // we even spend time compiling. Rust's regex engine is linear-time so this
    // would not actually hang, but the pattern is the classic ReDoS signature
    // and is rejected conservatively at the privacy boundary.
    if has_nested_quantifier(pattern) {
        return Err(PolicyValidationError::RegexTooSlow(format!(
            "catastrophic regex (nested quantifier): {pattern}"
        )));
    }
    // Compile with a time bound.
    let start = Instant::now();
    let re = regex::Regex::new(pattern)
        .map_err(|e| PolicyValidationError::RegexCompileError(format!("{pattern}: {e}")))?;
    if start.elapsed() > REGEX_COMPILE_TIME_LIMIT {
        return Err(PolicyValidationError::RegexTooSlow(format!(
            "regex compile exceeded {:?}: {pattern}",
            REGEX_COMPILE_TIME_LIMIT
        )));
    }
    // Capture-group complexity.
    if re.captures_len().saturating_sub(1) > MAX_CAPTURE_GROUPS {
        return Err(PolicyValidationError::RegexTooComplex(pattern.to_string()));
    }
    // regex-automata NFA state bound (automaton complexity).
    if let Ok(nfa) = regex_automata::nfa::thompson::NFA::compiler().build(pattern) {
        if nfa.states().len() > MAX_NFA_STATES {
            return Err(PolicyValidationError::RegexTooComplex(pattern.to_string()));
        }
    }
    // Match-time bound on a 1 KiB probe string (runtime safety net).
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
/// signature: a quantifier (`*`, `+`, or `{…}`) applied to a group that itself
/// contains an unbounded quantifier. Catches `(a+)+`, `(a*)*`, `(?:a+)+`, etc.
/// Conservative: it may reject a few benign patterns, which is the safe
/// direction for a privacy guardrail. Runs in O(n) over the pattern.
fn has_nested_quantifier(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let n = chars.len();
    // Stack of "does this group contain an unbounded quantifier".
    let mut group_has_unbounded: Vec<bool> = Vec::new();
    let mut in_class = false;
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if c == '\\' {
            // Skip the escaped character entirely.
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
                    // Special group (?i), (?:…), (?=…): the '?' is group
                    // syntax, not a quantifier.
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
                // The enclosing group now contains an unbounded quantifier if
                // this group either held one or is itself quantified.
                if inner || followed_by_quant {
                    if let Some(top) = group_has_unbounded.last_mut() {
                        *top = true;
                    }
                }
                if followed_by_quant {
                    i += 2; // consume ')' and the quantifier
                    if matches!(chars.get(i), Some('?') | Some('+')) {
                        i += 1; // lazy / possessive modifier
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
                    i += 1; // lazy / possessive modifier
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
