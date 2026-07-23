// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Redaction patterns and policy configuration.

use serde::{Deserialize, Serialize};

use super::ARGV_MAX_BYTES_DEFAULT;

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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncationFlags {
    pub argv_truncated: bool,
    pub path_truncated: bool,
    pub dns_truncated: bool,
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
        SecretPattern::Regex(r"AKIA[0-9A-Z]{16}".to_string()),
        SecretPattern::Regex(r"sk_(live|test)_[0-9A-Za-z]{16,}".to_string()),
        SecretPattern::Regex(r"(?i)api[_-]?key[=:]\s*[0-9A-Za-z._\-]{16,}".to_string()),
        SecretPattern::Regex(r"(?i)bearer\s+[0-9A-Za-z._\-]{16,}".to_string()),
        SecretPattern::Regex(r"(?i)(password|passwd|token)[=:]\s*\S{8,}".to_string()),
    ]
}
