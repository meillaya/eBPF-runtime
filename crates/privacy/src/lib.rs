// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Redaction for event and alert fields.
//!
//! The agent applies this before persistence and before any network send.
//! Raw ABI payload bytes never leave the decoder. The policy masks secrets
//! inside strings and can replace whole path prefixes.

#![forbid(unsafe_code)]

use event_model::{Alert, Event, RedactionFlags};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A path that must be replaced wholesale.
pub const REDACTED: &str = "[REDACTED]";
/// A secret substring replacement.
pub const MASKED: &str = "[MASKED]";

/// Policy configuration loaded from the agent config.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RedactionPolicy {
    /// Path prefixes to replace with `[REDACTED]`.
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    /// Regular expressions whose matches are replaced with `[MASKED]`.
    #[serde(default)]
    pub secret_patterns: Vec<String>,
    /// Maximum serialized argv length in bytes.
    #[serde(default = "default_argv_bytes")]
    pub max_argv_bytes: usize,
}

fn default_argv_bytes() -> usize {
    4096
}

/// A policy whose regular expressions have been compiled.
pub struct Redactor {
    path_prefixes: Vec<String>,
    secrets: Vec<Regex>,
    max_argv_bytes: usize,
}

/// Fields that were changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RedactionStats {
    /// Number of strings whose value changed.
    pub fields_changed: usize,
    /// Whether a path was replaced.
    pub path_redacted: bool,
    /// Whether argv was masked or truncated.
    pub argv_redacted: bool,
}

/// Policy compilation errors.
#[derive(Debug, Error)]
pub enum PrivacyError {
    /// A configured regular expression is invalid.
    #[error("invalid secret pattern: {0}")]
    InvalidPattern(String),
    /// The argv bound is zero or unreasonably large.
    #[error("max_argv_bytes must be in 1..=65536, got {0}")]
    InvalidArgvBound(usize),
}

impl Redactor {
    /// Compile a policy.
    pub fn new(policy: &RedactionPolicy) -> Result<Self, PrivacyError> {
        if policy.max_argv_bytes == 0 || policy.max_argv_bytes > 65_536 {
            return Err(PrivacyError::InvalidArgvBound(policy.max_argv_bytes));
        }
        let mut secrets = Vec::with_capacity(policy.secret_patterns.len());
        for pattern in &policy.secret_patterns {
            secrets.push(
                Regex::new(pattern).map_err(|_| PrivacyError::InvalidPattern(pattern.clone()))?,
            );
        }
        Ok(Self {
            path_prefixes: policy.path_prefixes.clone(),
            secrets,
            max_argv_bytes: policy.max_argv_bytes,
        })
    }

    /// Apply the policy to an event in place.
    pub fn apply(&self, event: &mut Event) -> RedactionStats {
        let mut stats = RedactionStats::default();
        stats.fields_changed += self.redact_path(&mut event.path, &mut stats);
        stats.fields_changed += self.redact_path(&mut event.old_path, &mut stats);
        stats.fields_changed += self.redact_path(&mut event.process_exec, &mut stats);
        stats.fields_changed += self.redact_text(&mut event.sensor, &mut stats);

        if let Some(argv) = &mut event.argv {
            let mut changed = false;
            let mut used = 0usize;
            let mut kept = Vec::new();
            for argument in argv.iter() {
                let mut value = argument.clone();
                if self.mask_secrets(&mut value) {
                    changed = true;
                }
                let remaining = self.max_argv_bytes.saturating_sub(used);
                if value.len() > remaining {
                    value.truncate(remaining);
                    changed = true;
                }
                used += value.len();
                if !value.is_empty() {
                    kept.push(value);
                }
            }
            if changed {
                stats.argv_redacted = true;
                stats.fields_changed += 1;
            }
            *argv = kept;
        }

        if let Some(dns) = &mut event.dns {
            if self.mask_secrets(&mut dns.qname) {
                stats.fields_changed += 1;
            }
        }
        if let Some(lsm) = &mut event.lsm {
            if self.mask_secrets(&mut lsm.selector) {
                stats.fields_changed += 1;
            }
        }
        event.redaction = RedactionFlags {
            path_redacted: stats.path_redacted,
            argv_redacted: stats.argv_redacted,
            message_redacted: false,
        };
        stats
    }

    /// Apply the policy to an alert explanation.
    pub fn apply_alert(&self, alert: &mut Alert) -> bool {
        self.mask_secrets(&mut alert.explanation)
    }

    fn redact_path(&self, field: &mut Option<String>, stats: &mut RedactionStats) -> usize {
        let Some(value) = field else {
            return 0;
        };
        let mut changed = false;
        if self
            .path_prefixes
            .iter()
            .any(|prefix| !prefix.is_empty() && value.starts_with(prefix))
        {
            *value = REDACTED.to_string();
            stats.path_redacted = true;
            changed = true;
        }
        if self.mask_secrets(value) {
            changed = true;
        }
        usize::from(changed)
    }

    fn redact_text(&self, field: &mut String, _stats: &mut RedactionStats) -> usize {
        usize::from(self.mask_secrets(field))
    }

    fn mask_secrets(&self, value: &mut String) -> bool {
        let mut changed = false;
        for pattern in &self.secrets {
            if pattern.is_match(value) {
                *value = pattern.replace_all(value, MASKED).into_owned();
                changed = true;
            }
        }
        changed
    }
}

impl RedactionPolicy {
    /// A policy with secret masking and no path redaction.
    pub fn defaults() -> Self {
        Self {
            path_prefixes: Vec::new(),
            secret_patterns: default_secret_patterns(),
            max_argv_bytes: default_argv_bytes(),
        }
    }
}

/// Default secret patterns. They cover credentials that commonly appear in
/// command lines and paths.
pub fn default_secret_patterns() -> Vec<String> {
    vec![
        r"(?i)aws_secret_access_key\s*=\s*\S+".to_string(),
        r"(?i)bearer\s+[A-Za-z0-9._~+/\-=]+".to_string(),
        r"(?i)(password|passwd|token|secret)\s*[=:]\s*\S+".to_string(),
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----".to_string(),
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b".to_string(),
        r"\bAKIA[0-9A-Z]{16}\b".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> Event {
        Event {
            time: "2026-01-01T00:00:00Z".to_string(),
            sensor: "file".to_string(),
            kind: "FileOpen".to_string(),
            event_id: "a".repeat(64),
            boot_id: "b".repeat(32),
            seq: 1,
            path: Some("/home/alice/.ssh/id_ed25519".to_string()),
            process_exec: Some("/usr/bin/cat".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn masks_secrets_in_paths_and_argv() {
        let policy = RedactionPolicy {
            path_prefixes: vec!["/home/".to_string()],
            secret_patterns: vec![r"secret=\S+".to_string()],
            max_argv_bytes: 1024,
        };
        let redactor = Redactor::new(&policy).unwrap();
        let mut event = event();
        event.argv = Some(vec!["tool".to_string(), "secret=abc".to_string()]);
        let stats = redactor.apply(&mut event);
        assert_eq!(event.path.as_deref(), Some(REDACTED));
        assert_eq!(event.argv.as_ref().unwrap()[1], MASKED);
        assert!(stats.path_redacted);
        assert!(stats.argv_redacted);
        assert!(event.redaction.path_redacted);
    }

    #[test]
    fn rejects_invalid_pattern() {
        let policy = RedactionPolicy {
            secret_patterns: vec!["(".to_string()],
            ..Default::default()
        };
        assert!(Redactor::new(&policy).is_err());
    }

    #[test]
    fn rejects_oversized_argv_bound() {
        let policy = RedactionPolicy {
            max_argv_bytes: 0,
            ..Default::default()
        };
        assert!(Redactor::new(&policy).is_err());
    }
}
