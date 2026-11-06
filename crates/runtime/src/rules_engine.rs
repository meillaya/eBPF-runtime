// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Evaluate the YAML rule packs against decoded events.
//!
//! Only plain conditions run here. A rule with a `sequences` block is
//! counted and skipped: correlating an ordered sequence needs state the
//! runtime does not keep yet, and firing the rule on its first step alone
//! would report a reverse shell on every shell exec.

use crate::decode::DecodedEvent;
use rules::predicates::{default_budget, Event as PredicateEvent, PredicateEvaluator};
use rules::{parse_ruleset, Action, Rule, RuleSet, Severity, Source, Value};
use serde::Serialize;
use std::path::Path;

/// A rule that matched an event.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    /// Rule id from the YAML.
    pub rule: String,
    /// Severity, lower case.
    pub severity: String,
    /// Action, lower case.
    pub action: String,
    /// Rule description.
    pub description: String,
    /// The event that matched.
    pub event: DecodedEvent,
}

/// Loaded rule packs.
pub struct Engine {
    rules: Vec<Rule>,
    evaluator: PredicateEvaluator,
    skipped_sequences: usize,
    errors: Vec<String>,
}

impl Engine {
    /// Load every `.yaml` and `.yml` file in `dir`.
    pub fn load(dir: &Path) -> Result<Self, EngineError> {
        let mut rules = Vec::new();
        let mut skipped_sequences = 0;
        let mut errors = Vec::new();

        let entries = std::fs::read_dir(dir).map_err(|error| EngineError::Read {
            path: dir.to_path_buf(),
            detail: error.to_string(),
        })?;

        let mut paths: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .and_then(|extension| extension.to_str())
                    .map(|extension| extension == "yaml" || extension == "yml")
                    .unwrap_or(false)
            })
            .collect();
        paths.sort();

        for path in paths {
            let text = std::fs::read_to_string(&path).map_err(|error| EngineError::Read {
                path: path.clone(),
                detail: error.to_string(),
            })?;
            let ruleset: RuleSet = match parse_ruleset(&text) {
                Ok(ruleset) => ruleset,
                Err(error) => {
                    errors.push(format!("{}: {error}", path.display()));
                    continue;
                }
            };
            for rule in ruleset.rules {
                if rule.action == Action::Deny {
                    errors.push(format!(
                        "{}: rule {} asks for deny, but this runtime does not enforce",
                        path.display(),
                        rule.id
                    ));
                    continue;
                }
                if !rule.sequences.is_empty() {
                    skipped_sequences += 1;
                }
                rules.push(rule);
            }
        }

        Ok(Self {
            rules,
            evaluator: PredicateEvaluator::new(default_budget()),
            skipped_sequences,
            errors,
        })
    }

    /// An engine with no rules.
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            evaluator: PredicateEvaluator::new(default_budget()),
            skipped_sequences: 0,
            errors: Vec::new(),
        }
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Number of sequence rules that were skipped.
    pub fn skipped_sequences(&self) -> usize {
        self.skipped_sequences
    }

    /// Rule files that failed to parse.
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Evaluate every rule against one event.
    pub fn evaluate(&mut self, event: &DecodedEvent) -> Vec<Alert> {
        let predicate = predicate_event(event);
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if !source_matches(rule.source, &event.sensor) || !rule.sequences.is_empty() {
                continue;
            }

            let matched =
                match self
                    .evaluator
                    .evaluate_condition(&rule.condition, &predicate, &rule.lists)
                {
                    Ok(result) => result.matched,
                    Err(_) => continue,
                };
            if !matched {
                continue;
            }

            let excepted = rule.exceptions.iter().any(|exception| {
                self.evaluator
                    .evaluate_exception(exception, &predicate)
                    .unwrap_or(false)
            });
            if excepted {
                continue;
            }

            alerts.push(Alert {
                rule: rule.id.clone(),
                severity: severity_name(rule.severity).to_string(),
                action: action_name(rule.action).to_string(),
                description: rule.description.clone(),
                event: event.clone(),
            });
        }

        alerts
    }
}

fn predicate_event(event: &DecodedEvent) -> PredicateEvent {
    let mut predicate = PredicateEvent::new()
        .with_field("process.pid", Value::Integer(i64::from(event.pid)))
        .with_field("process.tgid", Value::Integer(i64::from(event.tgid)))
        .with_field("identity.cgroup_id", Value::Integer(event.cgroup_id as i64))
        .with_field(
            "event.id",
            Value::String(format!("{:x}", event.monotonic_ns)),
        )
        .with_field("ts", Value::Integer(event.monotonic_ns as i64));

    if let Some(path) = &event.process_exec {
        predicate = predicate.with_field("process.exec_path", Value::String(path.clone()));
    } else if event.sensor == "process" && event.kind == "ProcessExec" {
        if let Some(path) = &event.path {
            predicate = predicate.with_field("process.exec_path", Value::String(path.clone()));
        }
    }
    if let Some(argv) = &event.argv {
        let values = argv.iter().cloned().map(Value::String).collect();
        predicate = predicate.with_field("process.argv", Value::Array(values));
    }
    if event.sensor == "file" {
        if let Some(path) = &event.path {
            predicate = predicate.with_field("file.path", Value::String(path.clone()));
        }
        predicate = predicate.with_field("file.kind", Value::String(event.kind.clone()));
    }

    if let Some(network) = &event.network {
        if let Some(address) = &network.address {
            predicate = predicate.with_field("network.dst_ip", Value::String(address.clone()));
        }
        if let Some(port) = network.port {
            predicate = predicate.with_field("network.dst_port", Value::Integer(i64::from(port)));
        }
        predicate =
            predicate.with_field("network.family", Value::Integer(i64::from(network.family)));
    }

    if let Some(syscall) = &event.syscall {
        predicate = predicate
            .with_field("syscall.nr", Value::Integer(syscall.nr as i64))
            .with_field(
                "syscall.latency_ns",
                Value::Integer(syscall.latency_ns as i64),
            );
    }

    if let Some(identity) = &event.identity {
        predicate = predicate
            .with_field("identity.ns_mnt", Value::Integer(identity.ns_mnt as i64))
            .with_field("identity.ns_net", Value::Integer(identity.ns_net as i64))
            .with_field("identity.ns_user", Value::Integer(identity.ns_user as i64));
    }

    if let Some(dns) = &event.dns {
        predicate = predicate
            .with_field("dns.qname", Value::String(dns.qname.clone()))
            .with_field("dns.qtype", Value::Integer(i64::from(dns.qtype)));
    }

    predicate
}

fn source_matches(source: Source, sensor: &str) -> bool {
    matches!(
        (source, sensor),
        (Source::Process, "process")
            | (Source::File, "file")
            | (Source::Network, "network")
            | (Source::Dns, "dns")
            | (Source::Syscall, "syscall")
            | (Source::Identity, "identity")
    )
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Alert => "alert",
        Action::Audit => "audit",
        Action::Deny => "deny",
    }
}

/// Failure to load a rule directory.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// A rule file could not be read.
    #[error("cannot read {path}: {detail}")]
    Read {
        /// Path that failed.
        path: std::path::PathBuf,
        /// Operating system error.
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::DecodedEvent;
    use chrono::Utc;

    fn file_event(path: &str) -> DecodedEvent {
        DecodedEvent {
            time: Utc::now().to_rfc3339(),
            sensor: "file".to_string(),
            kind: "FileOpen".to_string(),
            pid: 1,
            tgid: 1,
            cgroup_id: 0,
            monotonic_ns: 1,
            task_start_ns: None,
            path: Some(path.to_string()),
            old_path: None,
            process_exec: Some("/usr/bin/cat".to_string()),
            argv: None,
            parent_pid: None,
            child_pid: None,
            exit_code: None,
            thread: None,
            flags: None,
            open_flags: None,
            mode: None,
            length: None,
            network: None,
            syscall: None,
            identity: None,
            dns: None,
            lsm: None,
        }
    }

    #[test]
    fn sensitive_file_rule_matches_shadow_open() {
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/default");
        let mut engine = Engine::load(&rules_dir).expect("load rules");
        assert_eq!(engine.rule_count(), 2);
        assert_eq!(engine.skipped_sequences(), 0);

        let alerts = engine.evaluate(&file_event("/etc/shadow"));
        assert!(
            alerts
                .iter()
                .any(|alert| alert.rule == "sensitive-file-write-intent"),
            "alerts: {alerts:?}"
        );
    }

    #[test]
    fn process_exec_rule_sees_the_binary_path() {
        let directory = tempfile::tempdir().expect("tempdir");
        let rule = r#"
schema_version: 1
engine_version: "1.0.0"
rules:
  - id: watch-true
    version: 1
    severity: low
    source: process
    description: Watch /bin/true.
    condition:
      field: process.exec_path
      operator: eq
      value: "/bin/true"
    action: alert
"#;
        std::fs::write(directory.path().join("process.yaml"), rule).expect("write rule");
        let mut engine = Engine::load(directory.path()).expect("load rule");

        let event = DecodedEvent {
            time: Utc::now().to_rfc3339(),
            sensor: "process".to_string(),
            kind: "ProcessExec".to_string(),
            pid: 7,
            tgid: 7,
            cgroup_id: 0,
            monotonic_ns: 1,
            task_start_ns: None,
            path: Some("/bin/true".to_string()),
            old_path: None,
            process_exec: None,
            argv: None,
            parent_pid: None,
            child_pid: None,
            exit_code: None,
            thread: None,
            flags: None,
            open_flags: None,
            mode: None,
            length: None,
            network: None,
            syscall: None,
            identity: None,
            dns: None,
            lsm: None,
        };

        assert_eq!(engine.evaluate(&event).len(), 1);
    }

    #[test]
    fn deny_rule_is_rejected_with_an_error() {
        let directory = tempfile::tempdir().expect("tempdir");
        let rule = r#"
schema_version: 1
engine_version: "1.0.0"
rules:
  - id: block-shadow
    version: 1
    severity: critical
    source: file
    description: Block writes to shadow.
    condition:
      field: file.path
      operator: eq
      value: "/etc/shadow"
    action: deny
"#;
        std::fs::write(directory.path().join("deny.yaml"), rule).expect("write rule");
        let engine = Engine::load(directory.path()).expect("load rules");
        assert_eq!(engine.rule_count(), 0);
        assert_eq!(engine.errors().len(), 1);
        assert!(engine.errors()[0].contains("does not enforce"));
    }

    #[test]
    fn rule_does_not_match_unrelated_path() {
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/default");
        let mut engine = Engine::load(&rules_dir).expect("load rules");
        let alerts = engine.evaluate(&file_event("/tmp/notes.txt"));
        assert!(alerts.is_empty(), "alerts: {alerts:?}");
    }
}
