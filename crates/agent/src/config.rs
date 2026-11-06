// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent configuration.

use std::path::{Path, PathBuf};

use privacy::RedactionPolicy;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Cluster name reported to the control plane.
    pub cluster: String,
    /// Node name. Defaults to the hostname.
    pub node_name: String,
    /// Stable agent id. Generated from the machine id when empty.
    pub agent_id: String,
    /// Local API address. Must be loopback.
    pub listen: String,
    /// SQLCipher database path.
    pub db_path: PathBuf,
    /// 32-byte storage key path.
    pub key_path: PathBuf,
    /// Rule directory. Empty disables rules.
    pub rules_dir: PathBuf,
    /// Host proc root used for executable lookups.
    pub proc_root: PathBuf,
    /// Sensors to attach.
    pub sensors: Vec<String>,
    /// Flush when this many events are queued.
    pub batch_max_events: usize,
    /// Flush when this many serialized bytes are queued.
    pub batch_max_bytes: usize,
    /// Flush interval in milliseconds.
    pub flush_ms: u64,
    /// Delete acknowledged local rows after this many seconds.
    pub retention_secs: u64,
    /// Redaction policy.
    pub redaction: RedactionPolicy,
    /// Run without a control plane and use a test key when no key exists.
    pub dev: bool,
    /// Remote sink. None keeps batches local.
    #[serde(default)]
    pub transport: Option<transport::TransportConfig>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            cluster: "default".to_string(),
            node_name: hostname(),
            agent_id: String::new(),
            listen: "127.0.0.1:9464".to_string(),
            db_path: PathBuf::from("/var/lib/ebpf-agent/outbox.db"),
            key_path: PathBuf::from("/etc/ebpf-agent/storage.key"),
            rules_dir: PathBuf::from("rules/default"),
            proc_root: PathBuf::from("/proc"),
            sensors: vec!["process".to_string(), "file".to_string()],
            batch_max_events: 500,
            batch_max_bytes: 1024 * 1024,
            flush_ms: 1000,
            retention_secs: 7 * 24 * 60 * 60,
            redaction: RedactionPolicy::defaults(),
            dev: false,
            transport: None,
        }
    }
}

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read config {path}: {detail}")]
    Read {
        /// Path.
        path: PathBuf,
        /// Detail.
        detail: String,
    },
    /// The TOML is invalid.
    #[error("cannot parse config: {0}")]
    Parse(String),
    /// A value is out of bounds.
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl AgentConfig {
    /// Load a TOML config, or defaults when `path` is None.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut config = match path {
            Some(path) => {
                let text = std::fs::read_to_string(path).map_err(|error| ConfigError::Read {
                    path: path.to_path_buf(),
                    detail: error.to_string(),
                })?;
                toml::from_str(&text).map_err(|error| ConfigError::Parse(error.to_string()))?
            }
            None => Self::default(),
        };
        if config.node_name.is_empty() {
            config.node_name = hostname();
        }
        config.validate()?;
        Ok(config)
    }

    /// Validate bounds.
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        if self.batch_max_events == 0 || self.batch_max_events > 10_000 {
            return Err(ConfigError::Invalid(
                "batch_max_events must be in 1..=10000".to_string(),
            ));
        }
        if self.batch_max_bytes == 0 || self.batch_max_bytes > 16 * 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "batch_max_bytes must be in 1..=16777216".to_string(),
            ));
        }
        if self.flush_ms == 0 || self.flush_ms > 60_000 {
            return Err(ConfigError::Invalid(
                "flush_ms must be in 1..=60000".to_string(),
            ));
        }
        if self.sensors.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one sensor must be configured".to_string(),
            ));
        }
        if let Some(transport) = &self.transport {
            if transport.endpoint.is_empty() {
                return Err(ConfigError::Invalid(
                    "transport.endpoint must not be empty".to_string(),
                ));
            }
            if transport.timeout_secs == 0 || transport.timeout_secs > 600 {
                return Err(ConfigError::Invalid(
                    "transport.timeout_secs must be in 1..=600".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Hostname used to derive an agent id.
pub fn hostname_for_id() -> String {
    hostname()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
