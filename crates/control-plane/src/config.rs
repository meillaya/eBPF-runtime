// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Control-plane configuration.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Control-plane configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlConfig {
    /// gRPC listen address.
    pub grpc_listen: String,
    /// HTTP listen address.
    pub http_listen: String,
    /// PostgreSQL URL.
    pub database_url: String,
    /// Cluster name served by this instance.
    pub cluster: String,
    /// PEM CA bundle for client certificates.
    pub tls_ca: PathBuf,
    /// PEM server certificate.
    pub tls_cert: PathBuf,
    /// PEM server key.
    pub tls_key: PathBuf,
    /// Database pool size.
    pub max_connections: u32,
    /// Development mode binds loopback and skips TLS.
    pub dev: bool,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            grpc_listen: "127.0.0.1:9443".to_string(),
            http_listen: "127.0.0.1:8080".to_string(),
            database_url: "postgres://postgres@127.0.0.1:5432/control".to_string(),
            cluster: "default".to_string(),
            tls_ca: PathBuf::from("/etc/ebpf-control-plane/ca.pem"),
            tls_cert: PathBuf::from("/etc/ebpf-control-plane/tls.crt"),
            tls_key: PathBuf::from("/etc/ebpf-control-plane/tls.key"),
            max_connections: 10,
            dev: false,
        }
    }
}

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Read failure.
    #[error("cannot read config {path}: {detail}")]
    Read {
        /// Path.
        path: PathBuf,
        /// Detail.
        detail: String,
    },
    /// TOML failure.
    #[error("cannot parse config: {0}")]
    Parse(String),
    /// Validation failure.
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl ControlConfig {
    /// Load a TOML config.
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, ConfigError> {
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
        config.validate()?;
        Ok(config)
    }

    /// Validate bounds and TLS requirements.
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        if self.max_connections == 0 || self.max_connections > 100 {
            return Err(ConfigError::Invalid(
                "max_connections must be in 1..=100".to_string(),
            ));
        }
        if self.cluster.is_empty() {
            return Err(ConfigError::Invalid(
                "cluster must not be empty".to_string(),
            ));
        }
        if self.dev {
            let grpc: std::net::SocketAddr = self
                .grpc_listen
                .parse()
                .map_err(|_| ConfigError::Invalid("invalid grpc_listen".to_string()))?;
            let http: std::net::SocketAddr = self
                .http_listen
                .parse()
                .map_err(|_| ConfigError::Invalid("invalid http_listen".to_string()))?;
            if !grpc.ip().is_loopback() || !http.ip().is_loopback() {
                return Err(ConfigError::Invalid(
                    "dev mode must bind loopback only".to_string(),
                ));
            }
        }
        Ok(())
    }
}
