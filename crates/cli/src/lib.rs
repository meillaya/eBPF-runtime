// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet API client.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    /// API base, for example `http://127.0.0.1:8080/api/v1`.
    pub api_base: String,
    /// Bearer token file.
    pub token_path: PathBuf,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            api_base: "http://127.0.0.1:8080/api/v1".to_string(),
            token_path: default_token_path(),
        }
    }
}

fn default_token_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/ebpfctl/token")
}

/// CLI errors.
#[derive(Debug, Error)]
pub enum CliError {
    /// HTTP failure.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Configuration failure.
    #[error("config: {0}")]
    Config(String),
    /// The API returned a non-success status.
    #[error("api error {status}: {body}")]
    Api {
        /// Status code.
        status: u16,
        /// Body.
        body: String,
    },
}

/// API client.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl Client {
    /// Load config and token.
    pub fn from_config(config: &ClientConfig) -> Result<Self, CliError> {
        let token = match std::env::var("EBPF_TOKEN") {
            Ok(token) => Some(token),
            Err(_) => std::fs::read_to_string(&config.token_path)
                .ok()
                .map(|token| token.trim().to_string())
                .filter(|token| !token.is_empty()),
        };
        Ok(Self {
            http: reqwest::Client::new(),
            base: config.api_base.trim_end_matches('/').to_string(),
            token,
        })
    }

    /// GET a path.
    pub async fn get(&self, path: &str) -> Result<serde_json::Value, CliError> {
        self.send(self.http.get(format!("{}{path}", self.base)))
            .await
    }

    /// POST JSON to a path.
    pub async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, CliError> {
        self.send(self.http.post(format!("{}{path}", self.base)).json(&body))
            .await
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<serde_json::Value, CliError> {
        let request = if let Some(token) = &self.token {
            request.bearer_auth(token)
        } else {
            request
        };
        let response = request.send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(CliError::Api {
                status: status.as_u16(),
                body,
            });
        }
        serde_json::from_str(&body).map_err(|error| CliError::Config(error.to_string()))
    }
}

/// Load config from an optional path.
pub fn load_config(path: Option<&std::path::Path>) -> Result<ClientConfig, CliError> {
    let mut config = match path {
        Some(path) => {
            let text = std::fs::read_to_string(path)?;
            toml::from_str(&text).map_err(|error| CliError::Config(error.to_string()))?
        }
        None => ClientConfig::default(),
    };
    if let Ok(base) = std::env::var("EBPF_API_BASE") {
        config.api_base = base;
    }
    Ok(config)
}

/// Persist a token with mode 0600.
pub fn save_token(path: &std::path::Path, token: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
