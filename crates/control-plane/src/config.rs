// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Control-plane server configuration with bounded defaults.
//!
//! Every limit is finite and validated at construction time.
//! There is no "unlimited" mode.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use crate::error::{ControlPlaneError, Result};

/// Default maximum page size for paginated queries.
pub const DEFAULT_MAX_PAGE_SIZE: usize = 200;

/// Default maximum time window for historical queries (seconds).
/// 24 hours.
pub const DEFAULT_MAX_WINDOW_S: u64 = 86_400;

/// Default live event buffer capacity per subscriber.
pub const DEFAULT_LIVE_BUFFER_CAP: usize = 256;

/// Default slow-client threshold: if a subscriber has not
/// consumed events for this many consecutive publishes, it is
/// shed.
pub const DEFAULT_SLOW_CLIENT_THRESHOLD: u32 = 8;

/// Default static UI directory.
pub const DEFAULT_UI_DIR: &str = "web/dist";

/// Control-plane server configuration.
#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    /// Bind address. Must be set explicitly.
    pub bind_addr: IpAddr,
    /// Bind port.
    pub bind_port: u16,
    /// Maximum page size for paginated queries.
    pub max_page_size: usize,
    /// Maximum time window for historical queries (seconds).
    pub max_window_s: u64,
    /// Live event buffer capacity per subscriber.
    pub live_buffer_cap: usize,
    /// Slow-client shedding threshold (consecutive missed
    /// publishes).
    pub slow_client_threshold: u32,
    /// The cluster this control-plane instance is scoped to.
    /// All queries are scoped to this cluster. `None` means
    /// multi-cluster mode (operator must still supply a cluster
    /// per request).
    pub default_cluster: Option<String>,
    /// Static UI directory path.
    pub ui_dir: String,
    /// The protocol major version this control-plane supports.
    pub protocol_major: u16,
    /// The schema major version this control-plane supports.
    pub schema_major: u16,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            bind_addr: IpAddr::from([127, 0, 0, 1]),
            bind_port: 8080,
            max_page_size: DEFAULT_MAX_PAGE_SIZE,
            max_window_s: DEFAULT_MAX_WINDOW_S,
            live_buffer_cap: DEFAULT_LIVE_BUFFER_CAP,
            slow_client_threshold: DEFAULT_SLOW_CLIENT_THRESHOLD,
            default_cluster: None,
            ui_dir: DEFAULT_UI_DIR.to_string(),
            protocol_major: 1,
            schema_major: 1,
        }
    }
}

impl ControlPlaneConfig {
    /// Validate the configuration. Returns an error if any
    /// value is out of bounds.
    pub fn validate(&self) -> Result<()> {
        if self.max_page_size == 0 || self.max_page_size > 10_000 {
            return Err(ControlPlaneError::Internal(format!(
                "max_page_size must be in 1..=10000, got {}",
                self.max_page_size
            )));
        }
        if self.max_window_s == 0 || self.max_window_s > 30 * 86_400 {
            return Err(ControlPlaneError::Internal(format!(
                "max_window_s must be in 1..=2592000 (30 days), got {}",
                self.max_window_s
            )));
        }
        if self.live_buffer_cap == 0 || self.live_buffer_cap > 65_536 {
            return Err(ControlPlaneError::Internal(format!(
                "live_buffer_cap must be in 1..=65536, got {}",
                self.live_buffer_cap
            )));
        }
        if self.slow_client_threshold == 0 {
            return Err(ControlPlaneError::Internal(
                "slow_client_threshold must be >= 1".into(),
            ));
        }
        Ok(())
    }

    /// Clamp a requested page size to the configured maximum.
    pub fn clamp_page_size(&self, requested: usize) -> usize {
        requested.min(self.max_page_size).max(1)
    }

    /// Validate a requested time window against the configured
    /// maximum.
    pub fn validate_window(&self, window_s: u64) -> Result<()> {
        if window_s > self.max_window_s {
            return Err(ControlPlaneError::WindowExceeded {
                requested_s: window_s,
                max_s: self.max_window_s,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = ControlPlaneConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn zero_page_size_rejected() {
        let config = ControlPlaneConfig {
            max_page_size: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn oversized_page_size_rejected() {
        let config = ControlPlaneConfig {
            max_page_size: 100_000,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_window_rejected() {
        let config = ControlPlaneConfig {
            max_window_s: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn oversized_window_rejected() {
        let config = ControlPlaneConfig {
            max_window_s: 31 * 86_400,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_buffer_cap_rejected() {
        let config = ControlPlaneConfig {
            live_buffer_cap: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_slow_threshold_rejected() {
        let config = ControlPlaneConfig {
            slow_client_threshold: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn clamp_page_size_bounds() {
        let config = ControlPlaneConfig::default();
        assert_eq!(config.clamp_page_size(0), 1);
        assert_eq!(config.clamp_page_size(50), 50);
        assert_eq!(config.clamp_page_size(200), 200);
        assert_eq!(config.clamp_page_size(500), 200);
    }

    #[test]
    fn validate_window_within_bounds() {
        let config = ControlPlaneConfig::default();
        assert!(config.validate_window(3600).is_ok());
        assert!(config.validate_window(86_400).is_ok());
    }

    #[test]
    fn validate_window_exceeds_bounds() {
        let config = ControlPlaneConfig::default();
        let err = config.validate_window(86_401).unwrap_err();
        assert!(matches!(err, ControlPlaneError::WindowExceeded { .. }));
    }
}
