// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Connection pool configuration for PostgreSQL.
//!
//! Bounded pool with short-lived connections. The pool is
//! configured for the control plane's access pattern: many
//! short transactions, few long-running queries.

#![forbid(unsafe_code)]

use std::time::Duration;

/// Pool configuration with sensible defaults for the control
/// plane.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// PostgreSQL connection URL.
    pub database_url: String,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Minimum number of idle connections to maintain.
    pub min_connections: u32,
    /// Maximum time to wait for a connection from the pool.
    pub acquire_timeout: Duration,
    /// Maximum lifetime of a connection before recycling.
    pub max_lifetime: Duration,
    /// Idle timeout before a connection is closed.
    pub idle_timeout: Duration,
    /// Whether to run migrations on startup.
    pub auto_migrate: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            database_url: String::from(
                "postgres://control_app:control_app_dev_only@localhost:5432/control",
            ),
            // Bounded: the control plane has limited concurrency.
            max_connections: 10,
            min_connections: 2,
            // Short acquire timeout: fail fast rather than queue.
            acquire_timeout: Duration::from_secs(5),
            // Recycle connections every 30 minutes.
            max_lifetime: Duration::from_secs(1800),
            // Close idle connections after 10 minutes.
            idle_timeout: Duration::from_secs(600),
            auto_migrate: false,
        }
    }
}

impl PoolConfig {
    /// Create a pool config from a database URL with defaults.
    pub fn from_url(database_url: &str) -> Self {
        Self {
            database_url: database_url.to_string(),
            ..Default::default()
        }
    }

    /// Set the maximum connections.
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the acquire timeout.
    pub fn with_acquire_timeout(mut self, timeout: Duration) -> Self {
        self.acquire_timeout = timeout;
        self
    }

    /// Enable auto-migration on startup.
    pub fn with_auto_migrate(mut self) -> Self {
        self.auto_migrate = true;
        self
    }

    /// Build SQLx pool options from this configuration.
    pub fn to_pool_options(&self) -> sqlx::postgres::PgPoolOptions {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .acquire_timeout(self.acquire_timeout)
            .max_lifetime(self.max_lifetime)
            .idle_timeout(self.idle_timeout)
    }
}

/// The maximum advisory lock key value. Advisory locks are
/// bounded to prevent unbounded lock acquisition.
/// Keys are derived from cluster UUID hash mod this value.
pub const MAX_ADVISORY_LOCK_KEY: i64 = 1_000_000;

/// Compute a bounded advisory lock key from a cluster ID.
/// The key is always in [0, MAX_ADVISORY_LOCK_KEY].
pub fn advisory_key_for_cluster(cluster_id: uuid::Uuid) -> i64 {
    let bytes = cluster_id.as_bytes();
    // Use first 8 bytes as i64, then mod to bound.
    let raw = i64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    raw.unsigned_abs() as i64 % MAX_ADVISORY_LOCK_KEY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_config() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.min_connections, 2);
        assert_eq!(config.acquire_timeout, Duration::from_secs(5));
        assert!(!config.auto_migrate);
    }

    #[test]
    fn pool_config_builder() {
        let config = PoolConfig::from_url("postgres://localhost/test")
            .with_max_connections(20)
            .with_acquire_timeout(Duration::from_secs(10))
            .with_auto_migrate();
        assert_eq!(config.database_url, "postgres://localhost/test");
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.acquire_timeout, Duration::from_secs(10));
        assert!(config.auto_migrate);
    }

    #[test]
    fn advisory_key_is_bounded() {
        let id = uuid::Uuid::new_v4();
        let key = advisory_key_for_cluster(id);
        assert!(key >= 0);
        assert!(key < MAX_ADVISORY_LOCK_KEY);
    }

    #[test]
    fn advisory_key_deterministic() {
        let id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let k1 = advisory_key_for_cluster(id);
        let k2 = advisory_key_for_cluster(id);
        assert_eq!(k1, k2);
    }
}
