// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Health and compatibility endpoints.
//!
//! The health endpoint reports service status, protocol/schema
//! compatibility, and dependency reachability. It is the only
//! endpoint that does NOT require authentication (liveness/readiness
//! probes).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// The health status of the control-plane service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Service status: "ok" or "degraded".
    pub status: String,
    /// The protocol major version this instance supports.
    pub protocol_major: u16,
    /// The schema major version this instance supports.
    pub schema_major: u16,
    /// Whether the PostgreSQL control database is reachable.
    pub postgres_reachable: bool,
    /// Whether the ClickHouse analytics database is reachable.
    pub clickhouse_reachable: bool,
    /// Whether the Kafka event bus is reachable.
    pub kafka_reachable: bool,
    /// The cluster this instance is scoped to (if any).
    pub cluster_scope: Option<String>,
    /// Monotonic uptime in seconds.
    pub uptime_s: u64,
}

impl HealthStatus {
    /// Whether the service is healthy (all critical dependencies
    /// reachable).
    pub fn is_healthy(&self) -> bool {
        self.status == "ok" && self.postgres_reachable
    }
}

/// Compatibility information for client negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityInfo {
    /// The protocol major version.
    pub protocol_major: u16,
    /// The schema major version.
    pub schema_major: u16,
    /// Supported event kinds (proto names).
    pub supported_event_kinds: Vec<String>,
    /// The maximum page size the server accepts.
    pub max_page_size: usize,
    /// The maximum time window for historical queries (seconds).
    pub max_window_s: u64,
}

/// Build a health status from dependency reachability flags.
pub fn build_health(
    protocol_major: u16,
    schema_major: u16,
    postgres_reachable: bool,
    clickhouse_reachable: bool,
    kafka_reachable: bool,
    cluster_scope: Option<String>,
    uptime_s: u64,
) -> HealthStatus {
    let status = if postgres_reachable { "ok" } else { "degraded" };
    HealthStatus {
        status: status.to_string(),
        protocol_major,
        schema_major,
        postgres_reachable,
        clickhouse_reachable,
        kafka_reachable,
        cluster_scope,
        uptime_s,
    }
}

/// Build compatibility info from config.
pub fn build_compatibility(
    protocol_major: u16,
    schema_major: u16,
    max_page_size: usize,
    max_window_s: u64,
) -> CompatibilityInfo {
    CompatibilityInfo {
        protocol_major,
        schema_major,
        supported_event_kinds: vec![
            "EVENT_KIND_PROCESS_FORK".into(),
            "EVENT_KIND_PROCESS_EXEC_RESULT".into(),
            "EVENT_KIND_PROCESS_EXIT".into(),
            "EVENT_KIND_FILE_OPEN".into(),
            "EVENT_KIND_FILE_CREATE".into(),
            "EVENT_KIND_FILE_UNLINK".into(),
            "EVENT_KIND_FILE_RENAME".into(),
            "EVENT_KIND_NETWORK_CONNECT".into(),
            "EVENT_KIND_NETWORK_ACCEPT".into(),
            "EVENT_KIND_NETWORK_STATE".into(),
            "EVENT_KIND_DNS_PACKET".into(),
            "EVENT_KIND_SYSCALL_ENTER".into(),
            "EVENT_KIND_SYSCALL_EXIT".into(),
            "EVENT_KIND_LSM_DENY_OWN".into(),
            "EVENT_KIND_IDENTITY".into(),
        ],
        max_page_size,
        max_window_s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_when_postgres_reachable() {
        let h = build_health(1, 1, true, true, true, Some("prod".into()), 100);
        assert!(h.is_healthy());
        assert_eq!(h.status, "ok");
    }

    #[test]
    fn degraded_when_postgres_unreachable() {
        let h = build_health(1, 1, false, true, true, None, 100);
        assert!(!h.is_healthy());
        assert_eq!(h.status, "degraded");
    }

    #[test]
    fn compatibility_lists_event_kinds() {
        let c = build_compatibility(1, 1, 200, 86_400);
        assert_eq!(c.supported_event_kinds.len(), 15);
        assert!(c
            .supported_event_kinds
            .contains(&"EVENT_KIND_FILE_OPEN".to_string()));
        assert_eq!(c.max_page_size, 200);
        assert_eq!(c.max_window_s, 86_400);
    }

    #[test]
    fn health_serializes_to_json() {
        let h = build_health(1, 1, true, false, false, None, 42);
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"postgres_reachable\":true"));
        assert!(json.contains("\"clickhouse_reachable\":false"));
    }
}
