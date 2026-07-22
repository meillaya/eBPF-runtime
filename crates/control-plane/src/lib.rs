// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated stateless control-plane query and live-stream
//! API for the eBPF runtime security platform.
//!
//! This crate provides:
//!
//! - **Health/compatibility**: service status, protocol/schema
//!   version negotiation.
//! - **Agent inventory**: queries against PostgreSQL (control
//!   truth) for fleet state.
//! - **Historical queries**: ClickHouse-backed event history
//!   with exact-query deduplication.
//! - **PostgreSQL control queries**: clusters, policies,
//!   rollouts from the authoritative control database.
//! - **Redacted live event fanout**: WebSocket-style pub/sub
//!   with cursor-based reconnect and slow-client shedding.
//! - **Bounded query limits**: pagination with opaque cursors,
//!   maximum page sizes, and time window enforcement.
//! - **Cluster scoping**: every query is scoped to a cluster;
//!   cross-cluster access is denied.
//! - **OIDC/RBAC middleware**: stateless JWT-based auth with
//!   four roles (viewer/analyst/policy-admin/admin).
//! - **Audit hooks**: every mutation emits an actor-bound
//!   audit intent.
//! - **Static UI serving**: dashboard assets with content-type
//!   detection and path traversal protection.
//!
//! # Data source hierarchy
//!
//! - **PostgreSQL** is the control truth (fleet state, policies,
//!   rollouts, audit).
//! - **ClickHouse** is the event history store (historical
//!   queries with deduplication).
//! - **Kafka/gRPC** streams are live hints ONLY (not
//!   authoritative; used for low-latency notification).
//!
//! # BLOCKER
//!
//! This host does not have live PostgreSQL, ClickHouse, or
//! Kafka instances. All logic is validated with in-memory mocks
//! and fixtures. Live integration re-opens on the declared
//! self-hosted runner.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod audit;
pub mod config;
pub mod control;
pub mod error;
pub mod health;
pub mod history;
pub mod inventory;
pub mod live;
pub mod pagination;
pub mod redact;
pub mod router;
pub mod ui;

// Re-export primary types for convenience.
pub use audit::AuditHook;
pub use config::ControlPlaneConfig;
pub use error::{ControlPlaneError, Result};
pub use health::{CompatibilityInfo, HealthStatus};
pub use history::EventQueryFilters;
pub use live::{LiveEvent, LiveHub, Subscriber};
pub use pagination::{PageRequest, PageResponse};
pub use redact::RedactedEventRow;
pub use router::RequestContext;
pub use ui::StaticUi;

use auth::RbacPolicy;
use uuid::Uuid;

/// The control-plane orchestrator.
///
/// Holds the configuration, RBAC policy, audit hook, and live
/// hub. Repository access is passed per-call (generic over the
/// repository type) to support both live PostgreSQL and
/// in-memory mocks.
#[derive(Debug)]
pub struct ControlPlane {
    /// Server configuration with bounded limits.
    pub config: ControlPlaneConfig,
    /// The RBAC policy for route authorization.
    pub rbac: RbacPolicy,
    /// Audit hook for mutation tracking.
    pub audit: AuditHook,
    /// Live event fanout hub.
    pub live: LiveHub,
    /// Static UI server.
    pub ui: StaticUi,
}

impl ControlPlane {
    /// Create a new control-plane instance with the given
    /// configuration and RBAC policy.
    pub fn new(config: ControlPlaneConfig, rbac: RbacPolicy) -> Self {
        let live = LiveHub::new(config.live_buffer_cap, config.slow_client_threshold);
        let ui = StaticUi::new(&config.ui_dir);
        Self {
            config,
            rbac,
            audit: AuditHook::new(),
            live,
            ui,
        }
    }

    /// Create a control-plane with default configuration and
    /// the standard RBAC policy.
    pub fn with_defaults() -> Self {
        Self::new(
            ControlPlaneConfig::default(),
            auth::default_control_plane_policy(),
        )
    }

    /// Authenticate and authorize a request, returning the
    /// request context.
    pub fn authorize(
        &self,
        sub: &str,
        groups: &[String],
        method: &str,
        path: &str,
        cluster_id: Uuid,
    ) -> Result<RequestContext> {
        router::authorize_request(
            &self.rbac,
            &self.audit,
            sub,
            groups,
            method,
            path,
            cluster_id,
        )
    }

    /// Build a health status.
    pub fn health(
        &self,
        postgres_reachable: bool,
        clickhouse_reachable: bool,
        kafka_reachable: bool,
        uptime_s: u64,
    ) -> HealthStatus {
        health::build_health(
            self.config.protocol_major,
            self.config.schema_major,
            postgres_reachable,
            clickhouse_reachable,
            kafka_reachable,
            self.config.default_cluster.clone(),
            uptime_s,
        )
    }

    /// Build compatibility info.
    pub fn compatibility(&self) -> CompatibilityInfo {
        health::build_compatibility(
            self.config.protocol_major,
            self.config.schema_major,
            self.config.max_page_size,
            self.config.max_window_s,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_plane_with_defaults() {
        let cp = ControlPlane::with_defaults();
        assert_eq!(cp.config.max_page_size, config::DEFAULT_MAX_PAGE_SIZE);
        assert_eq!(cp.config.live_buffer_cap, config::DEFAULT_LIVE_BUFFER_CAP);
    }

    #[test]
    fn health_reports_status() {
        let cp = ControlPlane::with_defaults();
        let h = cp.health(true, true, true, 100);
        assert!(h.is_healthy());
        assert_eq!(h.protocol_major, 1);
        assert_eq!(h.schema_major, 1);
    }

    #[test]
    fn compatibility_reports_limits() {
        let cp = ControlPlane::with_defaults();
        let c = cp.compatibility();
        assert_eq!(c.max_page_size, config::DEFAULT_MAX_PAGE_SIZE);
        assert_eq!(c.max_window_s, config::DEFAULT_MAX_WINDOW_S);
        assert_eq!(c.supported_event_kinds.len(), 15);
    }

    #[test]
    fn authorize_viewer_read() {
        let cp = ControlPlane::with_defaults();
        let cid = Uuid::new_v4();
        let ctx = cp
            .authorize("u1", &["viewers".into()], "GET", "/api/v1/events", cid)
            .unwrap();
        assert_eq!(ctx.role, auth::Role::Viewer);
        assert_eq!(ctx.cluster_id, cid);
    }

    #[test]
    fn authorize_viewer_mutation_denied() {
        let cp = ControlPlane::with_defaults();
        let cid = Uuid::new_v4();
        let result = cp.authorize(
            "u1",
            &["viewers".into()],
            "POST",
            "/api/v1/policies/stage",
            cid,
        );
        assert!(result.is_err());
    }

    #[test]
    fn live_hub_integrated() {
        let cp = ControlPlane::with_defaults();
        let sub_id = cp.live.subscribe("prod");
        cp.live.publish(
            "prod",
            live::LiveEvent {
                seq: 0,
                event_id: "evt-001".into(),
                event_kind: "EVENT_KIND_FILE_OPEN".into(),
                node_name: "node-1".into(),
                cluster: "prod".into(),
                ts_monotonic_ns: 1_000_000,
                payload: "{}".into(),
            },
        );
        let events = cp.live.drain(sub_id, 10).unwrap();
        assert_eq!(events.len(), 1);
    }
}
