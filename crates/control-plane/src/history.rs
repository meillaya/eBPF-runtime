// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Historical ClickHouse queries for event history.
//!
//! ClickHouse is the event history store. Queries use the
//! `ExactQueryBuilder` from `analytics-clickhouse` to generate
//! deduplicated SQL. All queries are cluster-scoped and
//! time-window bounded.
//!
//! BLOCKER: No live ClickHouse on this host. Query building and
//! result mapping are tested with in-memory fixtures. Live
//! integration re-opens on the declared self-hosted runner.

#![forbid(unsafe_code)]

use analytics_clickhouse::query::{ExactQueryBuilder, ExactQueryStrategy};
use analytics_clickhouse::schema::{EventKind, EventRow};
use serde::{Deserialize, Serialize};

use crate::error::{ControlPlaneError, Result};
use crate::pagination::{validate_time_window, PageRequest, PageResponse};
use crate::redact::{redact_event_row, RedactedEventRow};

/// Filters for historical event queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventQueryFilters {
    /// Cluster name (mandatory for cluster scoping).
    pub cluster: Option<String>,
    /// Node name filter.
    pub node_name: Option<String>,
    /// Event kind filter (proto name).
    pub event_kind: Option<String>,
    /// Specific event ID (point lookup).
    pub event_id: Option<String>,
    /// Batch ID filter.
    pub batch_id: Option<String>,
    /// Start time (epoch seconds).
    pub start_epoch_s: Option<u64>,
    /// End time (epoch seconds).
    pub end_epoch_s: Option<u64>,
}

/// Build a ClickHouse SQL query from filters with cluster
/// scoping and pagination.
///
/// The cluster filter is MANDATORY. If not provided, returns
/// `MissingClusterScope`.
pub fn build_event_query(
    filters: &EventQueryFilters,
    page: &PageRequest,
    max_page_size: usize,
    max_window_s: u64,
    strategy: ExactQueryStrategy,
) -> Result<String> {
    // Cluster scope is mandatory.
    let cluster = filters
        .cluster
        .as_deref()
        .ok_or(ControlPlaneError::MissingClusterScope)?;

    // Validate time window if both bounds are provided.
    if let (Some(start), Some(end)) = (filters.start_epoch_s, filters.end_epoch_s) {
        validate_time_window(start, end, max_window_s)?;
    }

    let limit = page.limit.min(max_page_size).max(1);

    let mut builder = ExactQueryBuilder::new(strategy)
        .cluster(cluster)
        .limit(limit);

    if let Some(ref node) = filters.node_name {
        builder = builder.node_name(node);
    }
    if let Some(ref kind_str) = filters.event_kind {
        if let Some(kind) = EventKind::from_proto_name(kind_str) {
            builder = builder.event_kind(kind);
        } else {
            return Err(ControlPlaneError::HistoryQuery(format!(
                "unknown event kind: {kind_str}"
            )));
        }
    }
    if let Some(ref eid) = filters.event_id {
        builder = builder.event_id(eid);
    }
    if let Some(ref bid) = filters.batch_id {
        builder = builder.batch_id(bid);
    }

    Ok(builder.build())
}

/// Apply redaction to a batch of event rows.
///
/// Every row is redacted before crossing the API boundary.
/// This is the mandatory API-boundary redaction stage.
pub fn redact_rows(rows: &[EventRow]) -> Vec<RedactedEventRow> {
    rows.iter().map(redact_event_row).collect()
}

/// Build a paginated response from in-memory event rows
/// (for testing without live ClickHouse).
pub fn paginate_rows(
    rows: &[EventRow],
    page: &PageRequest,
    max_page_size: usize,
) -> Result<PageResponse<RedactedEventRow>> {
    let limit = page.limit.min(max_page_size).max(1);
    let offset = page.cursor_offset()?.unwrap_or(0) as usize;

    let total = rows.len() as u64;
    let page_rows: Vec<&EventRow> = rows.iter().skip(offset).take(limit).collect();
    let redacted: Vec<RedactedEventRow> = page_rows.iter().map(|r| redact_event_row(r)).collect();

    let next_offset = offset + redacted.len();
    let next_cursor = if next_offset < total as usize {
        Some(crate::pagination::encode_cursor(next_offset as u64))
    } else {
        None
    };

    Ok(PageResponse::new(redacted, next_cursor, Some(total)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_filters(cluster: &str) -> EventQueryFilters {
        EventQueryFilters {
            cluster: Some(cluster.to_string()),
            ..Default::default()
        }
    }

    fn test_row(event_id: &str, cluster: &str) -> EventRow {
        EventRow {
            kafka_topic: "events.v1".to_string(),
            kafka_partition: 0,
            kafka_offset: 42,
            event_id: event_id.to_string(),
            batch_id: "batch-1".to_string(),
            seq: 0,
            schema_major: 1,
            schema_minor: 0,
            event_kind: EventKind::FileOpen,
            sensor: "ops".to_string(),
            agent_generation: "gen-1".to_string(),
            node_name: "node-1".to_string(),
            cluster: cluster.to_string(),
            ts_monotonic_ns: 1_000_000,
            boot_id_hex: "00".repeat(16),
            pid_tgid: 1234,
            cgroup_id: 5678,
            uid: 1000,
            gid: 1000,
            payload: r#"{"path":"/etc/hostname"}"#.to_string(),
            version: 42,
        }
    }

    #[test]
    fn query_requires_cluster_scope() {
        let filters = EventQueryFilters::default();
        let page = PageRequest::first(10);
        let result = build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::Final);
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::MissingClusterScope
        ));
    }

    #[test]
    fn query_includes_cluster_filter() {
        let filters = test_filters("prod");
        let page = PageRequest::first(10);
        let sql =
            build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::Final).unwrap();
        assert!(sql.contains("cluster = 'prod'"));
        assert!(sql.contains("FINAL"));
    }

    #[test]
    fn query_with_all_filters() {
        let filters = EventQueryFilters {
            cluster: Some("prod".into()),
            node_name: Some("node-1".into()),
            event_kind: Some("EVENT_KIND_FILE_OPEN".into()),
            event_id: Some("evt-001".into()),
            batch_id: Some("batch-1".into()),
            start_epoch_s: Some(1000),
            end_epoch_s: Some(2000),
        };
        let page = PageRequest::first(10);
        let sql =
            build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::Final).unwrap();
        assert!(sql.contains("cluster = 'prod'"));
        assert!(sql.contains("node_name = 'node-1'"));
        assert!(sql.contains("event_kind = 'EVENT_KIND_FILE_OPEN'"));
        assert!(sql.contains("event_id = 'evt-001'"));
        assert!(sql.contains("batch_id = 'batch-1'"));
    }

    #[test]
    fn query_rejects_oversized_window() {
        let filters = EventQueryFilters {
            cluster: Some("prod".into()),
            start_epoch_s: Some(0),
            end_epoch_s: Some(200_000),
            ..Default::default()
        };
        let page = PageRequest::first(10);
        let result = build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::Final);
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::WindowExceeded { .. }
        ));
    }

    #[test]
    fn query_rejects_unknown_event_kind() {
        let filters = EventQueryFilters {
            cluster: Some("prod".into()),
            event_kind: Some("EVENT_KIND_BOGUS".into()),
            ..Default::default()
        };
        let page = PageRequest::first(10);
        let result = build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::Final);
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::HistoryQuery(_)
        ));
    }

    #[test]
    fn query_clamps_limit() {
        let filters = test_filters("prod");
        let page = PageRequest::first(1000);
        let sql =
            build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::Final).unwrap();
        assert!(sql.contains("LIMIT 200"));
    }

    #[test]
    fn argmax_strategy_generates_group_by() {
        let filters = test_filters("prod");
        let page = PageRequest::first(10);
        let sql =
            build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::ArgMax).unwrap();
        assert!(sql.contains("GROUP BY event_id"));
        assert!(sql.contains("argMax"));
    }

    #[test]
    fn redact_rows_masks_secrets() {
        let rows = vec![
            test_row("evt-001", "prod"),
            EventRow {
                payload: r#"{"key":"AKIAIOSFODNN7EXAMPLE"}"#.to_string(),
                ..test_row("evt-002", "prod")
            },
        ];
        let redacted = redact_rows(&rows);
        assert_eq!(redacted.len(), 2);
        assert!(!redacted[0].payload_redacted);
        assert!(redacted[1].payload_redacted);
        assert!(!redacted[1].payload.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn paginate_rows_works() {
        let rows: Vec<EventRow> = (0..5)
            .map(|i| test_row(&format!("evt-{i:03}"), "prod"))
            .collect();

        let page = PageRequest::first(2);
        let resp = paginate_rows(&rows, &page, 200).unwrap();
        assert_eq!(resp.items.len(), 2);
        assert!(resp.has_more());
        assert_eq!(resp.total, Some(5));
    }

    #[test]
    fn paginate_rows_last_page() {
        let rows: Vec<EventRow> = (0..3)
            .map(|i| test_row(&format!("evt-{i:03}"), "prod"))
            .collect();

        let page = PageRequest::first(10);
        let resp = paginate_rows(&rows, &page, 200).unwrap();
        assert_eq!(resp.items.len(), 3);
        assert!(!resp.has_more());
    }
}
