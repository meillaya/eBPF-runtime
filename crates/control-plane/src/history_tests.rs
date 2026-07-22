// SPDX-License-Identifier: Apache-2.0 OR MIT
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
    let sql = build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::Final).unwrap();
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
    let sql = build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::Final).unwrap();
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
    let sql = build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::Final).unwrap();
    assert!(sql.contains("LIMIT 200"));
}

#[test]
fn argmax_strategy_generates_group_by() {
    let filters = test_filters("prod");
    let page = PageRequest::first(10);
    let sql = build_event_query(&filters, &page, 200, 86_400, ExactQueryStrategy::ArgMax).unwrap();
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
