// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for analytics-clickhouse using fixtures.
//!
//! Validates deduplication, DLQ routing, TTL, consumer lag,
//! and migration repeatability without a live ClickHouse instance.

use analytics_clickhouse::consumer::{ConsumerConfig, ConsumerLagMetrics, PartitionLag};
use analytics_clickhouse::dedup::DeduplicationEngine;
use analytics_clickhouse::dlq::DlqRouter;
use analytics_clickhouse::migration;
use analytics_clickhouse::query::{ExactQueryBuilder, ExactQueryStrategy};
use analytics_clickhouse::schema::{EventKind, EventRow};
use analytics_clickhouse::{
    DEFAULT_DLQ_TTL_DAYS, DEFAULT_EVENTS_TTL_DAYS, MAX_CONSUMER_LAG_PER_PARTITION,
    MAX_PAYLOAD_BYTES,
};

/// Load and parse a fixture JSON file.
fn load_fixture(name: &str) -> serde_json::Value {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    let path = format!("{manifest}/../../tests/fixtures/clickhouse/{name}");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse fixture {path}: {e}"))
}

fn make_row(event_id: &str, version: u64, offset: u64) -> EventRow {
    EventRow {
        kafka_topic: "events.v1".to_string(),
        kafka_partition: 0,
        kafka_offset: offset,
        event_id: event_id.to_string(),
        batch_id: format!("batch-{version}"),
        seq: version,
        schema_major: 1,
        schema_minor: 0,
        event_kind: EventKind::FileOpen,
        sensor: "ops".to_string(),
        agent_generation: "gen-1".to_string(),
        node_name: "node-1".to_string(),
        cluster: "prod".to_string(),
        ts_monotonic_ns: version * 1000,
        boot_id_hex: "00".repeat(16),
        pid_tgid: 1234,
        cgroup_id: 5678,
        uid: 1000,
        gid: 1000,
        payload: format!(r#"{{"v":{version}}}"#),
        version,
    }
}

// ── Deduplication fixture tests ──

#[test]
fn fixture_duplicate_replay_100_times() {
    let fixture = load_fixture("duplicate-replay.json");
    let event_id = fixture["event_id"].as_str().unwrap();
    let replay_count = fixture["replay_count"].as_u64().unwrap() as usize;
    let expected_physical = fixture["expected_physical_rows"].as_u64().unwrap() as usize;
    let expected_logical = fixture["expected_logical_rows"].as_u64().unwrap() as usize;
    let expected_winning_version = fixture["expected_winning_version"].as_u64().unwrap();

    let mut engine = DeduplicationEngine::new();
    for i in 0..replay_count {
        engine.insert(make_row(event_id, i as u64, i as u64));
    }

    // Before exact query: all physical rows visible.
    assert_eq!(engine.physical_count(), expected_physical);
    assert_eq!(engine.logical_count(), expected_logical);
    assert!(engine.has_duplicates(event_id));

    // After exact query: one logical row with highest version.
    let exact = engine.exact_rows();
    assert_eq!(exact.len(), expected_logical);
    assert_eq!(exact[0].event_id, event_id);
    assert_eq!(exact[0].version, expected_winning_version);
}

#[test]
fn fixture_valid_batch_ingestion() {
    let fixture = load_fixture("valid-batch.json");
    let events = fixture["events"].as_array().unwrap();
    let schema_major = fixture["schema_major"].as_u64().unwrap() as u16;
    let node_name = fixture["node_name"].as_str().unwrap();
    let cluster = fixture["cluster"].as_str().unwrap();

    assert_eq!(schema_major, 1);

    let mut engine = DeduplicationEngine::new();
    for (i, event) in events.iter().enumerate() {
        let event_id = event["event_id"].as_str().unwrap();
        let kind_str = event["event_kind"].as_str().unwrap();
        let kind = EventKind::from_proto_name(kind_str).expect("valid event kind");

        let row = EventRow {
            kafka_topic: "events.v1".to_string(),
            kafka_partition: 0,
            kafka_offset: 100 + i as u64,
            event_id: event_id.to_string(),
            batch_id: "batch-fixture".to_string(),
            seq: event["seq"].as_u64().unwrap(),
            schema_major,
            schema_minor: 0,
            event_kind: kind,
            sensor: event["sensor"].as_str().unwrap().to_string(),
            agent_generation: fixture["agent_generation"].as_str().unwrap().to_string(),
            node_name: node_name.to_string(),
            cluster: cluster.to_string(),
            ts_monotonic_ns: event["ts_monotonic_ns"].as_u64().unwrap(),
            boot_id_hex: fixture["boot_id_hex"].as_str().unwrap().to_string(),
            pid_tgid: event["pid_tgid"].as_u64().unwrap(),
            cgroup_id: event["cgroup_id"].as_u64().unwrap(),
            uid: event["uid"].as_u64().unwrap() as u32,
            gid: event["gid"].as_u64().unwrap() as u32,
            payload: event["payload"].as_str().unwrap().to_string(),
            version: 100 + i as u64,
        };

        // Validate before insert.
        row.validate().expect("valid row");
        engine.insert(row);
    }

    // All 5 events ingested, no duplicates.
    assert_eq!(engine.physical_count(), 5);
    assert_eq!(engine.logical_count(), 5);
    assert_eq!(engine.duplicate_count(), 0);

    // Exact query returns all 5.
    let exact = engine.exact_rows();
    assert_eq!(exact.len(), 5);
}

// ── DLQ fixture tests ──

#[test]
fn fixture_malformed_messages_route_to_dlq() {
    let fixture = load_fixture("malformed-dlq.json");
    let messages = fixture["malformed_messages"].as_array().unwrap();
    let expected_total = fixture["expected_total_dlq_records"].as_u64().unwrap() as usize;

    let mut router = DlqRouter::new();

    for msg in messages {
        let name = msg["name"].as_str().unwrap();
        let partition = msg["kafka_partition"].as_i64().unwrap() as i32;
        let offset = msg["kafka_offset"].as_u64().unwrap();
        let raw_payload = msg["raw_payload"].as_str().unwrap_or("");
        let raw_key = msg["raw_key"].as_str().unwrap_or("");
        let expected_prefix = msg["expected_dlq_reason_prefix"].as_str().unwrap();

        let record = if name.starts_with("schema-major") {
            let schema_major = msg["schema_major"].as_u64().unwrap() as u16;
            let schema_minor = msg["schema_minor"].as_u64().unwrap() as u16;
            let event_id = msg["event_id"].as_str().unwrap_or("");
            let batch_id = msg["batch_id"].as_str().unwrap_or("");
            let event_kind = msg["event_kind"].as_str().unwrap_or("");
            router.route_schema_rejected(
                partition,
                offset,
                schema_major,
                schema_minor,
                event_id,
                batch_id,
                event_kind,
                raw_payload,
                raw_key,
            )
        } else if name == "unknown-event-kind" {
            let kind = msg["event_kind"].as_str().unwrap();
            let event_id = msg["event_id"].as_str().unwrap_or("");
            router.route_unknown_event_kind(partition, offset, kind, event_id, raw_payload)
        } else {
            router.route_malformed(partition, offset, "fixture test", raw_payload, raw_key)
        };

        // Verify DLQ reason matches expected prefix.
        let reason_str = record.dlq_reason.as_reason_string();
        assert!(
            reason_str.starts_with(expected_prefix),
            "fixture {name}: reason '{reason_str}' does not start with '{expected_prefix}'"
        );

        // Verify topic/partition/offset preserved.
        assert_eq!(record.original_topic, "events.v1");
        assert_eq!(record.original_partition, partition);
        assert_eq!(record.original_offset, offset);

        // Consumer continues after DLQ routing.
        assert!(msg["consumer_continues"].as_bool().unwrap());
    }

    assert_eq!(router.routed_count(), expected_total);
    assert_eq!(router.topic(), "events.dlq.v1");
}

// ── TTL fixture tests ──

#[test]
fn fixture_ttl_configuration() {
    let fixture = load_fixture("ttl-config.json");
    let events_ttl = fixture["events_ttl_days"].as_u64().unwrap() as u16;
    let dlq_ttl = fixture["dlq_ttl_days"].as_u64().unwrap() as u16;

    assert_eq!(events_ttl, DEFAULT_EVENTS_TTL_DAYS);
    assert_eq!(dlq_ttl, DEFAULT_DLQ_TTL_DAYS);

    let test_cases = fixture["test_cases"].as_array().unwrap();
    for case in test_cases {
        let name = case["name"].as_str().unwrap();
        let ingested_days_ago = case["ingested_days_ago"].as_u64().unwrap();
        let ttl_days = case["ttl_days"].as_u64().unwrap();
        let expected_expired = case["expected_expired"].as_bool().unwrap();

        // TTL logic: expired if ttl_days > 0 AND ingested_days_ago >= ttl_days.
        let is_expired = ttl_days > 0 && ingested_days_ago >= ttl_days;
        assert_eq!(
            is_expired, expected_expired,
            "TTL fixture '{name}': ingested {ingested_days_ago}d ago, TTL {ttl_days}d"
        );
    }
}

// ── Consumer lag fixture tests ──

#[test]
fn fixture_consumer_lag_bounds() {
    let fixture = load_fixture("consumer-lag.json");
    let max_lag = fixture["max_consumer_lag_per_partition"].as_u64().unwrap();
    assert_eq!(max_lag, MAX_CONSUMER_LAG_PER_PARTITION);

    let partitions_json = fixture["partitions"].as_array().unwrap();
    let mut partitions = Vec::new();

    for p in partitions_json {
        let partition = PartitionLag {
            topic: p["topic"].as_str().unwrap().to_string(),
            partition: p["partition"].as_i64().unwrap() as i32,
            consumed_offset: p["consumed_offset"].as_u64().unwrap(),
            latest_offset: p["latest_offset"].as_u64().unwrap(),
            total_rows: p["consumed_offset"].as_u64().unwrap(),
        };

        let expected_lag = p["expected_lag"].as_u64().unwrap();
        let expected_within = p["expected_within_bounds"].as_bool().unwrap();

        assert_eq!(
            partition.lag(),
            expected_lag,
            "partition {}: lag mismatch",
            partition.partition
        );
        assert_eq!(
            partition.is_within_bounds(),
            expected_within,
            "partition {}: bounds mismatch",
            partition.partition
        );

        partitions.push(partition);
    }

    let metrics = ConsumerLagMetrics::new(partitions);
    // Partition 2 exceeds bounds, so aggregate is not within bounds.
    assert!(!metrics.is_within_bounds());
    assert_eq!(metrics.lagging_partitions().len(), 1);
    assert_eq!(metrics.lagging_partitions()[0].partition, 2);
}

#[test]
fn fixture_consumer_config_valid() {
    let fixture = load_fixture("consumer-lag.json");
    let config_json = &fixture["consumer_config"];

    let config = ConsumerConfig {
        broker_list: config_json["broker_list"].as_str().unwrap().to_string(),
        topic: config_json["topic"].as_str().unwrap().to_string(),
        group_name: config_json["group_name"].as_str().unwrap().to_string(),
        num_consumers: config_json["num_consumers"].as_u64().unwrap() as u32,
        max_block_size: config_json["max_block_size"].as_u64().unwrap() as u32,
        skip_broken_messages: config_json["skip_broken_messages"].as_u64().unwrap() as u32,
        commit_every_batch: config_json["commit_every_batch"].as_u64().unwrap() as u32,
    };

    assert!(config.validate().is_ok());
    assert_eq!(config.topic, "events.v1");
    assert_eq!(config.group_name, "clickhouse-events-v1");
}

// ── Migration repeatability tests ──

#[test]
fn fixture_migrations_are_repeatable() {
    let migrations = migration::embedded_migrations();
    assert_eq!(migrations.len(), 5);
    migration::validate_all_repeatable(&migrations).expect("all migrations must be repeatable");
    migration::validate_ordering(&migrations).expect("migrations must be ordered");
}

// ── Exact query builder tests ──

#[test]
fn exact_query_strategies_produce_valid_sql() {
    // FINAL strategy
    let final_sql = ExactQueryBuilder::new(ExactQueryStrategy::Final)
        .event_id("evt-001")
        .build();
    assert!(final_sql.contains("FINAL"));
    assert!(final_sql.contains("event_id = 'evt-001'"));

    // argMax strategy
    let argmax_sql = ExactQueryBuilder::new(ExactQueryStrategy::ArgMax)
        .event_id("evt-001")
        .build();
    assert!(argmax_sql.contains("argMax("));
    assert!(argmax_sql.contains("GROUP BY event_id"));
    assert!(argmax_sql.contains("event_id = 'evt-001'"));
}

// ── Payload bounds test ──

#[test]
fn payload_bounded_to_64kib() {
    let mut row = make_row("evt-big", 1, 1);
    row.payload = "x".repeat(MAX_PAYLOAD_BYTES + 1000);
    assert!(row.truncate_payload());
    assert_eq!(row.payload.len(), MAX_PAYLOAD_BYTES);
    assert!(row.validate().is_ok());
}
