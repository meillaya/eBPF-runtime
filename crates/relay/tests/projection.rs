// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Live ClickHouse projection test. Set DATABASE_URL and CLICKHOUSE_URL.

use event_model::{Batch, Event};
use relay::{run, RelayConfig};
use uuid::Uuid;

#[tokio::test]
async fn projects_a_batch_to_clickhouse() {
    let (Ok(url), Ok(clickhouse)) = (
        std::env::var("DATABASE_URL"),
        std::env::var("CLICKHOUSE_URL"),
    ) else {
        return;
    };
    let cluster_name = format!("relay-{}", Uuid::new_v4());
    let pool = control_db::connect(&url, 4).await.expect("connect");
    control_db::migrate(&pool).await.expect("migrate");
    let cluster = control_db::ensure_cluster(&pool, &cluster_name)
        .await
        .expect("cluster");
    let agent = format!("agent-{}", Uuid::new_v4());
    control_db::register_agent(&pool, cluster, &agent, "node-1", "gen-1", "boot", &[])
        .await
        .expect("agent");
    let event_id = "a".repeat(64);
    let batch = Batch {
        batch_id: Uuid::new_v4().to_string(),
        agent_id: agent.clone(),
        cluster: cluster_name,
        node_name: "node-1".to_string(),
        agent_generation: "gen-1".to_string(),
        boot_id: "b".repeat(32),
        schema_major: 1,
        schema_minor: 0,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        events: vec![Event {
            event_id: event_id.clone(),
            time: "2026-01-01T00:00:00Z".to_string(),
            sensor: "file".to_string(),
            kind: "FileOpen".to_string(),
            boot_id: "b".repeat(32),
            seq: 1,
            path: Some("/tmp/relay".to_string()),
            ..Default::default()
        }],
        alerts: Vec::new(),
    };
    control_db::accept_batch(&pool, cluster, &agent, &batch)
        .await
        .expect("accept");

    run(
        RelayConfig {
            database_url: url,
            kafka_brokers: Vec::new(),
            kafka_topic: "ebpf.batches".to_string(),
            clickhouse_url: clickhouse.clone(),
            clickhouse_database: "ebpf".to_string(),
            poll_ms: 100,
            limit: 1000,
        },
        true,
    )
    .await
    .expect("relay");

    let query = format!(
        "SELECT count() FROM ebpf.events WHERE event_id = '{}'",
        event_id
    );
    let response = reqwest::Client::new()
        .post(&clickhouse)
        .body(query)
        .send()
        .await
        .expect("clickhouse");
    let count: u64 = response.text().await.unwrap().trim().parse().unwrap_or(0);
    assert!(count >= 1, "event was not projected");
}
