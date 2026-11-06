// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Live PostgreSQL smoke test. Run with DATABASE_URL set.

use control_db::{accept_batch, connect, ensure_cluster, migrate, recent_events, register_agent};
use event_model::{Batch, Event};
use uuid::Uuid;

fn batch(cluster: &str, agent: &str) -> Batch {
    let event = Event {
        time: "2026-01-01T00:00:00Z".to_string(),
        sensor: "file".to_string(),
        kind: "FileOpen".to_string(),
        event_id: "a".repeat(64),
        boot_id: "b".repeat(32),
        seq: 1,
        path: Some("/etc/shadow".to_string()),
        ..Default::default()
    };
    Batch {
        batch_id: Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        cluster: cluster.to_string(),
        node_name: "node-1".to_string(),
        agent_generation: "gen-1".to_string(),
        boot_id: "b".repeat(32),
        schema_major: 1,
        schema_minor: 0,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        events: vec![event],
        alerts: Vec::new(),
    }
}

#[tokio::test]
async fn accept_batch_is_idempotent() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = connect(&url, 4).await.expect("connect");
    migrate(&pool).await.expect("migrate");

    let cluster_name = format!("test-{}", Uuid::new_v4());
    let cluster = ensure_cluster(&pool, &cluster_name).await.expect("cluster");
    let agent = format!("agent-{}", Uuid::new_v4());
    register_agent(
        &pool,
        cluster,
        &agent,
        "node-1",
        "gen-1",
        "boot",
        &["process".into()],
    )
    .await
    .expect("agent");

    let batch = batch(&cluster_name, &agent);
    let first = accept_batch(&pool, cluster, &agent, &batch)
        .await
        .expect("first");
    assert!(!first.duplicate);
    let second = accept_batch(&pool, cluster, &agent, &batch)
        .await
        .expect("second");
    assert!(second.duplicate);

    let events = recent_events(&pool, cluster, 10).await.expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "FileOpen");
}
