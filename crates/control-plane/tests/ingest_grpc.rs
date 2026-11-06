// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Live gRPC ingest test. Run with DATABASE_URL set.

use std::time::Duration;

use control_plane::{serve, ControlConfig};
use event_model::{Batch, Event};
use transport::TransportClient;
use uuid::Uuid;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn batch(agent: &str) -> Batch {
    let event = Event {
        time: "2026-01-01T00:00:00Z".to_string(),
        sensor: "file".to_string(),
        kind: "FileOpen".to_string(),
        event_id: "c".repeat(64),
        boot_id: "d".repeat(32),
        seq: 1,
        path: Some("/etc/shadow".to_string()),
        ..Default::default()
    };
    Batch {
        batch_id: Uuid::new_v4().to_string(),
        agent_id: agent.to_string(),
        cluster: "grpc-test".to_string(),
        node_name: "node-1".to_string(),
        agent_generation: "gen-1".to_string(),
        boot_id: "d".repeat(32),
        schema_major: 1,
        schema_minor: 0,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        events: vec![event],
        alerts: Vec::new(),
    }
}

#[tokio::test]
async fn dev_grpc_accepts_batch_once() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let grpc_port = free_port();
    let http_port = free_port();
    let config = ControlConfig {
        grpc_listen: format!("127.0.0.1:{grpc_port}"),
        http_listen: format!("127.0.0.1:{http_port}"),
        database_url: url,
        cluster: format!("grpc-{}", Uuid::new_v4()),
        dev: true,
        ..Default::default()
    };
    let handle = tokio::spawn(serve(config));
    tokio::time::sleep(Duration::from_millis(800)).await;

    let agent = format!("agent-{}", Uuid::new_v4());
    let client = TransportClient::connect_insecure(
        &format!("http://127.0.0.1:{grpc_port}"),
        &agent,
        "gen-1",
    )
    .await
    .expect("connect");
    client
        .register(
            "grpc-test",
            "node-1",
            &"d".repeat(32),
            &["file".to_string()],
        )
        .await
        .expect("register");

    let batch = batch(&agent);
    let first = client.publish_batch(&batch).await.expect("first");
    assert!(first.accepted);
    assert!(!first.duplicate);
    let second = client.publish_batch(&batch).await.expect("second");
    assert!(second.duplicate);

    handle.abort();
}
