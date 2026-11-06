// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Live agent outbox delivery test. Run with DATABASE_URL set.

use std::sync::Arc;
use std::time::Duration;

use control_plane::{serve, ControlConfig};
use event_model::{Batch, Event};
use observability::Metrics;
use storage_local::{LocalStorage, StorageKey};
use transport::TransportConfig;
use uuid::Uuid;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn delivery_acks_and_clears_outbox() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let grpc_port = free_port();
    let http_port = free_port();
    let cluster = format!("delivery-{}", Uuid::new_v4());
    let server = tokio::spawn(serve(ControlConfig {
        grpc_listen: format!("127.0.0.1:{grpc_port}"),
        http_listen: format!("127.0.0.1:{http_port}"),
        database_url: url.clone(),
        cluster: cluster.clone(),
        dev: true,
        ..Default::default()
    }));
    tokio::time::sleep(Duration::from_millis(800)).await;

    let dir = tempfile::tempdir().unwrap();
    let storage =
        Arc::new(LocalStorage::open(&dir.path().join("outbox.db"), &StorageKey::test()).unwrap());
    let agent_id = format!("agent-{}", Uuid::new_v4());
    let event = Event {
        time: "2026-01-01T00:00:00Z".to_string(),
        sensor: "file".to_string(),
        kind: "FileOpen".to_string(),
        event_id: "e".repeat(64),
        boot_id: "f".repeat(32),
        seq: 1,
        path: Some("/etc/shadow".to_string()),
        ..Default::default()
    };
    storage.insert_event(&event).unwrap();
    let batch = Batch {
        batch_id: Uuid::new_v4().to_string(),
        agent_id: agent_id.clone(),
        cluster: cluster.clone(),
        node_name: "node-1".to_string(),
        agent_generation: "gen-1".to_string(),
        boot_id: "f".repeat(32),
        schema_major: 1,
        schema_minor: 0,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        events: vec![event],
        alerts: Vec::new(),
    };
    storage.insert_batch(&batch).unwrap();

    let transport = TransportConfig {
        endpoint: format!("http://127.0.0.1:{grpc_port}"),
        domain_name: "control-plane".to_string(),
        ca_path: Default::default(),
        cert_path: Default::default(),
        key_path: Default::default(),
        timeout_secs: 5,
    };
    let metrics = Arc::new(Metrics::new().unwrap());
    let handle = tokio::spawn(agent::delivery::run(agent::delivery::DeliveryConfig {
        storage: storage.clone(),
        transport,
        dev: true,
        agent_id,
        generation: "gen-1".to_string(),
        cluster,
        node_name: "node-1".to_string(),
        sensors: vec!["file".to_string()],
        metrics,
    }));

    let mut drained = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        if storage.outbox_depth().unwrap() == 0 {
            drained = true;
            break;
        }
    }
    handle.abort();
    server.abort();
    assert!(drained, "outbox did not drain");
    let _ = url;
}
