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
    let mut server = tokio::spawn(serve(ControlConfig {
        grpc_listen: format!("127.0.0.1:{grpc_port}"),
        http_listen: format!("127.0.0.1:{http_port}"),
        database_url: url.clone(),
        cluster: cluster.clone(),
        dev: true,
        ..Default::default()
    }));
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(1500)) => {},
        result = &mut server => panic!("control plane stopped early: {result:?}"),
    }

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
    let (policy_tx, _policy_rx) = tokio::sync::watch::channel(None);
    let (_policy_ack_tx, policy_ack_rx) = tokio::sync::mpsc::unbounded_channel();
    let handle = tokio::spawn(agent::delivery::run(agent::delivery::DeliveryConfig {
        storage: storage.clone(),
        transport,
        dev: true,
        agent_id,
        generation: "gen-1".to_string(),
        cluster,
        node_name: "node-1".to_string(),
        sensors: vec!["file".to_string()],
        policy_tx,
        policy_ack_rx,
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

    let rules = r#"schema_version: 1
engine_version: "1.0.0"
rules:
  - id: live-policy
    version: 1
    severity: low
    source: file
    description: Live policy.
    condition:
      field: file.path
      operator: eq
      value: "/tmp/live"
    action: alert
"#;
    let http = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{http_port}/api/v1");
    let stage = http
        .post(format!("{base}/policies/stage"))
        .json(&serde_json::json!({"version": 7, "content": rules, "name": "default"}))
        .send()
        .await
        .expect("stage");
    assert!(stage.status().is_success());
    let commit = http
        .post(format!("{base}/policies/commit"))
        .json(&serde_json::json!({"version": 7}))
        .send()
        .await
        .expect("commit");
    let commit_status = commit.status();
    let commit_body = commit.text().await.unwrap_or_default();
    assert!(commit_status.is_success(), "commit failed: {commit_body}");

    let mut applied = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        if let Ok(Some((version, _, _))) = storage.get_policy() {
            if version == "7" {
                applied = true;
                break;
            }
        }
    }

    handle.abort();
    server.abort();
    assert!(drained, "outbox did not drain");
    assert!(applied, "policy was not applied by the agent");
    let _ = url;
}
