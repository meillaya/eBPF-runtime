// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Live policy rollout tests. Run with DATABASE_URL set.

use std::time::Duration;

use control_plane::{serve, ControlConfig};
use protocol::v1::control_command::Command;
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use transport::TransportClient;
use uuid::Uuid;

const POLICY: &str = "schema_version: 1\nengine_version: \"1.0.0\"\nrules: []\n";

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

struct Server {
    base: String,
    grpc: String,
    cluster: String,
    pool: PgPool,
    handle: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn start(url: &str) -> Server {
    let grpc_port = free_port();
    let http_port = free_port();
    let cluster = format!("rollout-{}", Uuid::new_v4());
    let config = ControlConfig {
        grpc_listen: format!("127.0.0.1:{grpc_port}"),
        http_listen: format!("127.0.0.1:{http_port}"),
        database_url: url.to_string(),
        cluster: cluster.clone(),
        dev: true,
        ..Default::default()
    };
    let handle = tokio::spawn(async move {
        let _ = serve(config).await;
    });
    let http = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{http_port}");
    for _ in 0..80 {
        if http
            .get(format!("{base}/healthz"))
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pool = PgPool::connect(url).await.expect("db pool");
    Server {
        base: format!("{base}/api/v1"),
        grpc: format!("http://127.0.0.1:{grpc_port}"),
        cluster,
        pool,
        handle,
    }
}

async fn register(server: &Server, agent: &str) -> TransportClient {
    let client = TransportClient::connect_insecure(&server.grpc, agent, "gen-1")
        .await
        .expect("connect");
    client
        .register(
            &server.cluster,
            "node-1",
            &"b".repeat(32),
            &["file".to_string()],
        )
        .await
        .expect("register");
    client
}

async fn stage_commit(http: &reqwest::Client, base: &str, version: i64) -> String {
    let stage = http
        .post(format!("{base}/policies/stage"))
        .json(&json!({"version": version, "content": POLICY, "name": "default"}))
        .send()
        .await
        .expect("stage");
    assert!(
        stage.status().is_success(),
        "stage failed: {}",
        stage.status()
    );
    let staged: Value = stage.json().await.expect("stage json");
    let digest = staged["policy"]["digest"]
        .as_str()
        .expect("digest")
        .to_string();
    let commit = http
        .post(format!("{base}/policies/commit"))
        .json(&json!({"version": version}))
        .send()
        .await
        .expect("commit");
    assert!(
        commit.status().is_success(),
        "commit failed: {}",
        commit.status()
    );
    digest
}

async fn start_rollout(
    http: &reqwest::Client,
    base: &str,
    version: i64,
    min_ratio: f64,
    timeout_secs: i64,
) -> Value {
    let response = http
        .post(format!("{base}/policies/{version}/rollout"))
        .json(&json!({"min_ratio": min_ratio, "timeout_secs": timeout_secs}))
        .send()
        .await
        .expect("rollout request");
    assert!(
        response.status().is_success(),
        "rollout failed: {} {}",
        response.status(),
        response.text().await.unwrap_or_default()
    );
    response.json().await.expect("rollout json")
}

async fn wait_rollout(http: &reqwest::Client, base: &str, version: i64, expected: &str) -> Value {
    let mut last = String::new();
    for _ in 0..60 {
        let response = http
            .get(format!("{base}/policies/{version}/rollout"))
            .send()
            .await
            .expect("rollout status");
        if response.status().is_success() {
            let body: Value = response.json().await.expect("status json");
            last = body["rollout"]["status"].as_str().unwrap_or("").to_string();
            if body["rollout"]["status"] == expected {
                return body["rollout"].clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("rollout for version {version} never reached {expected}; last status {last}");
}

async fn expect_snapshot(
    watch: &mut tonic::Streaming<protocol::v1::ControlCommand>,
    version: &str,
) {
    for _ in 0..20 {
        let item = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("control stream timed out")
            .expect("control stream ended")
            .expect("control stream error");
        if let Some(Command::Policy(snapshot)) = item.command {
            if snapshot.version == version {
                return;
            }
        }
    }
    panic!("did not receive policy snapshot {version}");
}

async fn audit_has(http: &reqwest::Client, base: &str, action: &str) -> bool {
    let audit: Value = http
        .get(format!("{base}/audit"))
        .send()
        .await
        .expect("audit")
        .json()
        .await
        .expect("audit json");
    audit["audit"]
        .as_array()
        .map(|rows| rows.iter().any(|row| row["action"] == action))
        .unwrap_or(false)
}

#[tokio::test]
async fn rollout_promotes_when_threshold_is_met() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let server = start(&url).await;
    let http = reqwest::Client::new();
    let agents: Vec<String> = (0..3)
        .map(|_| format!("agent-{}", Uuid::new_v4()))
        .collect();
    let mut clients = Vec::new();
    for agent in &agents {
        clients.push(register(&server, agent).await);
    }
    stage_commit(&http, &server.base, 1).await;
    let digest = stage_commit(&http, &server.base, 2).await;
    let created = start_rollout(&http, &server.base, 2, 1.0, 5).await;
    assert_eq!(created["rollout"]["expected_agents"], 3);
    for client in &clients {
        client
            .report_policy_ack("2", &digest, "applied", "")
            .await
            .expect("ack");
    }
    let rollout = wait_rollout(&http, &server.base, 2, "promoted").await;
    assert_eq!(rollout["applied_agents"], 3);
    let policies: Value = http
        .get(format!("{}/policies", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let target = policies["policies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|policy| policy["version"] == 2)
        .expect("version 2");
    assert_eq!(target["status"], "applied");
    assert!(audit_has(&http, &server.base, "policy.rollout.promoted").await);
}

#[tokio::test]
async fn rollout_rolls_back_on_timeout_and_broadcasts_previous() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let server = start(&url).await;
    let http = reqwest::Client::new();
    let agents: Vec<String> = (0..3)
        .map(|_| format!("agent-{}", Uuid::new_v4()))
        .collect();
    let mut clients = Vec::new();
    for agent in &agents {
        clients.push(register(&server, agent).await);
    }
    stage_commit(&http, &server.base, 1).await;
    let digest = stage_commit(&http, &server.base, 2).await;
    let mut watch = clients[0].watch_control().await.expect("watch");
    expect_snapshot(&mut watch, "2").await;
    start_rollout(&http, &server.base, 2, 0.95, 2).await;
    for client in &clients[..2] {
        client
            .report_policy_ack("2", &digest, "applied", "")
            .await
            .expect("ack");
    }
    let rollout = wait_rollout(&http, &server.base, 2, "rolled_back").await;
    assert_eq!(rollout["applied_agents"], 2);
    expect_snapshot(&mut watch, "1").await;
    assert!(audit_has(&http, &server.base, "policy.rollout.rolled_back").await);
}

#[tokio::test]
async fn offline_agent_is_excluded_from_the_denominator() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let server = start(&url).await;
    let http = reqwest::Client::new();
    let agents: Vec<String> = (0..3)
        .map(|_| format!("agent-{}", Uuid::new_v4()))
        .collect();
    let mut clients = Vec::new();
    for agent in &agents {
        clients.push(register(&server, agent).await);
    }
    sqlx::query("UPDATE agents SET last_seen = now() - interval '10 minutes' WHERE spiffe_id = $1")
        .bind(&agents[2])
        .execute(&server.pool)
        .await
        .expect("age agent");
    stage_commit(&http, &server.base, 1).await;
    let digest = stage_commit(&http, &server.base, 2).await;
    let created = start_rollout(&http, &server.base, 2, 1.0, 5).await;
    assert_eq!(created["rollout"]["expected_agents"], 2);
    for client in &clients[..2] {
        client
            .report_policy_ack("2", &digest, "applied", "")
            .await
            .expect("ack");
    }
    wait_rollout(&http, &server.base, 2, "promoted").await;
}

#[tokio::test]
async fn rejected_ack_rolls_back_immediately() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let server = start(&url).await;
    let http = reqwest::Client::new();
    let agents: Vec<String> = (0..3)
        .map(|_| format!("agent-{}", Uuid::new_v4()))
        .collect();
    let mut clients = Vec::new();
    for agent in &agents {
        clients.push(register(&server, agent).await);
    }
    stage_commit(&http, &server.base, 1).await;
    let digest = stage_commit(&http, &server.base, 2).await;
    let mut watch = clients[0].watch_control().await.expect("watch");
    expect_snapshot(&mut watch, "2").await;
    start_rollout(&http, &server.base, 2, 0.95, 30).await;
    clients[0]
        .report_policy_ack("2", &digest, "rejected", "test rejection")
        .await
        .expect("reject");
    let rollout = wait_rollout(&http, &server.base, 2, "rolled_back").await;
    assert_eq!(rollout["rejected_agents"], 1);
    expect_snapshot(&mut watch, "1").await;
    assert!(audit_has(&http, &server.base, "policy.rollout.rolled_back").await);
}

#[tokio::test]
async fn rollout_requires_a_previous_version() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let server = start(&url).await;
    let http = reqwest::Client::new();
    register(&server, &format!("agent-{}", Uuid::new_v4())).await;
    stage_commit(&http, &server.base, 1).await;
    let response = http
        .post(format!("{}/policies/1/rollout", server.base))
        .json(&json!({"min_ratio": 1.0, "timeout_secs": 5}))
        .send()
        .await
        .expect("rollout request");
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn second_pending_rollout_conflicts() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let server = start(&url).await;
    let http = reqwest::Client::new();
    register(&server, &format!("agent-{}", Uuid::new_v4())).await;
    stage_commit(&http, &server.base, 1).await;
    stage_commit(&http, &server.base, 2).await;
    start_rollout(&http, &server.base, 2, 1.0, 30).await;
    let response = http
        .post(format!("{}/policies/2/rollout", server.base))
        .json(&json!({"min_ratio": 1.0, "timeout_secs": 30}))
        .send()
        .await
        .expect("second rollout");
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
}
