// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side unit tests for the standalone agent REST/WebSocket API (task 26).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent::api::{encode_cursor, ApiErrorKind, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, MAX_PAGE_WINDOW};
use agent::{seed_simulated_events, ApiServer};
use agent_core::{normalize_bytes, synthetic_record, Kind, NormalizedEvent, RawEvent};
use futures_util::StreamExt;
use observability::MetricsRegistry;
use privacy::{apply_redaction, DecodedRecord, RedactionPolicy};
use storage_local::LocalStorage;
use tokio_tungstenite::tungstenite::Message;

fn free_loopback_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

fn temp_db() -> PathBuf {
    std::env::temp_dir().join(format!("api-test-{}.db", uuid::Uuid::new_v4()))
}

async fn wait_for_health(url: &str) {
    let client = reqwest::Client::new();
    for _ in 0..200 {
        if let Ok(resp) = client.get(url).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not become healthy at {url}");
}

struct TestServer {
    base: String,
    storage: Arc<LocalStorage>,
    broadcaster: tokio::sync::broadcast::Sender<String>,
    handle: tokio::task::JoinHandle<()>,
    db: PathBuf,
}

async fn start_test_server() -> TestServer {
    let addr = free_loopback_addr();
    let db = temp_db();
    let storage = Arc::new(LocalStorage::open_with_test_key(&db).expect("open test storage"));
    storage.run_migrations().expect("migrations");
    let registry = Arc::new(MetricsRegistry::new());
    registry.set_storage_available(true);
    let server = Arc::new(ApiServer::new(storage.clone(), registry, addr));
    let broadcaster = server.broadcaster();
    let policy = RedactionPolicy::with_default_secrets();
    seed_simulated_events(&storage, &broadcaster, &policy).expect("seed events");
    let server_task = server.clone();
    let handle = tokio::spawn(async move {
        let _ = server_task.serve().await;
    });
    let base = format!("http://{addr}");
    wait_for_health(&format!("{base}/api/v1/health")).await;
    TestServer {
        base,
        storage,
        broadcaster,
        handle,
        db,
    }
}

impl TestServer {
    fn ws_url(&self) -> String {
        self.base.replace("http://", "ws://") + "/ws"
    }
    fn stop(self) {
        self.handle.abort();
        let _ = std::fs::remove_file(&self.db);
    }
}

async fn get_json(client: &reqwest::Client, url: &str) -> serde_json::Value {
    let resp = client.get(url).send().await.expect("send");
    assert!(resp.status().is_success(), "GET {url} -> {}", resp.status());
    resp.json().await.expect("json")
}

// ---------------------------------------------------------------------------
// Observability endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_server_serves_health_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let body = get_json(&client, &format!("{}/api/v1/health", server.base)).await;
    assert!(body["status"].is_string(), "health has status: {body}");
    assert!(body["reasons"].is_array());
    server.stop();
}

#[tokio::test]
async fn api_server_serves_readiness_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let body = get_json(&client, &format!("{}/api/v1/readiness", server.base)).await;
    assert!(body["status"].is_string(), "readiness has status: {body}");
    server.stop();
}

#[tokio::test]
async fn api_server_serves_metrics_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/metrics", server.base))
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success());
    let text = resp.text().await.expect("text");
    assert!(text.contains("ebpf_agent"), "prometheus metrics exposed: {text}");
    server.stop();
}

// ---------------------------------------------------------------------------
// Event endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_server_serves_events_endpoint_with_pagination() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let page1 = get_json(&client, &format!("{}/api/v1/events?limit=10", server.base)).await;
    assert_eq!(page1["count"].as_u64().unwrap(), 10);
    assert!(page1["events"].as_array().unwrap().len() == 10);
    let cursor = page1["next_cursor"].as_str().expect("next_cursor present");

    let page2 = get_json(
        &client,
        &format!("{}/api/v1/events?limit=10&cursor={cursor}", server.base),
    )
    .await;
    assert_eq!(page2["count"].as_u64().unwrap(), 10);
    // Pages are disjoint (cursor advances).
    let id1 = page1["events"][0]["event_id"].as_str().unwrap().to_string();
    let id2 = page2["events"][0]["event_id"].as_str().unwrap().to_string();
    assert_ne!(id1, id2, "cursor must advance to new events");
    server.stop();
}

#[tokio::test]
async fn api_server_serves_events_endpoint_with_filtering() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let body = get_json(&client, &format!("{}/api/v1/events?kind=DnsPacket", server.base)).await;
    let events = body["events"].as_array().expect("events array");
    assert!(!events.is_empty(), "expected DnsPacket events");
    for e in events {
        assert_eq!(e["kind"], "DnsPacket", "filter must return only DnsPacket");
    }
    server.stop();
}

#[tokio::test]
async fn api_server_serves_single_event_by_id() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let list = get_json(&client, &format!("{}/api/v1/events?limit=1", server.base)).await;
    let id = list["events"][0]["event_id"].as_str().expect("event_id").to_string();
    let single = get_json(&client, &format!("{}/api/v1/events/{id}", server.base)).await;
    assert_eq!(single["event_id"], id, "single event matches requested id");
    // Unknown id -> 404.
    let resp = client
        .get(format!("{}/api/v1/events/{}", server.base, "0".repeat(32)))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    server.stop();
}

// ---------------------------------------------------------------------------
// Derived-view endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_server_serves_process_tree_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let body = get_json(&client, &format!("{}/api/v1/process-tree", server.base)).await;
    let procs = body["processes"].as_array().expect("processes array");
    assert!(!procs.is_empty(), "process tree non-empty");
    assert!(body["count"].as_u64().unwrap() >= 1);
    // Each node has a pid and kind counts.
    assert!(procs[0]["pid"].is_number());
    assert!(procs[0]["kinds"].is_object());
    server.stop();
}

#[tokio::test]
async fn api_server_serves_sockets_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let body = get_json(&client, &format!("{}/api/v1/sockets", server.base)).await;
    let sockets = body["sockets"].as_array().expect("sockets array");
    assert!(!sockets.is_empty(), "socket table non-empty");
    assert!(sockets[0]["family"].is_string());
    assert!(sockets[0]["state"].is_string());
    // Filter by family.
    let filtered = get_json(&client, &format!("{}/api/v1/sockets?family=inet", server.base)).await;
    for s in filtered["sockets"].as_array().unwrap() {
        assert_eq!(s["family"], "inet");
    }
    server.stop();
}

#[tokio::test]
async fn api_server_serves_dns_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let body = get_json(&client, &format!("{}/api/v1/dns", server.base)).await;
    let dns = body["dns"].as_array().expect("dns array");
    assert!(!dns.is_empty(), "dns events non-empty");
    assert!(dns[0]["qname"].is_string());
    // Filter by qname substring.
    let filtered =
        get_json(&client, &format!("{}/api/v1/dns?qname=example.com", server.base)).await;
    for d in filtered["dns"].as_array().unwrap() {
        assert!(d["qname"].as_str().unwrap().contains("example.com"));
    }
    server.stop();
}

#[tokio::test]
async fn api_server_serves_files_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let body = get_json(&client, &format!("{}/api/v1/files", server.base)).await;
    let files = body["files"].as_array().expect("files array");
    assert!(!files.is_empty(), "file events non-empty");
    assert!(files[0]["path"].is_string());
    assert!(files[0]["kind"].is_string());
    server.stop();
}

#[tokio::test]
async fn api_server_serves_syscall_histograms_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let body = get_json(&client, &format!("{}/api/v1/syscall-histograms", server.base)).await;
    let histograms = body["histograms"].as_array().expect("histograms array");
    assert!(!histograms.is_empty(), "syscall histograms non-empty");
    assert!(histograms[0]["syscall"].is_string());
    assert!(histograms[0]["count"].is_number());
    assert!(body["total"].as_u64().unwrap() >= 1);
    server.stop();
}

#[tokio::test]
async fn api_server_serves_export_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/export?limit=5", server.base))
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success());
    let text = resp.text().await.expect("text");
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 5, "export yields 5 JSON lines");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("each line is valid JSON");
        assert!(v["event_id"].is_string());
    }
    server.stop();
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_server_serves_websocket_endpoint() {
    let server = start_test_server().await;
    let (mut ws, resp) = tokio_tungstenite::connect_async(server.ws_url())
        .await
        .expect("ws connect");
    assert_eq!(resp.status(), reqwest::StatusCode::SWITCHING_PROTOCOLS);
    server
        .broadcaster
        .send("{\"live\":true}".to_string())
        .expect("broadcast");
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("receive timeout")
        .expect("some message")
        .expect("ok message");
    match msg {
        Message::Text(t) => assert!(t.contains("live"), "live event received: {t}"),
        other => panic!("expected text frame, got {other:?}"),
    }
    server.stop();
}

#[tokio::test]
async fn api_server_rejects_non_loopback_bind() {
    let db = temp_db();
    let storage = Arc::new(LocalStorage::open_with_test_key(&db).expect("open"));
    storage.run_migrations().expect("migrations");
    let registry = Arc::new(MetricsRegistry::new());
    let server = ApiServer::new(storage, registry, "0.0.0.0:8080".parse().unwrap());
    let result = server.serve().await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err().kind,
        ApiErrorKind::NonLoopbackBindError(_)
    ));
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn api_server_rejects_invalid_cursor() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    for bad in ["garbage", "kc1:zzz", "kc2:10", "%"] {
        let resp = client
            .get(format!("{}/api/v1/events?cursor={bad}", server.base))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST, "cursor {bad}");
        let body: serde_json::Value = resp.json().await.expect("json");
        assert_eq!(body["error"]["kind"], "invalid_cursor_error", "cursor {bad}");
    }
    server.stop();
}

#[tokio::test]
async fn api_server_rejects_oversized_filter() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    // Oversized limit.
    let resp = client
        .get(format!("{}/api/v1/events?limit={}", server.base, MAX_PAGE_LIMIT + 1))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["kind"], "oversized_filter_error");
    // Oversized filter value.
    let huge = "x".repeat(2000);
    let resp = client
        .get(format!("{}/api/v1/events?kind={huge}", server.base))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["kind"], "oversized_filter_error");
    server.stop();
}

#[tokio::test]
async fn api_server_rejects_slow_websocket_consumer() {
    let server = start_test_server().await;
    // A consumer that connects but never reads.
    let (slow_ws, _resp) = tokio_tungstenite::connect_async(server.ws_url())
        .await
        .expect("slow consumer connects");
    // Hold the connection open without draining it.
    let _hold = tokio::spawn(async move {
        let mut ws = slow_ws;
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = ws.close(None).await;
    });
    // Flood past the bounded broadcast capacity.
    for i in 0..(agent::api::WS_BROADCAST_CAPACITY + 200) {
        let _ = server.broadcaster.send(format!("{{\"seq\":{i}}}"));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The server did NOT crash: health still serves.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/health", server.base))
        .send()
        .await
        .expect("server still reachable");
    assert!(resp.status().is_success(), "server survived slow consumer");
    // A fresh consumer is unaffected and still receives live events.
    let (mut fresh, _) = tokio_tungstenite::connect_async(server.ws_url())
        .await
        .expect("fresh consumer connects");
    server.broadcaster.send("{\"fresh\":1}".to_string()).expect("send");
    let msg = tokio::time::timeout(Duration::from_secs(5), fresh.next())
        .await
        .expect("fresh receives")
        .expect("some")
        .expect("ok");
    match msg {
        Message::Text(t) => assert!(t.contains("fresh")),
        other => panic!("expected text, got {other:?}"),
    }
    server.stop();
}

// ---------------------------------------------------------------------------
// Safety invariants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_server_never_exposes_loader_map_mutation() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    for method in [reqwest::Method::POST, reqwest::Method::PUT, reqwest::Method::DELETE] {
        let resp = client
            .request(method.clone(), format!("{}/api/v1/events", server.base))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    }
    for route in ["loader", "maps", "loader/attach", "maps/pin"] {
        let resp = client
            .get(format!("{}/api/v1/{route}", server.base))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    }
    server.stop();
}

#[tokio::test]
async fn api_server_never_bypasses_redaction() {
    let server = start_test_server().await;
    // Insert an event that carried a secret pre-redaction; only the redacted
    // projection may be stored and therefore served.
    let base = normalize_bytes(&synthetic_record(0)).expect("decode");
    let mut ev: NormalizedEvent = base.clone();
    ev.kind = Kind::ProcessExecResult;
    let record = DecodedRecord {
        argv: vec!["/bin/sh".into(), "password=hunter2secretvalue".into()],
        message: "token=abcdefghijklmnop".into(),
        ..Default::default()
    };
    ev.raw = RawEvent {
        payload: serde_json::to_vec(&record).unwrap().into_boxed_slice(),
    };
    let policy = RedactionPolicy::with_default_secrets();
    let redacted = apply_redaction(&ev, &policy);
    server.storage.insert_event(&redacted).expect("insert redacted");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/events?limit=1000", server.base))
        .send()
        .await
        .expect("send");
    let text = resp.text().await.expect("text");
    assert!(!text.contains("hunter2secretvalue"), "secret served by API");
    assert!(!text.contains("abcdefghijklmnop"), "token served by API");
    assert!(text.contains("[MASKED]"), "masked projection served");
    server.stop();
}

#[tokio::test]
async fn api_server_never_returns_unbounded_results() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    // Oversized limit rejected.
    let resp = client
        .get(format!("{}/api/v1/events?limit={}", server.base, MAX_PAGE_LIMIT + 1))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    // Default query bounded.
    let body = get_json(&client, &format!("{}/api/v1/events", server.base)).await;
    assert!(body["count"].as_u64().unwrap() <= DEFAULT_PAGE_LIMIT as u64);
    // Deep pagination beyond the window rejected.
    let deep = encode_cursor(MAX_PAGE_WINDOW);
    let resp = client
        .get(format!("{}/api/v1/events?cursor={deep}&limit=10", server.base))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    // Derived views are bounded too.
    let body = get_json(&client, &format!("{}/api/v1/dns?limit=3", server.base)).await;
    assert!(body["count"].as_u64().unwrap() <= 3);
    server.stop();
}
