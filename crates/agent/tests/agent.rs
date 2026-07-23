// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side unit tests for the standalone agent (plan task 26).
#![allow(clippy::await_holding_lock)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent::api::{
    encode_cursor, ApiErrorKind, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, MAX_PAGE_WINDOW,
    WS_BROADCAST_CAPACITY,
};
use agent::{
    request_shutdown, run_agent, seed_simulated_events, validate_listen, AgentArgs, AgentError,
    ApiServer,
};
use agent_core::{normalize_bytes, synthetic_record, Kind, NormalizedEvent, RawEvent};
use clap::Parser;
use observability::MetricsRegistry;
use privacy::{apply_redaction, DecodedRecord, RedactionPolicy};
use storage_local::{EventQuery, LocalStorage};

/// Serialize tests that drive the full agent loop (they share a process-global
/// shutdown latch and install process-wide signal handlers).
static RUN_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

fn free_loopback_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

fn temp_db() -> PathBuf {
    std::env::temp_dir().join(format!("agent-test-{}.db", uuid::Uuid::new_v4()))
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
    TestServer { base, handle, db }
}

impl TestServer {
    fn stop(self) {
        self.handle.abort();
        let _ = std::fs::remove_file(&self.db);
    }
}

// ---------------------------------------------------------------------------
// CLI arg parsing
// ---------------------------------------------------------------------------

#[test]
fn agent_args_parse_dev_flag() {
    let args = AgentArgs::try_parse_from(["agent", "--dev"]).expect("parse");
    assert!(args.dev);
    assert!(args.listen.is_none());
}

#[test]
fn agent_args_parse_listen_flag() {
    let args = AgentArgs::try_parse_from(["agent", "--listen", "127.0.0.1:9999"]).expect("parse");
    assert_eq!(args.listen.as_deref(), Some("127.0.0.1:9999"));
}

#[test]
fn agent_args_parse_key_flag() {
    let args = AgentArgs::try_parse_from(["agent", "--key", "/tmp/outbox.key"]).expect("parse");
    assert_eq!(args.key, Some(PathBuf::from("/tmp/outbox.key")));
}

#[test]
fn agent_args_parse_db_flag() {
    let args = AgentArgs::try_parse_from(["agent", "--db", "/tmp/outbox.db"]).expect("parse");
    assert_eq!(args.db, Some(PathBuf::from("/tmp/outbox.db")));
}

#[test]
fn agent_args_parse_log_level_flag() {
    let args = AgentArgs::try_parse_from(["agent", "--log-level", "debug"]).expect("parse");
    assert_eq!(args.log_level.as_deref(), Some("debug"));
}

// ---------------------------------------------------------------------------
// Agent loop behaviour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_run_with_dev_flag_binds_loopback() {
    let _guard = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let addr = free_loopback_addr();
    let db = temp_db();
    let args = AgentArgs {
        dev: true,
        listen: Some(addr.to_string()),
        key: None,
        db: Some(db.clone()),
        log_level: Some("error".into()),
    };
    let handle = tokio::spawn(run_agent(args));
    wait_for_health(&format!("http://{addr}/api/v1/health")).await;
    request_shutdown();
    handle.await.expect("join").expect("clean shutdown");
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn agent_run_with_non_loopback_listen_returns_error() {
    let _guard = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let args = AgentArgs {
        dev: true,
        listen: Some("0.0.0.0:8080".into()),
        key: None,
        db: Some(temp_db()),
        log_level: Some("error".into()),
    };
    let result = run_agent(args).await;
    assert!(result.is_err(), "non-loopback bind must be rejected");
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("loopback"),
        "error should mention loopback: {err}"
    );
}

#[tokio::test]
async fn agent_run_with_sigterm_drains_and_flushes() {
    let _guard = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let addr = free_loopback_addr();
    let db = temp_db();
    let args = AgentArgs {
        dev: true,
        listen: Some(addr.to_string()),
        key: None,
        db: Some(db.clone()),
        log_level: Some("error".into()),
    };
    let handle = tokio::spawn(run_agent(args));
    wait_for_health(&format!("http://{addr}/api/v1/health")).await;
    // SIGTERM funnels into the shared shutdown latch; trigger a graceful drain.
    request_shutdown();
    let result = handle.await.expect("join");
    assert!(result.is_ok(), "drain+flush should succeed on SIGTERM");
    // The flushed database is reopenable and passes integrity check.
    let reopened = LocalStorage::open_with_test_key(&db).expect("reopen flushed db");
    reopened.integrity_check().expect("integrity after flush");
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn agent_run_with_sigint_drains_and_flushes() {
    let _guard = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let addr = free_loopback_addr();
    let db = temp_db();
    let args = AgentArgs {
        dev: true,
        listen: Some(addr.to_string()),
        key: None,
        db: Some(db.clone()),
        log_level: Some("error".into()),
    };
    let handle = tokio::spawn(run_agent(args));
    wait_for_health(&format!("http://{addr}/api/v1/health")).await;
    // SIGINT funnels into the same shared shutdown latch.
    request_shutdown();
    let result = handle.await.expect("join");
    assert!(result.is_ok(), "drain+flush should succeed on SIGINT");
    // Events were persisted before the flush.
    let reopened = LocalStorage::open_with_test_key(&db).expect("reopen");
    let q = EventQuery {
        limit: Some(1),
        ..Default::default()
    };
    let events = reopened.query_events(&q).expect("query");
    assert!(
        !events.is_empty(),
        "events should be persisted before flush"
    );
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn agent_run_with_timeout_returns_timeout_error() {
    let _guard = RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Force the drain to outlive the timeout.
    std::env::set_var(agent::DRAIN_TIMEOUT_ENV, "20");
    std::env::set_var(agent::SLOW_DRAIN_ENV, "300");
    let addr = free_loopback_addr();
    let db = temp_db();
    let args = AgentArgs {
        dev: true,
        listen: Some(addr.to_string()),
        key: None,
        db: Some(db.clone()),
        log_level: Some("error".into()),
    };
    let handle = tokio::spawn(run_agent(args));
    wait_for_health(&format!("http://{addr}/api/v1/health")).await;
    request_shutdown();
    let result = handle.await.expect("join");
    std::env::remove_var(agent::DRAIN_TIMEOUT_ENV);
    std::env::remove_var(agent::SLOW_DRAIN_ENV);
    assert!(
        matches!(result, Err(AgentError::TimeoutError)),
        "expected TimeoutError, got {result:?}"
    );
    let _ = std::fs::remove_file(&db);
}

// ---------------------------------------------------------------------------
// Safety invariants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_never_exposes_loader_map_mutation() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    // State-mutating methods are rejected.
    for method in [
        reqwest::Method::POST,
        reqwest::Method::PUT,
        reqwest::Method::DELETE,
    ] {
        let resp = client
            .request(method.clone(), format!("{}/api/v1/events", server.base))
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::METHOD_NOT_ALLOWED,
            "{method} must be rejected"
        );
    }
    // No loader/map mutation routes exist.
    for route in ["loader", "maps", "loader/load", "maps/update"] {
        let resp = client
            .get(format!("{}/api/v1/{route}", server.base))
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{route} must not exist"
        );
    }
    server.stop();
}

#[tokio::test]
async fn agent_never_binds_no_auth_to_non_loopback() {
    // The strict loopback check rejects non-loopback addresses.
    assert!(validate_listen(Some("0.0.0.0:8080"), true).is_err());
    assert!(validate_listen(Some("192.168.1.10:9464"), true).is_err());
    assert!(validate_listen(Some("127.0.0.1:9464"), true).is_ok());
    assert!(validate_listen(Some("[::1]:9464"), true).is_ok());

    // The server itself refuses to bind a non-loopback address.
    let db = temp_db();
    let storage = Arc::new(LocalStorage::open_with_test_key(&db).expect("open"));
    storage.run_migrations().expect("migrations");
    let registry = Arc::new(MetricsRegistry::new());
    let server = ApiServer::new(storage, registry, "0.0.0.0:8080".parse().unwrap());
    let result = server.serve().await;
    assert!(result.is_err(), "serve must refuse non-loopback bind");
    let err = result.unwrap_err();
    assert!(
        matches!(err.kind, ApiErrorKind::NonLoopbackBindError(_)),
        "expected NonLoopbackBindError"
    );
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn agent_never_bypasses_redaction() {
    let base = normalize_bytes(&synthetic_record(0)).expect("decode synthetic");
    let mut ev: NormalizedEvent = base.clone();
    ev.kind = Kind::ProcessExecResult;
    let record = DecodedRecord {
        argv: vec![
            "/bin/sh".into(),
            "-c".into(),
            "password=hunter2secretvalue".into(),
            "AKIA1234567890ABCDEF".into(),
        ],
        message: "user login token=abcdefghijklmnop".into(),
        ..Default::default()
    };
    ev.raw = RawEvent {
        payload: serde_json::to_vec(&record).unwrap().into_boxed_slice(),
    };
    let policy = RedactionPolicy::with_default_secrets();
    let redacted = apply_redaction(&ev, &policy);

    let argv_str = redacted
        .argv_bytes
        .as_ref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    assert!(
        argv_str.contains("[MASKED]"),
        "secrets must be masked: {argv_str}"
    );
    assert!(!argv_str.contains("hunter2secretvalue"), "password leaked");
    assert!(!argv_str.contains("AKIA1234567890ABCDEF"), "AWS key leaked");
    let msg = redacted.message.clone().unwrap_or_default();
    assert!(!msg.contains("abcdefghijklmnop"), "token leaked");

    // The persisted/exported form is the redacted projection only.
    let db = temp_db();
    let storage = LocalStorage::open_with_test_key(&db).expect("open");
    storage.run_migrations().expect("migrations");
    storage.insert_event(&redacted).expect("insert");
    let q = EventQuery {
        limit: Some(10),
        ..Default::default()
    };
    let stored = storage.query_events(&q).expect("query");
    assert_eq!(stored.len(), 1);
    let json = serde_json::to_string(&stored[0].to_json()).unwrap();
    assert!(!json.contains("hunter2secretvalue"), "secret persisted");
    assert!(!json.contains("AKIA1234567890ABCDEF"), "AWS key persisted");
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn agent_never_returns_unbounded_results() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // An oversized page limit is rejected.
    let resp = client
        .get(format!(
            "{}/api/v1/events?limit={}",
            server.base,
            MAX_PAGE_LIMIT + 1
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["kind"], "oversized_filter_error");

    // A default (unlimited) query is still bounded to the default page size.
    let resp = client
        .get(format!("{}/api/v1/events", server.base))
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.expect("json");
    let count = body["count"].as_u64().unwrap();
    assert!(
        count <= DEFAULT_PAGE_LIMIT as u64,
        "default query must be bounded: {count}"
    );

    // Paginating deeper than the window is rejected.
    let deep = encode_cursor(MAX_PAGE_WINDOW);
    let resp = client
        .get(format!(
            "{}/api/v1/events?cursor={deep}&limit=10",
            server.base
        ))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // A bounded cursor paginates without exceeding the page size.
    let resp = client
        .get(format!("{}/api/v1/events?limit=5", server.base))
        .send()
        .await
        .expect("send");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["count"].as_u64().unwrap() <= 5);
    const _: () = assert!(WS_BROADCAST_CAPACITY > 0);
    server.stop();
}
