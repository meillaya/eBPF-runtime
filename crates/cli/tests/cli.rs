// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side unit tests for the standalone CLI (plan task 26).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent::{seed_simulated_events, ApiServer};
use agent_core::{normalize_bytes, synthetic_record, Kind, NormalizedEvent, RawEvent};
use cli::{resolve_addr, run_cli, CliArgs, CliCommand, CliError};
use clap::Parser;
use observability::MetricsRegistry;
use privacy::{apply_redaction, DecodedRecord, RedactionPolicy};
use storage_local::LocalStorage;

fn free_loopback_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

fn temp_db() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("cli-test-{}-{nanos}-{n}.db", std::process::id()))
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
    addr: SocketAddr,
    storage: Arc<LocalStorage>,
    broadcaster: tokio::sync::broadcast::Sender<String>,
    handle: tokio::task::JoinHandle<()>,
    db: PathBuf,
}

impl TestServer {
    fn addr_str(&self) -> String {
        self.addr.to_string()
    }
    fn stop(self) {
        self.handle.abort();
        let _ = std::fs::remove_file(&self.db);
    }
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
    wait_for_health(&format!("http://{addr}/api/v1/health")).await;
    TestServer {
        addr,
        storage,
        broadcaster,
        handle,
        db,
    }
}

/// Run the real CLI binary against `addr` and capture its output.
fn run_cli_binary(addr: &str, extra: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("--dev")
        .arg("--addr")
        .arg(addr)
        .args(extra)
        .output()
        .expect("run cli binary")
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

// ---------------------------------------------------------------------------
// CLI arg parsing (11 commands)
// ---------------------------------------------------------------------------

#[test]
fn cli_args_parse_preflight_command() {
    let args = CliArgs::try_parse_from(["cli", "preflight"]).expect("parse");
    assert!(matches!(args.command, CliCommand::Preflight));
}

#[test]
fn cli_args_parse_status_command() {
    let args = CliArgs::try_parse_from(["cli", "status"]).expect("parse");
    assert!(matches!(args.command, CliCommand::Status));
}

#[test]
fn cli_args_parse_health_command() {
    let args = CliArgs::try_parse_from(["cli", "health"]).expect("parse");
    assert!(matches!(args.command, CliCommand::Health));
}

#[test]
fn cli_args_parse_live_events_command() {
    let args = CliArgs::try_parse_from(["cli", "live-events", "--limit", "5"]).expect("parse");
    assert!(matches!(args.command, CliCommand::LiveEvents));
    assert_eq!(args.limit, Some(5));
}

#[test]
fn cli_args_parse_query_history_command() {
    let args = CliArgs::try_parse_from(["cli", "query-history", "--kind", "DnsPacket"])
        .expect("parse");
    assert!(matches!(args.command, CliCommand::QueryHistory));
    assert_eq!(args.kind.as_deref(), Some("DnsPacket"));
}

#[test]
fn cli_args_parse_process_tree_command() {
    let args = CliArgs::try_parse_from(["cli", "process-tree", "--pid", "42", "--depth", "3"])
        .expect("parse");
    assert!(matches!(args.command, CliCommand::ProcessTree));
    assert_eq!(args.pid, Some(42));
    assert_eq!(args.depth, Some(3));
}

#[test]
fn cli_args_parse_sockets_command() {
    let args =
        CliArgs::try_parse_from(["cli", "sockets", "--state", "established", "--family", "inet"])
            .expect("parse");
    assert!(matches!(args.command, CliCommand::Sockets));
    assert_eq!(args.state.as_deref(), Some("established"));
    assert_eq!(args.family.as_deref(), Some("inet"));
}

#[test]
fn cli_args_parse_dns_packets_command() {
    let args = CliArgs::try_parse_from(["cli", "dns-packets", "--qname", "example.com"])
        .expect("parse");
    assert!(matches!(args.command, CliCommand::DnsPackets));
    assert_eq!(args.qname.as_deref(), Some("example.com"));
}

#[test]
fn cli_args_parse_files_command() {
    let args = CliArgs::try_parse_from(["cli", "files", "--path", "/etc"]).expect("parse");
    assert!(matches!(args.command, CliCommand::Files));
    assert_eq!(args.path.as_deref(), Some("/etc"));
}

#[test]
fn cli_args_parse_syscall_histograms_command() {
    let args = CliArgs::try_parse_from(["cli", "syscall-histograms", "--syscall", "read"])
        .expect("parse");
    assert!(matches!(args.command, CliCommand::SyscallHistograms));
    assert_eq!(args.syscall.as_deref(), Some("read"));
}

#[test]
fn cli_args_parse_export_command() {
    let args = CliArgs::try_parse_from(["cli", "export", "--limit", "10"]).expect("parse");
    assert!(matches!(args.command, CliCommand::Export));
    assert_eq!(args.limit, Some(10));
}

// ---------------------------------------------------------------------------
// CLI command execution against a live agent API
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_preflight_prints_coverage_matrix() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["preflight"]);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = stdout_of(&output);
    assert!(stdout.contains("PREFLIGHT COVERAGE MATRIX"), "{stdout}");
    for program in ["process", "file", "network", "dns", "syscall", "identity"] {
        assert!(stdout.contains(program), "coverage matrix lists {program}: {stdout}");
    }
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_status_prints_agent_status() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["status"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("health:"), "{stdout}");
    assert!(stdout.contains("readiness:"), "{stdout}");
    assert!(stdout.contains("metrics:"), "{stdout}");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_health_prints_health_status() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["health"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("status"), "{stdout}");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_live_events_connects_to_websocket() {
    let server = start_test_server().await;
    let broadcaster = server.broadcaster.clone();
    let drip = tokio::spawn(async move {
        for i in 0..300 {
            let _ = broadcaster.send(format!("{{\"live\":{i}}}"));
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    });
    let output = run_cli_binary(&server.addr_str(), &["live-events", "--limit", "3"]);
    drip.abort();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = stdout_of(&output);
    let live_lines = stdout.lines().filter(|l| l.contains("live")).count();
    assert!(live_lines >= 3, "received >=3 live events: {stdout}");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_query_history_queries_events() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["query-history", "--limit", "10"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("events"), "{stdout}");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_process_tree_prints_process_tree() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["process-tree"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("processes"), "{stdout}");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_sockets_prints_socket_table() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["sockets"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("sockets"), "{stdout}");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_dns_packets_prints_dns_events() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["dns-packets"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("dns"), "{stdout}");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_files_prints_file_events() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["files"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("files"), "{stdout}");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_syscall_histograms_prints_syscall_histograms() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["syscall-histograms"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(stdout.contains("histograms"), "{stdout}");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_run_export_exports_events_as_json_lines() {
    let server = start_test_server().await;
    let output = run_cli_binary(&server.addr_str(), &["export", "--limit", "5"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 5, "export yields 5 JSON lines: {stdout}");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
        assert!(v["event_id"].is_string());
    }
    server.stop();
}

// ---------------------------------------------------------------------------
// Safety invariants
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_never_exposes_loader_map_mutation() {
    let server = start_test_server().await;
    // The CLI exposes no loader/map mutation subcommand.
    for bad in ["loader", "maps", "load", "attach", "mutate"] {
        let output = run_cli_binary(&server.addr_str(), &[bad]);
        assert!(!output.status.success(), "unknown command {bad} must fail");
    }
    // run_cli only issues reads; an unknown route is surfaced as an error.
    let result = run_cli(CliArgs {
        command: CliCommand::Health,
        dev: true,
        addr: Some(server.addr_str()),
        key: None,
        db: None,
        log_level: Some("error".into()),
        kind: None,
        from: None,
        to: None,
        acked: None,
        limit: None,
        cursor: None,
        pid: None,
        depth: None,
        state: None,
        family: None,
        qname: None,
        qtype: None,
        path: None,
        syscall: None,
    })
    .await;
    assert!(result.is_ok(), "read-only health command succeeds");
    server.stop();
}

#[test]
fn cli_never_binds_no_auth_to_non_loopback() {
    // The CLI refuses to connect to a non-loopback agent address.
    assert!(resolve_addr(Some("0.0.0.0:8080"), true).is_err());
    assert!(resolve_addr(Some("192.168.1.10:9464"), true).is_err());
    assert!(resolve_addr(Some("10.0.0.1:9464"), false).is_err());
    // Loopback is accepted.
    assert!(resolve_addr(Some("127.0.0.1:9464"), true).is_ok());
    assert!(resolve_addr(Some("[::1]:9464"), true).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_never_bypasses_redaction() {
    let server = start_test_server().await;
    // Store only the redacted projection of an event that carried a secret.
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

    let output = run_cli_binary(&server.addr_str(), &["query-history", "--limit", "1000"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    assert!(!stdout.contains("hunter2secretvalue"), "secret printed by CLI");
    assert!(!stdout.contains("abcdefghijklmnop"), "token printed by CLI");
    assert!(stdout.contains("[MASKED]"), "masked projection printed");
    server.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_never_returns_unbounded_results() {
    let server = start_test_server().await;
    // An oversized limit is rejected by the API and surfaced as a CLI error.
    let output = run_cli_binary(&server.addr_str(), &["query-history", "--limit", "100000"]);
    assert!(!output.status.success(), "oversized limit must fail");
    // A bounded query succeeds and stays within the page size.
    let output = run_cli_binary(&server.addr_str(), &["query-history", "--limit", "10"]);
    assert!(output.status.success());
    let stdout = stdout_of(&output);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json");
    assert!(v["count"].as_u64().unwrap() <= 10, "bounded result");
    // run_cli propagates the typed rejection as an error (not a crash).
    let err = run_cli(CliArgs {
        command: CliCommand::QueryHistory,
        dev: true,
        addr: Some(server.addr_str()),
        key: None,
        db: None,
        log_level: Some("error".into()),
        kind: None,
        from: None,
        to: None,
        acked: None,
        limit: Some(100000),
        cursor: None,
        pid: None,
        depth: None,
        state: None,
        family: None,
        qname: None,
        qtype: None,
        path: None,
        syscall: None,
    })
    .await
    .expect_err("oversized limit errors");
    assert!(matches!(err, CliError::QueryError(_)), "typed query error: {err}");
    server.stop();
}
