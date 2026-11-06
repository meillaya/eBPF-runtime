// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local HTTP collector smoke test.

use std::sync::Arc;
use std::time::Duration;

use observability::Metrics;
use otlp::{run, OtlpConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

#[tokio::test]
async fn posts_to_a_collector() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let captured = Arc::new(tokio::sync::Mutex::new(String::new()));
    let captured_server = captured.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = socket.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buffer[..position]).to_string();
                let length = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if buffer.len() >= position + 4 + length {
                    break;
                }
            }
        }
        *captured_server.lock().await = String::from_utf8_lossy(&buffer).to_string();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    });

    let metrics = Arc::new(Metrics::new().unwrap());
    metrics.events_total.inc_by(9);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let exporter = tokio::spawn(run(
        OtlpConfig {
            endpoint,
            interval_secs: 1,
            service_name: "test-agent".to_string(),
            headers: Vec::new(),
        },
        metrics,
        shutdown_rx,
    ));

    let mut body = String::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        body = captured.lock().await.clone();
        if body.contains("resourceMetrics") {
            break;
        }
    }
    let _ = shutdown_tx.send(true);
    let _ = exporter.await;
    server.abort();
    assert!(body.contains("resourceMetrics"), "body: {body}");
    assert!(body.contains("test-agent"), "body: {body}");
    assert!(body.contains("ebpf_runtime_events_total"), "body: {body}");
}
