// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Ingest benchmark.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use event_model::{Batch, Event};
use transport::TransportClient;
use uuid::Uuid;

/// Benchmark settings.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    /// gRPC endpoint.
    pub endpoint: String,
    /// Use plaintext loopback gRPC.
    pub insecure: bool,
    /// TLS server name.
    pub domain_name: String,
    /// CA path.
    pub ca_path: String,
    /// Client certificate path.
    pub cert_path: String,
    /// Client key path.
    pub key_path: String,
    /// Cluster name.
    pub cluster: String,
    /// Node name.
    pub node_name: String,
    /// Agent id.
    pub agent_id: String,
    /// Total events.
    pub events: usize,
    /// Events per batch.
    pub batch_size: usize,
    /// Warmup batches.
    pub warmup: usize,
    /// p99 threshold in milliseconds.
    pub max_p99_ms: f64,
    /// Throughput threshold in events per second.
    pub min_events_per_sec: f64,
}

/// Benchmark result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchResult {
    /// Events sent.
    pub events: usize,
    /// Batches sent.
    pub batches: usize,
    /// Elapsed seconds.
    pub elapsed_secs: f64,
    /// Events per second.
    pub events_per_sec: f64,
    /// Median batch latency in milliseconds.
    pub p50_ms: f64,
    /// p99 batch latency in milliseconds.
    pub p99_ms: f64,
    /// Gate passed.
    pub passed: bool,
}

impl BenchResult {
    /// Gate status with reasons.
    pub fn failures(&self, config: &BenchConfig) -> Vec<String> {
        let mut failures = Vec::new();
        if self.p99_ms > config.max_p99_ms {
            failures.push(format!(
                "p99 {:.2} ms exceeds {:.2} ms",
                self.p99_ms, config.max_p99_ms
            ));
        }
        if self.events_per_sec < config.min_events_per_sec {
            failures.push(format!(
                "throughput {:.0}/s is below {:.0}/s",
                self.events_per_sec, config.min_events_per_sec
            ));
        }
        failures
    }
}

/// Run the benchmark.
pub async fn run(config: &BenchConfig) -> Result<BenchResult, String> {
    if config.batch_size == 0 || config.events == 0 {
        return Err("events and batch-size must be positive".to_string());
    }
    let client = if config.insecure {
        TransportClient::connect_insecure(&config.endpoint, &config.agent_id, "bench")
            .await
            .map_err(|error| error.to_string())?
    } else {
        let tls = transport::TransportConfig {
            endpoint: config.endpoint.clone(),
            domain_name: config.domain_name.clone(),
            ca_path: config.ca_path.clone().into(),
            cert_path: config.cert_path.clone().into(),
            key_path: config.key_path.clone().into(),
            timeout_secs: 10,
        };
        TransportClient::connect(&tls, &config.agent_id, "bench")
            .await
            .map_err(|error| error.to_string())?
    };
    client
        .register(
            &config.cluster,
            &config.node_name,
            &"a".repeat(32),
            &["process".to_string(), "file".to_string()],
        )
        .await
        .map_err(|error| error.to_string())?;

    let batches = config.events.div_ceil(config.batch_size);
    for index in 0..config.warmup {
        let batch = make_batch(config, index, config.batch_size);
        let _ = client.publish_batch(&batch).await;
    }

    let started = Instant::now();
    let mut latencies = Vec::with_capacity(batches);
    let mut sent = 0usize;
    for index in 0..batches {
        let remaining = config.events - sent;
        let count = remaining.min(config.batch_size);
        let batch = make_batch(config, index, count);
        let batch_started = Instant::now();
        let ack = client
            .publish_batch(&batch)
            .await
            .map_err(|error| error.to_string())?;
        if !ack.accepted {
            return Err(format!("batch rejected: {}", ack.error));
        }
        latencies.push(batch_started.elapsed());
        sent += count;
    }
    let elapsed = started.elapsed();

    latencies.sort();
    let p50 = percentile(&latencies, 0.50);
    let p99 = percentile(&latencies, 0.99);
    let seconds = elapsed.as_secs_f64().max(0.001);
    let result = BenchResult {
        events: sent,
        batches,
        elapsed_secs: seconds,
        events_per_sec: sent as f64 / seconds,
        p50_ms: p50.as_secs_f64() * 1000.0,
        p99_ms: p99.as_secs_f64() * 1000.0,
        passed: false,
    };
    let failures = result.failures(config);
    let mut result = result;
    result.passed = failures.is_empty();
    if !failures.is_empty() {
        return Err(format!("{}; {:?}", failures.join("; "), result));
    }
    Ok(result)
}

fn make_batch(config: &BenchConfig, index: usize, count: usize) -> Batch {
    let mut events = Vec::with_capacity(count);
    for offset in 0..count {
        let sequence = index * config.batch_size + offset;
        let event_id = format!("{sequence:064x}");
        events.push(Event {
            time: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            sensor: "file".to_string(),
            kind: "FileOpen".to_string(),
            event_id,
            boot_id: "a".repeat(32),
            seq: sequence as u64,
            pid: 1000 + (sequence % 1000) as u32,
            tgid: 1000 + (sequence % 1000) as u32,
            path: Some(format!("/tmp/bench/{sequence}")),
            process_exec: Some("/usr/bin/bench".to_string()),
            ..Default::default()
        });
    }
    Batch {
        batch_id: Uuid::new_v4().to_string(),
        agent_id: config.agent_id.clone(),
        cluster: config.cluster.clone(),
        node_name: config.node_name.clone(),
        agent_generation: "bench".to_string(),
        boot_id: "a".repeat(32),
        schema_major: 1,
        schema_minor: 0,
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        events,
        alerts: Vec::new(),
    }
}

fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_handles_edges() {
        let values = vec![
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
        ];
        assert_eq!(percentile(&values, 0.5), Duration::from_millis(2));
        assert_eq!(percentile(&values, 0.99), Duration::from_millis(3));
        assert_eq!(percentile(&[], 0.5), Duration::ZERO);
    }
}
