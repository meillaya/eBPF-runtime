// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OTLP/HTTP JSON metrics export.
//!
//! The agent keeps Prometheus as its local scrape endpoint. This exporter
//! reads the same registry and posts a cumulative OTLP JSON payload to a
//! collector. No kernel data is sent through this path.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use observability::Metrics;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::watch;

/// OTLP exporter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OtlpConfig {
    /// Collector base URL, for example `http://127.0.0.1:4318`.
    pub endpoint: String,
    /// Export interval in seconds.
    pub interval_secs: u64,
    /// `service.name` resource attribute.
    pub service_name: String,
    /// Extra HTTP headers, for example an authorization token.
    pub headers: Vec<(String, String)>,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:4318".to_string(),
            interval_secs: 15,
            service_name: "ebpf-agent".to_string(),
            headers: Vec::new(),
        }
    }
}

/// One numeric sample.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricPoint {
    /// Metric name.
    pub name: String,
    /// Current value.
    pub value: f64,
    /// Monotonic sum.
    pub monotonic: bool,
}

/// OTLP errors.
#[derive(Debug, Error)]
pub enum OtlpError {
    /// HTTP failure.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    /// Collector rejected the payload.
    #[error("collector rejected payload: {0}")]
    Rejected(String),
    /// Configuration failure.
    #[error("invalid config: {0}")]
    Config(String),
}

/// Run the exporter until shutdown.
pub async fn run(
    config: OtlpConfig,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), OtlpError> {
    if config.endpoint.is_empty() {
        return Err(OtlpError::Config("endpoint is empty".to_string()));
    }
    let interval = Duration::from_secs(config.interval_secs.clamp(1, 3600));
    let client = reqwest::Client::new();
    let url = format!("{}/v1/metrics", config.endpoint.trim_end_matches('/'));
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let payload = build_payload(&metrics.render(), &config.service_name, now_ns());
                let mut request = client.post(&url).json(&payload);
                for (name, value) in &config.headers {
                    request = request.header(name, value);
                }
                match request.send().await {
                    Ok(response) if response.status().is_success() => {},
                    Ok(response) => {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        tracing::warn!(%status, %body, "OTLP export rejected");
                    }
                    Err(error) => tracing::warn!(%error, "OTLP export failed"),
                }
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

/// Parse Prometheus text into numeric samples.
pub fn parse_prometheus(text: &str) -> Vec<MetricPoint> {
    let mut points = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next().and_then(|value| value.parse::<f64>().ok()) else {
            continue;
        };
        if !value.is_finite() {
            continue;
        }
        let name = name.split('{').next().unwrap_or(name).to_string();
        let monotonic = name.ends_with("_total") || name.ends_with("_count");
        points.push(MetricPoint {
            name,
            value,
            monotonic,
        });
    }
    points
}

/// Build an OTLP JSON metrics payload.
pub fn build_payload(text: &str, service_name: &str, time_unix_nano: u128) -> Value {
    let points = parse_prometheus(text);
    let metrics: Vec<Value> = points
        .into_iter()
        .map(|point| {
            let data_point = json!({
                "asDouble": point.value,
                "timeUnixNano": time_unix_nano.to_string(),
            });
            if point.monotonic {
                json!({
                    "name": point.name,
                    "sum": {
                        "dataPoints": [data_point],
                        "aggregationTemporality": 2,
                        "isMonotonic": true,
                    }
                })
            } else {
                json!({
                    "name": point.name,
                    "gauge": {
                        "dataPoints": [data_point],
                    }
                })
            }
        })
        .collect();
    json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": service_name}},
                    {"key": "service.version", "value": {"stringValue": env!("CARGO_PKG_VERSION")}},
                ]
            },
            "scopeMetrics": [{
                "scope": {"name": "ebpf-runtime"},
                "metrics": metrics,
            }]
        }]
    })
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_counters_and_gauges() {
        let points = parse_prometheus(
            "# HELP x\n\
             ebpf_runtime_events_total 12\n\
             ebpf_runtime_outbox_depth 3\n",
        );
        assert_eq!(points.len(), 2);
        assert!(points[0].monotonic);
        assert!(!points[1].monotonic);
        assert_eq!(points[0].value, 12.0);
    }

    #[test]
    fn payload_has_resource_and_scope() {
        let payload = build_payload("ebpf_runtime_events_total 2\n", "agent", 42);
        assert_eq!(
            payload["resourceMetrics"][0]["resource"]["attributes"][0]["value"]["stringValue"],
            "agent"
        );
        assert_eq!(
            payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["dataPoints"][0]
                ["asDouble"],
            2.0
        );
    }
}
