// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ClickHouse projection.
//!
//! The relay inserts JSONEachRow into two MergeTree tables. PostgreSQL keeps
//! the durable batch and `relayed_at` is set only after the insert succeeds.

#![forbid(unsafe_code)]

use event_model::{Alert, Batch, Event};
use serde_json::{json, Value};
use thiserror::Error;

/// ClickHouse errors.
#[derive(Debug, Error)]
pub enum ClickHouseError {
    /// HTTP failure.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    /// The server rejected the request.
    #[error("clickhouse rejected request: {0}")]
    Rejected(String),
    /// Serialization failure.
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// HTTP client for one ClickHouse database.
#[derive(Clone)]
pub struct ClickHouse {
    base: String,
    client: reqwest::Client,
}

impl ClickHouse {
    /// Build a client. `base` is for example `http://127.0.0.1:8123`.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Create the projection tables.
    pub async fn ensure_schema(&self, database: &str) -> Result<(), ClickHouseError> {
        self.execute(&format!("CREATE DATABASE IF NOT EXISTS {database}"))
            .await?;
        let events = format!(
            "CREATE TABLE IF NOT EXISTS {database}.events (
                event_id String,
                time String,
                sensor LowCardinality(String),
                kind LowCardinality(String),
                pid UInt32,
                tgid UInt32,
                cgroup_id UInt64,
                path String,
                process_exec String,
                cluster LowCardinality(String),
                node_name LowCardinality(String),
                ingested_at DateTime DEFAULT now()
             ) ENGINE = MergeTree
             ORDER BY (cluster, time, event_id)"
        );
        self.execute(&events).await?;
        let alerts = format!(
            "CREATE TABLE IF NOT EXISTS {database}.alerts (
                alert_id String,
                rule_id LowCardinality(String),
                severity LowCardinality(String),
                event_id String,
                fired_at String,
                explanation String,
                cluster LowCardinality(String),
                node_name LowCardinality(String),
                ingested_at DateTime DEFAULT now()
             ) ENGINE = MergeTree
             ORDER BY (cluster, fired_at, alert_id)"
        );
        self.execute(&alerts).await?;
        Ok(())
    }

    /// Insert one batch. Events and alerts are two HTTP requests.
    pub async fn insert_batch(&self, database: &str, batch: &Batch) -> Result<(), ClickHouseError> {
        if !batch.events.is_empty() {
            let mut body = String::new();
            for event in &batch.events {
                body.push_str(&serde_json::to_string(&event_row(event, batch))?);
                body.push('\n');
            }
            self.insert(database, "events", &body).await?;
        }
        if !batch.alerts.is_empty() {
            let mut body = String::new();
            for alert in &batch.alerts {
                body.push_str(&serde_json::to_string(&alert_row(alert, batch))?);
                body.push('\n');
            }
            self.insert(database, "alerts", &body).await?;
        }
        Ok(())
    }

    /// Run a query and return the JSON response.
    pub async fn query_json(&self, sql: &str) -> Result<serde_json::Value, ClickHouseError> {
        let response = self
            .client
            .post(&self.base)
            .query(&[("query", format!("{sql} FORMAT JSON"))])
            .header(reqwest::header::CONTENT_LENGTH, "0")
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ClickHouseError::Rejected(response.text().await?));
        }
        Ok(response.json().await?)
    }

    async fn insert(&self, database: &str, table: &str, body: &str) -> Result<(), ClickHouseError> {
        let query = format!("INSERT INTO {database}.{table} FORMAT JSONEachRow");
        let response = self
            .client
            .post(&self.base)
            .query(&[("query", query)])
            .header(reqwest::header::CONTENT_LENGTH, body.len().to_string())
            .body(body.to_string())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ClickHouseError::Rejected(response.text().await?));
        }
        Ok(())
    }

    async fn execute(&self, statement: &str) -> Result<(), ClickHouseError> {
        let response = self
            .client
            .post(&self.base)
            .query(&[("query", statement)])
            .header(reqwest::header::CONTENT_LENGTH, "0")
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(ClickHouseError::Rejected(response.text().await?));
        }
        Ok(())
    }
}

fn event_row(event: &Event, batch: &Batch) -> Value {
    json!({
        "event_id": event.event_id,
        "time": event.time,
        "sensor": event.sensor,
        "kind": event.kind,
        "pid": event.pid,
        "tgid": event.tgid,
        "cgroup_id": event.cgroup_id,
        "path": event.path.clone().unwrap_or_default(),
        "process_exec": event.process_exec.clone().unwrap_or_default(),
        "cluster": batch.cluster,
        "node_name": batch.node_name,
    })
}

fn alert_row(alert: &Alert, batch: &Batch) -> Value {
    json!({
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "severity": alert.severity,
        "event_id": alert.event_id,
        "fired_at": alert.fired_at,
        "explanation": alert.explanation,
        "cluster": batch.cluster,
        "node_name": batch.node_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_include_batch_identity() {
        let batch = Batch {
            batch_id: "b".to_string(),
            agent_id: "a".to_string(),
            cluster: "prod".to_string(),
            node_name: "node-1".to_string(),
            agent_generation: "g".to_string(),
            boot_id: "boot".to_string(),
            schema_major: 1,
            schema_minor: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            events: Vec::new(),
            alerts: Vec::new(),
        };
        let event = Event {
            event_id: "e".to_string(),
            sensor: "file".to_string(),
            kind: "FileOpen".to_string(),
            ..Default::default()
        };
        let row = event_row(&event, &batch);
        assert_eq!(row["cluster"], "prod");
        assert_eq!(row["node_name"], "node-1");
        assert_eq!(row["event_id"], "e");
    }
}
