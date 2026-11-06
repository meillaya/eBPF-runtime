// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Batch accumulation and flushing.

use event_model::{Alert, Batch, Event};
use uuid::Uuid;

/// Accumulates events and alerts until a size or time bound is reached.
pub struct BatchBuilder {
    events: Vec<Event>,
    alerts: Vec<Alert>,
    bytes: usize,
    max_events: usize,
    max_bytes: usize,
}

impl BatchBuilder {
    /// Create a builder.
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            events: Vec::new(),
            alerts: Vec::new(),
            bytes: 0,
            max_events,
            max_bytes,
        }
    }

    /// Add an event and its alerts.
    pub fn push(&mut self, event: Event, alerts: Vec<Alert>) {
        self.bytes += serde_json::to_vec(&event)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        for alert in &alerts {
            self.bytes += serde_json::to_vec(alert)
                .map(|bytes| bytes.len())
                .unwrap_or(0);
        }
        self.events.push(event);
        self.alerts.extend(alerts);
    }

    /// Whether the batch should flush before adding another event.
    pub fn should_flush(&self) -> bool {
        self.events.len() >= self.max_events || self.bytes >= self.max_bytes
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.alerts.is_empty()
    }

    /// Number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Build a batch and reset the builder.
    pub fn take(
        &mut self,
        agent_id: &str,
        cluster: &str,
        node_name: &str,
        generation: &str,
    ) -> Option<Batch> {
        if self.is_empty() {
            return None;
        }
        let batch = Batch {
            batch_id: Uuid::new_v4().to_string(),
            agent_id: agent_id.to_string(),
            cluster: cluster.to_string(),
            node_name: node_name.to_string(),
            agent_generation: generation.to_string(),
            boot_id: self
                .events
                .first()
                .map(|event| event.boot_id.clone())
                .unwrap_or_default(),
            schema_major: 1,
            schema_minor: 0,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            events: std::mem::take(&mut self.events),
            alerts: std::mem::take(&mut self.alerts),
        };
        self.bytes = 0;
        Some(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str) -> Event {
        Event {
            event_id: id.to_string(),
            kind: "FileOpen".to_string(),
            sensor: "file".to_string(),
            boot_id: "b".repeat(32),
            ..Default::default()
        }
    }

    #[test]
    fn flushes_at_event_bound() {
        let mut builder = BatchBuilder::new(2, 1024 * 1024);
        builder.push(event("a"), Vec::new());
        assert!(!builder.should_flush());
        builder.push(event("b"), Vec::new());
        assert!(builder.should_flush());
        let batch = builder
            .take("agent", "cluster", "node", "gen")
            .expect("batch");
        assert_eq!(batch.events.len(), 2);
        assert!(builder.take("agent", "cluster", "node", "gen").is_none());
    }

    #[test]
    fn batches_keep_alerts() {
        let mut builder = BatchBuilder::new(10, 1024 * 1024);
        let alert = Alert {
            alert_id: "alert".to_string(),
            rule_id: "rule".to_string(),
            ..Default::default()
        };
        builder.push(event("a"), vec![alert]);
        let batch = builder
            .take("agent", "cluster", "node", "gen")
            .expect("batch");
        assert_eq!(batch.alerts.len(), 1);
    }
}
