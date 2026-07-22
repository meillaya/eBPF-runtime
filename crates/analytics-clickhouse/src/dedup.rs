// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Deduplication logic for ClickHouse ReplacingMergeTree.
//!
//! ReplacingMergeTree collapses rows with the same ORDER BY key
//! (event_id) during background merges, keeping the row with the
//! highest `_version`. This module provides in-memory deduplication
//! that mirrors the ClickHouse semantics:
//!
//! - Before exact query: duplicates are visible (multiple physical rows)
//! - After exact query (FINAL/argMax): one logical row per event_id
//!
//! This is used for fixture testing without a live ClickHouse instance.

use std::collections::HashMap;

use crate::schema::EventRow;

/// In-memory deduplication engine mirroring ReplacingMergeTree semantics.
///
/// Stores all physical rows (including duplicates) and provides
/// both "raw" (pre-merge) and "exact" (post-merge) views.
#[derive(Debug, Default)]
pub struct DeduplicationEngine {
    /// All physical rows, including duplicates.
    physical_rows: Vec<EventRow>,
    /// Index: event_id → indices into physical_rows.
    index: HashMap<String, Vec<usize>>,
}

impl DeduplicationEngine {
    /// Create a new empty engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a row. Duplicates (same event_id) are stored as
    /// separate physical rows, mirroring Kafka re-delivery.
    pub fn insert(&mut self, row: EventRow) {
        let idx = self.physical_rows.len();
        self.index
            .entry(row.event_id.clone())
            .or_default()
            .push(idx);
        self.physical_rows.push(row);
    }

    /// Insert multiple rows (e.g., replaying the same event N times).
    pub fn insert_batch(&mut self, rows: Vec<EventRow>) {
        for row in rows {
            self.insert(row);
        }
    }

    /// Total physical rows (including duplicates).
    pub fn physical_count(&self) -> usize {
        self.physical_rows.len()
    }

    /// Number of unique event_ids (logical rows after dedup).
    pub fn logical_count(&self) -> usize {
        self.index.len()
    }

    /// Number of physical duplicates (rows beyond the first per event_id).
    pub fn duplicate_count(&self) -> usize {
        self.physical_count() - self.logical_count()
    }

    /// Whether a given event_id has physical duplicates.
    pub fn has_duplicates(&self, event_id: &str) -> bool {
        self.index
            .get(event_id)
            .map(|indices| indices.len() > 1)
            .unwrap_or(false)
    }

    /// Get all physical rows for an event_id (pre-merge view).
    pub fn physical_rows_for(&self, event_id: &str) -> Vec<&EventRow> {
        self.index
            .get(event_id)
            .map(|indices| indices.iter().map(|&i| &self.physical_rows[i]).collect())
            .unwrap_or_default()
    }

    /// Exact query: returns one row per event_id, keeping the row
    /// with the highest `_version` (mirrors FINAL / argMax).
    ///
    /// This is the deduplicated view. For an event_id with N
    /// physical rows, only the one with max(_version) is returned.
    pub fn exact_rows(&self) -> Vec<&EventRow> {
        let mut result = Vec::with_capacity(self.index.len());
        for indices in self.index.values() {
            let best = indices
                .iter()
                .max_by_key(|&&i| self.physical_rows[i].version)
                .map(|&i| &self.physical_rows[i]);
            if let Some(row) = best {
                result.push(row);
            }
        }
        // Sort by event_id for deterministic output.
        result.sort_by(|a, b| a.event_id.cmp(&b.event_id));
        result
    }

    /// Exact query for a single event_id.
    /// Returns the row with the highest _version, or None.
    pub fn exact_row_for(&self, event_id: &str) -> Option<&EventRow> {
        self.index.get(event_id).and_then(|indices| {
            indices
                .iter()
                .max_by_key(|&&i| self.physical_rows[i].version)
                .map(|&i| &self.physical_rows[i])
        })
    }

    /// List event_ids that have physical duplicates.
    pub fn duplicated_event_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self
            .index
            .iter()
            .filter(|(_, indices)| indices.len() > 1)
            .map(|(id, _)| id.as_str())
            .collect();
        ids.sort();
        ids
    }

    /// All physical rows (for inspection).
    pub fn all_physical_rows(&self) -> &[EventRow] {
        &self.physical_rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::EventKind;

    fn make_row(event_id: &str, version: u64, offset: u64) -> EventRow {
        EventRow {
            kafka_topic: "events.v1".to_string(),
            kafka_partition: 0,
            kafka_offset: offset,
            event_id: event_id.to_string(),
            batch_id: format!("batch-{version}"),
            seq: version,
            schema_major: 1,
            schema_minor: 0,
            event_kind: EventKind::FileOpen,
            sensor: "ops".to_string(),
            agent_generation: "gen-1".to_string(),
            node_name: "node-1".to_string(),
            cluster: "prod".to_string(),
            ts_monotonic_ns: version * 1000,
            boot_id_hex: "00".repeat(16),
            pid_tgid: 1234,
            cgroup_id: 5678,
            uid: 1000,
            gid: 1000,
            payload: format!(r#"{{"v":{version}}}"#),
            version,
        }
    }

    #[test]
    fn single_insert_no_duplicates() {
        let mut engine = DeduplicationEngine::new();
        engine.insert(make_row("evt-001", 1, 10));

        assert_eq!(engine.physical_count(), 1);
        assert_eq!(engine.logical_count(), 1);
        assert_eq!(engine.duplicate_count(), 0);
        assert!(!engine.has_duplicates("evt-001"));
    }

    #[test]
    fn replay_same_event_100_times() {
        let mut engine = DeduplicationEngine::new();

        // Replay the same event_id 100 times with increasing versions.
        for i in 0..100 {
            engine.insert(make_row("evt-replay", i, i));
        }

        // Before exact query: 100 physical rows visible.
        assert_eq!(engine.physical_count(), 100);
        assert_eq!(engine.logical_count(), 1);
        assert_eq!(engine.duplicate_count(), 99);
        assert!(engine.has_duplicates("evt-replay"));

        // After exact query: one logical row with the highest version.
        let exact = engine.exact_rows();
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].event_id, "evt-replay");
        assert_eq!(exact[0].version, 99);
        assert_eq!(exact[0].payload, r#"{"v":99}"#);
    }

    #[test]
    fn exact_row_for_returns_highest_version() {
        let mut engine = DeduplicationEngine::new();
        engine.insert(make_row("evt-001", 5, 50));
        engine.insert(make_row("evt-001", 10, 100));
        engine.insert(make_row("evt-001", 3, 30));

        let row = engine.exact_row_for("evt-001").unwrap();
        assert_eq!(row.version, 10);
        assert_eq!(row.kafka_offset, 100);
    }

    #[test]
    fn exact_row_for_missing_returns_none() {
        let engine = DeduplicationEngine::new();
        assert!(engine.exact_row_for("nonexistent").is_none());
    }

    #[test]
    fn multiple_events_dedup_independently() {
        let mut engine = DeduplicationEngine::new();

        // evt-001: 3 duplicates
        engine.insert(make_row("evt-001", 1, 10));
        engine.insert(make_row("evt-001", 2, 20));
        engine.insert(make_row("evt-001", 3, 30));

        // evt-002: 2 duplicates
        engine.insert(make_row("evt-002", 1, 40));
        engine.insert(make_row("evt-002", 2, 50));

        // evt-003: no duplicates
        engine.insert(make_row("evt-003", 1, 60));

        assert_eq!(engine.physical_count(), 6);
        assert_eq!(engine.logical_count(), 3);
        assert_eq!(engine.duplicate_count(), 3);

        let exact = engine.exact_rows();
        assert_eq!(exact.len(), 3);

        // Sorted by event_id
        assert_eq!(exact[0].event_id, "evt-001");
        assert_eq!(exact[0].version, 3);
        assert_eq!(exact[1].event_id, "evt-002");
        assert_eq!(exact[1].version, 2);
        assert_eq!(exact[2].event_id, "evt-003");
        assert_eq!(exact[2].version, 1);
    }

    #[test]
    fn duplicated_event_ids_lists_only_dupes() {
        let mut engine = DeduplicationEngine::new();
        engine.insert(make_row("evt-001", 1, 10));
        engine.insert(make_row("evt-001", 2, 20));
        engine.insert(make_row("evt-002", 1, 30));

        let dupes = engine.duplicated_event_ids();
        assert_eq!(dupes, vec!["evt-001"]);
    }

    #[test]
    fn physical_rows_for_returns_all_versions() {
        let mut engine = DeduplicationEngine::new();
        engine.insert(make_row("evt-001", 1, 10));
        engine.insert(make_row("evt-001", 2, 20));
        engine.insert(make_row("evt-001", 3, 30));

        let rows = engine.physical_rows_for("evt-001");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].version, 1);
        assert_eq!(rows[1].version, 2);
        assert_eq!(rows[2].version, 3);
    }

    #[test]
    fn insert_batch_works() {
        let mut engine = DeduplicationEngine::new();
        let rows: Vec<EventRow> = (0..5).map(|i| make_row("evt-batch", i, i)).collect();
        engine.insert_batch(rows);

        assert_eq!(engine.physical_count(), 5);
        assert_eq!(engine.logical_count(), 1);
    }
}
