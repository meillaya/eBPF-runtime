// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact-query SQL builders using `FINAL` / `argMax`.
//!
//! ReplacingMergeTree does NOT guarantee immediate deduplication.
//! These builders generate SQL that returns exactly one row per
//! `event_id` regardless of background merge state.

use crate::schema::EventKind;

/// Strategy for exact (deduplicated) queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactQueryStrategy {
    /// `SELECT ... FROM events_v1 FINAL` — merge-on-read.
    /// Correct but slower for large scans.
    Final,
    /// `SELECT argMax(col, _version) ... GROUP BY event_id` — aggregate dedup.
    /// Faster for large scans.
    ArgMax,
}

/// Builder for exact-query SQL against `events_v1`.
///
/// Generates SQL that returns exactly one row per `event_id`,
/// regardless of whether background merges have collapsed
/// physical duplicates.
#[derive(Debug, Clone)]
pub struct ExactQueryBuilder {
    strategy: ExactQueryStrategy,
    table: String,
    filters: Vec<String>,
    limit: Option<usize>,
}

impl ExactQueryBuilder {
    /// Create a new builder with the given strategy.
    pub fn new(strategy: ExactQueryStrategy) -> Self {
        Self {
            strategy,
            table: "events_v1".to_string(),
            filters: Vec::new(),
            limit: None,
        }
    }

    /// Use a custom table name (e.g., for testing).
    pub fn table(mut self, table: impl Into<String>) -> Self {
        self.table = table.into();
        self
    }

    /// Filter by event_id (point lookup).
    pub fn event_id(mut self, id: &str) -> Self {
        self.filters
            .push(format!("event_id = '{}'", escape_sql(id)));
        self
    }

    /// Filter by node_name (low-cardinality dimension).
    pub fn node_name(mut self, name: &str) -> Self {
        self.filters
            .push(format!("node_name = '{}'", escape_sql(name)));
        self
    }

    /// Filter by event_kind (low-cardinality dimension).
    pub fn event_kind(mut self, kind: EventKind) -> Self {
        self.filters
            .push(format!("event_kind = '{}'", kind.as_proto_name()));
        self
    }

    /// Filter by cluster (low-cardinality dimension).
    pub fn cluster(mut self, cluster: &str) -> Self {
        self.filters
            .push(format!("cluster = '{}'", escape_sql(cluster)));
        self
    }

    /// Filter by batch_id.
    pub fn batch_id(mut self, id: &str) -> Self {
        self.filters
            .push(format!("batch_id = '{}'", escape_sql(id)));
        self
    }

    /// Limit the number of results.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Build the SQL query string.
    pub fn build(&self) -> String {
        match self.strategy {
            ExactQueryStrategy::Final => self.build_final(),
            ExactQueryStrategy::ArgMax => self.build_argmax(),
        }
    }

    fn build_final(&self) -> String {
        let mut sql = format!("SELECT * FROM {} FINAL", self.table);
        if !self.filters.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&self.filters.join(" AND "));
        }
        if let Some(n) = self.limit {
            sql.push_str(&format!(" LIMIT {n}"));
        }
        sql
    }

    fn build_argmax(&self) -> String {
        let columns = [
            "batch_id",
            "seq",
            "schema_major",
            "schema_minor",
            "event_kind",
            "sensor",
            "agent_generation",
            "node_name",
            "cluster",
            "ts_monotonic_ns",
            "boot_id_hex",
            "pid_tgid",
            "cgroup_id",
            "uid",
            "gid",
            "payload",
            "kafka_topic",
            "kafka_partition",
            "kafka_offset",
        ];

        let select_cols: Vec<String> = columns
            .iter()
            .map(|c| format!("argMax({c}, _version) AS {c}"))
            .collect();

        let mut sql = format!(
            "SELECT event_id, {}, max(_version) AS _version FROM {}",
            select_cols.join(", "),
            self.table
        );

        if !self.filters.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&self.filters.join(" AND "));
        }

        sql.push_str(" GROUP BY event_id");

        if let Some(n) = self.limit {
            sql.push_str(&format!(" LIMIT {n}"));
        }

        sql
    }
}

/// Build a duplicate-detector query.
///
/// Returns event_ids with more than one physical row (duplicates
/// not yet merged by ReplacingMergeTree).
pub fn build_duplicate_detector_query(table: &str) -> String {
    format!(
        "SELECT event_id, count() AS physical_rows, \
         min(_version) AS min_version, max(_version) AS max_version, \
         groupArray(kafka_offset) AS kafka_offsets \
         FROM {table} GROUP BY event_id HAVING count() > 1"
    )
}

/// Build a count query for exact (deduplicated) event count.
pub fn build_exact_count_query(table: &str, strategy: ExactQueryStrategy) -> String {
    match strategy {
        ExactQueryStrategy::Final => {
            format!("SELECT count() FROM (SELECT event_id FROM {table} FINAL)")
        }
        ExactQueryStrategy::ArgMax => {
            format!("SELECT count() FROM (SELECT event_id FROM {table} GROUP BY event_id)")
        }
    }
}

/// Escape a string for SQL single-quote context.
fn escape_sql(s: &str) -> String {
    s.replace('\'', "''").replace('\\', "\\\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_query_no_filters() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::Final).build();
        assert_eq!(sql, "SELECT * FROM events_v1 FINAL");
    }

    #[test]
    fn final_query_with_event_id() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::Final)
            .event_id("evt-001")
            .build();
        assert_eq!(
            sql,
            "SELECT * FROM events_v1 FINAL WHERE event_id = 'evt-001'"
        );
    }

    #[test]
    fn final_query_with_multiple_filters() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::Final)
            .node_name("node-1")
            .event_kind(EventKind::FileOpen)
            .cluster("prod")
            .build();
        assert_eq!(
            sql,
            "SELECT * FROM events_v1 FINAL WHERE node_name = 'node-1' AND event_kind = 'EVENT_KIND_FILE_OPEN' AND cluster = 'prod'"
        );
    }

    #[test]
    fn final_query_with_limit() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::Final)
            .limit(10)
            .build();
        assert_eq!(sql, "SELECT * FROM events_v1 FINAL LIMIT 10");
    }

    #[test]
    fn argmax_query_no_filters() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::ArgMax).build();
        assert!(sql.contains("argMax(batch_id, _version) AS batch_id"));
        assert!(sql.contains("GROUP BY event_id"));
        assert!(sql.contains("max(_version) AS _version"));
        assert!(!sql.contains("WHERE"));
    }

    #[test]
    fn argmax_query_with_filters() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::ArgMax)
            .event_id("evt-001")
            .build();
        assert!(sql.contains("WHERE event_id = 'evt-001'"));
        assert!(sql.contains("GROUP BY event_id"));
    }

    #[test]
    fn argmax_query_with_limit() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::ArgMax)
            .limit(5)
            .build();
        assert!(sql.ends_with("LIMIT 5"));
    }

    #[test]
    fn custom_table_name() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::Final)
            .table("test_events")
            .build();
        assert_eq!(sql, "SELECT * FROM test_events FINAL");
    }

    #[test]
    fn duplicate_detector_query() {
        let sql = build_duplicate_detector_query("events_v1");
        assert!(sql.contains("HAVING count() > 1"));
        assert!(sql.contains("groupArray(kafka_offset)"));
    }

    #[test]
    fn exact_count_final() {
        let sql = build_exact_count_query("events_v1", ExactQueryStrategy::Final);
        assert!(sql.contains("FINAL"));
        assert!(sql.contains("count()"));
    }

    #[test]
    fn exact_count_argmax() {
        let sql = build_exact_count_query("events_v1", ExactQueryStrategy::ArgMax);
        assert!(sql.contains("GROUP BY event_id"));
        assert!(sql.contains("count()"));
    }

    #[test]
    fn sql_injection_escaped() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::Final)
            .event_id("evt'; DROP TABLE events_v1; --")
            .build();
        assert!(sql.contains("evt''; DROP TABLE events_v1; --"));
        assert!(!sql.contains("evt'; DROP"));
    }

    #[test]
    fn batch_id_filter() {
        let sql = ExactQueryBuilder::new(ExactQueryStrategy::Final)
            .batch_id("batch-42")
            .build();
        assert!(sql.contains("batch_id = 'batch-42'"));
    }
}
