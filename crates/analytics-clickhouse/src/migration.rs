// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Migration repeatability validation.
//!
//! Validates that all SQL migrations in `deploy/clickhouse/` are
//! repeatable (idempotent): they can be run multiple times without
//! error or data loss.
//!
//! Rules:
//! - All DDL uses `IF NOT EXISTS` / `IF EXISTS` guards
//! - No `DROP TABLE` / `TRUNCATE` / destructive `ALTER`
//! - No `INSERT` / `DELETE` / `UPDATE` (migrations are schema-only)

use crate::error::{AnalyticsError, AnalyticsResult};

/// A migration file with its content.
#[derive(Debug, Clone)]
pub struct MigrationFile {
    /// File name (e.g., "0001_events_v1.sql").
    pub name: String,
    /// SQL content.
    pub content: String,
}

/// Destructive patterns that violate migration repeatability.
const DESTRUCTIVE_PATTERNS: &[&str] = &[
    "DROP TABLE",
    "DROP VIEW",
    "DROP DATABASE",
    "TRUNCATE",
    "DELETE FROM",
    "UPDATE ",
    "INSERT INTO",
    "ALTER TABLE", // except ADD INDEX IF NOT EXISTS
];

/// Safe ALTER patterns (non-destructive).
const SAFE_ALTER_PATTERNS: &[&str] = &["ADD INDEX IF NOT EXISTS", "ADD COLUMN IF NOT EXISTS"];

/// Strip SQL single-line comments (`-- ...`) from content.
/// Prevents false positives from comments mentioning destructive ops.
fn strip_sql_comments(sql: &str) -> String {
    sql.lines()
        .map(|line| {
            // Find `--` that isn't inside a string literal.
            // Simple heuristic: split at first `--` occurrence.
            if let Some(idx) = line.find("--") {
                &line[..idx]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Validate that a migration file is repeatable.
pub fn validate_repeatable(migration: &MigrationFile) -> AnalyticsResult<()> {
    let stripped = strip_sql_comments(&migration.content);
    let upper = stripped.to_uppercase();

    // Check for destructive patterns.
    for pattern in DESTRUCTIVE_PATTERNS {
        if upper.contains(pattern) {
            // ALTER TABLE is OK if it's a safe pattern.
            if *pattern == "ALTER TABLE" {
                let is_safe = SAFE_ALTER_PATTERNS.iter().any(|safe| upper.contains(safe));
                if is_safe {
                    continue;
                }
            }
            return Err(AnalyticsError::MigrationNotRepeatable {
                file: migration.name.clone(),
                reason: format!("contains destructive pattern: {pattern}"),
            });
        }
    }

    // Check that CREATE statements use IF NOT EXISTS.
    let create_count = upper.matches("CREATE TABLE").count()
        + upper.matches("CREATE MATERIALIZED VIEW").count()
        + upper.matches("CREATE VIEW").count();
    let if_not_exists_count = upper.matches("IF NOT EXISTS").count();

    if create_count > 0 && if_not_exists_count < create_count {
        return Err(AnalyticsError::MigrationNotRepeatable {
            file: migration.name.clone(),
            reason: format!(
                "CREATE without IF NOT EXISTS: {create_count} CREATEs, {if_not_exists_count} guards"
            ),
        });
    }

    Ok(())
}

/// Validate all migration files are repeatable.
pub fn validate_all_repeatable(migrations: &[MigrationFile]) -> AnalyticsResult<()> {
    for migration in migrations {
        validate_repeatable(migration)?;
    }
    Ok(())
}

/// Check that migration files are in correct order (numeric prefix).
pub fn validate_ordering(migrations: &[MigrationFile]) -> AnalyticsResult<()> {
    let mut last_num: Option<u32> = None;
    for migration in migrations {
        let num_str = migration.name.split('_').next().unwrap_or("0");
        let num: u32 = num_str.parse().unwrap_or(0);
        if let Some(last) = last_num {
            if num <= last {
                return Err(AnalyticsError::MigrationNotRepeatable {
                    file: migration.name.clone(),
                    reason: format!("migration {num:04} is not after {last:04}"),
                });
            }
        }
        last_num = Some(num);
    }
    Ok(())
}

/// Load the embedded migration files (compile-time inclusion).
/// These are the actual SQL files from deploy/clickhouse/.
pub fn embedded_migrations() -> Vec<MigrationFile> {
    vec![
        MigrationFile {
            name: "0001_events_v1.sql".to_string(),
            content: include_str!("../../../deploy/clickhouse/0001_events_v1.sql").to_string(),
        },
        MigrationFile {
            name: "0002_kafka_consumer.sql".to_string(),
            content: include_str!("../../../deploy/clickhouse/0002_kafka_consumer.sql").to_string(),
        },
        MigrationFile {
            name: "0003_dlq_metadata.sql".to_string(),
            content: include_str!("../../../deploy/clickhouse/0003_dlq_metadata.sql").to_string(),
        },
        MigrationFile {
            name: "0004_consumer_lag_metrics.sql".to_string(),
            content: include_str!("../../../deploy/clickhouse/0004_consumer_lag_metrics.sql")
                .to_string(),
        },
        MigrationFile {
            name: "0005_exact_query_helpers.sql".to_string(),
            content: include_str!("../../../deploy/clickhouse/0005_exact_query_helpers.sql")
                .to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_embedded_migrations_are_repeatable() {
        let migrations = embedded_migrations();
        assert_eq!(migrations.len(), 5);
        assert!(validate_all_repeatable(&migrations).is_ok());
    }

    #[test]
    fn all_embedded_migrations_are_ordered() {
        let migrations = embedded_migrations();
        assert!(validate_ordering(&migrations).is_ok());
    }

    #[test]
    fn drop_table_rejected() {
        let migration = MigrationFile {
            name: "0099_bad.sql".to_string(),
            content: "DROP TABLE events_v1;".to_string(),
        };
        let err = validate_repeatable(&migration).unwrap_err();
        assert!(matches!(err, AnalyticsError::MigrationNotRepeatable { .. }));
    }

    #[test]
    fn truncate_rejected() {
        let migration = MigrationFile {
            name: "0099_bad.sql".to_string(),
            content: "TRUNCATE TABLE events_v1;".to_string(),
        };
        assert!(validate_repeatable(&migration).is_err());
    }

    #[test]
    fn insert_rejected() {
        let migration = MigrationFile {
            name: "0099_bad.sql".to_string(),
            content: "INSERT INTO events_v1 VALUES (1);".to_string(),
        };
        assert!(validate_repeatable(&migration).is_err());
    }

    #[test]
    fn delete_rejected() {
        let migration = MigrationFile {
            name: "0099_bad.sql".to_string(),
            content: "DELETE FROM events_v1 WHERE 1=1;".to_string(),
        };
        assert!(validate_repeatable(&migration).is_err());
    }

    #[test]
    fn create_without_if_not_exists_rejected() {
        let migration = MigrationFile {
            name: "0099_bad.sql".to_string(),
            content: "CREATE TABLE events_v1 (id UInt64) ENGINE = MergeTree() ORDER BY id;"
                .to_string(),
        };
        let err = validate_repeatable(&migration).unwrap_err();
        assert!(err.to_string().contains("IF NOT EXISTS"));
    }

    #[test]
    fn create_with_if_not_exists_accepted() {
        let migration = MigrationFile {
            name: "0099_good.sql".to_string(),
            content:
                "CREATE TABLE IF NOT EXISTS events_v1 (id UInt64) ENGINE = MergeTree() ORDER BY id;"
                    .to_string(),
        };
        assert!(validate_repeatable(&migration).is_ok());
    }

    #[test]
    fn alter_add_index_if_not_exists_accepted() {
        let migration = MigrationFile {
            name: "0099_good.sql".to_string(),
            content: "ALTER TABLE events_v1 ADD INDEX IF NOT EXISTS idx_test (col) TYPE bloom_filter GRANULARITY 4;"
                .to_string(),
        };
        assert!(validate_repeatable(&migration).is_ok());
    }

    #[test]
    fn ordering_rejects_out_of_order() {
        let migrations = vec![
            MigrationFile {
                name: "0002_second.sql".to_string(),
                content: String::new(),
            },
            MigrationFile {
                name: "0001_first.sql".to_string(),
                content: String::new(),
            },
        ];
        assert!(validate_ordering(&migrations).is_err());
    }

    #[test]
    fn ordering_accepts_correct_order() {
        let migrations = vec![
            MigrationFile {
                name: "0001_first.sql".to_string(),
                content: String::new(),
            },
            MigrationFile {
                name: "0002_second.sql".to_string(),
                content: String::new(),
            },
        ];
        assert!(validate_ordering(&migrations).is_ok());
    }

    #[test]
    fn embedded_migrations_contain_expected_tables() {
        let migrations = embedded_migrations();
        let all_sql: String = migrations.iter().map(|m| m.content.as_str()).collect();

        assert!(all_sql.contains("events_v1"));
        assert!(all_sql.contains("events_v1_kafka"));
        assert!(all_sql.contains("events_v1_mv"));
        assert!(all_sql.contains("events_dlq_v1"));
        assert!(all_sql.contains("events_v1_exact_final"));
        assert!(all_sql.contains("events_v1_exact_argmax"));
        assert!(all_sql.contains("events_v1_duplicates"));
        assert!(all_sql.contains("events_v1_consumer_lag"));
        assert!(all_sql.contains("ReplacingMergeTree"));
        assert!(all_sql.contains("argMax"));
        assert!(all_sql.contains("FINAL"));
    }
}
