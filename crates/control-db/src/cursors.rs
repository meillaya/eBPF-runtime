// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Event ingress cursor repository.
//!
//! Per-agent sequence tracking with idempotent upsert. Duplicate
//! (agent_id, sequence) or (agent_id, idempotency_key) inserts
//! are detected and reported as IdempotentDuplicate.

#![forbid(unsafe_code)]

use uuid::Uuid;

use crate::error::{ControlDbError, Result};
use crate::models::EventCursor;

/// Trait for event cursor operations.
#[allow(async_fn_in_trait)]
pub trait CursorRepository: Send + Sync {
    /// Advance the cursor for an agent. Idempotent: if the
    /// sequence or idempotency_key already exists, returns
    /// IdempotentDuplicate (safe no-op).
    async fn advance_cursor(
        &self,
        agent_id: Uuid,
        sequence: i64,
        idempotency_key: &str,
        batch_size: i32,
    ) -> Result<EventCursor>;

    /// Get the latest cursor for an agent (highest sequence).
    async fn get_latest_cursor(&self, agent_id: Uuid) -> Result<Option<EventCursor>>;

    /// Check if a specific sequence has been ingested.
    async fn has_sequence(&self, agent_id: Uuid, sequence: i64) -> Result<bool>;
}

/// SQLx-backed cursor repository.
pub struct SqlxCursorRepository {
    pool: sqlx::PgPool,
}

impl SqlxCursorRepository {
    /// Create a new repository.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl CursorRepository for SqlxCursorRepository {
    async fn advance_cursor(
        &self,
        agent_id: Uuid,
        sequence: i64,
        idempotency_key: &str,
        batch_size: i32,
    ) -> Result<EventCursor> {
        // Attempt insert; unique constraint violation = idempotent duplicate.
        let result = sqlx::query_as::<_, CursorRow>(
            r#"
            INSERT INTO event_cursors (agent_id, sequence, idempotency_key, batch_size)
            VALUES ($1, $2, $3, $4)
            RETURNING id, agent_id, sequence, idempotency_key, batch_size, ingested_at
            "#,
        )
        .bind(agent_id)
        .bind(sequence)
        .bind(idempotency_key)
        .bind(batch_size)
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(row) => Ok(row.into()),
            Err(sqlx::Error::Database(db_err)) => {
                let code = db_err.code().unwrap_or_default();
                if code == "23505" {
                    // unique_violation
                    Err(ControlDbError::IdempotentDuplicate {
                        key: format!("{agent_id}:{sequence}:{idempotency_key}"),
                    })
                } else {
                    Err(ControlDbError::Database(db_err.to_string()))
                }
            }
            Err(e) => Err(ControlDbError::Database(e.to_string())),
        }
    }

    async fn get_latest_cursor(&self, agent_id: Uuid) -> Result<Option<EventCursor>> {
        let row = sqlx::query_as::<_, CursorRow>(
            r#"SELECT id, agent_id, sequence, idempotency_key, batch_size, ingested_at
               FROM event_cursors WHERE agent_id = $1 ORDER BY sequence DESC LIMIT 1"#,
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.map(Into::into))
    }

    async fn has_sequence(&self, agent_id: Uuid, sequence: i64) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM event_cursors WHERE agent_id = $1 AND sequence = $2)",
        )
        .bind(agent_id)
        .bind(sequence)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(exists)
    }
}

#[derive(sqlx::FromRow)]
struct CursorRow {
    id: Uuid,
    agent_id: Uuid,
    sequence: i64,
    idempotency_key: String,
    batch_size: i32,
    ingested_at: chrono::DateTime<chrono::Utc>,
}

impl From<CursorRow> for EventCursor {
    fn from(r: CursorRow) -> Self {
        Self {
            id: r.id,
            agent_id: r.agent_id,
            sequence: r.sequence,
            idempotency_key: r.idempotency_key,
            batch_size: r.batch_size,
            ingested_at: r.ingested_at,
        }
    }
}
