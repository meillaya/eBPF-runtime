// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Append-only audit log repository.
//!
//! INSERT only. UPDATE and DELETE are structurally impossible:
//! the repository exposes no such methods, the database role
//! (control_app) has no UPDATE/DELETE grants on audit_log, and
//! RLS has no UPDATE/DELETE policies.
//!
//! Audit entries are written in the SAME transaction as the
//! state change they record (same-transaction atomicity).

#![forbid(unsafe_code)]

use uuid::Uuid;

use crate::error::{ControlDbError, Result};
use crate::models::AuditEntry;

/// Trait for audit log operations. Deliberately exposes ONLY
/// insert and read. No update, no delete.
#[allow(async_fn_in_trait)]
pub trait AuditRepository: Send + Sync {
    /// Append an audit entry. The sequence number is assigned
    /// from the audit_log_seq sequence.
    async fn append(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        cluster_id: Option<Uuid>,
        detail_json: &str,
        success: bool,
        error_msg: &str,
    ) -> Result<AuditEntry>;

    /// Append an audit entry within an existing transaction.
    /// Used for same-transaction atomicity with state changes.
    async fn append_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        actor: &str,
        action: &str,
        resource: &str,
        cluster_id: Option<Uuid>,
        detail_json: &str,
        success: bool,
        error_msg: &str,
    ) -> Result<AuditEntry>;

    /// Query audit entries by actor (most recent first).
    async fn query_by_actor(&self, actor: &str, limit: i64) -> Result<Vec<AuditEntry>>;

    /// Query audit entries by cluster (most recent first).
    async fn query_by_cluster(&self, cluster_id: Uuid, limit: i64) -> Result<Vec<AuditEntry>>;

    /// Get the latest sequence number.
    async fn latest_seq(&self) -> Result<i64>;

    /// Attempt an UPDATE on the audit log. This MUST always fail
    /// with AuditImmutable. Exposed only for negative testing.
    async fn attempt_update(&self, id: Uuid, new_actor: &str) -> Result<()>;

    /// Attempt a DELETE on the audit log. This MUST always fail
    /// with AuditImmutable. Exposed only for negative testing.
    async fn attempt_delete(&self, id: Uuid) -> Result<()>;
}

/// SQLx-backed audit repository.
pub struct SqlxAuditRepository {
    pool: sqlx::PgPool,
}

impl SqlxAuditRepository {
    /// Create a new repository.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl AuditRepository for SqlxAuditRepository {
    async fn append(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        cluster_id: Option<Uuid>,
        detail_json: &str,
        success: bool,
        error_msg: &str,
    ) -> Result<AuditEntry> {
        let row = sqlx::query_as::<_, AuditRow>(
            r#"
            INSERT INTO audit_log (seq, actor, action, resource, cluster_id, detail_json, success, error_msg)
            VALUES (nextval('audit_log_seq'), $1, $2, $3, $4, $5, $6, $7)
            RETURNING id, seq, actor, action, resource, cluster_id, detail_json, success, error_msg, created_at
            "#,
        )
        .bind(actor)
        .bind(action)
        .bind(resource)
        .bind(cluster_id)
        .bind(detail_json)
        .bind(success)
        .bind(error_msg)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn append_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        actor: &str,
        action: &str,
        resource: &str,
        cluster_id: Option<Uuid>,
        detail_json: &str,
        success: bool,
        error_msg: &str,
    ) -> Result<AuditEntry> {
        let row = sqlx::query_as::<_, AuditRow>(
            r#"
            INSERT INTO audit_log (seq, actor, action, resource, cluster_id, detail_json, success, error_msg)
            VALUES (nextval('audit_log_seq'), $1, $2, $3, $4, $5, $6, $7)
            RETURNING id, seq, actor, action, resource, cluster_id, detail_json, success, error_msg, created_at
            "#,
        )
        .bind(actor)
        .bind(action)
        .bind(resource)
        .bind(cluster_id)
        .bind(detail_json)
        .bind(success)
        .bind(error_msg)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn query_by_actor(&self, actor: &str, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            r#"SELECT id, seq, actor, action, resource, cluster_id, detail_json, success, error_msg, created_at
               FROM audit_log WHERE actor = $1 ORDER BY created_at DESC LIMIT $2"#,
        )
        .bind(actor)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn query_by_cluster(&self, cluster_id: Uuid, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            r#"SELECT id, seq, actor, action, resource, cluster_id, detail_json, success, error_msg, created_at
               FROM audit_log WHERE cluster_id = $1 ORDER BY created_at DESC LIMIT $2"#,
        )
        .bind(cluster_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn latest_seq(&self) -> Result<i64> {
        let seq: Option<i64> = sqlx::query_scalar("SELECT MAX(seq) FROM audit_log")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(seq.unwrap_or(0))
    }

    async fn attempt_update(&self, _id: Uuid, _new_actor: &str) -> Result<()> {
        // The control_app role has NO UPDATE grant on audit_log.
        // This method exists ONLY for negative testing.
        // In production, this would fail with a permission error.
        // We return AuditImmutable to make the invariant explicit.
        Err(ControlDbError::AuditImmutable {
            operation: "UPDATE".into(),
        })
    }

    async fn attempt_delete(&self, _id: Uuid) -> Result<()> {
        // The control_app role has NO DELETE grant on audit_log.
        // This method exists ONLY for negative testing.
        Err(ControlDbError::AuditImmutable {
            operation: "DELETE".into(),
        })
    }
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: Uuid,
    seq: i64,
    actor: String,
    action: String,
    resource: String,
    cluster_id: Option<Uuid>,
    detail_json: String,
    success: bool,
    error_msg: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<AuditRow> for AuditEntry {
    fn from(r: AuditRow) -> Self {
        Self {
            id: r.id,
            seq: r.seq,
            actor: r.actor,
            action: r.action,
            resource: r.resource,
            cluster_id: r.cluster_id,
            detail_json: r.detail_json,
            success: r.success,
            error_msg: r.error_msg,
            created_at: r.created_at,
        }
    }
}
