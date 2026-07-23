// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Policy rollout repository: policies, versions, targets,
//! rollouts, acks.
//!
//! Optimistic version checks on rollout state transitions.
//! Concurrent rollout races resolve to exactly one winner via
//! unique constraints and version guards. Same-transaction audit.

#![forbid(unsafe_code)]

use uuid::Uuid;

use crate::error::{ControlDbError, Result};
use crate::models::{Policy, PolicyVersion, Rollout, RolloutAck};

/// Trait for policy rollout operations.
#[allow(async_fn_in_trait)]
pub trait PolicyRepository: Send + Sync {
    /// Create a policy. Idempotent on name.
    async fn create_policy(&self, name: &str, description: &str) -> Result<Policy>;

    /// Get a policy by ID.
    async fn get_policy(&self, id: Uuid) -> Result<Policy>;

    /// Stage a new policy version. The version must be strictly
    /// greater than the current max version for the policy
    /// (monotonic). Writes audit in the same transaction.
    async fn stage_version(
        &self,
        policy_id: Uuid,
        version: i64,
        content_digest: &str,
        content_hex: &str,
        actor: &str,
    ) -> Result<PolicyVersion>;

    /// Get a policy version by ID.
    async fn get_version(&self, id: Uuid) -> Result<PolicyVersion>;

    /// Transition a policy version's status with optimistic
    /// check on current status.
    async fn transition_version_status(
        &self,
        version_id: Uuid,
        from_status: &str,
        to_status: &str,
        actor: &str,
    ) -> Result<PolicyVersion>;

    /// Create a rollout for a policy version. Only one active
    /// rollout per version (unique constraint).
    async fn create_rollout(
        &self,
        policy_version_id: Uuid,
        threshold_percent: i32,
        actor: &str,
    ) -> Result<Rollout>;

    /// Get a rollout by ID.
    async fn get_rollout(&self, id: Uuid) -> Result<Rollout>;

    /// Record an agent's ack for a rollout. Idempotent: one ack
    /// per agent per rollout (unique constraint). Updates
    /// aggregate counts atomically.
    async fn record_ack(
        &self,
        rollout_id: Uuid,
        agent_id: Uuid,
        policy_version: i64,
        digest_hex: &str,
        accepted: bool,
        rejected_reason: &str,
    ) -> Result<RolloutAck>;

    /// Complete a rollout (transition to completed/failed).
    /// Uses optimistic version check.
    async fn complete_rollout(
        &self,
        rollout_id: Uuid,
        expected_version: i64,
        final_state: &str,
        actor: &str,
    ) -> Result<Rollout>;

    /// Get the latest version for a policy.
    async fn get_latest_version(&self, policy_id: Uuid) -> Result<Option<PolicyVersion>>;
}

/// SQLx-backed policy repository.
pub struct SqlxPolicyRepository {
    pool: sqlx::PgPool,
}

impl SqlxPolicyRepository {
    /// Create a new repository.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl PolicyRepository for SqlxPolicyRepository {
    async fn create_policy(&self, name: &str, description: &str) -> Result<Policy> {
        let row = sqlx::query_as::<_, PolicyRow>(
            r#"
            INSERT INTO policies (name, description)
            VALUES ($1, $2)
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id, name, description, version, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(description)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn get_policy(&self, id: Uuid) -> Result<Policy> {
        let row = sqlx::query_as::<_, PolicyRow>(
            "SELECT id, name, description, version, created_at, updated_at FROM policies WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::NotFound {
            table: "policies".into(),
            key: id.to_string(),
        })?;

        Ok(row.into())
    }

    async fn stage_version(
        &self,
        policy_id: Uuid,
        version: i64,
        content_digest: &str,
        content_hex: &str,
        actor: &str,
    ) -> Result<PolicyVersion> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        // Monotonic version check: version must be > current max.
        let max_version: Option<i64> =
            sqlx::query_scalar("SELECT MAX(version) FROM policy_versions WHERE policy_id = $1")
                .bind(policy_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| ControlDbError::Database(e.to_string()))?;

        if let Some(max) = max_version {
            if version <= max {
                return Err(ControlDbError::VersionConflict {
                    table: "policy_versions".into(),
                    expected: max + 1,
                    found: version,
                });
            }
        }

        let row = sqlx::query_as::<_, PolicyVersionRow>(
            r#"
            INSERT INTO policy_versions (policy_id, version, content_digest, content_hex, status)
            VALUES ($1, $2, $3, $4, 'staged')
            RETURNING id, policy_id, version, content_digest, content_hex, status, created_at
            "#,
        )
        .bind(policy_id)
        .bind(version)
        .bind(content_digest)
        .bind(content_hex)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        // Same-transaction audit.
        let seq: i64 = sqlx::query_scalar("SELECT nextval('audit_log_seq')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO audit_log (seq, actor, action, resource, detail_json, success)
            VALUES ($1, $2, 'policy.stage', $3, $4, true)
            "#,
        )
        .bind(seq)
        .bind(actor)
        .bind(format!("policy_version:{version}"))
        .bind(format!(
            "{{\"policy_id\":\"{policy_id}\",\"version\":{version}}}"
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn get_version(&self, id: Uuid) -> Result<PolicyVersion> {
        let row = sqlx::query_as::<_, PolicyVersionRow>(
            "SELECT id, policy_id, version, content_digest, content_hex, status, created_at FROM policy_versions WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::NotFound {
            table: "policy_versions".into(),
            key: id.to_string(),
        })?;

        Ok(row.into())
    }

    async fn transition_version_status(
        &self,
        version_id: Uuid,
        from_status: &str,
        to_status: &str,
        actor: &str,
    ) -> Result<PolicyVersion> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        let row = sqlx::query_as::<_, PolicyVersionRow>(
            r#"
            UPDATE policy_versions
            SET status = $3
            WHERE id = $1 AND status = $2
            RETURNING id, policy_id, version, content_digest, content_hex, status, created_at
            "#,
        )
        .bind(version_id)
        .bind(from_status)
        .bind(to_status)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::InvalidRolloutTransition {
            from: from_status.to_string(),
            action: format!("->{to_status}"),
        })?;

        // Same-transaction audit.
        let seq: i64 = sqlx::query_scalar("SELECT nextval('audit_log_seq')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO audit_log (seq, actor, action, resource, detail_json, success)
            VALUES ($1, $2, $3, $4, $5, true)
            "#,
        )
        .bind(seq)
        .bind(actor)
        .bind(format!("policy.{to_status}"))
        .bind(format!("policy_version:{version_id}"))
        .bind(format!(
            "{{\"from\":\"{from_status}\",\"to\":\"{to_status}\"}}"
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn create_rollout(
        &self,
        policy_version_id: Uuid,
        threshold_percent: i32,
        actor: &str,
    ) -> Result<Rollout> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        let result = sqlx::query_as::<_, RolloutRow>(
            r#"
            INSERT INTO rollouts (policy_version_id, threshold_percent, state)
            VALUES ($1, $2, 'pending')
            RETURNING id, policy_version_id, state, threshold_percent,
                      committed_count, ack_count, rejected_count, version,
                      started_at, completed_at
            "#,
        )
        .bind(policy_version_id)
        .bind(threshold_percent)
        .fetch_one(&mut *tx)
        .await;

        let row = match result {
            Ok(r) => r,
            Err(sqlx::Error::Database(db_err)) => {
                let code = db_err.code().unwrap_or_default();
                if code == "23505" {
                    return Err(ControlDbError::IdempotentDuplicate {
                        key: format!("rollout:{policy_version_id}"),
                    });
                }
                return Err(ControlDbError::Database(db_err.to_string()));
            }
            Err(e) => return Err(ControlDbError::Database(e.to_string())),
        };

        // Same-transaction audit.
        let seq: i64 = sqlx::query_scalar("SELECT nextval('audit_log_seq')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO audit_log (seq, actor, action, resource, detail_json, success)
            VALUES ($1, $2, 'rollout.create', $3, $4, true)
            "#,
        )
        .bind(seq)
        .bind(actor)
        .bind(format!("rollout:{}", row.id))
        .bind(format!("{{\"threshold\":{threshold_percent}}}"))
        .execute(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn get_rollout(&self, id: Uuid) -> Result<Rollout> {
        let row = sqlx::query_as::<_, RolloutRow>(
            r#"SELECT id, policy_version_id, state, threshold_percent,
                      committed_count, ack_count, rejected_count, version,
                      started_at, completed_at
               FROM rollouts WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::NotFound {
            table: "rollouts".into(),
            key: id.to_string(),
        })?;

        Ok(row.into())
    }

    async fn record_ack(
        &self,
        rollout_id: Uuid,
        agent_id: Uuid,
        policy_version: i64,
        digest_hex: &str,
        accepted: bool,
        rejected_reason: &str,
    ) -> Result<RolloutAck> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        // Idempotent: one ack per agent per rollout.
        let result = sqlx::query_as::<_, RolloutAckRow>(
            r#"
            INSERT INTO rollout_acks (rollout_id, agent_id, policy_version, digest_hex, accepted, rejected_reason)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, rollout_id, agent_id, policy_version, digest_hex, accepted, rejected_reason, acked_at
            "#,
        )
        .bind(rollout_id)
        .bind(agent_id)
        .bind(policy_version)
        .bind(digest_hex)
        .bind(accepted)
        .bind(rejected_reason)
        .fetch_one(&mut *tx)
        .await;

        let row = match result {
            Ok(r) => r,
            Err(sqlx::Error::Database(db_err)) => {
                let code = db_err.code().unwrap_or_default();
                if code == "23505" {
                    return Err(ControlDbError::IdempotentDuplicate {
                        key: format!("ack:{rollout_id}:{agent_id}"),
                    });
                }
                return Err(ControlDbError::Database(db_err.to_string()));
            }
            Err(e) => return Err(ControlDbError::Database(e.to_string())),
        };

        // Update aggregate counts atomically.
        if accepted {
            sqlx::query(
                "UPDATE rollouts SET ack_count = ack_count + 1, committed_count = committed_count + 1 WHERE id = $1",
            )
            .bind(rollout_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;
        } else {
            sqlx::query(
                "UPDATE rollouts SET ack_count = ack_count + 1, rejected_count = rejected_count + 1 WHERE id = $1",
            )
            .bind(rollout_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn complete_rollout(
        &self,
        rollout_id: Uuid,
        expected_version: i64,
        final_state: &str,
        actor: &str,
    ) -> Result<Rollout> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        let row = sqlx::query_as::<_, RolloutRow>(
            r#"
            UPDATE rollouts
            SET state = $3, version = version + 1, completed_at = now()
            WHERE id = $1 AND version = $2
            RETURNING id, policy_version_id, state, threshold_percent,
                      committed_count, ack_count, rejected_count, version,
                      started_at, completed_at
            "#,
        )
        .bind(rollout_id)
        .bind(expected_version)
        .bind(final_state)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::VersionConflict {
            table: "rollouts".into(),
            expected: expected_version,
            found: -1,
        })?;

        // Same-transaction audit.
        let seq: i64 = sqlx::query_scalar("SELECT nextval('audit_log_seq')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO audit_log (seq, actor, action, resource, detail_json, success)
            VALUES ($1, $2, 'rollout.complete', $3, $4, true)
            "#,
        )
        .bind(seq)
        .bind(actor)
        .bind(format!("rollout:{rollout_id}"))
        .bind(format!("{{\"state\":\"{final_state}\"}}"))
        .execute(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn get_latest_version(&self, policy_id: Uuid) -> Result<Option<PolicyVersion>> {
        let row = sqlx::query_as::<_, PolicyVersionRow>(
            r#"SELECT id, policy_id, version, content_digest, content_hex, status, created_at
               FROM policy_versions WHERE policy_id = $1 ORDER BY version DESC LIMIT 1"#,
        )
        .bind(policy_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.map(Into::into))
    }
}

// -- SQLx row types --

#[derive(sqlx::FromRow)]
struct PolicyRow {
    id: Uuid,
    name: String,
    description: String,
    version: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<PolicyRow> for Policy {
    fn from(r: PolicyRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            version: r.version,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct PolicyVersionRow {
    id: Uuid,
    policy_id: Uuid,
    version: i64,
    content_digest: String,
    content_hex: String,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<PolicyVersionRow> for PolicyVersion {
    fn from(r: PolicyVersionRow) -> Self {
        Self {
            id: r.id,
            policy_id: r.policy_id,
            version: r.version,
            content_digest: r.content_digest,
            content_hex: r.content_hex,
            status: r.status,
            created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RolloutRow {
    id: Uuid,
    policy_version_id: Uuid,
    state: String,
    threshold_percent: i32,
    committed_count: i32,
    ack_count: i32,
    rejected_count: i32,
    version: i64,
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<RolloutRow> for Rollout {
    fn from(r: RolloutRow) -> Self {
        Self {
            id: r.id,
            policy_version_id: r.policy_version_id,
            state: r.state,
            threshold_percent: r.threshold_percent,
            committed_count: r.committed_count,
            ack_count: r.ack_count,
            rejected_count: r.rejected_count,
            version: r.version,
            started_at: r.started_at,
            completed_at: r.completed_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RolloutAckRow {
    id: Uuid,
    rollout_id: Uuid,
    agent_id: Uuid,
    policy_version: i64,
    digest_hex: String,
    accepted: bool,
    rejected_reason: String,
    acked_at: chrono::DateTime<chrono::Utc>,
}

impl From<RolloutAckRow> for RolloutAck {
    fn from(r: RolloutAckRow) -> Self {
        Self {
            id: r.id,
            rollout_id: r.rollout_id,
            agent_id: r.agent_id,
            policy_version: r.policy_version,
            digest_hex: r.digest_hex,
            accepted: r.accepted,
            rejected_reason: r.rejected_reason,
            acked_at: r.acked_at,
        }
    }
}
