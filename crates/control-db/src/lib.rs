// SPDX-License-Identifier: Apache-2.0 OR MIT
//! PostgreSQL control truth and durable batch ingress.
//!
//! The control plane commits a batch to PostgreSQL before acknowledging it.
//! Kafka and ClickHouse are projections that can replay from `event_batches`.

#![forbid(unsafe_code)]

use event_model::{Batch, Event};
use serde::Serialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;

/// Database errors.
#[derive(Debug, Error)]
pub enum DbError {
    /// SQLx error.
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Migration error.
    #[error("migration: {0}")]
    Migration(String),
    /// The cluster is missing.
    #[error("cluster {0} does not exist")]
    ClusterMissing(String),
    /// The agent is not registered.
    #[error("agent {0} is not registered in this cluster")]
    AgentMissing(String),
    /// Payload serialization error.
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The requested object does not exist.
    #[error("{0}")]
    NotFound(String),
    /// The request conflicts with current state.
    #[error("{0}")]
    Conflict(String),
}

/// A registered agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentRecord {
    /// Database id.
    pub id: Uuid,
    /// Cluster id.
    pub cluster_id: Uuid,
    /// SPIFFE id or phase-2 agent key.
    pub spiffe_id: String,
    /// Node name.
    pub node_name: String,
    /// Agent generation.
    pub agent_generation: String,
    /// Last seen epoch seconds.
    pub last_seen_epoch: i64,
}

/// Result of accepting a batch.
#[derive(Debug, Clone, Serialize)]
pub struct AcceptOutcome {
    /// Whether the batch is accepted.
    pub accepted: bool,
    /// Whether it was already present.
    pub duplicate: bool,
    /// Accepted-at epoch seconds.
    pub accepted_at_unix: i64,
}

/// Connect to PostgreSQL.
pub async fn connect(url: &str, max_connections: u32) -> Result<PgPool, DbError> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await?;
    Ok(pool)
}

/// Run migrations.
pub async fn migrate(pool: &PgPool) -> Result<(), DbError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|error| DbError::Migration(error.to_string()))
}

/// Ensure a cluster exists and return its id.
pub async fn ensure_cluster(pool: &PgPool, name: &str) -> Result<Uuid, DbError> {
    let row = sqlx::query(
        "INSERT INTO clusters (name) VALUES ($1)
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await?;
    Ok(row.get("id"))
}

/// Register or refresh an agent.
pub async fn register_agent(
    pool: &PgPool,
    cluster_id: Uuid,
    agent_key: &str,
    node_name: &str,
    generation: &str,
    boot_id: &str,
    sensors: &[String],
) -> Result<AgentRecord, DbError> {
    let sensors = serde_json::to_value(sensors)?;
    let row = sqlx::query(
        "INSERT INTO agents
           (cluster_id, spiffe_id, node_name, agent_generation, boot_id, sensors, last_seen)
         VALUES ($1, $2, $3, $4, $5, $6, now())
         ON CONFLICT (spiffe_id) DO UPDATE SET
           node_name = EXCLUDED.node_name,
           agent_generation = EXCLUDED.agent_generation,
           boot_id = EXCLUDED.boot_id,
           sensors = EXCLUDED.sensors,
           last_seen = now()
         RETURNING id, cluster_id, spiffe_id, node_name, agent_generation,
                   extract(epoch FROM last_seen)::bigint AS last_seen_epoch",
    )
    .bind(cluster_id)
    .bind(agent_key)
    .bind(node_name)
    .bind(generation)
    .bind(boot_id)
    .bind(sensors)
    .fetch_one(pool)
    .await?;
    if row.get::<Uuid, _>("cluster_id") != cluster_id {
        return Err(DbError::AgentMissing(agent_key.to_string()));
    }
    Ok(AgentRecord {
        id: row.get("id"),
        cluster_id: row.get("cluster_id"),
        spiffe_id: row.get("spiffe_id"),
        node_name: row.get("node_name"),
        agent_generation: row.get("agent_generation"),
        last_seen_epoch: row.get("last_seen_epoch"),
    })
}

/// Accept a batch idempotently.
pub async fn accept_batch(
    pool: &PgPool,
    cluster_id: Uuid,
    agent_key: &str,
    batch: &Batch,
) -> Result<AcceptOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let agent = sqlx::query("SELECT id, cluster_id FROM agents WHERE spiffe_id = $1 FOR UPDATE")
        .bind(agent_key)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| DbError::AgentMissing(agent_key.to_string()))?;
    let agent_id: Uuid = agent.get("id");
    if agent.get::<Uuid, _>("cluster_id") != cluster_id {
        return Err(DbError::AgentMissing(agent_key.to_string()));
    }

    let payload = serde_json::to_value(batch)?;
    let inserted = sqlx::query(
        "INSERT INTO event_batches
           (batch_id, agent_id, cluster_id, idempotency_key, event_count, payload)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (batch_id) DO NOTHING
         RETURNING extract(epoch FROM received_at)::bigint AS accepted_at",
    )
    .bind(&batch.batch_id)
    .bind(agent_id)
    .bind(cluster_id)
    .bind(&batch.batch_id)
    .bind(batch.events.len() as i32)
    .bind(payload)
    .fetch_optional(&mut *tx)
    .await?;

    let (duplicate, accepted_at) = match inserted {
        Some(row) => (false, row.get::<i64, _>("accepted_at")),
        None => {
            let row = sqlx::query(
                "SELECT extract(epoch FROM received_at)::bigint AS accepted_at
                 FROM event_batches WHERE batch_id = $1",
            )
            .bind(&batch.batch_id)
            .fetch_one(&mut *tx)
            .await?;
            (true, row.get::<i64, _>("accepted_at"))
        }
    };
    sqlx::query("UPDATE agents SET last_seen = now() WHERE id = $1")
        .bind(agent_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(AcceptOutcome {
        accepted: true,
        duplicate,
        accepted_at_unix: accepted_at,
    })
}

/// Update an agent's last-seen timestamp.
pub async fn touch_agent(pool: &PgPool, agent_key: &str) -> Result<(), DbError> {
    let result = sqlx::query("UPDATE agents SET last_seen = now() WHERE spiffe_id = $1")
        .bind(agent_key)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(DbError::AgentMissing(agent_key.to_string()));
    }
    Ok(())
}

/// A policy version.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyVersionRecord {
    /// Database id.
    pub id: Uuid,
    /// Policy name.
    pub name: String,
    /// Monotonic version.
    pub version: i64,
    /// YAML content.
    pub content: String,
    /// SHA-256 digest.
    pub digest: String,
    /// staged, committed, applied, rejected.
    pub status: String,
    /// Creation epoch seconds.
    pub created_at_epoch: i64,
}

/// Store a staged policy version.
pub async fn stage_policy(
    pool: &PgPool,
    cluster_id: Uuid,
    name: &str,
    version: i64,
    content: &str,
    digest: &str,
    author: &str,
) -> Result<PolicyVersionRecord, DbError> {
    let policy = sqlx::query(
        "INSERT INTO policies (name, cluster_id) VALUES ($1, $2)
         ON CONFLICT (cluster_id, name) DO UPDATE SET name = EXCLUDED.name
         RETURNING id",
    )
    .bind(name)
    .bind(cluster_id)
    .fetch_one(pool)
    .await?;
    let policy_id: Uuid = policy.get("id");
    let row = sqlx::query(
        "INSERT INTO policy_versions (policy_id, version, content, digest, status, author)
         VALUES ($1, $2, $3, $4, 'staged', $5)
         ON CONFLICT (policy_id, version) DO UPDATE SET
           content = EXCLUDED.content,
           digest = EXCLUDED.digest,
           status = 'staged',
           author = EXCLUDED.author
         RETURNING id, version, content, digest, status,
                   extract(epoch FROM created_at)::bigint AS created_at_epoch",
    )
    .bind(policy_id)
    .bind(version)
    .bind(content)
    .bind(digest)
    .bind(author)
    .fetch_one(pool)
    .await?;
    Ok(PolicyVersionRecord {
        id: row.get("id"),
        name: name.to_string(),
        version: row.get("version"),
        content: row.get("content"),
        digest: row.get("digest"),
        status: row.get("status"),
        created_at_epoch: row.get("created_at_epoch"),
    })
}

/// List policy versions, newest first.
pub async fn list_policies(
    pool: &PgPool,
    cluster_id: Uuid,
) -> Result<Vec<PolicyVersionRecord>, DbError> {
    let rows = sqlx::query(
        "SELECT p.name, v.id, v.version, v.content, v.digest, v.status,
                extract(epoch FROM v.created_at)::bigint AS created_at_epoch
         FROM policy_versions v JOIN policies p ON p.id = v.policy_id
         WHERE p.cluster_id = $1
         ORDER BY v.created_at DESC LIMIT 200",
    )
    .bind(cluster_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PolicyVersionRecord {
            id: row.get("id"),
            name: row.get("name"),
            version: row.get("version"),
            content: row.get("content"),
            digest: row.get("digest"),
            status: row.get("status"),
            created_at_epoch: row.get("created_at_epoch"),
        })
        .collect())
}

/// Fetch one policy version.
pub async fn get_policy(
    pool: &PgPool,
    cluster_id: Uuid,
    version: i64,
) -> Result<Option<PolicyVersionRecord>, DbError> {
    let row = sqlx::query(
        "SELECT p.name, v.id, v.version, v.content, v.digest, v.status,
                extract(epoch FROM v.created_at)::bigint AS created_at_epoch
         FROM policy_versions v JOIN policies p ON p.id = v.policy_id
         WHERE p.cluster_id = $1 AND v.version = $2
         ORDER BY v.created_at DESC LIMIT 1",
    )
    .bind(cluster_id)
    .bind(version)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| PolicyVersionRecord {
        id: row.get("id"),
        name: row.get("name"),
        version: row.get("version"),
        content: row.get("content"),
        digest: row.get("digest"),
        status: row.get("status"),
        created_at_epoch: row.get("created_at_epoch"),
    }))
}

/// Record an agent policy acknowledgement.
pub async fn record_policy_ack(
    pool: &PgPool,
    version: i64,
    agent_key: &str,
    status: &str,
    digest: &str,
    message: &str,
) -> Result<(), DbError> {
    let agent = sqlx::query("SELECT id FROM agents WHERE spiffe_id = $1")
        .bind(agent_key)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| DbError::AgentMissing(agent_key.to_string()))?;
    let agent_id: Uuid = agent.get("id");
    sqlx::query(
        "INSERT INTO policy_acks (policy_version, agent_id, status, digest, message)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (policy_version, agent_id) DO UPDATE SET
           status = EXCLUDED.status,
           digest = EXCLUDED.digest,
           message = EXCLUDED.message,
           updated_at = now()",
    )
    .bind(version)
    .bind(agent_id)
    .bind(status)
    .bind(digest)
    .bind(message)
    .execute(pool)
    .await?;
    Ok(())
}

/// A policy acknowledgement row.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyAckRecord {
    /// Policy version.
    pub policy_version: i64,
    /// Agent SPIFFE id.
    pub agent_id: String,
    /// ready, applied, rejected.
    pub status: String,
    /// Digest.
    pub digest: String,
    /// Error message.
    pub message: String,
    /// Update epoch seconds.
    pub updated_at_epoch: i64,
}

/// List acknowledgements for a policy version.
pub async fn list_policy_acks(
    pool: &PgPool,
    version: i64,
) -> Result<Vec<PolicyAckRecord>, DbError> {
    let rows = sqlx::query(
        "SELECT a.policy_version, a.status, a.digest, a.message,
                extract(epoch FROM a.updated_at)::bigint AS updated_at_epoch,
                ag.spiffe_id
         FROM policy_acks a JOIN agents ag ON ag.id = a.agent_id
         WHERE a.policy_version = $1 ORDER BY ag.spiffe_id",
    )
    .bind(version)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| PolicyAckRecord {
            policy_version: row.get("policy_version"),
            agent_id: row.get("spiffe_id"),
            status: row.get("status"),
            digest: row.get("digest"),
            message: row.get("message"),
            updated_at_epoch: row.get("updated_at_epoch"),
        })
        .collect())
}

/// Set one policy version status by its row id.
pub async fn set_policy_status_by_id(
    pool: &PgPool,
    policy_version_id: Uuid,
    status: &str,
) -> Result<(), DbError> {
    sqlx::query("UPDATE policy_versions SET status = $1 WHERE id = $2")
        .bind(status)
        .bind(policy_version_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Fetch one policy version by its row id.
pub async fn get_policy_by_id(
    pool: &PgPool,
    policy_version_id: Uuid,
) -> Result<Option<PolicyVersionRecord>, DbError> {
    let row = sqlx::query(
        "SELECT p.name, v.id, v.version, v.content, v.digest, v.status,
                extract(epoch FROM v.created_at)::bigint AS created_at_epoch
         FROM policy_versions v JOIN policies p ON p.id = v.policy_id
         WHERE v.id = $1",
    )
    .bind(policy_version_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(policy_record_from_row))
}

/// Fetch one policy version of one policy by version number.
pub async fn get_policy_version(
    pool: &PgPool,
    policy_id: Uuid,
    version: i64,
) -> Result<Option<PolicyVersionRecord>, DbError> {
    let row = sqlx::query(
        "SELECT p.name, v.id, v.version, v.content, v.digest, v.status,
                extract(epoch FROM v.created_at)::bigint AS created_at_epoch
         FROM policy_versions v JOIN policies p ON p.id = v.policy_id
         WHERE v.policy_id = $1 AND v.version = $2",
    )
    .bind(policy_id)
    .bind(version)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(policy_record_from_row))
}

/// The policy an agent should converge to after connecting.
///
/// Pending rollouts intentionally win over the previous applied version so a
/// reconnect during a rollout re-applies the target. A rolled-back target is
/// excluded, so reconnects converge back to the previous policy.
pub async fn current_policy(
    pool: &PgPool,
    cluster_id: Uuid,
) -> Result<Option<PolicyVersionRecord>, DbError> {
    let row = sqlx::query(
        "SELECT p.name, v.id, v.version, v.content, v.digest, v.status,
                extract(epoch FROM v.created_at)::bigint AS created_at_epoch
         FROM policy_versions v JOIN policies p ON p.id = v.policy_id
         WHERE p.cluster_id = $1
           AND v.status IN ('committed', 'applied', 'rolling_out')
         ORDER BY v.created_at DESC LIMIT 1",
    )
    .bind(cluster_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(policy_record_from_row))
}

fn policy_record_from_row(row: sqlx::postgres::PgRow) -> PolicyVersionRecord {
    PolicyVersionRecord {
        id: row.get("id"),
        name: row.get("name"),
        version: row.get("version"),
        content: row.get("content"),
        digest: row.get("digest"),
        status: row.get("status"),
        created_at_epoch: row.get("created_at_epoch"),
    }
}

/// A thresholded policy rollout.
#[derive(Debug, Clone, Serialize)]
pub struct RolloutRecord {
    /// Row id.
    pub id: Uuid,
    /// Cluster id.
    pub cluster_id: Uuid,
    /// Policy id (not the version row id).
    pub policy_id: Uuid,
    /// Policy name.
    pub name: String,
    /// Target version.
    pub version: i64,
    /// Previous version used for rollback.
    pub previous_version: Option<i64>,
    /// Actor that requested the rollout.
    pub requested_by: String,
    /// Minimum applied ratio.
    pub min_ratio: f64,
    /// Timeout in seconds.
    pub timeout_secs: i32,
    /// Whether offline agents were included.
    pub force: bool,
    /// pending, promoted, rolled_back, failed.
    pub status: String,
    /// Snapshot of the denominator.
    pub expected_agents: i32,
    /// Applied acknowledgements.
    pub applied_agents: i32,
    /// Rejected acknowledgements.
    pub rejected_agents: i32,
    /// Human-readable finish reason.
    pub reason: String,
    /// Extra structured detail.
    pub detail: serde_json::Value,
    /// Target digest.
    pub digest: String,
    /// Start epoch seconds.
    pub started_at_epoch: i64,
    /// Deadline epoch seconds.
    pub deadline_epoch: i64,
    /// Finish epoch seconds.
    pub finished_at_epoch: Option<i64>,
}

/// Create a rollout for one committed policy version.
///
/// Fails closed when there is no previous committed/applied version to roll
/// back to, when no agent is online, or when another rollout is pending.
#[allow(clippy::too_many_arguments)]
pub async fn create_rollout(
    pool: &PgPool,
    cluster_id: Uuid,
    version: i64,
    requested_by: &str,
    min_ratio: f64,
    timeout_secs: i32,
    force: bool,
) -> Result<RolloutRecord, DbError> {
    let mut tx = pool.begin().await?;
    let target = sqlx::query(
        "SELECT v.id, v.policy_id, v.version, v.digest, v.status, p.name
         FROM policy_versions v JOIN policies p ON p.id = v.policy_id
         WHERE p.cluster_id = $1 AND v.version = $2
         ORDER BY v.created_at DESC LIMIT 1
         FOR UPDATE OF v",
    )
    .bind(cluster_id)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| DbError::NotFound(format!("policy version {version} not found")))?;
    let policy_version_id: Uuid = target.get("id");
    let policy_id: Uuid = target.get("policy_id");
    let target_status: String = target.get("status");
    if target_status != "committed" {
        return Err(DbError::Conflict(format!(
            "policy version {version} is {target_status}; commit it before rolling out"
        )));
    }

    let pending = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM policy_rollouts WHERE cluster_id = $1 AND status = 'pending' LIMIT 1",
    )
    .bind(cluster_id)
    .fetch_optional(&mut *tx)
    .await?;
    if pending.is_some() {
        return Err(DbError::Conflict(
            "another rollout is already pending for this cluster".to_string(),
        ));
    }

    let previous_version = sqlx::query_scalar::<_, i64>(
        "SELECT v.version FROM policy_versions v
         WHERE v.policy_id = $1 AND v.version <> $2
           AND v.status IN ('committed', 'applied')
         ORDER BY v.created_at DESC LIMIT 1",
    )
    .bind(policy_id)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        DbError::Conflict(
            "a previous committed policy version is required for rollback".to_string(),
        )
    })?;

    let expected_agents = sqlx::query_scalar::<_, i64>(
        "SELECT count(*)::bigint FROM agents
         WHERE cluster_id = $1
           AND ($2 OR last_seen >= now() - interval '5 minutes')",
    )
    .bind(cluster_id)
    .bind(force)
    .fetch_one(&mut *tx)
    .await?;
    if expected_agents == 0 {
        return Err(DbError::Conflict(
            "no online agents are available for a rollout".to_string(),
        ));
    }

    let inserted = sqlx::query(
        "INSERT INTO policy_rollouts
           (cluster_id, policy_id, version, previous_version, requested_by,
            min_ratio, timeout_secs, force, expected_agents, deadline_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 now() + ($7 * interval '1 second'))
         RETURNING id",
    )
    .bind(cluster_id)
    .bind(policy_id)
    .bind(version)
    .bind(previous_version)
    .bind(requested_by)
    .bind(min_ratio)
    .bind(timeout_secs)
    .bind(force)
    .bind(expected_agents as i32)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| {
        if is_unique_violation(&error) {
            DbError::Conflict("another rollout is already pending for this cluster".to_string())
        } else {
            DbError::Sqlx(error)
        }
    })?;
    let rollout_id: Uuid = inserted.get("id");
    sqlx::query("UPDATE policy_versions SET status = 'rolling_out' WHERE id = $1")
        .bind(policy_version_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    get_rollout(pool, rollout_id)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("rollout {rollout_id} disappeared")))
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database) if database.code().as_deref() == Some("23505")
    )
}

/// Fetch one rollout by id.
pub async fn get_rollout(
    pool: &PgPool,
    rollout_id: Uuid,
) -> Result<Option<RolloutRecord>, DbError> {
    let row = sqlx::query(ROLLOUT_SELECT)
        .bind(rollout_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(rollout_record_from_row))
}

/// Fetch the latest rollout for a policy version.
pub async fn latest_rollout(
    pool: &PgPool,
    cluster_id: Uuid,
    version: i64,
) -> Result<Option<RolloutRecord>, DbError> {
    let row = sqlx::query(
        "SELECT r.id, r.cluster_id, r.policy_id, r.version, r.previous_version,
                r.requested_by, r.min_ratio, r.timeout_secs, r.force, r.status,
                r.expected_agents, r.applied_agents, r.rejected_agents, r.reason,
                r.detail,
                floor(extract(epoch FROM r.started_at))::bigint AS started_at_epoch,
                floor(extract(epoch FROM r.deadline_at))::bigint AS deadline_epoch,
                floor(extract(epoch FROM r.finished_at))::bigint AS finished_at_epoch,
                v.digest AS target_digest, p.name
         FROM policy_rollouts r
         JOIN policies p ON p.id = r.policy_id
         JOIN policy_versions v ON v.policy_id = r.policy_id AND v.version = r.version
         WHERE r.cluster_id = $1 AND r.version = $2
         ORDER BY r.started_at DESC LIMIT 1",
    )
    .bind(cluster_id)
    .bind(version)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(rollout_record_from_row))
}

/// List recent rollouts in a cluster.
pub async fn list_rollouts(
    pool: &PgPool,
    cluster_id: Uuid,
    limit: usize,
) -> Result<Vec<RolloutRecord>, DbError> {
    let rows = sqlx::query(
        "SELECT r.id, r.cluster_id, r.policy_id, r.version, r.previous_version,
                r.requested_by, r.min_ratio, r.timeout_secs, r.force, r.status,
                r.expected_agents, r.applied_agents, r.rejected_agents, r.reason,
                r.detail,
                floor(extract(epoch FROM r.started_at))::bigint AS started_at_epoch,
                floor(extract(epoch FROM r.deadline_at))::bigint AS deadline_epoch,
                floor(extract(epoch FROM r.finished_at))::bigint AS finished_at_epoch,
                v.digest AS target_digest, p.name
         FROM policy_rollouts r
         JOIN policies p ON p.id = r.policy_id
         JOIN policy_versions v ON v.policy_id = r.policy_id AND v.version = r.version
         WHERE r.cluster_id = $1
         ORDER BY r.started_at DESC LIMIT $2",
    )
    .bind(cluster_id)
    .bind(limit as i64)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(rollout_record_from_row).collect())
}

/// List pending rollouts across clusters.
pub async fn pending_rollouts(pool: &PgPool) -> Result<Vec<RolloutRecord>, DbError> {
    let rows = sqlx::query(
        "SELECT r.id, r.cluster_id, r.policy_id, r.version, r.previous_version,
                r.requested_by, r.min_ratio, r.timeout_secs, r.force, r.status,
                r.expected_agents, r.applied_agents, r.rejected_agents, r.reason,
                r.detail,
                floor(extract(epoch FROM r.started_at))::bigint AS started_at_epoch,
                floor(extract(epoch FROM r.deadline_at))::bigint AS deadline_epoch,
                floor(extract(epoch FROM r.finished_at))::bigint AS finished_at_epoch,
                v.digest AS target_digest, p.name
         FROM policy_rollouts r
         JOIN policies p ON p.id = r.policy_id
         JOIN policy_versions v ON v.policy_id = r.policy_id AND v.version = r.version
         WHERE r.status = 'pending'
         ORDER BY r.started_at",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(rollout_record_from_row).collect())
}

/// Return the pending rollout id for a cluster, if any.
pub async fn pending_rollout(pool: &PgPool, cluster_id: Uuid) -> Result<Option<Uuid>, DbError> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM policy_rollouts WHERE cluster_id = $1 AND status = 'pending' LIMIT 1",
    )
    .bind(cluster_id)
    .fetch_optional(pool)
    .await?)
}

/// Count applied and rejected acknowledgements for a rollout.
pub async fn count_rollout_acks(
    pool: &PgPool,
    rollout: &RolloutRecord,
) -> Result<(i32, i32), DbError> {
    let row = sqlx::query(
        "SELECT
           count(*) FILTER (
             WHERE a.status = 'applied' AND a.digest = $4
           )::int AS applied,
           count(*) FILTER (WHERE a.status = 'rejected')::int AS rejected
         FROM policy_acks a JOIN agents ag ON ag.id = a.agent_id
         WHERE a.policy_version = $1
           AND a.updated_at >= to_timestamp($2)
           AND ag.cluster_id = $3",
    )
    .bind(rollout.version)
    .bind(rollout.started_at_epoch)
    .bind(rollout.cluster_id)
    .bind(&rollout.digest)
    .fetch_one(pool)
    .await?;
    Ok((row.get("applied"), row.get("rejected")))
}

/// Finish a pending rollout. Returns false when another worker won the race.
pub async fn finish_rollout(
    pool: &PgPool,
    rollout_id: Uuid,
    status: &str,
    applied: i32,
    rejected: i32,
    reason: &str,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE policy_rollouts
         SET status = $2, applied_agents = $3, rejected_agents = $4,
             reason = $5, finished_at = now()
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(rollout_id)
    .bind(status)
    .bind(applied)
    .bind(rejected)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

const ROLLOUT_SELECT: &str = "SELECT r.id, r.cluster_id, r.policy_id, r.version,
        r.previous_version, r.requested_by, r.min_ratio, r.timeout_secs,
        r.force, r.status, r.expected_agents, r.applied_agents,
        r.rejected_agents, r.reason, r.detail,
        floor(extract(epoch FROM r.started_at))::bigint AS started_at_epoch,
        floor(extract(epoch FROM r.deadline_at))::bigint AS deadline_epoch,
        floor(extract(epoch FROM r.finished_at))::bigint AS finished_at_epoch,
        v.digest AS target_digest, p.name
     FROM policy_rollouts r
     JOIN policies p ON p.id = r.policy_id
     JOIN policy_versions v ON v.policy_id = r.policy_id AND v.version = r.version
     WHERE r.id = $1";

fn rollout_record_from_row(row: sqlx::postgres::PgRow) -> RolloutRecord {
    RolloutRecord {
        id: row.get("id"),
        cluster_id: row.get("cluster_id"),
        policy_id: row.get("policy_id"),
        name: row.get("name"),
        version: row.get("version"),
        previous_version: row.get("previous_version"),
        requested_by: row.get("requested_by"),
        min_ratio: row.get("min_ratio"),
        timeout_secs: row.get("timeout_secs"),
        force: row.get("force"),
        status: row.get("status"),
        expected_agents: row.get("expected_agents"),
        applied_agents: row.get("applied_agents"),
        rejected_agents: row.get("rejected_agents"),
        reason: row.get("reason"),
        detail: row.get("detail"),
        digest: row.get("target_digest"),
        started_at_epoch: row.get("started_at_epoch"),
        deadline_epoch: row.get("deadline_epoch"),
        finished_at_epoch: row.get("finished_at_epoch"),
    }
}

/// Append an audit row.
pub async fn audit(
    pool: &PgPool,
    actor: &str,
    action: &str,
    resource: &str,
    success: bool,
    detail: serde_json::Value,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO audit_log (actor, action, resource, success, detail)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(actor)
    .bind(action)
    .bind(resource)
    .bind(success)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

/// Recent audit rows.
pub async fn list_audit(pool: &PgPool, limit: usize) -> Result<Vec<serde_json::Value>, DbError> {
    let rows = sqlx::query(
        "SELECT actor, action, resource, success, detail,
                extract(epoch FROM created_at)::bigint AS created_at_epoch
         FROM audit_log ORDER BY seq DESC LIMIT $1",
    )
    .bind(limit as i64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "actor": row.get::<String, _>("actor"),
                "action": row.get::<String, _>("action"),
                "resource": row.get::<String, _>("resource"),
                "success": row.get::<bool, _>("success"),
                "detail": row.get::<serde_json::Value, _>("detail"),
                "created_at_epoch": row.get::<i64, _>("created_at_epoch"),
            })
        })
        .collect())
}

/// Recent events for the phase-2 API. ClickHouse replaces this in phase 5.
pub async fn recent_events(
    pool: &PgPool,
    cluster_id: Uuid,
    limit: usize,
) -> Result<Vec<Event>, DbError> {
    let rows = sqlx::query(
        "SELECT payload FROM event_batches
         WHERE cluster_id = $1
         ORDER BY received_at DESC LIMIT $2",
    )
    .bind(cluster_id)
    .bind(limit as i64)
    .fetch_all(pool)
    .await?;
    let mut events = Vec::new();
    for row in rows {
        let payload: serde_json::Value = row.get("payload");
        let batch: Batch = serde_json::from_value(payload)?;
        events.extend(batch.events);
        if events.len() >= limit {
            break;
        }
    }
    events.truncate(limit);
    Ok(events)
}

/// Recent alerts for the API.
pub async fn recent_alerts(
    pool: &PgPool,
    cluster_id: Uuid,
    limit: usize,
) -> Result<Vec<event_model::Alert>, DbError> {
    let rows = sqlx::query(
        "SELECT payload FROM event_batches
         WHERE cluster_id = $1
         ORDER BY received_at DESC LIMIT $2",
    )
    .bind(cluster_id)
    .bind(limit as i64)
    .fetch_all(pool)
    .await?;
    let mut alerts = Vec::new();
    for row in rows {
        let payload: serde_json::Value = row.get("payload");
        let batch: Batch = serde_json::from_value(payload)?;
        alerts.extend(batch.alerts);
        if alerts.len() >= limit {
            break;
        }
    }
    alerts.truncate(limit);
    Ok(alerts)
}

/// One batch waiting for Kafka and ClickHouse projection.
#[derive(Debug, Clone)]
pub struct PendingProjection {
    /// Batch id.
    pub batch_id: String,
    /// Raw batch JSON.
    pub payload: Vec<u8>,
    /// Event count.
    pub event_count: i32,
}

/// Claim batches that have not been projected yet.
pub async fn pending_projections(
    pool: &PgPool,
    limit: usize,
) -> Result<Vec<PendingProjection>, DbError> {
    let rows = sqlx::query(
        "SELECT batch_id, payload, event_count FROM event_batches
         WHERE relayed_at IS NULL
         ORDER BY received_at ASC LIMIT $1",
    )
    .bind(limit as i64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let payload: serde_json::Value = row.get("payload");
            PendingProjection {
                batch_id: row.get("batch_id"),
                payload: serde_json::to_vec(&payload).unwrap_or_default(),
                event_count: row.get("event_count"),
            }
        })
        .collect())
}

/// Mark a batch as projected.
pub async fn mark_relayed(pool: &PgPool, batch_id: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE event_batches SET relayed_at = now() WHERE batch_id = $1")
        .bind(batch_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Count batches waiting for projection.
pub async fn projection_depth(pool: &PgPool) -> Result<i64, DbError> {
    let row = sqlx::query("SELECT count(*) AS count FROM event_batches WHERE relayed_at IS NULL")
        .fetch_one(pool)
        .await?;
    Ok(row.get("count"))
}

/// List agents in a cluster.
pub async fn list_agents(pool: &PgPool, cluster_id: Uuid) -> Result<Vec<AgentRecord>, DbError> {
    let rows = sqlx::query(
        "SELECT id, cluster_id, spiffe_id, node_name, agent_generation,
                extract(epoch FROM last_seen)::bigint AS last_seen_epoch
         FROM agents WHERE cluster_id = $1 ORDER BY node_name",
    )
    .bind(cluster_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| AgentRecord {
            id: row.get("id"),
            cluster_id: row.get("cluster_id"),
            spiffe_id: row.get("spiffe_id"),
            node_name: row.get("node_name"),
            agent_generation: row.get("agent_generation"),
            last_seen_epoch: row.get("last_seen_epoch"),
        })
        .collect())
}
