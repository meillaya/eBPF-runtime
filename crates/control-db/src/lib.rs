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
