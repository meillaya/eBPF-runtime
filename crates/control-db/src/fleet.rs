// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet repository: clusters, nodes, agents.
//!
//! Uses optimistic concurrency (version column checks), bounded
//! advisory transaction locks on cluster keys, and same-transaction
//! audit writes. Short transactions only.

#![forbid(unsafe_code)]

use uuid::Uuid;

use crate::error::{ControlDbError, Result};
use crate::models::{Agent, Cluster, Node};
use crate::pool::advisory_key_for_cluster;

/// Trait for fleet state operations. Implemented by
/// `SqlxFleetRepository` (live PostgreSQL) and
/// `MockFleetRepository` (test fixture).
#[allow(async_fn_in_trait)]
pub trait FleetRepository: Send + Sync {
    /// Create a cluster. Idempotent on name: returns existing if
    /// name matches.
    async fn create_cluster(&self, name: &str, trust_domain: &str) -> Result<Cluster>;

    /// Get a cluster by ID.
    async fn get_cluster(&self, id: Uuid) -> Result<Cluster>;

    /// Update a cluster with optimistic concurrency check.
    /// Returns VersionConflict if the version doesn't match.
    async fn update_cluster(
        &self,
        id: Uuid,
        expected_version: i64,
        name: &str,
        trust_domain: &str,
    ) -> Result<Cluster>;

    /// Create a node in a cluster. Uses a bounded advisory
    /// transaction lock on the cluster key to serialize node
    /// creation within a cluster (prevents duplicate names under
    /// concurrency).
    async fn create_node(
        &self,
        cluster_id: Uuid,
        name: &str,
        hostname: &str,
        kernel_release: &str,
    ) -> Result<Node>;

    /// Get a node by ID.
    async fn get_node(&self, id: Uuid) -> Result<Node>;

    /// Register an agent with SPIFFE identity. Idempotent on
    /// spiffe_id: returns existing if SPIFFE ID matches.
    /// Writes an audit entry in the same transaction.
    async fn register_agent(
        &self,
        node_id: Uuid,
        cluster_id: Uuid,
        spiffe_id: &str,
        agent_generation: &str,
        boot_id_hex: &str,
        protocol_major: i32,
        actor: &str,
    ) -> Result<Agent>;

    /// Get an agent by ID.
    async fn get_agent(&self, id: Uuid) -> Result<Agent>;

    /// Update agent health with optimistic concurrency.
    async fn update_agent_health(
        &self,
        id: Uuid,
        expected_version: i64,
        health_epoch_s: i64,
        events_emitted: i64,
        events_dropped: i64,
    ) -> Result<Agent>;

    /// List agents in a cluster.
    async fn list_agents_by_cluster(&self, cluster_id: Uuid) -> Result<Vec<Agent>>;
}

/// SQLx-backed fleet repository.
///
/// All operations use short transactions. Advisory locks are
/// bounded to cluster keys (mod MAX_ADVISORY_LOCK_KEY). Audit
/// writes happen in the same transaction as state changes.
pub struct SqlxFleetRepository {
    pool: sqlx::PgPool,
}

impl SqlxFleetRepository {
    /// Create a new repository backed by the given pool.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Acquire a bounded advisory transaction lock for a cluster.
    /// The lock is released at transaction end (COMMIT/ROLLBACK).
    async fn acquire_cluster_lock(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        cluster_id: Uuid,
    ) -> Result<()> {
        let key = advisory_key_for_cluster(cluster_id);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(&mut **tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;
        Ok(())
    }
}

impl FleetRepository for SqlxFleetRepository {
    async fn create_cluster(&self, name: &str, trust_domain: &str) -> Result<Cluster> {
        // Idempotent: try insert, on conflict return existing.
        let row = sqlx::query_as::<_, ClusterRow>(
            r#"
            INSERT INTO clusters (name, trust_domain)
            VALUES ($1, $2)
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id, name, trust_domain, version, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(trust_domain)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn get_cluster(&self, id: Uuid) -> Result<Cluster> {
        let row = sqlx::query_as::<_, ClusterRow>(
            "SELECT id, name, trust_domain, version, created_at, updated_at FROM clusters WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::NotFound {
            table: "clusters".into(),
            key: id.to_string(),
        })?;

        Ok(row.into())
    }

    async fn update_cluster(
        &self,
        id: Uuid,
        expected_version: i64,
        name: &str,
        trust_domain: &str,
    ) -> Result<Cluster> {
        let row = sqlx::query_as::<_, ClusterRow>(
            r#"
            UPDATE clusters
            SET name = $3, trust_domain = $4, version = version + 1, updated_at = now()
            WHERE id = $1 AND version = $2
            RETURNING id, name, trust_domain, version, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(expected_version)
        .bind(name)
        .bind(trust_domain)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::VersionConflict {
            table: "clusters".into(),
            expected: expected_version,
            found: -1,
        })?;

        Ok(row.into())
    }

    async fn create_node(
        &self,
        cluster_id: Uuid,
        name: &str,
        hostname: &str,
        kernel_release: &str,
    ) -> Result<Node> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        // Bounded advisory lock on cluster key (released at tx end).
        Self::acquire_cluster_lock(&mut tx, cluster_id).await?;

        let row = sqlx::query_as::<_, NodeRow>(
            r#"
            INSERT INTO nodes (cluster_id, name, hostname, kernel_release)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (cluster_id, name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id, cluster_id, name, hostname, kernel_release, version, created_at, updated_at
            "#,
        )
        .bind(cluster_id)
        .bind(name)
        .bind(hostname)
        .bind(kernel_release)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn get_node(&self, id: Uuid) -> Result<Node> {
        let row = sqlx::query_as::<_, NodeRow>(
            "SELECT id, cluster_id, name, hostname, kernel_release, version, created_at, updated_at FROM nodes WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::NotFound {
            table: "nodes".into(),
            key: id.to_string(),
        })?;

        Ok(row.into())
    }

    async fn register_agent(
        &self,
        node_id: Uuid,
        cluster_id: Uuid,
        spiffe_id: &str,
        agent_generation: &str,
        boot_id_hex: &str,
        protocol_major: i32,
        actor: &str,
    ) -> Result<Agent> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        // Idempotent insert on spiffe_id.
        let row = sqlx::query_as::<_, AgentRow>(
            r#"
            INSERT INTO agents (node_id, cluster_id, spiffe_id, agent_generation, boot_id_hex, protocol_major)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (spiffe_id) DO UPDATE SET spiffe_id = EXCLUDED.spiffe_id
            RETURNING id, node_id, cluster_id, spiffe_id, agent_generation, boot_id_hex,
                      protocol_major, health_epoch_s, events_emitted, events_dropped,
                      version, registered_at, updated_at
            "#,
        )
        .bind(node_id)
        .bind(cluster_id)
        .bind(spiffe_id)
        .bind(agent_generation)
        .bind(boot_id_hex)
        .bind(protocol_major)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        // Same-transaction audit write.
        let seq: i64 = sqlx::query_scalar("SELECT nextval('audit_log_seq')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO audit_log (seq, actor, action, resource, cluster_id, detail_json, success)
            VALUES ($1, $2, 'agent.register', $3, $4, $5, true)
            "#,
        )
        .bind(seq)
        .bind(actor)
        .bind(spiffe_id)
        .bind(cluster_id)
        .bind(format!("{{\"agent_generation\":\"{agent_generation}\"}}"))
        .execute(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn get_agent(&self, id: Uuid) -> Result<Agent> {
        let row = sqlx::query_as::<_, AgentRow>(
            r#"SELECT id, node_id, cluster_id, spiffe_id, agent_generation, boot_id_hex,
                      protocol_major, health_epoch_s, events_emitted, events_dropped,
                      version, registered_at, updated_at
               FROM agents WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::NotFound {
            table: "agents".into(),
            key: id.to_string(),
        })?;

        Ok(row.into())
    }

    async fn update_agent_health(
        &self,
        id: Uuid,
        expected_version: i64,
        health_epoch_s: i64,
        events_emitted: i64,
        events_dropped: i64,
    ) -> Result<Agent> {
        let row = sqlx::query_as::<_, AgentRow>(
            r#"
            UPDATE agents
            SET health_epoch_s = $3, events_emitted = $4, events_dropped = $5,
                version = version + 1, updated_at = now()
            WHERE id = $1 AND version = $2
            RETURNING id, node_id, cluster_id, spiffe_id, agent_generation, boot_id_hex,
                      protocol_major, health_epoch_s, events_emitted, events_dropped,
                      version, registered_at, updated_at
            "#,
        )
        .bind(id)
        .bind(expected_version)
        .bind(health_epoch_s)
        .bind(events_emitted)
        .bind(events_dropped)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::VersionConflict {
            table: "agents".into(),
            expected: expected_version,
            found: -1,
        })?;

        Ok(row.into())
    }

    async fn list_agents_by_cluster(&self, cluster_id: Uuid) -> Result<Vec<Agent>> {
        let rows = sqlx::query_as::<_, AgentRow>(
            r#"SELECT id, node_id, cluster_id, spiffe_id, agent_generation, boot_id_hex,
                      protocol_major, health_epoch_s, events_emitted, events_dropped,
                      version, registered_at, updated_at
               FROM agents WHERE cluster_id = $1 ORDER BY registered_at"#,
        )
        .bind(cluster_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }
}

// -- SQLx row types (private, converted to domain models) --

#[derive(sqlx::FromRow)]
struct ClusterRow {
    id: Uuid,
    name: String,
    trust_domain: String,
    version: i64,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<ClusterRow> for Cluster {
    fn from(r: ClusterRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            trust_domain: r.trust_domain,
            version: r.version,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct NodeRow {
    id: Uuid,
    cluster_id: Uuid,
    name: String,
    hostname: String,
    kernel_release: String,
    version: i64,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<NodeRow> for Node {
    fn from(r: NodeRow) -> Self {
        Self {
            id: r.id,
            cluster_id: r.cluster_id,
            name: r.name,
            hostname: r.hostname,
            kernel_release: r.kernel_release,
            version: r.version,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct AgentRow {
    id: Uuid,
    node_id: Uuid,
    cluster_id: Uuid,
    spiffe_id: String,
    agent_generation: String,
    boot_id_hex: String,
    protocol_major: i32,
    health_epoch_s: i64,
    events_emitted: i64,
    events_dropped: i64,
    version: i64,
    registered_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<AgentRow> for Agent {
    fn from(r: AgentRow) -> Self {
        Self {
            id: r.id,
            node_id: r.node_id,
            cluster_id: r.cluster_id,
            spiffe_id: r.spiffe_id,
            agent_generation: r.agent_generation,
            boot_id_hex: r.boot_id_hex,
            protocol_major: r.protocol_major,
            health_epoch_s: r.health_epoch_s,
            events_emitted: r.events_emitted,
            events_dropped: r.events_dropped,
            version: r.version,
            registered_at: r.registered_at,
            updated_at: r.updated_at,
        }
    }
}

use chrono::Utc;
