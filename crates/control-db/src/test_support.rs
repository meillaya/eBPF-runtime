// SPDX-License-Identifier: Apache-2.0 OR MIT
//! In-memory mock repositories for testing without live PostgreSQL.
//!
//! BLOCKER: this host has no running PostgreSQL instance. These
//! mocks validate repository LOGIC (optimistic concurrency,
//! idempotency, audit atomicity, RLS denial simulation) without
//! requiring a live database. Live integration tests re-open on
//! the declared self-hosted runner.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use uuid::Uuid;

use crate::error::{ControlDbError, Result};
use crate::models::*;
use crate::notify::WakeHint;

/// Shared in-memory state for mock repositories.
#[derive(Debug)]
pub struct MockDb {
    pub clusters: Mutex<HashMap<Uuid, Cluster>>,
    pub nodes: Mutex<HashMap<Uuid, Node>>,
    pub agents: Mutex<HashMap<Uuid, Agent>>,
    pub cursors: Mutex<Vec<EventCursor>>,
    pub policies: Mutex<HashMap<Uuid, Policy>>,
    pub policy_versions: Mutex<Vec<PolicyVersion>>,
    pub rollouts: Mutex<HashMap<Uuid, Rollout>>,
    pub rollout_acks: Mutex<Vec<RolloutAck>>,
    pub role_bindings: Mutex<Vec<OidcRoleBinding>>,
    pub sessions: Mutex<HashMap<String, OidcSession>>,
    pub revocations: Mutex<Vec<OidcRevocation>>,
    pub audit_log: Mutex<Vec<AuditEntry>>,
    pub audit_seq: AtomicI64,
    /// Simulated RLS context: (cluster_id, role, sub).
    pub rls_context: Mutex<Option<RlsContext>>,
}

/// Simulated RLS context for negative testing.
#[derive(Debug, Clone)]
pub struct RlsContext {
    pub cluster_id: Option<Uuid>,
    pub role: String,
    pub sub: String,
}

impl MockDb {
    /// Create a fresh in-memory database.
    pub fn new() -> Self {
        Self {
            clusters: Mutex::new(HashMap::new()),
            nodes: Mutex::new(HashMap::new()),
            agents: Mutex::new(HashMap::new()),
            cursors: Mutex::new(Vec::new()),
            policies: Mutex::new(HashMap::new()),
            policy_versions: Mutex::new(Vec::new()),
            rollouts: Mutex::new(HashMap::new()),
            rollout_acks: Mutex::new(Vec::new()),
            role_bindings: Mutex::new(Vec::new()),
            sessions: Mutex::new(HashMap::new()),
            revocations: Mutex::new(Vec::new()),
            audit_log: Mutex::new(Vec::new()),
            audit_seq: AtomicI64::new(1),
            rls_context: Mutex::new(None),
        }
    }

    /// Set the RLS context for subsequent operations.
    pub fn set_rls_context(&self, ctx: RlsContext) {
        *self.rls_context.lock() = Some(ctx);
    }

    /// Clear the RLS context (superuser/bypass mode).
    pub fn clear_rls_context(&self) {
        *self.rls_context.lock() = None;
    }

    /// Check RLS cluster isolation. Returns RlsDenied if the
    /// context cluster doesn't match.
    fn check_cluster_rls(&self, cluster_id: Uuid) -> Result<()> {
        let ctx = self.rls_context.lock();
        if let Some(ref c) = *ctx {
            if let Some(ctx_cluster) = c.cluster_id {
                if ctx_cluster != cluster_id {
                    return Err(ControlDbError::RlsDenied {
                        reason: format!(
                            "cross-cluster access: context={ctx_cluster}, target={cluster_id}"
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Check RLS role gate. Returns RlsDenied if the role is
    /// insufficient.
    fn check_role_rls(&self, required_roles: &[&str]) -> Result<()> {
        let ctx = self.rls_context.lock();
        if let Some(ref c) = *ctx {
            if !required_roles.contains(&c.role.as_str()) {
                return Err(ControlDbError::RlsDenied {
                    reason: format!("role '{}' not in {:?}", c.role, required_roles),
                });
            }
        }
        Ok(())
    }

    /// Append an audit entry (same-transaction simulation).
    fn append_audit(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        cluster_id: Option<Uuid>,
        detail_json: &str,
        success: bool,
        error_msg: &str,
    ) -> AuditEntry {
        let seq = self.audit_seq.fetch_add(1, Ordering::SeqCst);
        let entry = AuditEntry {
            id: Uuid::new_v4(),
            seq,
            actor: actor.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            cluster_id,
            detail_json: detail_json.to_string(),
            success,
            error_msg: error_msg.to_string(),
            created_at: Utc::now(),
        };
        self.audit_log.lock().push(entry.clone());
        entry
    }
}

impl Default for MockDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock fleet repository backed by MockDb.
pub struct MockFleetRepository {
    pub db: Arc<MockDb>,
}

impl MockFleetRepository {
    /// Create a new mock fleet repository.
    pub fn new(db: Arc<MockDb>) -> Self {
        Self { db }
    }
}

impl crate::fleet::FleetRepository for MockFleetRepository {
    async fn create_cluster(&self, name: &str, trust_domain: &str) -> Result<Cluster> {
        let mut clusters = self.db.clusters.lock();
        // Idempotent on name.
        if let Some(existing) = clusters.values().find(|c| c.name == name) {
            return Ok(existing.clone());
        }
        let cluster = Cluster {
            id: Uuid::new_v4(),
            name: name.to_string(),
            trust_domain: trust_domain.to_string(),
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        clusters.insert(cluster.id, cluster.clone());
        Ok(cluster)
    }

    async fn get_cluster(&self, id: Uuid) -> Result<Cluster> {
        self.db.check_cluster_rls(id)?;
        self.db
            .clusters
            .lock()
            .get(&id)
            .cloned()
            .ok_or_else(|| ControlDbError::NotFound {
                table: "clusters".into(),
                key: id.to_string(),
            })
    }

    async fn update_cluster(
        &self,
        id: Uuid,
        expected_version: i64,
        name: &str,
        trust_domain: &str,
    ) -> Result<Cluster> {
        self.db.check_cluster_rls(id)?;
        let mut clusters = self.db.clusters.lock();
        let cluster = clusters
            .get_mut(&id)
            .ok_or_else(|| ControlDbError::NotFound {
                table: "clusters".into(),
                key: id.to_string(),
            })?;
        if cluster.version != expected_version {
            return Err(ControlDbError::VersionConflict {
                table: "clusters".into(),
                expected: expected_version,
                found: cluster.version,
            });
        }
        cluster.name = name.to_string();
        cluster.trust_domain = trust_domain.to_string();
        cluster.version += 1;
        cluster.updated_at = Utc::now();
        Ok(cluster.clone())
    }

    async fn create_node(
        &self,
        cluster_id: Uuid,
        name: &str,
        hostname: &str,
        kernel_release: &str,
    ) -> Result<Node> {
        self.db.check_cluster_rls(cluster_id)?;
        let mut nodes = self.db.nodes.lock();
        // Idempotent on (cluster_id, name).
        if let Some(existing) = nodes
            .values()
            .find(|n| n.cluster_id == cluster_id && n.name == name)
        {
            return Ok(existing.clone());
        }
        let node = Node {
            id: Uuid::new_v4(),
            cluster_id,
            name: name.to_string(),
            hostname: hostname.to_string(),
            kernel_release: kernel_release.to_string(),
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        nodes.insert(node.id, node.clone());
        Ok(node)
    }

    async fn get_node(&self, id: Uuid) -> Result<Node> {
        self.db
            .nodes
            .lock()
            .get(&id)
            .cloned()
            .ok_or_else(|| ControlDbError::NotFound {
                table: "nodes".into(),
                key: id.to_string(),
            })
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
        self.db.check_cluster_rls(cluster_id)?;
        let mut agents = self.db.agents.lock();
        // Idempotent on spiffe_id.
        if let Some(existing) = agents.values().find(|a| a.spiffe_id == spiffe_id) {
            return Ok(existing.clone());
        }
        let agent = Agent {
            id: Uuid::new_v4(),
            node_id,
            cluster_id,
            spiffe_id: spiffe_id.to_string(),
            agent_generation: agent_generation.to_string(),
            boot_id_hex: boot_id_hex.to_string(),
            protocol_major,
            health_epoch_s: 0,
            events_emitted: 0,
            events_dropped: 0,
            version: 1,
            registered_at: Utc::now(),
            updated_at: Utc::now(),
        };
        agents.insert(agent.id, agent.clone());

        // Same-transaction audit.
        self.db.append_audit(
            actor,
            "agent.register",
            spiffe_id,
            Some(cluster_id),
            &format!("{{\"agent_generation\":\"{agent_generation}\"}}"),
            true,
            "",
        );

        Ok(agent)
    }

    async fn get_agent(&self, id: Uuid) -> Result<Agent> {
        self.db
            .agents
            .lock()
            .get(&id)
            .cloned()
            .ok_or_else(|| ControlDbError::NotFound {
                table: "agents".into(),
                key: id.to_string(),
            })
    }

    async fn update_agent_health(
        &self,
        id: Uuid,
        expected_version: i64,
        health_epoch_s: i64,
        events_emitted: i64,
        events_dropped: i64,
    ) -> Result<Agent> {
        let mut agents = self.db.agents.lock();
        let agent = agents
            .get_mut(&id)
            .ok_or_else(|| ControlDbError::NotFound {
                table: "agents".into(),
                key: id.to_string(),
            })?;
        if agent.version != expected_version {
            return Err(ControlDbError::VersionConflict {
                table: "agents".into(),
                expected: expected_version,
                found: agent.version,
            });
        }
        agent.health_epoch_s = health_epoch_s;
        agent.events_emitted = events_emitted;
        agent.events_dropped = events_dropped;
        agent.version += 1;
        agent.updated_at = Utc::now();
        Ok(agent.clone())
    }

    async fn list_agents_by_cluster(&self, cluster_id: Uuid) -> Result<Vec<Agent>> {
        self.db.check_cluster_rls(cluster_id)?;
        Ok(self
            .db
            .agents
            .lock()
            .values()
            .filter(|a| a.cluster_id == cluster_id)
            .cloned()
            .collect())
    }
}

/// Mock cursor repository.
pub struct MockCursorRepository {
    pub db: Arc<MockDb>,
}

impl MockCursorRepository {
    /// Create a new mock cursor repository.
    pub fn new(db: Arc<MockDb>) -> Self {
        Self { db }
    }
}

impl crate::cursors::CursorRepository for MockCursorRepository {
    async fn advance_cursor(
        &self,
        agent_id: Uuid,
        sequence: i64,
        idempotency_key: &str,
        batch_size: i32,
    ) -> Result<EventCursor> {
        let mut cursors = self.db.cursors.lock();
        // Idempotent: check (agent_id, sequence) and (agent_id, idempotency_key).
        if cursors
            .iter()
            .any(|c| c.agent_id == agent_id && c.sequence == sequence)
        {
            return Err(ControlDbError::IdempotentDuplicate {
                key: format!("{agent_id}:{sequence}"),
            });
        }
        if cursors
            .iter()
            .any(|c| c.agent_id == agent_id && c.idempotency_key == idempotency_key)
        {
            return Err(ControlDbError::IdempotentDuplicate {
                key: format!("{agent_id}:{idempotency_key}"),
            });
        }
        let cursor = EventCursor {
            id: Uuid::new_v4(),
            agent_id,
            sequence,
            idempotency_key: idempotency_key.to_string(),
            batch_size,
            ingested_at: Utc::now(),
        };
        cursors.push(cursor.clone());
        Ok(cursor)
    }

    async fn get_latest_cursor(&self, agent_id: Uuid) -> Result<Option<EventCursor>> {
        Ok(self
            .db
            .cursors
            .lock()
            .iter()
            .filter(|c| c.agent_id == agent_id)
            .max_by_key(|c| c.sequence)
            .cloned())
    }

    async fn has_sequence(&self, agent_id: Uuid, sequence: i64) -> Result<bool> {
        Ok(self
            .db
            .cursors
            .lock()
            .iter()
            .any(|c| c.agent_id == agent_id && c.sequence == sequence))
    }
}

/// Mock policy repository.
pub struct MockPolicyRepository {
    pub db: Arc<MockDb>,
}

impl MockPolicyRepository {
    /// Create a new mock policy repository.
    pub fn new(db: Arc<MockDb>) -> Self {
        Self { db }
    }
}

impl crate::policy::PolicyRepository for MockPolicyRepository {
    async fn create_policy(&self, name: &str, description: &str) -> Result<Policy> {
        self.db.check_role_rls(&["policy-admin", "admin"])?;
        let mut policies = self.db.policies.lock();
        if let Some(existing) = policies.values().find(|p| p.name == name) {
            return Ok(existing.clone());
        }
        let policy = Policy {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: description.to_string(),
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        policies.insert(policy.id, policy.clone());
        Ok(policy)
    }

    async fn get_policy(&self, id: Uuid) -> Result<Policy> {
        self.db
            .policies
            .lock()
            .get(&id)
            .cloned()
            .ok_or_else(|| ControlDbError::NotFound {
                table: "policies".into(),
                key: id.to_string(),
            })
    }

    async fn stage_version(
        &self,
        policy_id: Uuid,
        version: i64,
        content_digest: &str,
        content_hex: &str,
        actor: &str,
    ) -> Result<PolicyVersion> {
        self.db.check_role_rls(&["policy-admin", "admin"])?;
        let mut versions = self.db.policy_versions.lock();
        // Monotonic version check.
        let max = versions
            .iter()
            .filter(|v| v.policy_id == policy_id)
            .map(|v| v.version)
            .max()
            .unwrap_or(0);
        if version <= max {
            return Err(ControlDbError::VersionConflict {
                table: "policy_versions".into(),
                expected: max + 1,
                found: version,
            });
        }
        let pv = PolicyVersion {
            id: Uuid::new_v4(),
            policy_id,
            version,
            content_digest: content_digest.to_string(),
            content_hex: content_hex.to_string(),
            status: "staged".to_string(),
            created_at: Utc::now(),
        };
        versions.push(pv.clone());

        // Same-transaction audit.
        self.db.append_audit(
            actor,
            "policy.stage",
            &format!("policy_version:{version}"),
            None,
            &format!("{{\"policy_id\":\"{policy_id}\",\"version\":{version}}}"),
            true,
            "",
        );

        Ok(pv)
    }

    async fn get_version(&self, id: Uuid) -> Result<PolicyVersion> {
        self.db
            .policy_versions
            .lock()
            .iter()
            .find(|v| v.id == id)
            .cloned()
            .ok_or_else(|| ControlDbError::NotFound {
                table: "policy_versions".into(),
                key: id.to_string(),
            })
    }

    async fn transition_version_status(
        &self,
        version_id: Uuid,
        from_status: &str,
        to_status: &str,
        actor: &str,
    ) -> Result<PolicyVersion> {
        self.db.check_role_rls(&["policy-admin", "admin"])?;
        let mut versions = self.db.policy_versions.lock();
        let pv = versions
            .iter_mut()
            .find(|v| v.id == version_id)
            .ok_or_else(|| ControlDbError::NotFound {
                table: "policy_versions".into(),
                key: version_id.to_string(),
            })?;
        if pv.status != from_status {
            return Err(ControlDbError::InvalidRolloutTransition {
                from: pv.status.clone(),
                action: format!("->{to_status}"),
            });
        }
        pv.status = to_status.to_string();

        // Same-transaction audit.
        self.db.append_audit(
            actor,
            &format!("policy.{to_status}"),
            &format!("policy_version:{version_id}"),
            None,
            &format!("{{\"from\":\"{from_status}\",\"to\":\"{to_status}\"}}"),
            true,
            "",
        );

        Ok(pv.clone())
    }

    async fn create_rollout(
        &self,
        policy_version_id: Uuid,
        threshold_percent: i32,
        actor: &str,
    ) -> Result<Rollout> {
        self.db.check_role_rls(&["policy-admin", "admin"])?;
        let mut rollouts = self.db.rollouts.lock();
        // One rollout per version.
        if rollouts
            .values()
            .any(|r| r.policy_version_id == policy_version_id)
        {
            return Err(ControlDbError::IdempotentDuplicate {
                key: format!("rollout:{policy_version_id}"),
            });
        }
        let rollout = Rollout {
            id: Uuid::new_v4(),
            policy_version_id,
            state: "pending".to_string(),
            threshold_percent,
            committed_count: 0,
            ack_count: 0,
            rejected_count: 0,
            version: 1,
            started_at: Utc::now(),
            completed_at: None,
        };
        rollouts.insert(rollout.id, rollout.clone());

        // Same-transaction audit.
        self.db.append_audit(
            actor,
            "rollout.create",
            &format!("rollout:{}", rollout.id),
            None,
            &format!("{{\"threshold\":{threshold_percent}}}"),
            true,
            "",
        );

        Ok(rollout)
    }

    async fn get_rollout(&self, id: Uuid) -> Result<Rollout> {
        self.db
            .rollouts
            .lock()
            .get(&id)
            .cloned()
            .ok_or_else(|| ControlDbError::NotFound {
                table: "rollouts".into(),
                key: id.to_string(),
            })
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
        let mut acks = self.db.rollout_acks.lock();
        // Idempotent: one ack per agent per rollout.
        if acks
            .iter()
            .any(|a| a.rollout_id == rollout_id && a.agent_id == agent_id)
        {
            return Err(ControlDbError::IdempotentDuplicate {
                key: format!("ack:{rollout_id}:{agent_id}"),
            });
        }
        let ack = RolloutAck {
            id: Uuid::new_v4(),
            rollout_id,
            agent_id,
            policy_version,
            digest_hex: digest_hex.to_string(),
            accepted,
            rejected_reason: rejected_reason.to_string(),
            acked_at: Utc::now(),
        };
        acks.push(ack.clone());

        // Update aggregate counts.
        let mut rollouts = self.db.rollouts.lock();
        if let Some(rollout) = rollouts.get_mut(&rollout_id) {
            rollout.ack_count += 1;
            if accepted {
                rollout.committed_count += 1;
            } else {
                rollout.rejected_count += 1;
            }
        }

        Ok(ack)
    }

    async fn complete_rollout(
        &self,
        rollout_id: Uuid,
        expected_version: i64,
        final_state: &str,
        actor: &str,
    ) -> Result<Rollout> {
        self.db.check_role_rls(&["policy-admin", "admin"])?;
        let mut rollouts = self.db.rollouts.lock();
        let rollout = rollouts
            .get_mut(&rollout_id)
            .ok_or_else(|| ControlDbError::NotFound {
                table: "rollouts".into(),
                key: rollout_id.to_string(),
            })?;
        if rollout.version != expected_version {
            return Err(ControlDbError::VersionConflict {
                table: "rollouts".into(),
                expected: expected_version,
                found: rollout.version,
            });
        }
        rollout.state = final_state.to_string();
        rollout.version += 1;
        rollout.completed_at = Some(Utc::now());

        // Same-transaction audit.
        self.db.append_audit(
            actor,
            "rollout.complete",
            &format!("rollout:{rollout_id}"),
            None,
            &format!("{{\"state\":\"{final_state}\"}}"),
            true,
            "",
        );

        Ok(rollout.clone())
    }

    async fn get_latest_version(&self, policy_id: Uuid) -> Result<Option<PolicyVersion>> {
        Ok(self
            .db
            .policy_versions
            .lock()
            .iter()
            .filter(|v| v.policy_id == policy_id)
            .max_by_key(|v| v.version)
            .cloned())
    }
}

/// Mock audit repository.
pub struct MockAuditRepository {
    pub db: Arc<MockDb>,
}

impl MockAuditRepository {
    /// Create a new mock audit repository.
    pub fn new(db: Arc<MockDb>) -> Self {
        Self { db }
    }
}

impl crate::audit::AuditRepository for MockAuditRepository {
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
        Ok(self.db.append_audit(
            actor,
            action,
            resource,
            cluster_id,
            detail_json,
            success,
            error_msg,
        ))
    }

    async fn append_in_tx(
        _tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        _actor: &str,
        _action: &str,
        _resource: &str,
        _cluster_id: Option<Uuid>,
        _detail_json: &str,
        _success: bool,
        _error_msg: &str,
    ) -> Result<AuditEntry> {
        // Mock doesn't use real transactions.
        Err(ControlDbError::Database(
            "append_in_tx requires live PostgreSQL".into(),
        ))
    }

    async fn query_by_actor(&self, actor: &str, limit: i64) -> Result<Vec<AuditEntry>> {
        Ok(self
            .db
            .audit_log
            .lock()
            .iter()
            .filter(|e| e.actor == actor)
            .rev()
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn query_by_cluster(&self, cluster_id: Uuid, limit: i64) -> Result<Vec<AuditEntry>> {
        Ok(self
            .db
            .audit_log
            .lock()
            .iter()
            .filter(|e| e.cluster_id == Some(cluster_id))
            .rev()
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn latest_seq(&self) -> Result<i64> {
        Ok(self
            .db
            .audit_log
            .lock()
            .iter()
            .map(|e| e.seq)
            .max()
            .unwrap_or(0))
    }

    async fn attempt_update(&self, _id: Uuid, _new_actor: &str) -> Result<()> {
        Err(ControlDbError::AuditImmutable {
            operation: "UPDATE".into(),
        })
    }

    async fn attempt_delete(&self, _id: Uuid) -> Result<()> {
        Err(ControlDbError::AuditImmutable {
            operation: "DELETE".into(),
        })
    }
}

/// Mock notify channel.
pub struct MockNotifyChannel {
    hints: Mutex<Vec<WakeHint>>,
}

impl MockNotifyChannel {
    /// Create a new mock notify channel.
    pub fn new() -> Self {
        Self {
            hints: Mutex::new(Vec::new()),
        }
    }

    /// Push a hint (simulates receiving a NOTIFY).
    pub fn push_hint(&self, hint: WakeHint) {
        self.hints.lock().push(hint);
    }
}

impl Default for MockNotifyChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::notify::NotifyChannel for MockNotifyChannel {
    async fn notify(&self, channel: &str, payload: &str) -> Result<()> {
        self.hints.lock().push(WakeHint {
            channel: channel.to_string(),
            payload: payload.to_string(),
        });
        Ok(())
    }

    async fn wait_for_hint(
        &self,
        _channel: &str,
        _timeout: std::time::Duration,
    ) -> Result<Option<WakeHint>> {
        // Pop the first hint if available.
        Ok(self.hints.lock().pop())
    }
}
