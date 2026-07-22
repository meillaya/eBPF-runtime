// SPDX-License-Identifier: Apache-2.0 OR MIT
//! PostgreSQL control queries (control truth).
//!
//! PostgreSQL is the authoritative source for cluster state,
//! policies, and rollouts. The control-plane exposes read-only
//! queries for these resources. Mutations go through dedicated
//! admin routes with RBAC enforcement.
//!
//! All queries are cluster-scoped. Cross-cluster access is
//! denied at the repository level (RLS) and at the API level
//! (cluster scope check).

#![forbid(unsafe_code)]

use control_db::fleet::FleetRepository;
use control_db::models::{Cluster, Node, Policy, PolicyVersion, Rollout};
use control_db::policy::PolicyRepository;
use uuid::Uuid;

use crate::error::{ControlPlaneError, Result};

/// Get a cluster by ID.
pub async fn get_cluster(
    fleet: &impl FleetRepository,
    cluster_id: Uuid,
) -> Result<Cluster> {
    fleet
        .get_cluster(cluster_id)
        .await
        .map_err(ControlPlaneError::from)
}

/// Get a node by ID, verifying cluster membership.
pub async fn get_node(
    fleet: &impl FleetRepository,
    node_id: Uuid,
    expected_cluster_id: Uuid,
) -> Result<Node> {
    let node = fleet
        .get_node(node_id)
        .await
        .map_err(ControlPlaneError::from)?;

    if node.cluster_id != expected_cluster_id {
        return Err(ControlPlaneError::CrossClusterDenied {
            context: expected_cluster_id.to_string(),
            target: node.cluster_id.to_string(),
        });
    }

    Ok(node)
}

/// Get a policy by ID.
pub async fn get_policy(
    policy_repo: &impl PolicyRepository,
    policy_id: Uuid,
) -> Result<Policy> {
    policy_repo
        .get_policy(policy_id)
        .await
        .map_err(ControlPlaneError::from)
}

/// Get the latest version of a policy.
pub async fn get_latest_policy_version(
    policy_repo: &impl PolicyRepository,
    policy_id: Uuid,
) -> Result<Option<PolicyVersion>> {
    policy_repo
        .get_latest_version(policy_id)
        .await
        .map_err(ControlPlaneError::from)
}

/// Get a rollout by ID.
pub async fn get_rollout(
    policy_repo: &impl PolicyRepository,
    rollout_id: Uuid,
) -> Result<Rollout> {
    policy_repo
        .get_rollout(rollout_id)
        .await
        .map_err(ControlPlaneError::from)
}

/// Stage a new policy version (mutation — requires Admin role).
/// Emits an audit intent.
pub async fn stage_policy_version(
    policy_repo: &impl PolicyRepository,
    policy_id: Uuid,
    version: i64,
    content_digest: &str,
    content_hex: &str,
    actor: &str,
) -> Result<PolicyVersion> {
    policy_repo
        .stage_version(policy_id, version, content_digest, content_hex, actor)
        .await
        .map_err(ControlPlaneError::from)
}

/// Create a rollout (mutation — requires Admin role).
/// Emits an audit intent.
pub async fn create_rollout(
    policy_repo: &impl PolicyRepository,
    policy_version_id: Uuid,
    threshold_percent: i32,
    actor: &str,
) -> Result<Rollout> {
    policy_repo
        .create_rollout(policy_version_id, threshold_percent, actor)
        .await
        .map_err(ControlPlaneError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use control_db::test_support::{MockDb, MockFleetRepository, MockPolicyRepository};
    use std::sync::Arc;

    async fn setup() -> (Arc<MockDb>, MockFleetRepository, MockPolicyRepository, Uuid) {
        let db = Arc::new(MockDb::new());
        let fleet = MockFleetRepository::new(Arc::clone(&db));
        let policy_repo = MockPolicyRepository::new(Arc::clone(&db));

        let cluster = fleet
            .create_cluster("prod", "kernel-v1.test")
            .await
            .unwrap();

        (db, fleet, policy_repo, cluster.id)
    }

    #[tokio::test]
    async fn get_cluster_works() {
        let (_db, fleet, _pr, cluster_id) = setup().await;
        let cluster = get_cluster(&fleet, cluster_id).await.unwrap();
        assert_eq!(cluster.name, "prod");
        assert_eq!(cluster.trust_domain, "kernel-v1.test");
    }

    #[tokio::test]
    async fn get_cluster_not_found() {
        let (_db, fleet, _pr, _cid) = setup().await;
        let result = get_cluster(&fleet, Uuid::new_v4()).await;
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::NotFound { .. }
        ));
    }

    #[tokio::test]
    async fn get_node_cluster_isolation() {
        let (_db, fleet, _pr, cluster_id) = setup().await;

        let node = fleet
            .create_node(cluster_id, "node-1", "host-1", "6.1.0")
            .await
            .unwrap();

        // Correct cluster.
        let result = get_node(&fleet, node.id, cluster_id).await;
        assert!(result.is_ok());

        // Wrong cluster.
        let other = Uuid::new_v4();
        let result = get_node(&fleet, node.id, other).await;
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::CrossClusterDenied { .. }
        ));
    }

    #[tokio::test]
    async fn policy_lifecycle() {
        let (_db, _fleet, pr, _cid) = setup().await;

        // Create policy.
        let policy = pr.create_policy("test-policy", "A test policy").await.unwrap();
        assert_eq!(policy.name, "test-policy");

        // Get policy.
        let fetched = get_policy(&pr, policy.id).await.unwrap();
        assert_eq!(fetched.id, policy.id);

        // Stage version.
        let pv = stage_policy_version(
            &pr,
            policy.id,
            1,
            "sha256:abc",
            "deadbeef",
            "admin-1",
        )
        .await
        .unwrap();
        assert_eq!(pv.status, "staged");

        // Get latest version.
        let latest = get_latest_policy_version(&pr, policy.id).await.unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().version, 1);

        // Create rollout.
        let rollout = create_rollout(&pr, pv.id, 80, "admin-1").await.unwrap();
        assert_eq!(rollout.state, "pending");
        assert_eq!(rollout.threshold_percent, 80);

        // Get rollout.
        let fetched_rollout = get_rollout(&pr, rollout.id).await.unwrap();
        assert_eq!(fetched_rollout.id, rollout.id);
    }

    #[tokio::test]
    async fn get_policy_not_found() {
        let (_db, _fleet, pr, _cid) = setup().await;
        let result = get_policy(&pr, Uuid::new_v4()).await;
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::NotFound { .. }
        ));
    }
}
