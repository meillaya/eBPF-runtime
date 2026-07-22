// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent inventory queries from PostgreSQL (control-db).
//!
//! PostgreSQL is the authoritative source for agent inventory.
//! All queries are scoped to a cluster. The inventory is
//! read-only through the control-plane API (mutations go
//! through the agent registration flow).

#![forbid(unsafe_code)]

use control_db::fleet::FleetRepository;
use control_db::models::Agent;
use uuid::Uuid;

use crate::error::{ControlPlaneError, Result};
use crate::pagination::{encode_cursor, PageRequest, PageResponse};

/// List agents in a cluster with pagination.
///
/// The cluster_id is mandatory (cluster scoping invariant).
/// The page size is clamped to `max_page_size`.
pub async fn list_agents(
    fleet: &impl FleetRepository,
    cluster_id: Uuid,
    page: &PageRequest,
    max_page_size: usize,
) -> Result<PageResponse<Agent>> {
    let limit = page.limit.min(max_page_size).max(1);
    let offset = page.cursor_offset()?.unwrap_or(0) as usize;

    let all_agents = fleet
        .list_agents_by_cluster(cluster_id)
        .await
        .map_err(|e| ControlPlaneError::ControlQuery(e.to_string()))?;

    let total = all_agents.len() as u64;
    let items: Vec<Agent> = all_agents
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();

    let next_offset = offset + items.len();
    let next_cursor = if next_offset < total as usize {
        Some(encode_cursor(next_offset as u64))
    } else {
        None
    };

    Ok(PageResponse::new(items, next_cursor, Some(total)))
}

/// Get a single agent by ID, verifying it belongs to the
/// expected cluster (cluster isolation).
pub async fn get_agent(
    fleet: &impl FleetRepository,
    agent_id: Uuid,
    expected_cluster_id: Uuid,
) -> Result<Agent> {
    let agent = fleet
        .get_agent(agent_id)
        .await
        .map_err(|e| ControlPlaneError::ControlQuery(e.to_string()))?;

    // Cluster isolation: the agent MUST belong to the scoped
    // cluster.
    if agent.cluster_id != expected_cluster_id {
        return Err(ControlPlaneError::CrossClusterDenied {
            context: expected_cluster_id.to_string(),
            target: agent.cluster_id.to_string(),
        });
    }

    Ok(agent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use control_db::test_support::{MockDb, MockFleetRepository};
    use std::sync::Arc;

    async fn setup_fleet() -> (Arc<MockDb>, MockFleetRepository, Uuid) {
        let db = Arc::new(MockDb::new());
        let fleet = MockFleetRepository::new(Arc::clone(&db));

        let cluster = fleet
            .create_cluster("prod", "kernel-v1.test")
            .await
            .unwrap();
        let node = fleet
            .create_node(cluster.id, "node-1", "host-1", "6.1.0")
            .await
            .unwrap();

        // Register 5 agents.
        for i in 0..5 {
            fleet
                .register_agent(
                    node.id,
                    cluster.id,
                    &format!("spiffe://kernel-v1.test/agent/prod/node-1/{i}"),
                    "gen-1",
                    &format!("{i:032x}"),
                    1,
                    "test-actor",
                )
                .await
                .unwrap();
        }

        (db, fleet, cluster.id)
    }

    #[tokio::test]
    async fn list_agents_returns_all() {
        let (_db, fleet, cluster_id) = setup_fleet().await;
        let page = PageRequest::first(10);
        let resp = list_agents(&fleet, cluster_id, &page, 200).await.unwrap();
        assert_eq!(resp.items.len(), 5);
        assert_eq!(resp.total, Some(5));
        assert!(!resp.has_more());
    }

    #[tokio::test]
    async fn list_agents_paginates() {
        let (_db, fleet, cluster_id) = setup_fleet().await;

        // Page 1: limit 2.
        let page1 = PageRequest::first(2);
        let resp1 = list_agents(&fleet, cluster_id, &page1, 200).await.unwrap();
        assert_eq!(resp1.items.len(), 2);
        assert!(resp1.has_more());

        // Page 2: use cursor.
        let page2 = PageRequest::new(2, resp1.next_cursor.clone());
        let resp2 = list_agents(&fleet, cluster_id, &page2, 200).await.unwrap();
        assert_eq!(resp2.items.len(), 2);
        assert!(resp2.has_more());

        // Page 3: last page.
        let page3 = PageRequest::new(2, resp2.next_cursor.clone());
        let resp3 = list_agents(&fleet, cluster_id, &page3, 200).await.unwrap();
        assert_eq!(resp3.items.len(), 1);
        assert!(!resp3.has_more());

        // No duplicate agents across pages.
        let mut all_ids: Vec<Uuid> = Vec::new();
        all_ids.extend(resp1.items.iter().map(|a| a.id));
        all_ids.extend(resp2.items.iter().map(|a| a.id));
        all_ids.extend(resp3.items.iter().map(|a| a.id));
        all_ids.sort();
        all_ids.dedup();
        assert_eq!(all_ids.len(), 5);
    }

    #[tokio::test]
    async fn list_agents_clamps_page_size() {
        let (_db, fleet, cluster_id) = setup_fleet().await;
        let page = PageRequest::first(1000);
        let resp = list_agents(&fleet, cluster_id, &page, 3).await.unwrap();
        assert_eq!(resp.items.len(), 3);
        assert!(resp.has_more());
    }

    #[tokio::test]
    async fn get_agent_cluster_isolation() {
        let (_db, fleet, cluster_id) = setup_fleet().await;

        // Create a second cluster.
        let cluster2 = fleet
            .create_cluster("staging", "kernel-v1.test")
            .await
            .unwrap();

        // Get an agent from cluster 1.
        let agents = fleet.list_agents_by_cluster(cluster_id).await.unwrap();
        let agent = &agents[0];

        // Accessing with correct cluster succeeds.
        let result = get_agent(&fleet, agent.id, cluster_id).await;
        assert!(result.is_ok());

        // Accessing with wrong cluster is denied.
        let result = get_agent(&fleet, agent.id, cluster2.id).await;
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::CrossClusterDenied { .. }
        ));
    }

    #[tokio::test]
    async fn list_agents_empty_cluster() {
        let db = Arc::new(MockDb::new());
        let fleet = MockFleetRepository::new(Arc::clone(&db));
        let cluster = fleet
            .create_cluster("empty", "kernel-v1.test")
            .await
            .unwrap();

        let page = PageRequest::first(10);
        let resp = list_agents(&fleet, cluster.id, &page, 200).await.unwrap();
        assert!(resp.items.is_empty());
        assert_eq!(resp.total, Some(0));
        assert!(!resp.has_more());
    }
}
