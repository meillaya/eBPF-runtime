// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Partition key derivation for per-agent ordering.
//!
//! The partition key is derived from the cluster and agent
//! identity (SPIFFE path) so that all events from a single
//! agent land on the same partition, guaranteeing per-agent
//! ordering. Different agents may share a partition (hash
//! collision), but events from one agent are NEVER split across
//! partitions.
//!
//! # Determinism
//!
//! The partition assignment is deterministic: the same
//! (cluster, agent) pair ALWAYS maps to the same partition for
//! a given partition count. This enables replay and
//! reconciliation without partition drift.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// Derive a deterministic partition key from cluster and agent
/// identity.
///
/// The key format is `{cluster}/{agent_path}` where agent_path
/// is the SPIFFE path component (e.g., `agent/prod/node-1`).
/// This is used as the Kafka record key, ensuring all records
/// for the same agent hash to the same partition.
pub fn partition_key(cluster: &str, agent_path: &str) -> String {
    format!("{cluster}/{agent_path}")
}

/// Compute the partition for a given key and partition count.
///
/// Uses SHA-256 of the key, takes the first 8 bytes as a u64,
/// and mods by partition count. This gives a uniform
/// distribution across partitions while being deterministic.
pub fn partition_for_key(key: &str, partition_count: u32) -> i32 {
    debug_assert!(partition_count > 0, "partition_count must be > 0");
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let hash = hasher.finalize();
    // Take first 8 bytes as big-endian u64.
    let value = u64::from_be_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ]);
    (value % u64::from(partition_count)) as i32
}

/// Derive the partition for a given cluster/agent identity.
///
/// Convenience function combining `partition_key` and
/// `partition_for_key`.
pub fn partition_for_agent(cluster: &str, agent_path: &str, partition_count: u32) -> i32 {
    let key = partition_key(cluster, agent_path);
    partition_for_key(&key, partition_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_agent_same_partition() {
        let p1 = partition_for_agent("prod", "agent/prod/node-1", 12);
        let p2 = partition_for_agent("prod", "agent/prod/node-1", 12);
        assert_eq!(p1, p2, "same agent must map to same partition");
    }

    #[test]
    fn different_agents_may_differ() {
        // With 12 partitions, different agents should (usually)
        // land on different partitions. Not guaranteed, but
        // statistically likely for these specific inputs.
        let p1 = partition_for_agent("prod", "agent/prod/node-1", 12);
        let p2 = partition_for_agent("prod", "agent/prod/node-2", 12);
        // We don't assert they differ (hash collision is
        // possible), but we verify both are valid.
        assert!((0..12).contains(&p1));
        assert!((0..12).contains(&p2));
    }

    #[test]
    fn partition_in_range() {
        for i in 0..100 {
            let p = partition_for_agent("prod", &format!("agent/prod/node-{i}"), 12);
            assert!(
                (0..12).contains(&p),
                "partition {p} out of range for agent {i}"
            );
        }
    }

    #[test]
    fn deterministic_across_calls() {
        let key = partition_key("staging", "agent/staging/worker-42");
        let p1 = partition_for_key(&key, 6);
        let p2 = partition_for_key(&key, 6);
        assert_eq!(p1, p2);
    }

    #[test]
    fn partition_key_format() {
        let key = partition_key("prod", "agent/prod/node-1");
        assert_eq!(key, "prod/agent/prod/node-1");
    }

    #[test]
    fn single_partition_always_zero() {
        for i in 0..20 {
            let p = partition_for_agent("prod", &format!("agent/prod/node-{i}"), 1);
            assert_eq!(p, 0);
        }
    }

    #[test]
    fn distribution_covers_all_partitions() {
        // With 100 agents and 4 partitions, all partitions
        // should be hit.
        let mut seen = [false; 4];
        for i in 0..100 {
            let p = partition_for_agent("prod", &format!("agent/prod/node-{i}"), 4) as usize;
            seen[p] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "all partitions should be covered with 100 agents"
        );
    }
}
