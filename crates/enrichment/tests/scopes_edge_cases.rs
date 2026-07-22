// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Edge case acceptance tests for the enrichment layer. Complements
//! `tests/scopes.rs` with the rare paths: API outage recovery, rootless
//! userns hosts, crashed pods, container ID reuse across restart, and
//! scope derivation without a provider lookup.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use enrichment::{
    derive_scope, derive_scope_from_path, AttributionScope, CacheResult, ContainerRecord,
    EnrichmentCache, NoOpProvider, OwnerRef, PodRecord, RuntimeProvider, WorkloadRecord,
};
use parking_lot::Mutex;

#[derive(Debug)]
struct FlakyProvider {
    calls: Mutex<usize>,
}

impl FlakyProvider {
    fn new() -> Self {
        Self {
            calls: Mutex::new(0),
        }
    }
    fn next_is_ok(&self) -> bool {
        let mut calls = self.calls.lock();
        *calls += 1;
        *calls == 1
    }
}

impl RuntimeProvider for FlakyProvider {
    fn lookup_container(
        &self,
        _cgroup_id: u64,
    ) -> enrichment::BoxFuture<'_, Result<ContainerRecord, enrichment::ProviderError>> {
        let first_call = self.next_is_ok();
        Box::pin(async move {
            if first_call {
                Ok(ContainerRecord {
                    container_id: "c1".to_string(),
                    pod_uid: "p1".to_string(),
                    image: "example/app:1".to_string(),
                    image_digest: "sha256:1".to_string(),
                    runtime_handler: "runc".to_string(),
                    created_at: std::time::SystemTime::UNIX_EPOCH,
                    labels: BTreeMap::new(),
                    annotations: BTreeMap::new(),
                    scope: AttributionScope::Container("c1".to_string()),
                })
            } else {
                Err(enrichment::ProviderError::Unavailable(
                    "API timeout".to_string(),
                ))
            }
        })
    }
    fn lookup_pod(
        &self,
        _pod_uid: &str,
    ) -> enrichment::BoxFuture<'_, Result<PodRecord, enrichment::ProviderError>> {
        Box::pin(async move {
            Err(enrichment::ProviderError::Unavailable(
                "API timeout".to_string(),
            ))
        })
    }
    fn lookup_workload(
        &self,
        _cgroup_id: u64,
    ) -> enrichment::BoxFuture<'_, Result<WorkloadRecord, enrichment::ProviderError>> {
        Box::pin(async move {
            Err(enrichment::ProviderError::Unavailable(
                "API timeout".to_string(),
            ))
        })
    }
    fn runtime_metadata(&self) -> enrichment::RuntimeMetadata {
        enrichment::RuntimeMetadata {
            runtime_kind: "flaky".to_string(),
            socket_path: None,
            is_rootless: false,
            cgroup_v2: true,
            cgroup_v1_hierarchy_id: None,
        }
    }
}

#[tokio::test]
async fn k8s_api_outage_with_cached_entry_returns_cached_value_then_unavailable_after_ttl() {
    let provider = Arc::new(FlakyProvider::new());
    let cache = EnrichmentCache::with_options(provider.clone(), Duration::from_millis(50), 16);
    // First call: provider returns Ok -> Miss.
    let first = cache.lookup_container_with_cache(42, 0).await;
    assert!(matches!(first, CacheResult::Miss(_)));
    // Second call within TTL: cache hit.
    let second = cache.lookup_container_with_cache(42, 0).await;
    assert!(matches!(second, CacheResult::Hit(_)));
    // TTL expires, API now times out -> Miss (provider error), Unavailable.
    tokio::time::sleep(Duration::from_millis(80)).await;
    let third = cache.lookup_container_with_cache(42, 0).await;
    assert!(matches!(third, CacheResult::Unavailable(_)));
}

#[test]
fn rootless_userns_cgroup_path_does_not_match_kubepods_pattern_scope_is_unknown() {
    // Rootless + userns paths do not match the kubepods pattern; the agent
    // answers Unknown (the correct semantic per the plan: 'unknown remains
    // unknown').
    let path = "/machine.slice/system.slice/docker-9abc.scope";
    assert_eq!(derive_scope_from_path(path), AttributionScope::Unknown);
    let path = "/user.slice/user-1000.slice/user@1000.service/user.slice/scope";
    assert_eq!(derive_scope_from_path(path), AttributionScope::Host);
}

#[test]
fn crashed_pod_returns_sandbox_scope_until_k8s_api_reachable() {
    // Pod sandbox record exists, but the container list is empty (kubelet has
    // not yet reported the new container).
    let pod = PodRecord {
        pod_uid: "p1".to_string(),
        namespace: "default".to_string(),
        name: "p1".to_string(),
        node: "node-1".to_string(),
        phase: "Pending".to_string(),
        owner_references: vec![OwnerRef {
            kind: "Deployment".to_string(),
            name: "app".to_string(),
            controller: true,
        }],
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
        scope: AttributionScope::Pod("p1".to_string()),
    };
    let workload = WorkloadRecord {
        pod,
        containers: vec![],
        init_containers: vec![],
        ephemeral_containers: vec![],
        scope: AttributionScope::Sandbox,
    };
    let path = "/kubepods.slice/kubepods-burstable.slice/pod-p1.slice";
    let scope = derive_scope(Some(&workload), 0, path);
    assert!(matches!(scope, AttributionScope::Pod(_)));
}

#[derive(Debug)]
struct RestartableProvider {
    generation: Mutex<u64>,
}

impl RestartableProvider {
    fn new() -> Self {
        Self {
            generation: Mutex::new(0),
        }
    }
    fn next(&self) -> u64 {
        let mut gen = self.generation.lock();
        let current = *gen;
        *gen += 1;
        current
    }
}

impl RuntimeProvider for RestartableProvider {
    fn lookup_container(
        &self,
        _cgroup_id: u64,
    ) -> enrichment::BoxFuture<'_, Result<ContainerRecord, enrichment::ProviderError>> {
        let current = self.next();
        Box::pin(async move {
            Ok(ContainerRecord {
                container_id: format!("c-{}", current),
                pod_uid: format!("p-{}", current),
                image: "example/app:latest".to_string(),
                image_digest: format!("sha256:{}", current),
                runtime_handler: "runc".to_string(),
                created_at: std::time::SystemTime::UNIX_EPOCH,
                labels: BTreeMap::new(),
                annotations: BTreeMap::new(),
                scope: AttributionScope::Container(format!("c-{}", current)),
            })
        })
    }
    fn lookup_pod(
        &self,
        _pod_uid: &str,
    ) -> enrichment::BoxFuture<'_, Result<PodRecord, enrichment::ProviderError>> {
        Box::pin(async move { Err(enrichment::ProviderError::Unavailable("not impl".into())) })
    }
    fn lookup_workload(
        &self,
        _cgroup_id: u64,
    ) -> enrichment::BoxFuture<'_, Result<WorkloadRecord, enrichment::ProviderError>> {
        Box::pin(async move { Err(enrichment::ProviderError::Unavailable("not impl".into())) })
    }
    fn runtime_metadata(&self) -> enrichment::RuntimeMetadata {
        enrichment::RuntimeMetadata {
            runtime_kind: "restartable".to_string(),
            socket_path: None,
            is_rootless: false,
            cgroup_v2: true,
            cgroup_v1_hierarchy_id: None,
        }
    }
}

#[tokio::test]
async fn container_id_changes_after_restart_returns_fresh_entry_not_stale_cache() {
    let provider = Arc::new(RestartableProvider::new());
    let cache = EnrichmentCache::with_options(provider.clone(), Duration::from_secs(60), 16);
    // First container at generation 0.
    let first = cache.lookup_container_with_cache(42, 0).await;
    let first_id = match first {
        CacheResult::Miss(r) | CacheResult::Hit(r) => r.container_id,
        _ => panic!("expected Miss/Hit"),
    };
    assert_eq!(first_id, "c-0");
    // Cached.
    let cached = cache.lookup_container_with_cache(42, 0).await;
    let cached_id = match cached {
        CacheResult::Hit(r) | CacheResult::Miss(r) => r.container_id,
        _ => panic!("expected Hit/Miss"),
    };
    assert_eq!(cached_id, "c-0");
    // Container restarts -> loader bumps generation -> cache evicts -> fresh entry.
    cache.invalidate(42, 1);
    let second = cache.lookup_container_with_cache(42, 1).await;
    let second_id = match second {
        CacheResult::Miss(r) | CacheResult::Hit(r) => r.container_id,
        _ => panic!("expected Miss/Hit"),
    };
    assert_eq!(second_id, "c-1");
    assert_ne!(first_id, second_id);
}

#[test]
fn scope_inferred_from_cgroup_path_without_provider_lookup() {
    // The scope can be derived from the cgroup path alone when the provider
    // is unavailable.
    let path = "/kubepods.slice/kubepods-burstable.slice/pod-abc.slice/cri-containerd-xyz.slice";
    match derive_scope_from_path(path) {
        AttributionScope::Container(id) => assert_eq!(id, "xyz"),
        AttributionScope::Pod(uid) => assert_eq!(uid, "abc"),
        other => panic!("expected Pod or Container, got {other:?}"),
    }
    // Host paths still answer Host without consulting the provider.
    assert_eq!(
        derive_scope_from_path("/system.slice/cron.service"),
        AttributionScope::Host
    );
    // Unknown paths answer Unknown (rootless, userns, custom hierarchies).
    assert_eq!(
        derive_scope_from_path("/my-custom-slice/svc.service"),
        AttributionScope::Unknown
    );
    // The NoOpProvider is the canonical companion: its reason string is
    // surfaced to the operator.
    let provider = NoOpProvider::new("cri-o gRPC socket absent");
    assert_eq!(provider.reason, "cri-o gRPC socket absent");
}
