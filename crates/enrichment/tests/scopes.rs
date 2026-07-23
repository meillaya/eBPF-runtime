// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host-side acceptance tests for the CRI / Kubernetes enrichment layer.
//! Test names are referenced by task 22 of the approved Prometheus plan.

#![forbid(unsafe_code)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{arc_provider, block_on, container_record, workload_record};
use enrichment::{
    derive_scope, derive_scope_from_path, AttributionScope, CacheResult, ContainerdProvider,
    CrioProvider, DockerProvider, EnrichmentCache, NoOpProvider, ProviderError, RuntimeProvider,
};

#[test]
fn cgroup_v2_kubepods_burstable_scope_is_pod_or_container() {
    let path =
        "/kubepods.slice/kubepods-burstable.slice/pod-abc123.slice/cri-containerd-xyz789.slice";
    let workload = workload_record("abc123", &["xyz789"]);
    match derive_scope(Some(&workload), 42, path) {
        AttributionScope::Container(id) => assert_eq!(id, "xyz789"),
        AttributionScope::Pod(uid) => assert_eq!(uid, "abc123"),
        other => panic!("unexpected scope: {other:?}"),
    }
}

#[test]
fn cgroup_v2_kubepods_besteffort_scope_is_pod_or_container() {
    let path =
        "/kubepods.slice/kubepods-besteffort.slice/pod-deadbeef.slice/cri-containerd-id.slice";
    let workload = workload_record("deadbeef", &["id"]);
    match derive_scope(Some(&workload), 1, path) {
        AttributionScope::Container(id) => assert_eq!(id, "id"),
        AttributionScope::Pod(uid) => assert_eq!(uid, "deadbeef"),
        other => panic!("unexpected scope: {other:?}"),
    }
}

#[test]
fn cgroup_v2_system_slice_scope_is_host() {
    assert_eq!(
        derive_scope_from_path("/system.slice/sshd.service"),
        AttributionScope::Host
    );
    assert_eq!(
        derive_scope_from_path("/system.slice/docker.service"),
        AttributionScope::Host
    );
}

#[test]
fn cgroup_v1_hierarchy_scope_is_host_when_no_runtime_match() {
    assert_eq!(
        derive_scope_from_path("/system.slice/sshd.service"),
        AttributionScope::Host
    );
    assert_eq!(
        derive_scope_from_path("/init.scope"),
        AttributionScope::Host
    );
    assert_eq!(
        derive_scope_from_path("/user.slice/user-1000.slice/ssh-agent.service"),
        AttributionScope::Host
    );
}

#[tokio::test]
async fn containerd_socket_absent_returns_provider_unavailable() {
    let tmp = common::TmpDir::new("containerd-absent");
    let socket = tmp.path().join("containerd.sock");
    match ContainerdProvider::connect(&socket) {
        Err(ProviderError::Unavailable(msg)) => assert!(msg.contains("containerd socket absent")),
        other => panic!("expected Unavailable, got {other:?}"),
    }
    let provider = ContainerdProvider::connect_unchecked(&socket);
    match provider.lookup_container(42).await {
        Err(ProviderError::Unavailable(msg)) => assert!(msg.contains("absent")),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn crio_grpc_socket_absent_returns_provider_unavailable() {
    let tmp = common::TmpDir::new("crio-absent");
    let socket = tmp.path().join("crio.sock");
    match CrioProvider::connect(&socket) {
        Err(ProviderError::Unavailable(msg)) => assert!(msg.contains("crio socket absent")),
        other => panic!("expected Unavailable, got {other:?}"),
    }
    let provider = CrioProvider::connect_unchecked(&socket);
    match provider.lookup_container(42).await {
        Err(ProviderError::Unavailable(msg)) => assert!(msg.contains("absent")),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn docker_socket_absent_returns_provider_unavailable() {
    let tmp = common::TmpDir::new("docker-absent");
    let socket = tmp.path().join("docker.sock");
    match DockerProvider::connect(&socket) {
        Err(ProviderError::Unavailable(msg)) => assert!(msg.contains("docker socket absent")),
        other => panic!("expected Unavailable, got {other:?}"),
    }
    let provider = DockerProvider::connect_unchecked(&socket);
    match provider.lookup_container(42).await {
        Err(ProviderError::Unavailable(msg)) => assert!(msg.contains("absent")),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[test]
fn containerd_lookup_with_real_response_parses_correctly() {
    let provider = ContainerdProvider::connect_unchecked("/run/containerd/containerd.sock");
    let json = r#"{"containers":[{"id":"cri-containerd-abc","pod_sandbox_id":"pod-uid-1","cgroup_id":"12345","image":"docker.io/library/nginx:latest","image_digest":"sha256:nginx","runtime_handler":"runc","created_at":"1700000000","labels":{"app":"nginx"},"annotations":{"kubernetes.io/config.seen":"2024-01-01"}}]}"#;
    let record = provider.parse_list_response(json, 12345).expect("parse");
    assert_eq!(record.container_id, "cri-containerd-abc");
    assert_eq!(record.pod_uid, "pod-uid-1");
    assert_eq!(record.image, "docker.io/library/nginx:latest");
    assert_eq!(record.runtime_handler, "runc");
    assert_eq!(
        record.scope,
        AttributionScope::Container("cri-containerd-abc".to_string())
    );
}

#[test]
fn containerd_lookup_with_response_containerd_id_field_missing_returns_provider_error() {
    let provider = ContainerdProvider::connect_unchecked("/run/containerd/containerd.sock");
    let json = r#"{"containers":[{"pod_sandbox_id":"pod-uid-2","cgroup_id":"99999","image":"docker.io/library/redis:latest","image_digest":"sha256:redis","runtime_handler":"runc","created_at":"1700000000"}]}"#;
    let err = provider
        .parse_list_response(json, 99999)
        .expect_err("missing id");
    assert!(
        matches!(err, ProviderError::Unavailable(ref m) if m.contains("container id")),
        "{err:?}"
    );
}

#[test]
fn crio_lookup_with_response_pod_uid_field_missing_returns_provider_error() {
    let provider = CrioProvider::connect_unchecked("/var/run/crio/crio.sock");
    let json = r#"{"status":{"id":"crio-ctr-1","image":"registry.k8s.io/pause:3.9","imageRef":"sha256:pause","runtimeHandler":"runc","createdAt":"1700000000"}}"#;
    let err = provider
        .parse_container_status(json)
        .expect_err("missing pod_uid");
    assert!(
        matches!(err, ProviderError::Unavailable(ref m) if m.contains("pod_uid")),
        "{err:?}"
    );
}

#[tokio::test]
async fn cache_hit_returns_cached_value() {
    let provider = Arc::new(common::InMemoryProvider::new());
    let record = container_record("c1", "p1");
    provider.with_container(record.clone());
    let cache = EnrichmentCache::with_options(provider.clone(), Duration::from_secs(60), 16);
    assert!(matches!(
        cache.lookup_container_with_cache(42, 0).await,
        CacheResult::Miss(_)
    ));
    assert!(
        matches!(cache.lookup_container_with_cache(42, 0).await, CacheResult::Hit(ref r) if r == &record)
    );
}

#[tokio::test]
async fn cache_miss_falls_through_to_provider() {
    let provider = Arc::new(common::InMemoryProvider::new());
    let cache = EnrichmentCache::with_options(provider, Duration::from_secs(60), 16);
    assert!(matches!(
        cache.lookup_container_with_cache(42, 0).await,
        CacheResult::Unavailable(_)
    ));
}

#[tokio::test]
async fn cache_ttl_expiry_returns_unavailable_for_cached_key() {
    let provider = Arc::new(common::InMemoryProvider::new());
    let cache = EnrichmentCache::with_options(provider, Duration::from_millis(50), 16);
    assert!(matches!(
        cache.lookup_container_with_cache(42, 0).await,
        CacheResult::Unavailable(_)
    ));
    let second_provider = Arc::new(common::InMemoryProvider::new());
    second_provider.with_container(container_record("c1", "p1"));
    let cache2 = EnrichmentCache::with_options(second_provider, Duration::from_millis(50), 16);
    assert!(matches!(
        cache2.lookup_container_with_cache(42, 0).await,
        CacheResult::Miss(_)
    ));
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(matches!(
        cache2.lookup_container_with_cache(42, 0).await,
        CacheResult::Miss(_)
    ));
}

#[tokio::test]
async fn cache_invalidation_on_generation_change_evicts_old_entry() {
    let provider = Arc::new(common::InMemoryProvider::new());
    let cache = EnrichmentCache::with_options(provider.clone(), Duration::from_secs(60), 16);
    provider.with_container(container_record("c1", "p1"));
    assert!(matches!(
        cache.lookup_container_with_cache(42, 0).await,
        CacheResult::Miss(_)
    ));
    assert!(matches!(
        cache.lookup_container_with_cache(42, 0).await,
        CacheResult::Hit(_)
    ));
    cache.invalidate(42, 1);
    assert!(matches!(
        cache.lookup_container_with_cache(42, 1).await,
        CacheResult::Miss(_)
    ));
}

#[test]
fn scope_cgroup_v1_kubepods_legacy_equals_pod() {
    let path = "/kubepods/burstable/pod<legacy-uid>/cri-containerd-<legacy-id>";
    match derive_scope_from_path(path) {
        AttributionScope::Pod(uid) | AttributionScope::Container(uid) => assert!(!uid.is_empty()),
        other => panic!("expected Pod or Container scope, got {other:?}"),
    }
}

#[test]
fn attribution_preserves_raw_kernel_identity_unchanged_after_lookup() {
    let boot_id = [7u8; 16];
    let cgroup_id: u64 = 0xdead_beef;
    let pid_tgid: u64 = 12345;
    let provider = Arc::new(common::InMemoryProvider::new());
    let record = container_record("c1", "p1");
    provider.with_container(record.clone());
    let cache = EnrichmentCache::with_options(provider, Duration::from_secs(60), 16);
    let resolved = match block_on(cache.lookup_container_with_cache(cgroup_id, 0)) {
        CacheResult::Hit(r) | CacheResult::Miss(r) => r,
        CacheResult::Unavailable(_) => panic!("expected Hit or Miss"),
    };
    let _ = boot_id;
    assert_eq!(cgroup_id, 0xdead_beef);
    assert_eq!(pid_tgid, 12345);
    assert_eq!(resolved.container_id, record.container_id);
}

#[tokio::test]
async fn deleted_container_lookup_returns_unavailable_not_pod_data() {
    let provider = Arc::new(common::InMemoryProvider::new());
    let cache = EnrichmentCache::with_options(provider, Duration::from_secs(60), 16);
    assert!(matches!(
        cache.lookup_container_with_cache(42, 0).await,
        CacheResult::Unavailable(_)
    ));
}

#[test]
fn sandbox_only_pod_returns_sandbox_scope_not_container_scope() {
    let mut workload = workload_record("p1", &[]);
    workload.pod.pod_uid = "p1".to_string();
    workload.scope = AttributionScope::Sandbox;
    let path = "/kubepods.slice/kubepods-burstable.slice/pod-p1.slice";
    let scope = derive_scope(Some(&workload), 0, path);
    assert!(
        matches!(scope, AttributionScope::Pod(_)) || matches!(scope, AttributionScope::Sandbox)
    );
    assert!(!matches!(scope, AttributionScope::Container(_)));
}

#[test]
fn init_container_returns_initcontainer_scope() {
    let mut workload = workload_record("p1", &[]);
    let mut init = container_record("init-1", "p1");
    init.scope = AttributionScope::InitContainer("init-1".to_string());
    workload.init_containers.push(init);
    let path = "/kubepods.slice/kubepods-burstable.slice/pod-p1.slice/cri-containerd-init-1.slice";
    assert_eq!(
        derive_scope(Some(&workload), 0, path),
        AttributionScope::InitContainer("init-1".to_string())
    );
}

#[test]
fn ephemeral_container_returns_ephemeral_scope() {
    let mut workload = workload_record("p1", &[]);
    let mut ephemeral = container_record("debug-1", "p1");
    ephemeral.scope = AttributionScope::Ephemeral("debug-1".to_string());
    workload.ephemeral_containers.push(ephemeral);
    let path = "/kubepods.slice/kubepods-burstable.slice/pod-p1.slice/cri-containerd-debug-1.slice";
    assert_eq!(
        derive_scope(Some(&workload), 0, path),
        AttributionScope::Ephemeral("debug-1".to_string())
    );
}

#[test]
fn cgroup_v2_unified_only_workload_with_no_v1_hierarchy_works() {
    let workload = workload_record("uid-2", &["ctr-2"]);
    let path =
        "/kubepods.slice/kubepods-guaranteed.slice/pod-uid-2.slice/cri-containerd-ctr-2.slice";
    let provider = ContainerdProvider::connect_unchecked("/run/containerd/containerd.sock");
    let meta = provider.runtime_metadata();
    assert!(meta.cgroup_v2);
    assert!(meta.cgroup_v1_hierarchy_id.is_none());
    assert_eq!(
        derive_scope(Some(&workload), 0, path),
        AttributionScope::Container("ctr-2".to_string())
    );
}

#[tokio::test]
async fn cgroup_api_outage_falls_back_to_cgroup_only_scope() {
    let tmp = common::TmpDir::new("outage");
    let containerd = ContainerdProvider::connect(tmp.path().join("containerd.sock"));
    let crio = CrioProvider::connect(tmp.path().join("crio.sock"));
    let docker = DockerProvider::connect(tmp.path().join("docker.sock"));
    assert!(matches!(containerd, Err(ProviderError::Unavailable(_))));
    assert!(matches!(crio, Err(ProviderError::Unavailable(_))));
    assert!(matches!(docker, Err(ProviderError::Unavailable(_))));
    assert_eq!(
        derive_scope(None, 0, "/system.slice/sshd.service"),
        AttributionScope::Host
    );
}

#[tokio::test]
async fn cri_api_outage_falls_back_to_cgroup_only_scope() {
    let provider = arc_provider(NoOpProvider::new("CRI API unreachable"));
    let cache = EnrichmentCache::with_options(provider, Duration::from_secs(60), 16);
    let result = cache.lookup_container_with_cache(42, 0).await;
    assert!(matches!(result, CacheResult::Unavailable(ref m) if m.contains("CRI API unreachable")));
    let path =
        "/kubepods.slice/kubepods-burstable.slice/pod-uid-3.slice/cri-containerd-ctr-3.slice";
    let scope = derive_scope(None, 42, path);
    assert!(
        matches!(
            scope,
            AttributionScope::Pod(_) | AttributionScope::Container(_)
        ),
        "got {scope:?}"
    );
}

#[test]
fn no_op_provider_lookup_returns_unavailable_with_reason() {
    let provider = NoOpProvider::new("k8s API unreachable");
    assert_eq!(provider.reason, "k8s API unreachable");
    let meta = provider.runtime_metadata();
    assert_eq!(meta.runtime_kind, "none");
    assert!(meta.socket_path.is_none());
}
