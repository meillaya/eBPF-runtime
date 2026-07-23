// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared test helpers for the enrichment crate. Each integration test
//! file imports these via `mod common;` so the per-test pure-LOC stays
//! under the 250-line ceiling.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use enrichment::{
    AttributionScope, ContainerRecord, OwnerRef, PodRecord, ProviderError, RuntimeMetadata,
    RuntimeProvider, WorkloadRecord,
};
use parking_lot::Mutex;

/// RAII temp dir helper.
pub struct TmpDir(pub PathBuf);

impl TmpDir {
    pub fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "enrichment-tests-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).expect("create tmpdir");
        Self(path)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn container_record(container_id: &str, pod_uid: &str) -> ContainerRecord {
    ContainerRecord {
        container_id: container_id.to_string(),
        pod_uid: pod_uid.to_string(),
        image: "ghcr.io/example/app:1.2.3".to_string(),
        image_digest: "sha256:deadbeef".to_string(),
        runtime_handler: "runc".to_string(),
        created_at: SystemTime::UNIX_EPOCH,
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
        scope: AttributionScope::Container(container_id.to_string()),
    }
}

pub fn pod_record(pod_uid: &str) -> PodRecord {
    PodRecord {
        pod_uid: pod_uid.to_string(),
        namespace: "default".to_string(),
        name: format!("pod-{pod_uid}"),
        node: "node-1".to_string(),
        phase: "Running".to_string(),
        owner_references: vec![OwnerRef {
            kind: "Deployment".to_string(),
            name: "app".to_string(),
            controller: true,
        }],
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
        scope: AttributionScope::Pod(pod_uid.to_string()),
    }
}

pub fn workload_record(pod_uid: &str, containers: &[&str]) -> WorkloadRecord {
    WorkloadRecord {
        pod: pod_record(pod_uid),
        containers: containers
            .iter()
            .map(|id| container_record(id, pod_uid))
            .collect(),
        init_containers: vec![],
        ephemeral_containers: vec![],
        scope: AttributionScope::Pod(pod_uid.to_string()),
    }
}

#[derive(Debug)]
pub struct InMemoryProvider {
    pub container: Mutex<Option<ContainerRecord>>,
    pub pod: Mutex<Option<PodRecord>>,
    pub workload: Mutex<Option<WorkloadRecord>>,
}

impl InMemoryProvider {
    pub fn new() -> Self {
        Self {
            container: Mutex::new(None),
            pod: Mutex::new(None),
            workload: Mutex::new(None),
        }
    }
    pub fn with_container(&self, record: ContainerRecord) {
        *self.container.lock() = Some(record);
    }
}

impl RuntimeProvider for InMemoryProvider {
    fn lookup_container(
        &self,
        _cgroup_id: u64,
    ) -> enrichment::BoxFuture<'_, Result<ContainerRecord, ProviderError>> {
        let guard = self.container.lock().clone();
        Box::pin(async move { guard.ok_or(ProviderError::Unavailable("absent".into())) })
    }
    fn lookup_pod(
        &self,
        _pod_uid: &str,
    ) -> enrichment::BoxFuture<'_, Result<PodRecord, ProviderError>> {
        let guard = self.pod.lock().clone();
        Box::pin(async move { guard.ok_or(ProviderError::Unavailable("absent".into())) })
    }
    fn lookup_workload(
        &self,
        _cgroup_id: u64,
    ) -> enrichment::BoxFuture<'_, Result<WorkloadRecord, ProviderError>> {
        let guard = self.workload.lock().clone();
        Box::pin(async move { guard.ok_or(ProviderError::Unavailable("absent".into())) })
    }
    fn runtime_metadata(&self) -> RuntimeMetadata {
        RuntimeMetadata {
            runtime_kind: "in-memory".to_string(),
            socket_path: None,
            is_rootless: false,
            cgroup_v2: true,
            cgroup_v1_hierarchy_id: None,
        }
    }
}

/// Run a future on a fresh current-thread Tokio runtime.
pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(fut)
}

/// Convenience: build an `Arc<dyn RuntimeProvider>` from a concrete provider.
pub fn arc_provider<P: RuntimeProvider + 'static>(provider: P) -> Arc<dyn RuntimeProvider> {
    Arc::new(provider)
}
