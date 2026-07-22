// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CRI / containerd / CRI-O / Docker / Kubernetes enrichment adapters.
//!
//! The kernel emits events keyed by raw identity
//! `(boot_id, cgroup_id, pid/tgid, task_start_ns, namespace inode tuple)`.
//! This crate provides a node-local enrichment layer that maps that raw
//! identity onto an `AttributionScope` and a structured `ContainerRecord` /
//! `PodRecord` / `WorkloadRecord` without ever guessing when the runtime or
//! Kubernetes API is unreachable.
//!
//! Three contract-first rules govern the layer:
//!
//! 1. Raw kernel identity is preserved verbatim. The `EnrichmentCache` only
//!    attaches structured metadata; it never overwrites the cgroup_id, boot_id,
//!    pid/tgid, or event-time container id captured by the agent-core pipeline.
//! 2. Unknown stays unknown. A `ProviderError::Unavailable` from any provider
//!    degrades the scope to `AttributionScope::Unknown` (or `Host` when the
//!    cgroup path itself proves the process is outside a container). The layer
//!    never fabricates a `Pod(...)` or `Container(...)` attribution when the
//!    provider is unreachable.
//! 3. Deletion is explicit. After a container has been deleted by the runtime
//!    the cache key is invalidated; the next lookup returns
//!    `ProviderError::Unavailable` rather than serving the stale record.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

pub mod cache;
pub mod containerd;
pub mod crio;
pub mod docker;
pub mod no_op;
pub mod scopes;

pub use cache::{CacheResult, EnrichmentCache, DEFAULT_TTL_SECONDS};
pub use containerd::ContainerdProvider;
pub use crio::CrioProvider;
pub use docker::DockerProvider;
pub use no_op::NoOpProvider;
pub use scopes::{derive_scope, derive_scope_from_path};

/// Type alias for a `Send` boxed future. The trait uses this so that
/// `dyn RuntimeProvider` is dyn-compatible (`impl Future` in a trait method
/// is not).
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The canonical runtime provider interface.
///
/// Every concrete runtime (containerd, CRI-O, Docker, Kubernetes API) and the
/// deliberate `NoOpProvider` fallback implement this trait. The trait is async
/// because real wire calls (`reqwest`, `tonic`) require a Tokio runtime, but
/// the trait surface itself does not depend on a particular HTTP/gRPC stack —
/// the agent simply awaits the future and degrades to `AttributionScope::Unknown`
/// on `ProviderError::Unavailable`.
///
/// Implementations must NOT fabricate data:
/// - if the runtime says the container was deleted, return `NotFound`;
/// - if the socket is absent or the API times out, return `Unavailable`;
/// - if credentials are wrong, return `AuthDenied`.
/// The cache layer above this trait translates these outcomes into honest
/// scopes and TTL-bounded entries.
pub trait RuntimeProvider: Send + Sync + fmt::Debug {
    /// Look up a single container by its kernel cgroup id.
    ///
    /// The cgroup id is the `cgroup_id` field of the agent-core normalized
    /// event. Implementations must look up by the kernel identity, not by the
    /// event-time container id recorded by the ABI (which can be stale across
    /// restarts).
    fn lookup_container(&self, cgroup_id: u64) -> BoxFuture<'_, Result<ContainerRecord, ProviderError>>;

    /// Look up a Kubernetes pod by its Pod UID.
    ///
    /// The Pod UID is the stable Kubernetes identifier (RFC 4122 UUID). Pod
    /// UID never collides across restart cycles, which is exactly why the
    /// enrichment layer keys attribution on it rather than on pod name +
    /// namespace.
    fn lookup_pod(&self, pod_uid: &str) -> BoxFuture<'_, Result<PodRecord, ProviderError>>;

    /// Look up a workload that joins container + pod + init/ephemeral siblings.
    ///
    /// This is the preferred entry point for the agent-core pipeline when
    /// enriching a process event: it returns the full structured payload in
    /// a single round trip (best case) and degrades gracefully when only
    /// part of the join succeeds.
    fn lookup_workload(&self, cgroup_id: u64) -> BoxFuture<'_, Result<WorkloadRecord, ProviderError>>;

    /// Report the runtime metadata (kind, socket path, rootless flag, cgroup
    /// hierarchy version). Used by health/readiness surfaces and by the
    /// cache layer when deciding whether a stale entry should be evicted.
    fn runtime_metadata(&self) -> RuntimeMetadata;
}

/// Structured container record produced by a successful provider lookup.
///
/// Fields map 1:1 onto the CRI `Container` message and Kubernetes pod spec
/// where the information is preserved in both runtimes. `runtime_handler`
/// records which runtime handler (e.g. `runc`, `crun`, `kata-qemu`) actually
/// launched the container — important for compatibility reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRecord {
    pub container_id: String,
    pub pod_uid: String,
    pub image: String,
    pub image_digest: String,
    pub runtime_handler: String,
    pub created_at: SystemTime,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    pub scope: AttributionScope,
}

/// Structured pod record produced by a successful Kubernetes (or CRI sandbox)
/// lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodRecord {
    pub pod_uid: String,
    pub namespace: String,
    pub name: String,
    pub node: String,
    pub phase: String,
    pub owner_references: Vec<OwnerRef>,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    pub scope: AttributionScope,
}

/// A Kubernetes `OwnerReference` (Deployment, StatefulSet, DaemonSet, Job, …).
/// The enrichment layer surfaces these so policy authors can reason about
/// the workload that produced the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRef {
    pub kind: String,
    pub name: String,
    pub controller: bool,
}

/// Joined container + pod + init/ephemeral siblings. Returned by
/// `RuntimeProvider::lookup_workload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRecord {
    pub pod: PodRecord,
    pub containers: Vec<ContainerRecord>,
    pub init_containers: Vec<ContainerRecord>,
    pub ephemeral_containers: Vec<ContainerRecord>,
    pub scope: AttributionScope,
}

/// Explicit scope assignment. The mapping is exhaustive — the agent can
/// always answer "is this event host, pod, container, sandbox, init, ephemeral,
/// or unknown" without guessing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttributionScope {
    /// The process runs directly on the host kernel (not inside any container).
    Host,
    /// The process runs inside the named pod, but we have no container record
    /// (e.g. the kubelet hasn't reported the sidecar yet).
    Pod(String),
    /// The process runs inside the named container of a pod.
    Container(String),
    /// The process runs inside a pod sandbox but the runtime hasn't started a
    /// container yet (pause container, sandboxed runtime pre-start).
    Sandbox,
    /// The process runs inside an init container.
    InitContainer(String),
    /// The process runs inside an ephemeral container (kubectl debug).
    Ephemeral(String),
    /// The provider cannot answer; the agent surfaces raw kernel identity
    /// only and never fabricates a pod/container attribution.
    Unknown,
}

impl fmt::Display for AttributionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host => f.write_str("host"),
            Self::Pod(uid) => write!(f, "pod:{uid}"),
            Self::Container(id) => write!(f, "container:{id}"),
            Self::Sandbox => f.write_str("sandbox"),
            Self::InitContainer(id) => write!(f, "init_container:{id}"),
            Self::Ephemeral(id) => write!(f, "ephemeral:{id}"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

/// Static runtime metadata. Returned by `RuntimeProvider::runtime_metadata`.
///
/// `cgroup_v2` and `cgroup_v1_hierarchy_id` are not mutually exclusive: a
/// hybrid host exposes both, with the v2 unified hierarchy used for new pods
/// and a v1 hierarchy retained for legacy cgroup-aware tooling. The provider
/// reports whichever hierarchy it actually consulted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMetadata {
    pub runtime_kind: String,
    pub socket_path: Option<PathBuf>,
    pub is_rootless: bool,
    pub cgroup_v2: bool,
    pub cgroup_v1_hierarchy_id: Option<u64>,
}

/// Failure mode reported by every `RuntimeProvider` implementation.
///
/// `Unavailable` is the canonical "I do not know" signal: the runtime socket
/// is missing, the API is down, or DNS for the kube-apiserver failed. The
/// enrichment layer translates this into `AttributionScope::Unknown`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    #[error("container/pod not found in runtime")]
    NotFound,
    #[error("runtime API temporarily unavailable: {0}")]
    Unavailable(String),
    #[error("runtime API retriable error: {0}")]
    Retriable(String),
    #[error("runtime API authentication denied")]
    AuthDenied,
    #[error("runtime API timed out after {0:?}")]
    Timeout(Duration),
}

/// Default TTL used by `EnrichmentCache`. Re-exported for tests.
pub const DEFAULT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribution_scope_display_is_stable_for_provenance() {
        assert_eq!(AttributionScope::Host.to_string(), "host");
        assert_eq!(
            AttributionScope::Pod("uid-abc".to_string()).to_string(),
            "pod:uid-abc"
        );
        assert_eq!(
            AttributionScope::Container("cri-1".to_string()).to_string(),
            "container:cri-1"
        );
        assert_eq!(AttributionScope::Sandbox.to_string(), "sandbox");
        assert_eq!(
            AttributionScope::InitContainer("init-1".to_string()).to_string(),
            "init_container:init-1"
        );
        assert_eq!(
            AttributionScope::Ephemeral("debug-1".to_string()).to_string(),
            "ephemeral:debug-1"
        );
        assert_eq!(AttributionScope::Unknown.to_string(), "unknown");
    }

    #[test]
    fn provider_error_display_includes_context() {
        let err = ProviderError::Unavailable("socket absent".to_string());
        assert_eq!(
            err.to_string(),
            "runtime API temporarily unavailable: socket absent"
        );
    }
}