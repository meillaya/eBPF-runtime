// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CRI-O provider.
//!
//! CRI-O exposes the gRPC CRI service over a Unix-socket transport. The
//! provider connects to the named socket and queries `ContainerStatus` /
//! `PodSandboxStatus` to produce a `ContainerRecord` / `PodRecord`.
//!
//! Wire compatibility:
//! - The gRPC schema follows `runtimeapi/v1` from the Kubernetes CRI
//!   containerd-shim and CRI-O source.
//! - When the gRPC socket is absent, the provider returns
//!   `ProviderError::Unavailable("crio socket absent: ...")` so the
//!   enrichment layer falls back to `cgroup-only` attribution.
//!
//! Parse-path:
//! - The provider also accepts a hand-written JSON projection of the CRI
//!   `ContainerStatusResponse` message so the unit tests can exercise the
//!   mapping without a live gRPC socket. This mirrors how the existing
//!   agent-core crate exposes deterministic parsers for kernel ABI
//!   decoding.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::{
    AttributionScope, ContainerRecord, OwnerRef, PodRecord, ProviderError, RuntimeMetadata,
    RuntimeProvider, WorkloadRecord,
};

/// gRPC channel placeholder. When the wire is wired in, this resolves to
/// `tonic::transport::Channel`. In the default build the field is `()` so
/// the struct compiles without forcing every CI lane to compile the heavy
/// `tonic` dependency tree.
#[derive(Debug, Clone, Copy, Default)]
pub struct GrpcChannelPlaceholder;

/// CRI-O provider.
#[derive(Debug, Clone)]
pub struct CrioProvider {
    pub socket: PathBuf,
    pub grpc: GrpcChannelPlaceholder,
    pub namespace: String,
}

impl CrioProvider {
    /// Connect to the CRI-O gRPC socket. Returns `ProviderError::Unavailable`
    /// when the socket does not exist.
    pub fn connect(socket: impl AsRef<Path>) -> Result<Self, ProviderError> {
        let socket = socket.as_ref().to_path_buf();
        if !socket.exists() {
            return Err(ProviderError::Unavailable(format!(
                "crio socket absent: {}",
                socket.display()
            )));
        }
        Ok(Self {
            socket,
            grpc: GrpcChannelPlaceholder,
            namespace: "k8s.io".to_string(),
        })
    }

    /// Connect, ignoring the socket-presence check.
    pub fn connect_unchecked(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: socket.as_ref().to_path_buf(),
            grpc: GrpcChannelPlaceholder,
            namespace: "k8s.io".to_string(),
        }
    }

    /// Parse a `ContainerStatusResponse` JSON projection into a
    /// `ContainerRecord`. Missing required fields produce a typed error.
    pub fn parse_container_status(&self, json: &str) -> Result<ContainerRecord, ProviderError> {
        let envelope: ContainerStatusEnvelope = serde_json::from_str(json)
            .map_err(|err| ProviderError::Unavailable(format!("malformed crio response: {err}")))?;
        let status = envelope.status.ok_or_else(|| {
            ProviderError::Unavailable("crio response missing status field".to_string())
        })?;
        let container_id = status.id.clone().ok_or_else(|| {
            ProviderError::Unavailable("crio response missing container id field".to_string())
        })?;
        let pod_uid = status.pod_sandbox_id.clone().ok_or_else(|| {
            ProviderError::Unavailable(
                "crio response missing pod_uid field (pod_sandbox_id)".to_string(),
            )
        })?;
        Ok(ContainerRecord {
            container_id: container_id.clone(),
            pod_uid,
            image: status.image.clone().unwrap_or_default(),
            image_digest: status.image_ref.unwrap_or_default(),
            runtime_handler: status
                .runtime_handler
                .clone()
                .or_else(|| status.handler.clone())
                .unwrap_or_default(),
            created_at: status
                .created_at
                .as_ref()
                .and_then(|ts| ts.parse::<u64>().ok())
                .and_then(|secs| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs)))
                .unwrap_or(SystemTime::UNIX_EPOCH),
            labels: status.labels.clone().unwrap_or_default(),
            annotations: status.annotations.clone().unwrap_or_default(),
            scope: AttributionScope::Container(container_id),
        })
    }

    /// Parse a `PodSandboxStatusResponse` JSON projection into a `PodRecord`.
    pub fn parse_pod_sandbox_status(&self, json: &str) -> Result<PodRecord, ProviderError> {
        let envelope: PodSandboxStatusEnvelope = serde_json::from_str(json)
            .map_err(|err| ProviderError::Unavailable(format!("malformed crio response: {err}")))?;
        let status = envelope.status.ok_or_else(|| {
            ProviderError::Unavailable("crio response missing status field".to_string())
        })?;
        let pod_uid = status.metadata.clone().and_then(|m| m.uid).ok_or_else(|| {
            ProviderError::Unavailable(
                "crio response missing pod_uid field (metadata.uid)".to_string(),
            )
        })?;
        Ok(PodRecord {
            pod_uid: pod_uid.clone(),
            namespace: status
                .metadata
                .as_ref()
                .and_then(|m| m.namespace.clone())
                .unwrap_or_default(),
            name: status
                .metadata
                .as_ref()
                .and_then(|m| m.name.clone())
                .unwrap_or_default(),
            node: status
                .metadata
                .as_ref()
                .and_then(|m| m.node.clone())
                .unwrap_or_default(),
            phase: status.state.unwrap_or_default(),
            owner_references: status
                .metadata
                .as_ref()
                .map(|m| m.owner_references.clone())
                .unwrap_or_default()
                .into_iter()
                .map(|o| OwnerRef {
                    kind: o.kind.unwrap_or_default(),
                    name: o.name.unwrap_or_default(),
                    controller: o.controller.unwrap_or(false),
                })
                .collect(),
            labels: status
                .metadata
                .as_ref()
                .and_then(|m| m.labels.clone())
                .unwrap_or_default(),
            annotations: status
                .metadata
                .as_ref()
                .and_then(|m| m.annotations.clone())
                .unwrap_or_default(),
            scope: AttributionScope::Pod(pod_uid),
        })
    }
}

impl RuntimeProvider for CrioProvider {
    fn lookup_container(
        &self,
        _cgroup_id: u64,
    ) -> crate::BoxFuture<'_, Result<ContainerRecord, ProviderError>> {
        let socket = self.socket.clone();
        Box::pin(async move {
            if !socket.exists() {
                return Err(ProviderError::Unavailable(format!(
                    "crio socket absent: {}",
                    socket.display()
                )));
            }
            Err(ProviderError::Unavailable(
                "crio wire not wired in this build (parse_container_status drives the unit tests)"
                    .to_string(),
            ))
        })
    }

    fn lookup_pod(&self, _pod_uid: &str) -> crate::BoxFuture<'_, Result<PodRecord, ProviderError>> {
        let socket = self.socket.clone();
        Box::pin(async move {
            if !socket.exists() {
                return Err(ProviderError::Unavailable(format!(
                    "crio socket absent: {}",
                    socket.display()
                )));
            }
            Err(ProviderError::Unavailable(
                "crio wire not wired in this build (parse_pod_sandbox_status drives the unit tests)"
                    .to_string(),
            ))
        })
    }

    fn lookup_workload(
        &self,
        _cgroup_id: u64,
    ) -> crate::BoxFuture<'_, Result<WorkloadRecord, ProviderError>> {
        Box::pin(async move {
            Err(ProviderError::Unavailable(
                "crio wire not wired in this build".to_string(),
            ))
        })
    }

    fn runtime_metadata(&self) -> RuntimeMetadata {
        RuntimeMetadata {
            runtime_kind: "cri-o".to_string(),
            socket_path: Some(self.socket.clone()),
            is_rootless: false,
            cgroup_v2: true,
            cgroup_v1_hierarchy_id: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ContainerStatusEnvelope {
    status: Option<ContainerStatusBody>,
}

#[derive(Debug, Deserialize)]
struct ContainerStatusBody {
    id: Option<String>,
    pod_sandbox_id: Option<String>,
    image: Option<String>,
    image_ref: Option<String>,
    runtime_handler: Option<String>,
    #[serde(alias = "RuntimeHandler")]
    handler: Option<String>,
    created_at: Option<String>,
    labels: Option<BTreeMap<String, String>>,
    annotations: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct PodSandboxStatusEnvelope {
    status: Option<PodSandboxStatusBody>,
}

#[derive(Debug, Deserialize)]
struct PodSandboxStatusBody {
    state: Option<String>,
    metadata: Option<PodSandboxMetadata>,
}

#[derive(Debug, Deserialize, Clone)]
struct PodSandboxMetadata {
    uid: Option<String>,
    name: Option<String>,
    namespace: Option<String>,
    node: Option<String>,
    #[serde(default)]
    owner_references: Vec<PodSandboxOwnerRef>,
    labels: Option<BTreeMap<String, String>>,
    annotations: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct PodSandboxOwnerRef {
    kind: Option<String>,
    name: Option<String>,
    controller: Option<bool>,
}

impl fmt::Display for CrioProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CrioProvider(socket={}, namespace={})",
            self.socket.display(),
            self.namespace
        )
    }
}
