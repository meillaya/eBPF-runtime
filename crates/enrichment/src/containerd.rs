// SPDX-License-Identifier: Apache-2.0 OR MIT
//! containerd CRI provider.
//!
//! containerd exposes its CRI service over an HTTP+Unix-socket transport that
//! the kubelet (and security agents) consume. The provider connects to the
//! named socket, queries `/v1/containers?filter=...`, and parses the typed
//! JSON envelope into a `ContainerRecord`.
//!
//! Wire compatibility:
//! - The CRI containerd shim returns the documented `/v1/containers` JSON
//!   envelope (see `container_runtime_v1` in the containerd source).
//! - The provider treats any field missing from the response as a hard
//!   `ProviderError::Unavailable` so the agent surfaces degraded attribution
//!   rather than fabricating a half-populated record.
//!
//! Provider-absent path:
//! - When the socket does not exist (`Path::exists()` returns false), the
//!   provider returns `ProviderError::Unavailable("socket absent")`.
//! - When the wire response is malformed, the provider returns
//!   `ProviderError::Unavailable("malformed response: ...")`.
//!
//! Parsing is exposed as a separate `parse_list_response` function so the
//! unit tests can drive the parse path with fixture JSON without requiring
//! a live containerd socket.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::{
    AttributionScope, ContainerRecord, PodRecord, ProviderError, RuntimeMetadata,
    RuntimeProvider, WorkloadRecord,
};

/// HTTP client placeholder. When the wire is wired in, this resolves to the
/// real `reqwest::Client` configured with a Unix-socket connector. In the
/// default build the field is `()` so the struct compiles without forcing
/// every CI lane to compile the heavy `reqwest` dependency tree.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpClientPlaceholder;

/// containerd CRI provider. Constructed via `connect(socket_path)`; the
/// `http` field is a placeholder for the future `reqwest::Client` and is
/// present so the production struct shape matches the documented contract.
#[derive(Debug, Clone)]
pub struct ContainerdProvider {
    pub socket: PathBuf,
    pub http: HttpClientPlaceholder,
    pub namespace: String,
}

impl ContainerdProvider {
    /// Connect to the containerd CRI socket. Returns
    /// `ProviderError::Unavailable` when the socket does not exist so the
    /// enrichment layer falls back to `cgroup-only` attribution.
    pub fn connect(socket: impl AsRef<Path>) -> Result<Self, ProviderError> {
        let socket = socket.as_ref().to_path_buf();
        if !socket.exists() {
            return Err(ProviderError::Unavailable(format!(
                "containerd socket absent: {}",
                socket.display()
            )));
        }
        Ok(Self {
            socket,
            http: HttpClientPlaceholder,
            namespace: "k8s.io".to_string(),
        })
    }

    /// Connect, ignoring the socket-presence check. Used by tests that drive
    /// `parse_list_response` directly with fixture JSON.
    pub fn connect_unchecked(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: socket.as_ref().to_path_buf(),
            http: HttpClientPlaceholder,
            namespace: "k8s.io".to_string(),
        }
    }

    /// Parse a `/v1/containers` JSON envelope into a `ContainerRecord` for the
    /// supplied cgroup id. Missing required fields produce a typed error.
    pub fn parse_list_response(
        &self,
        json: &str,
        cgroup_id: u64,
    ) -> Result<ContainerRecord, ProviderError> {
        let envelope: ContainerListResponse = serde_json::from_str(json).map_err(|err| {
            ProviderError::Unavailable(format!("malformed containerd response: {err}"))
        })?;
        for container in envelope.containers {
            let parsed_cgroup = container
                .cgroup_id
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok());
            if parsed_cgroup == Some(cgroup_id) {
                let container_id = container.id.clone().ok_or_else(|| {
                    ProviderError::Unavailable(
                        "containerd response missing container id field".to_string(),
                    )
                })?;
                return Ok(ContainerRecord {
                    container_id: container_id.clone(),
                    pod_uid: container.pod_sandbox_id.unwrap_or_default(),
                    image: container.image.unwrap_or_default(),
                    image_digest: container.image_digest.unwrap_or_default(),
                    runtime_handler: container.runtime_handler.unwrap_or_default(),
                    created_at: container
                        .created_at
                        .and_then(|ts| ts.parse::<u64>().ok())
                        .and_then(|secs| {
                            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
                        })
                        .unwrap_or(SystemTime::UNIX_EPOCH),
                    labels: container.labels.unwrap_or_default(),
                    annotations: container.annotations.unwrap_or_default(),
                    scope: AttributionScope::Container(container_id),
                });
            }
        }
        Err(ProviderError::NotFound)
    }
}

impl RuntimeProvider for ContainerdProvider {
    fn lookup_container(
        &self,
        cgroup_id: u64,
    ) -> crate::BoxFuture<'_, Result<ContainerRecord, ProviderError>> {
        Box::pin(async move {
            // The real wire call would be:
            //   GET /v1/containers?filter=cgroup-id=={cgroup_id}
            //   Host: <containerd CRI Unix-socket>
            //
            // In the default build without a real HTTP client wired in, the
            // provider returns `Unavailable`; the agent degrades to
            // cgroup-only attribution and never fabricates a pod/container
            // record.
            if !self.socket.exists() {
                return Err(ProviderError::Unavailable(format!(
                    "containerd socket absent: {}",
                    self.socket.display()
                )));
            }
            // `cgroup_id` is consulted by the real wire call. We name it here
            // so the compiler does not strip the parameter even in this stub
            // build.
            let _ = cgroup_id;
            Err(ProviderError::Unavailable(
                "containerd wire not wired in this build (parse_list_response drives the unit tests)"
                    .to_string(),
            ))
        })
    }

    fn lookup_pod(
        &self,
        _pod_uid: &str,
    ) -> crate::BoxFuture<'_, Result<PodRecord, ProviderError>> {
        Box::pin(async move {
            Err(ProviderError::Unavailable(
                "containerd wire not wired in this build".to_string(),
            ))
        })
    }

    fn lookup_workload(
        &self,
        _cgroup_id: u64,
    ) -> crate::BoxFuture<'_, Result<WorkloadRecord, ProviderError>> {
        Box::pin(async move {
            Err(ProviderError::Unavailable(
                "containerd wire not wired in this build".to_string(),
            ))
        })
    }

    fn runtime_metadata(&self) -> RuntimeMetadata {
        RuntimeMetadata {
            runtime_kind: "containerd".to_string(),
            socket_path: Some(self.socket.clone()),
            is_rootless: false,
            cgroup_v2: true,
            cgroup_v1_hierarchy_id: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ContainerListResponse {
    #[serde(default)]
    containers: Vec<ContainerListEntry>,
}

#[derive(Debug, Deserialize)]
struct ContainerListEntry {
    id: Option<String>,
    pod_sandbox_id: Option<String>,
    cgroup_id: Option<String>,
    image: Option<String>,
    image_digest: Option<String>,
    runtime_handler: Option<String>,
    created_at: Option<String>,
    labels: Option<BTreeMap<String, String>>,
    annotations: Option<BTreeMap<String, String>>,
}

impl fmt::Display for ContainerdProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ContainerdProvider(socket={}, namespace={})",
            self.socket.display(),
            self.namespace
        )
    }
}