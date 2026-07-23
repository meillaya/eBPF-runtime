// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Standalone Docker provider.
//!
//! Explicitly **not the production runtime**. Docker was deprecated as a
//! Kubernetes runtime when dockershim was removed from kubelet (see
//! <https://kubernetes.io/docs/tasks/administer-cluster/migrating-from-dockershim/migrating-telemetry-and-security-agents/>);
//! this provider is kept for standalone hosts that do not run Kubernetes.
//!
//! Wire compatibility:
//! - The provider talks to the Docker daemon over its Unix-socket HTTP API
//!   at `/containers/json?filters=...`. The response envelope is the
//!   standard Docker Engine API v1.40+ `ContainerSummary` message.
//! - When the socket is absent, the provider returns
//!   `ProviderError::Unavailable("docker socket absent")`.
//!
//! Like the other providers, the parse path is exposed as a separate
//! function so the unit tests can drive it from fixture JSON.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::{
    AttributionScope, ContainerRecord, PodRecord, ProviderError, RuntimeMetadata, RuntimeProvider,
    WorkloadRecord,
};

/// Standalone Docker provider. Holds only the daemon socket path; the
/// `reqwest::Client` (HTTP over Unix socket) is added when the wire is
/// wired in.
#[derive(Debug, Clone)]
pub struct DockerProvider {
    pub socket: PathBuf,
}

impl DockerProvider {
    pub const DEFAULT_SOCKET: &'static str = "/var/run/docker.sock";

    /// Connect to the Docker daemon socket. Returns
    /// `ProviderError::Unavailable` when the socket does not exist.
    pub fn connect(socket: impl AsRef<Path>) -> Result<Self, ProviderError> {
        let socket = socket.as_ref().to_path_buf();
        if !socket.exists() {
            return Err(ProviderError::Unavailable(format!(
                "docker socket absent: {}",
                socket.display()
            )));
        }
        Ok(Self { socket })
    }

    /// Connect, ignoring the socket-presence check.
    pub fn connect_unchecked(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: socket.as_ref().to_path_buf(),
        }
    }

    /// Parse a `/containers/json` envelope into a `ContainerRecord` whose
    /// `Labels` contain the supplied `cgroup_id` key. Missing required fields
    /// produce a typed error.
    pub fn parse_containers_json(
        &self,
        json: &str,
        cgroup_id: u64,
    ) -> Result<ContainerRecord, ProviderError> {
        let containers: Vec<DockerContainerSummary> =
            serde_json::from_str(json).map_err(|err| {
                ProviderError::Unavailable(format!("malformed docker response: {err}"))
            })?;
        for container in containers {
            if container
                .labels
                .as_ref()
                .and_then(|labels| labels.get("io.kubernetes.cgroup.id"))
                .and_then(|raw| raw.parse::<u64>().ok())
                == Some(cgroup_id)
            {
                let container_id = container.id.clone().ok_or_else(|| {
                    ProviderError::Unavailable(
                        "docker response missing container id field".to_string(),
                    )
                })?;
                return Ok(ContainerRecord {
                    container_id: container_id.clone(),
                    pod_uid: container
                        .labels
                        .as_ref()
                        .and_then(|labels| labels.get("io.kubernetes.pod.uid"))
                        .cloned()
                        .unwrap_or_default(),
                    image: container.image.clone().unwrap_or_default(),
                    image_digest: String::new(),
                    runtime_handler: "docker".to_string(),
                    created_at: container
                        .created
                        .as_ref()
                        .and_then(|ts| ts.parse::<i64>().ok())
                        .and_then(|secs| {
                            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
                        })
                        .unwrap_or(SystemTime::UNIX_EPOCH),
                    labels: container.labels.clone().unwrap_or_default(),
                    annotations: BTreeMap::new(),
                    scope: AttributionScope::Container(container_id),
                });
            }
        }
        Err(ProviderError::NotFound)
    }
}

impl RuntimeProvider for DockerProvider {
    fn lookup_container(
        &self,
        cgroup_id: u64,
    ) -> crate::BoxFuture<'_, Result<ContainerRecord, ProviderError>> {
        let socket = self.socket.clone();
        Box::pin(async move {
            if !socket.exists() {
                return Err(ProviderError::Unavailable(format!(
                    "docker socket absent: {}",
                    socket.display()
                )));
            }
            let _ = cgroup_id;
            Err(ProviderError::Unavailable(
                "docker wire not wired in this build (parse_containers_json drives the unit tests)"
                    .to_string(),
            ))
        })
    }

    fn lookup_pod(&self, _pod_uid: &str) -> crate::BoxFuture<'_, Result<PodRecord, ProviderError>> {
        Box::pin(async move {
            Err(ProviderError::Unavailable(
                "docker is not a kubernetes runtime; pod lookup unsupported".to_string(),
            ))
        })
    }

    fn lookup_workload(
        &self,
        _cgroup_id: u64,
    ) -> crate::BoxFuture<'_, Result<WorkloadRecord, ProviderError>> {
        Box::pin(async move {
            Err(ProviderError::Unavailable(
                "docker is not a kubernetes runtime; workload lookup unsupported".to_string(),
            ))
        })
    }

    fn runtime_metadata(&self) -> RuntimeMetadata {
        RuntimeMetadata {
            runtime_kind: "docker".to_string(),
            socket_path: Some(self.socket.clone()),
            is_rootless: false,
            cgroup_v2: true,
            cgroup_v1_hierarchy_id: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DockerContainerSummary {
    id: Option<String>,
    image: Option<String>,
    created: Option<String>,
    labels: Option<BTreeMap<String, String>>,
}

impl fmt::Display for DockerProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DockerProvider(socket={})", self.socket.display())
    }
}
