// SPDX-License-Identifier: Apache-2.0 OR MIT
//! The fallback provider. Used when the agent runs outside Kubernetes, when
//! no supported runtime socket is present, or when the explicit configuration
//! disables CRI enrichment.
//!
//! `NoOpProvider` always returns `ProviderError::Unavailable` with the
//! documented reason. The cache layer above this provider therefore degrades
//! every lookup to `AttributionScope::Unknown` (or to `Host` when the cgroup
//! path proves the process is outside any container). The agent-core pipeline
//! never fabricates pod or container attribution on this path.

use std::fmt;

use crate::{ContainerRecord, PodRecord, ProviderError, RuntimeMetadata, RuntimeProvider, WorkloadRecord};

/// Fallback provider. The reason string is part of the documented surface so
/// health/readiness surfaces can include it in their degraded-mode report.
#[derive(Debug, Clone, Copy)]
pub struct NoOpProvider {
    pub reason: &'static str,
}

impl NoOpProvider {
    pub const fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl Default for NoOpProvider {
    fn default() -> Self {
        Self::new("enrichment disabled")
    }
}

impl RuntimeProvider for NoOpProvider {
    fn lookup_container(
        &self,
        _cgroup_id: u64,
    ) -> crate::BoxFuture<'_, Result<ContainerRecord, ProviderError>> {
        let reason = self.reason;
        Box::pin(async move { Err(ProviderError::Unavailable(reason.to_string())) })
    }

    fn lookup_pod(
        &self,
        _pod_uid: &str,
    ) -> crate::BoxFuture<'_, Result<PodRecord, ProviderError>> {
        let reason = self.reason;
        Box::pin(async move { Err(ProviderError::Unavailable(reason.to_string())) })
    }

    fn lookup_workload(
        &self,
        _cgroup_id: u64,
    ) -> crate::BoxFuture<'_, Result<WorkloadRecord, ProviderError>> {
        let reason = self.reason;
        Box::pin(async move { Err(ProviderError::Unavailable(reason.to_string())) })
    }

    fn runtime_metadata(&self) -> RuntimeMetadata {
        RuntimeMetadata {
            runtime_kind: "none".to_string(),
            socket_path: None,
            is_rootless: false,
            cgroup_v2: false,
            cgroup_v1_hierarchy_id: None,
        }
    }
}

impl fmt::Display for NoOpProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoOpProvider(reason={})", self.reason)
    }
}