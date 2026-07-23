// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit `AttributionScope` derivation from cgroup path + provider workload.
//!
//! Scope assignment is intentionally pure: the function does not perform IO,
//! does not look at the wall clock, and does not consult the provider
//! directly. This makes the rule machine-checkable from kernel identity alone,
//! which is the contract the agent-core pipeline relies on when correlating
//! enrichment with a process event.
//!
//! Mapping (cgroup v1 and v2) — see the cgroup-aware acceptance tests in
//! `tests/scopes.rs`:
//!
//! | cgroup path prefix                                     | scope                                  |
//! |--------------------------------------------------------|----------------------------------------|
//! | `/kubepods.slice/...` (cgroup v2 systemd driver)       | `Pod(uid)` or `Container(id)`          |
//! | `/kubepods/burstable/...` (cgroup v1 kubelet driver)   | `Pod(uid)` or `Container(id)`          |
//! | `/kubepods/besteffort/...`                             | `Pod(uid)` or `Container(id)`          |
//! | `/kubepods/guaranteed/...`                             | `Pod(uid)` or `Container(id)`          |
//! | `/system.slice/...`                                    | `Host`                                 |
//! | `/init.scope/...`                                      | `Host`                                 |
//! | `/user.slice/user-N.slice/...`                         | `Host`                                 |
//! | `/machine.slice/system.slice/...` (rootless)           | `Unknown` (rootless, no kubepods hint) |
//! | anything else                                          | `Unknown`                              |
//!
//! When `workload` is `Some(_)` and the cgroup id maps onto the pod's known
//! container set, the scope is upgraded to `Container(id)` (or `InitContainer`
//! / `Ephemeral` when the lookup flags distinguish the role). When the cgroup
//! is in the pod tree but the container is not yet known, the scope stays
//! `Pod(uid)` so the agent surfaces "pod-level event" provenance.

use crate::{AttributionScope, WorkloadRecord};

/// Pure scope derivation.
///
/// `workload` is the optional structured lookup result; when `None`, the
/// function falls back to cgroup path heuristics. `cgroup_id` is the raw
/// kernel cgroup id of the normalized event and is preserved verbatim by
/// the caller (this function never mutates or replaces it).
pub fn derive_scope(
    workload: Option<&WorkloadRecord>,
    cgroup_id: u64,
    cgroup_path: &str,
) -> AttributionScope {
    if let Some(record) = workload {
        return scope_from_workload(record, cgroup_id, cgroup_path);
    }
    derive_scope_from_path(cgroup_path)
}

/// Derive a scope from the cgroup path alone. Used by the agent-core pipeline
/// when the provider lookup returned `ProviderError::Unavailable` — we still
/// answer `Host` (when the path is provably outside any container) or
/// `Unknown` (otherwise) so the operator sees an explicit signal that the
/// event was not pod-attributed.
pub fn derive_scope_from_path(cgroup_path: &str) -> AttributionScope {
    let trimmed = cgroup_path.trim();
    if trimmed.is_empty() {
        return AttributionScope::Unknown;
    }

    // Kubepods on cgroup v2 (systemd driver) — `/kubepods.slice/kubepods-<qos>.slice/pod-<uid>.slice/cri-<id>.slice`.
    if let Some(uid) = extract_pod_uid_v2_kubepods(trimmed) {
        if let Some(container_id) = extract_container_id_v2_kubepods(trimmed) {
            return AttributionScope::Container(container_id);
        }
        return AttributionScope::Pod(uid);
    }

    // Kubepods on cgroup v1 (legacy kubelet cgroup driver).
    if let Some(uid) = extract_pod_uid_v1_kubepods(trimmed) {
        if let Some(container_id) = extract_container_id_v1_kubepods(trimmed) {
            return AttributionScope::Container(container_id);
        }
        return AttributionScope::Pod(uid);
    }

    // Host system services.
    if trimmed.starts_with("/system.slice/")
        || trimmed.starts_with("/system/")
        || trimmed.starts_with("/init.scope/")
        || trimmed.starts_with("/user.slice/")
        || trimmed == "/"
        || trimmed == "/init"
        || trimmed == "/system"
        || trimmed == "/init.scope"
        || trimmed == "/system.slice"
        || trimmed == "/user.slice"
    {
        return AttributionScope::Host;
    }

    // Default: we cannot prove the process is inside a pod or on the host.
    // Rootless / userns / Kata-shim / gVisor paths fall here by design.
    AttributionScope::Unknown
}

fn scope_from_workload(
    record: &WorkloadRecord,
    _cgroup_id: u64,
    cgroup_path: &str,
) -> AttributionScope {
    // Find the container that matches the cgroup path. If we find a match in
    // `init_containers`, the scope is `InitContainer`; ephemeral containers
    // map to `Ephemeral`; regular containers map to `Container`; otherwise we
    // answer `Sandbox` (annotation-only) so the operator still sees the pod
    // provenance without falsely claiming container-level attribution.
    for c in &record.init_containers {
        if cgroup_path_contains(&c.container_id, cgroup_path) {
            return AttributionScope::InitContainer(c.container_id.clone());
        }
    }
    for c in &record.ephemeral_containers {
        if cgroup_path_contains(&c.container_id, cgroup_path) {
            return AttributionScope::Ephemeral(c.container_id.clone());
        }
    }
    for c in &record.containers {
        if cgroup_path_contains(&c.container_id, cgroup_path) {
            return AttributionScope::Container(c.container_id.clone());
        }
    }
    // The cgroup is in the pod tree (the path or the workload itself implies
    // it) but we have no container record yet — return `Pod(uid)` so the
    // operator sees pod-level provenance.
    if !record.pod.pod_uid.is_empty() {
        return AttributionScope::Pod(record.pod.pod_uid.clone());
    }
    AttributionScope::Sandbox
}

fn cgroup_path_contains(container_id: &str, cgroup_path: &str) -> bool {
    if container_id.is_empty() {
        return false;
    }
    cgroup_path.contains(container_id)
}

/// `pod-<uid>.slice` → `uid`.
fn extract_pod_uid_v2_kubepods(path: &str) -> Option<String> {
    let start = path.find("/pod-")?;
    let after = &path[start + "/pod-".len()..];
    let end = after.find(".slice")?;
    Some(after[..end].to_string())
}

/// `cri-<runtime>-<id>.slice` or `cri-containerd-<id>.slice` → `<id>`.
fn extract_container_id_v2_kubepods(path: &str) -> Option<String> {
    let marker = "/cri-";
    let start = path.find(marker)?;
    let after = &path[start + marker.len()..];
    let end = after.find(".slice")?;
    let raw = &after[..end];
    // Strip the runtime prefix when present: `cri-containerd-abc123` -> `abc123`.
    if let Some(idx) = raw.find('-') {
        Some(raw[idx + 1..].to_string())
    } else {
        Some(raw.to_string())
    }
}

/// cgroup v1 kubelet path: `/kubepods/burstable/pod<uid>/<container_id>`.
fn extract_pod_uid_v1_kubepods(path: &str) -> Option<String> {
    let marker = "/pod";
    let start = path.find(marker)?;
    let after = &path[start + marker.len()..];
    // Pod UID is everything up to the next `/`.
    let end = after.find('/').unwrap_or(after.len());
    if end == 0 {
        return None;
    }
    Some(after[..end].to_string())
}

fn extract_container_id_v1_kubepods(path: &str) -> Option<String> {
    // Last path segment in the v1 kubepods tree, e.g.
    // `/kubepods/burstable/pod<uid>/cri-containerd-<id>` -> `cri-containerd-<id>`.
    let marker = "/pod";
    let start = path.find(marker)?;
    let after = &path[start + marker.len()..];
    let segments: Vec<&str> = after.split('/').collect();
    if segments.len() < 2 {
        return None;
    }
    Some(segments[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_returns_unknown() {
        assert_eq!(derive_scope_from_path(""), AttributionScope::Unknown);
        assert_eq!(derive_scope_from_path("   "), AttributionScope::Unknown);
    }

    #[test]
    fn root_path_returns_host() {
        assert_eq!(derive_scope_from_path("/"), AttributionScope::Host);
    }

    #[test]
    fn system_slice_returns_host() {
        assert_eq!(
            derive_scope_from_path("/system.slice/sshd.service"),
            AttributionScope::Host
        );
    }

    #[test]
    fn init_scope_returns_host() {
        assert_eq!(
            derive_scope_from_path("/init.scope"),
            AttributionScope::Host
        );
    }

    #[test]
    fn kubepods_burstable_v2_returns_pod_or_container() {
        let path =
            "/kubepods.slice/kubepods-burstable.slice/pod-abc123.slice/cri-containerd-xyz789.slice";
        match derive_scope_from_path(path) {
            AttributionScope::Container(id) => assert_eq!(id, "xyz789"),
            AttributionScope::Pod(uid) => assert_eq!(uid, "abc123"),
            other => panic!("unexpected scope: {other:?}"),
        }
    }

    #[test]
    fn kubepods_besteffort_v1_returns_pod_or_container() {
        let path = "/kubepods/besteffort/pod<uid-1>/cri-containerd-<id-1>";
        match derive_scope_from_path(path) {
            AttributionScope::Container(id) => assert_eq!(id, "cri-containerd-<id-1>"),
            AttributionScope::Pod(uid) => assert_eq!(uid, "<uid-1>"),
            other => panic!("unexpected scope: {other:?}"),
        }
    }
}
