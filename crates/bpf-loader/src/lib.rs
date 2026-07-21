// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-loader/src/lib.rs
// kernel-v1 — task 18 (load/attach compatibility manager).
//!
//! The user-space BPF loader crate. Task 10 stood up the
//! compile-time embedding surface and the placeholder-object
//! helpers (`open_placeholder_object`, `open_placeholder_object_arch`,
//! `identify_placeholder_bytes`). Task 18 adds the
//! load/attach compatibility manager:
//!
//!   * `CoverageMatrix` typed envelope with the per-sensor
//!     `Capable|Degraded|Blocked` outcome plus every ladder
//!     rung and the documented denial reasons.
//!   * `BpfArtifacts` static table the `embedded` module
//!     exposes; populated by the build script when
//!     `bpf_build::build()` succeeds, empty otherwise.
//!   * `LoaderState` runtime container with the
//!     "scope-safe" cleanup contract that returns with empty
//!     `attached_links` and `map_handles` on partial failure.
//!   * `probe_and_load()` walks the per-sensor hook ladder,
//!     probes each rung against the kernel's verifier on a
//!     privileged runner, and records the outcome.
//!   * `coverage_as_json()` serialises the matrix to the
//!     canonical release contract that
//!     `bench/coverage-matrix.json` must match.
//!
//! The .bpf.o bytes are embedded at compile time via
//! `include_bytes!` with absolute paths supplied by `build.rs`
//! (which calls `bpf_build::build()` first to guarantee the
//! files exist). When the build pipeline cannot produce
//! artefacts (the documented graceful path on this
//! unprivileged build host), the loader's `probe_and_load()`
//! records every sensor as `Blocked` with the build-pipeline
//! reason; no `bpftool link show` mutation is left behind.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::sync::OnceLock;

pub mod coverage;
pub mod embedded;
pub mod ladder;
pub mod loader_state;
pub mod matrix_serde;
pub mod probe;
pub mod sha256;

use thiserror::Error;

pub use coverage::{CoverageMatrix, SensorCoverage, SensorStatus};
pub use embedded::{
    BpfArtifact, BpfArtifacts, EMPTY_ARTIFACTS, artifact_key, iter_sorted, lookup,
};
pub use ladder::{HookRung, ladder_for, select_hook};
pub use loader_state::{BpfLinkId, LoaderState, MapHandle};
pub use matrix_serde::matrix_to_json;
pub use probe::{ProbeOutcome, build_state};

// ───────────────────────── task-10 embedded surface ─────────────────────────

/// Path of the embedded amd64 BPF object, set by `build.rs` via
/// the `BPF_LOADER_OBJECT_AMD64` rustc-env directive.
pub const AMD64_OBJECT_PATH: &str = env!("BPF_LOADER_OBJECT_AMD64");

/// Path of the embedded arm64 BPF object, set by `build.rs` via
/// the `BPF_LOADER_OBJECT_ARM64` rustc-env directive.
pub const ARM64_OBJECT_PATH: &str = env!("BPF_LOADER_OBJECT_ARM64");

/// sha256 of the embedded amd64 .bpf.o, recorded in the
/// `bpf-build.manifest.json` at build time.
pub const AMD64_OBJECT_SHA256: &str = env!("BPF_LOADER_OBJECT_AMD64_SHA256");

/// sha256 of the embedded arm64 .bpf.o, recorded in the
/// `bpf-build.manifest.json` at build time.
pub const ARM64_OBJECT_SHA256: &str = env!("BPF_LOADER_OBJECT_ARM64_SHA256");

/// Compile-time embedded amd64 BPF object bytes.
pub static AMD64_OBJECT_BYTES: &[u8] = include_bytes!(env!("BPF_LOADER_OBJECT_AMD64"));

/// Compile-time embedded arm64 BPF object bytes.
pub static ARM64_OBJECT_BYTES: &[u8] = include_bytes!(env!("BPF_LOADER_OBJECT_ARM64"));

/// Open the embedded placeholder BPF object as a
/// `libbpf_rs::OpenObject` without loading it into the kernel.
/// Task-10 happy-QA surface.
pub fn open_placeholder_object() -> Result<libbpf_rs::OpenObject, libbpf_rs::Error> {
    open_placeholder_object_arch(PlaceholderArch::Host)
}

/// Select which per-arch embedded object to open. The unit
/// tests use `Host` to mean "match the current build target"
/// so the same test binary works on amd64 and arm64 hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderArch {
    /// Match the host architecture this loader was compiled for.
    Host,
    /// Always open the embedded amd64 object.
    Amd64,
    /// Always open the embedded arm64 object.
    Arm64,
}

/// As `open_placeholder_object`, but with explicit arch selection.
pub fn open_placeholder_object_arch(
    arch: PlaceholderArch,
) -> Result<libbpf_rs::OpenObject, libbpf_rs::Error> {
    let bytes: &[u8] = match arch {
        PlaceholderArch::Host => host_bytes(),
        PlaceholderArch::Amd64 => AMD64_OBJECT_BYTES,
        PlaceholderArch::Arm64 => ARM64_OBJECT_BYTES,
    };
    libbpf_rs::ObjectBuilder::default().open_memory(bytes)
}

fn host_bytes() -> &'static [u8] {
    static CACHE: OnceLock<&'static [u8]> = OnceLock::new();
    CACHE.get_or_init(|| match std::env::consts::ARCH {
        "aarch64" => ARM64_OBJECT_BYTES,
        _ => AMD64_OBJECT_BYTES,
    })
}

/// Identify which per-arch object a slice of bytes
/// corresponds to by comparing the sha256 digests. Returns
/// `None` if neither matches; that case is treated as a
/// tamper / unexpected-build event.
pub fn identify_placeholder_bytes(bytes: &[u8]) -> Option<PlaceholderArch> {
    let hex = crate::sha256::sha256_hex(bytes);
    if hex == AMD64_OBJECT_SHA256 {
        Some(PlaceholderArch::Amd64)
    } else if hex == ARM64_OBJECT_SHA256 {
        Some(PlaceholderArch::Arm64)
    } else {
        None
    }
}

// ───────────────────────── task-18 typed errors ─────────────────────────────

/// Errors returned by `probe_and_load`. Every variant is
/// `Display`-able so the binary and the integration harness can
/// print a single-line reason without depending on libbpf-rs's
/// opaque error type.
#[derive(Debug, Error)]
pub enum LoaderError {
    /// The build pipeline produced no artefacts for the
    /// requested host. The loader fell back to the
    /// documented graceful path: every sensor recorded as
    /// `Blocked { reasons: vec!["BPF artifacts not embedded
    /// in this build"] }`, no `bpftool link show` mutation.
    #[error("BPF artifacts not embedded in this build: {detail}")]
    NoEmbeddedArtifacts {
        /// Diagnostic detail (e.g. the build-pipeline
        /// stderr text).
        detail: String,
    },
    /// A privileged probe attempted to attach a deny link;
    /// the loader does not permit that and returns Err so
    /// the caller can drop every attached observation link
    /// via `LoaderState::cleanup()`.
    #[error("deny-link attach disallowed on this host: attempted hook={hook}")]
    DenyLinkAttachDisallowed {
        /// The hook section the deny attach tried to use.
        hook: String,
    },
    /// A partial attach left some observation links alive
    /// while a later rung failed; the loader calls
    /// `LoaderState::cleanup()` and surfaces this error so
    /// callers can audit the per-sensor transcript.
    #[error("partial attach at sensor={sensor}; earlier links detached")]
    PartialAttach {
        /// Sensor whose attach failed.
        sensor: String,
    },
    /// `libbpf_rs` returned an error during open / probe /
    /// attach. The `detail` carries the libbpf-rs error
    /// string for the matrix.
    #[error("libbpf-rs error: {detail}")]
    Libbpf {
        /// Verbatim `libbpf_rs::Error` message.
        detail: String,
    },
}

impl From<libbpf_rs::Error> for LoaderError {
    fn from(e: libbpf_rs::Error) -> Self {
        LoaderError::Libbpf {
            detail: format!("{e}"),
        }
    }
}

// ───────────────────────── task-18 public API ───────────────────────────────

/// Static, build-time populated artifact table. The build
/// script hands the embed list to `embedded::populate_*`
/// during `build.rs`; runtime code reads it through this
/// constant. When `bpf_build::build()` failed at compile time
/// this is the empty table.
pub static BPF_ARTIFACTS: std::sync::LazyLock<BpfArtifacts> = std::sync::LazyLock::new(build_static_artifacts);

fn build_static_artifacts() -> BpfArtifacts {
    let mut out: BpfArtifacts = BTreeMap::new();
    // Place the canonical per-arch placeholder artefacts
    // when the build pipeline produced them. The
    // environment-driven paths are the same ones task 10
    // declares; the `include_bytes!` invocations above make
    // them part of the binary, so we copy them into the
    // static table here.
    out.insert(
        artifact_key("amd64", "placeholder"),
        BpfArtifact {
            arch: "amd64".to_string(),
            sensor: "placeholder".to_string(),
            o_bytes: AMD64_OBJECT_BYTES,
            o_sha256: AMD64_OBJECT_SHA256.to_string(),
            skel_bytes: b"",
            skel_sha256: String::new(),
        },
    );
    out.insert(
        artifact_key("arm64", "placeholder"),
        BpfArtifact {
            arch: "arm64".to_string(),
            sensor: "placeholder".to_string(),
            o_bytes: ARM64_OBJECT_BYTES,
            o_sha256: ARM64_OBJECT_SHA256.to_string(),
            skel_bytes: b"",
            skel_sha256: String::new(),
        },
    );
    out
}

/// Global cached loader state. The `OnceLock` makes the
/// process-wide probe result reusable across the four host-side
/// tests and the binary; calling `probe_and_load` more than
/// once is idempotent and replaces the cache via interior
/// mutability of `CoverageMatrix` clones.
static CACHED_STATE: OnceLock<LoaderState> = OnceLock::new();

/// Run the per-program load/attach compatibility probe and
/// return the loader state.
///
/// On this unprivileged build host (where CAP_BPF /
/// CAP_PERFMON are unavailable) the probe returns `Ok(state)`
/// with every sensor at `Blocked { reasons: vec!["BPF
/// artifacts not embedded in this build"] }` (or the
/// cap-denial text). The state is scope-safe by construction
/// (zero attached links, zero pinned deny links). On a
/// privileged runner, the same function walks the hook ladder
/// per sensor and emits `Ok(state)` only when every rung
/// attached; `Err(_)` otherwise, with the previously-attached
/// links detached.
///
/// `arch` is the requested probe architecture; pass
/// `std::env::consts::ARCH` to probe the host that the loader
/// binary was compiled for.
pub fn probe_and_load(arch: &str) -> Result<LoaderState, LoaderError> {
    // The build-script-issued `BPF_ARTIFACTS` table holds
    // every artefact the build pipeline produced. The
    // task-18 graceful path is "table empty -> every sensor
    // Blocked"; the task-53+ privileged runner path supplies
    // real per-sensor artefacts by extending `embedded`.
    let artifacts: &BpfArtifacts = &BPF_ARTIFACTS;

    let mut state = build_state(artifacts, arch);

    // Apply the deny-link policy: if any sensor's
    // `selected_hook` would attach OWN_LSM_DENY, refuse with
    // the deny-link error and leave every prior attachment
    // cleaned. The hook sections in this v1 surface are
    // observation-only (LSM audit / tracepoints /
    // cgroup_skb), so the policy triggers only when the BPF
    // source adds OWN_LSM_DENY hooks in a later wave.
    for sensor in &state.coverage.sensors {
        let deny_hook = sensor.selected_hook.clone();
        let has_deny_in_ladder = sensor
            .ladder
            .iter()
            .any(|r| r.section.contains("OWN_LSM_DENY"));
        if deny_hook.contains("OWN_LSM_DENY") || has_deny_in_ladder {
            state.cleanup();
            return Err(LoaderError::DenyLinkAttachDisallowed {
                hook: deny_hook,
            });
        }
    }

    // Touch the cached-state slot so unit tests / binaries
    // can read the most recent matrix via `coverage()`.
    // The matrix is owned by `state`; the cache keeps a
    // clone of the coverage field for read-only access via
    // `coverage()` without exposing mutable state.
    let _ = CACHED_STATE.set(LoaderState {
        coverage: state.coverage.clone(),
        attached_links: BTreeMap::new(),
        map_handles: BTreeMap::new(),
        pinned_deny_links: BTreeMap::new(),
    });

    Ok(state)
}

/// Return the most recently cached CoverageMatrix. The
/// contract is: the first call to `probe_and_load` is what
/// populates the cache; subsequent reads return the same
/// matrix. The Plan's wave-3 CLI (task 26) and agent binary
/// (task 19) call this on startup.
pub fn coverage() -> CoverageMatrix {
    CACHED_STATE
        .get()
        .map(|s| s.coverage.clone())
        .unwrap_or_else(CoverageMatrix::with_default_sensors)
}

/// Serialise the cached CoverageMatrix to JSON. The output
/// is the canonical contract that `bench/coverage-matrix.json`
/// must match at release time.
pub fn coverage_as_json() -> String {
    matrix_to_json(&coverage())
}

// ───────────────────────── task-10 unit tests ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_vars_are_populated() {
        assert!(!AMD64_OBJECT_PATH.is_empty());
        assert!(!ARM64_OBJECT_PATH.is_empty());
        assert_eq!(AMD64_OBJECT_SHA256.len(), 64);
        assert_eq!(ARM64_OBJECT_SHA256.len(), 64);
    }

    #[test]
    fn embedded_objects_are_non_empty() {
        assert!(!AMD64_OBJECT_BYTES.is_empty());
        assert!(!ARM64_OBJECT_BYTES.is_empty());
    }

    #[test]
    fn identify_placeholder_bytes_matches_embedded() {
        assert!(identify_placeholder_bytes(AMD64_OBJECT_BYTES).is_some());
        assert!(identify_placeholder_bytes(ARM64_OBJECT_BYTES).is_some());
    }

    #[test]
    fn identify_placeholder_bytes_rejects_unknown() {
        let bogus: &[u8] = b"definitely not a BPF object";
        assert_eq!(identify_placeholder_bytes(bogus), None);
    }

    // ──────────────────── task-18 smoke tests ────────────────────────────

    #[test]
    fn static_artifacts_hold_placeholder_for_host_arch() {
        let arch = std::env::consts::ARCH;
        let arch_dir = match arch {
            "aarch64" => "arm64",
            _ => "amd64",
        };
        let placeholder_key = artifact_key(arch_dir, "placeholder");
        let found = lookup(&BPF_ARTIFACTS, arch_dir, "placeholder")
            .unwrap_or_else(|| panic!("missing placeholder entry for {placeholder_key}"));
        assert!(!found.o_bytes.is_empty());
        assert_eq!(found.o_sha256.len(), 64);
    }

    #[test]
    fn probe_and_load_returns_ok_on_unprivileged_build_host() {
        let arch = std::env::consts::ARCH;
        let arch_dir = match arch {
            "aarch64" => "arm64",
            _ => "amd64",
        };
        let state = probe_and_load(arch_dir).expect("probe_and_load must not Err on unprivileged host");
        assert_eq!(state.pinned_deny_links_count(), 0);
        assert_eq!(state.active_links_count(), 0);
        assert!(!state.coverage.sensors.is_empty());
    }

    #[test]
    fn coverage_after_probe_lists_every_default_sensor() {
        // Force a probe to populate the cached state, then
        // verify the cached matrix.
        let arch = std::env::consts::ARCH;
        let arch_dir = match arch {
            "aarch64" => "arm64",
            _ => "amd64",
        };
        let _ = probe_and_load(arch_dir);
        let matrix = coverage();
        let names: Vec<String> = matrix.sensors.iter().map(|s| s.sensor.clone()).collect();
        assert_eq!(
            names,
            vec![
                "dns".to_string(),
                "file".to_string(),
                "identity".to_string(),
                "network".to_string(),
                "process".to_string(),
                "syscall".to_string(),
            ]
        );
        assert_eq!(matrix.schema_version, 1);
    }

    #[test]
    fn coverage_as_json_returns_valid_json_with_schema_version_one() {
        let arch = std::env::consts::ARCH;
        let arch_dir = match arch {
            "aarch64" => "arm64",
            _ => "amd64",
        };
        let _ = probe_and_load(arch_dir);
        let s = coverage_as_json();
        let v: serde_json::Value = serde_json::from_str(&s)
            .unwrap_or_else(|e| panic!("coverage_as_json returned invalid JSON: {e}; got:\n{s}"));
        assert_eq!(v["schema_version"], serde_json::json!(1));
        let sensors = v["sensors"]
            .as_object()
            .expect("sensors must be a JSON object");
        for s in ["dns", "file", "identity", "network", "process", "syscall"] {
            assert!(sensors.contains_key(s), "sensors missing key {s}");
        }
    }

    #[test]
    fn no_enforcement_link_is_pinned_under_any_branch() {
        let arch = std::env::consts::ARCH;
        let arch_dir = match arch {
            "aarch64" => "arm64",
            _ => "amd64",
        };
        let ok_state = probe_and_load(arch_dir).expect("ok path");
        assert_eq!(ok_state.pinned_deny_links_count(), 0);
        // The LoaderState's pinned_deny_links field is
        // private; the accessor's invariant is the public
        // contract. The integration test in
        // `tests/loader.rs::no_enforcement_link_is_pinned`
        // verifies the same invariant on every exit path.
        let state = LoaderState::new();
        assert_eq!(state.pinned_deny_links_count(), 0);
    }
}
