// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-loader/src/embedded.rs
// kernel-v1 — task 18 (load/attach compatibility manager).
//!
//! Compile-time static table of BPF artifacts available to the
//! loader. The build script (`build.rs`) calls
//! `bpf_build::build()` to populate `BPF_ARTIFACTS` for every
//! `(arch, sensor)` pair that the build pipeline produced. When
//! `bpf_build::build()` returns Err — for example on a build host
//! whose clang has no BPF target support, or whose `/sys/kernel/
//! btf/vmlinux` does not match `EXPECTED_SHA256` — the table is
//! intentionally left empty. The loader's `probe_and_load()`
//! observes the empty table and records every sensor as
//! `Blocked { reasons: vec!["BPF artifacts not embedded in this
//! build"] }`. That is the documented "I cannot load BPF here"
//! graceful path.
//!
//! The empty-table state is an explicit, machine-readable
//! degraded/blocked report, not a silent skip. The
//! `crates/bpf-loader/tests/loader.rs` integration suite checks
//! this contract via `coverage_matrix_with_no_embedded_artifacts_
//! records_blocked_for_every_sensor`.
//!
//! The `BpfArtifacts` type intentionally owns its bytes via
//! `&'static [u8]` so the loader never allocates during a
//! probe. The build pipeline's `cargo:rustc-env` directives wire
//! the absolute paths; the loader's `lib.rs` consumes them via
//! `include_bytes!` at compile time.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// A single BPF artifact plus the audit metadata the loader
/// surfaces for diagnostic / preflight use.
#[derive(Debug, Clone)]
pub struct BpfArtifact {
    /// Architecture name as recorded by `bpf_build::build`
    /// (`"amd64"` or `"arm64"`).
    pub arch: String,
    /// Sensor identifier. Maps 1:1 to the names used by the
    /// `bpf/sensors/*.bpf.c` files: `process`, `file`, `network`,
    /// `dns`, `syscall`, `identity`, plus the `placeholder`
    /// stub the build pipeline always compiles for the
    /// happy-QA path.
    pub sensor: String,
    /// Compiled BPF object bytes (.bpf.o). When the artifact is
    /// populated by a successful `bpf_build::build()` invocation
    /// the slice contains the full ELF. Empty slices are reserved
    /// for the "build pipeline failed at compile time" graceful
    /// path; the loader treats them as `Blocked`.
    pub o_bytes: &'static [u8],
    /// SHA-256 of the `.bpf.o` bytes. Lower-case hex; 64 chars.
    pub o_sha256: String,
    /// Generated Rust skeleton bytes (empty until task 10's
    /// `SkeletonBuilder` emits one per sensor; the v1 sensor set
    /// produces one). Skeletons are not used at runtime by the
    /// loader — the loader opens the ELF directly via libbpf-rs —
    /// but the digest is recorded so future tasks that switch to
    /// a skeleton-only path can verify byte-for-byte stability.
    pub skel_bytes: &'static [u8],
    /// SHA-256 of the skeleton bytes. Empty string when
    /// `skel_bytes` is empty.
    pub skel_sha256: String,
}

/// Static, build-time populated artifact table. Keyed by
/// `"{arch}/{sensor}"`, e.g. `"amd64/process"`. Lookups never
/// miss because `BTreeMap::get` returns `Option<&BpfArtifact>`;
/// the loader treats `None` and `BpfArtifact { o_bytes: empty,
/// .. }` identically.
pub type BpfArtifacts = BTreeMap<String, BpfArtifact>;

/// The empty artifacts table. Constructed once at startup when
/// the build pipeline cannot populate the static table. The
/// loader's `probe_and_load()` uses this value as the lower
/// bound on every per-sensor probe: every sensor reports
/// `Blocked { reasons: vec!["BPF artifacts not embedded in this
/// build"] }`.
pub const EMPTY_ARTIFACTS: BpfArtifacts = BpfArtifacts::new();

/// Helper: construct the canonical key from an arch and a sensor
/// name. The form is `"{arch}/{sensor}"` (single forward slash);
/// the loader's runtime probes always use this exact shape.
pub fn artifact_key(arch: &str, sensor: &str) -> String {
    let mut out = String::with_capacity(arch.len() + sensor.len() + 1);
    out.push_str(arch);
    out.push('/');
    out.push_str(sensor);
    out
}

/// Lookup helper: fetch an artifact by its canonical
/// `"{arch}/{sensor}"` key. Returns `None` when the build pipeline
/// produced no entries (the documented graceful path). Callers
/// must treat `None` and `Some(empty)` symmetrically.
pub fn lookup<'a>(artifacts: &'a BpfArtifacts, arch: &str, sensor: &str) -> Option<&'a BpfArtifact> {
    artifacts.get(&artifact_key(arch, sensor))
}

/// Iterate every `{arch,sensor}` pair in deterministic order
/// regardless of `BTreeMap`'s internal ordering. Used by the
/// loader to produce a stable CoverageMatrix ordering.
pub fn iter_sorted(artifacts: &BpfArtifacts) -> impl Iterator<Item = (&str, &str, &BpfArtifact)> {
    let mut entries: Vec<(&String, &BpfArtifact)> = artifacts.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries
        .into_iter()
        .map(|(k, v)| {
            // `k` is `"{arch}/{sensor}"`; split on the single
            // '/' that the `artifact_key` helper inserts.
            let (arch, sensor) = k.split_once('/').unwrap_or(("?", "?"));
            (arch, sensor, v)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_key_is_arch_slash_sensor() {
        assert_eq!(artifact_key("amd64", "process"), "amd64/process");
        assert_eq!(artifact_key("arm64", "identity"), "arm64/identity");
        assert_eq!(artifact_key("", ""), "/");
    }

    #[test]
    fn empty_artifacts_lookup_returns_none() {
        let artifacts: BpfArtifacts = BpfArtifacts::new();
        assert!(lookup(&artifacts, "amd64", "process").is_none());
        assert!(iter_sorted(&artifacts).next().is_none());
    }

    #[test]
    fn populated_artifacts_lookup_finds_key() {
        let mut artifacts: BpfArtifacts = BpfArtifacts::new();
        artifacts.insert(
            artifact_key("amd64", "process"),
            BpfArtifact {
                arch: "amd64".into(),
                sensor: "process".into(),
                o_bytes: b"dummy-bytes",
                o_sha256: "0".repeat(64),
                skel_bytes: b"",
                skel_sha256: String::new(),
            },
        );
        let found = lookup(&artifacts, "amd64", "process").expect("must find inserted key");
        assert_eq!(found.arch, "amd64");
        assert_eq!(found.sensor, "process");
    }

    #[test]
    fn iter_sorted_returns_deterministic_order() {
        let mut artifacts: BpfArtifacts = BpfArtifacts::new();
        for sensor in ["identity", "process", "file"] {
            artifacts.insert(
                artifact_key("amd64", sensor),
                BpfArtifact {
                    arch: "amd64".into(),
                    sensor: sensor.into(),
                    o_bytes: b"x",
                    o_sha256: "0".repeat(64),
                    skel_bytes: b"",
                    skel_sha256: String::new(),
                },
            );
        }
        let order: Vec<String> = iter_sorted(&artifacts)
            .map(|(a, s, _)| format!("{a}/{s}"))
            .collect();
        // BTreeMap is already ordered; iter_sorted is the
        // explicit promise of determinism.
        assert_eq!(
            order,
            vec![
                "amd64/file".to_string(),
                "amd64/identity".to_string(),
                "amd64/process".to_string(),
            ]
        );
    }
}
