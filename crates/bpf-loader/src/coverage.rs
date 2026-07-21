// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-loader/src/coverage.rs
// kernel-v1 — task 18 (load/attach compatibility manager).
//!
//! Typed coverage matrix emitted by the BPF loader on every
//! `probe_and_load` invocation. The shape is the canonical
//! contract that `bench/coverage-matrix.json` must match at
//! release time (the schema lives under
//! `bench/schemas/coverage-matrix.v1.json`).
//!
//! DESIGN NOTES
//!   * The matrix is built at startup from real per-program
//!     load/attach probes — NOT inferred from `uname -r`.
//!     "Inferring support from version alone" is one of the
//!     explicit anti-patterns the plan named.
//!   * `SensorStatus::Blocked` with reason `"BPF artifacts not
//!     embedded in this build"` is the documented graceful path
//!     for the unprivileged / build-host-failed case. The
//!     `crates/bpf-loader/tests/loader.rs` integration suite
//!     asserts this entry shape on every sensor.
//!   * The matrix is plain Rust types (no serde dependencies
//!     inside the loader core) and is serialised in `lib.rs`
//!     via `serde_json::to_string_pretty`. The serialiser is
//!     the only point that touches JSON so the loader core
//!     stays unit-testable.

#![forbid(unsafe_code)]

use std::fmt;

/// Per-sensor probe outcome.
///
/// The three variants map 1:1 to the preflight
/// `preflight_schema::SensorStatus` enum so a downstream
/// dashboard can read both without bespoke translators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorStatus {
    /// The loader probes read the per-program verifier log,
    /// attached every selected hook, and recorded non-empty
    /// active links for this sensor.
    Capable,
    /// The loader attached at least one hook but at least one
    /// other hook in the primary/fallback ladder failed; the
    /// `reasons` vec names every degraded path.
    Degraded,
    /// The loader could not attach this sensor at all (build
    /// artefacts missing, or the kernel rejected every hook
    /// variant). The `reasons` vec names the cause; multiple
    /// reasons are joined by `\n` in the JSON envelope.
    Blocked,
}

impl SensorStatus {
    /// Stable lowercase string used in the JSON envelope and
    /// by preflight cross-checks.
    pub const fn as_str(self) -> &'static str {
        match self {
            SensorStatus::Capable => "capable",
            SensorStatus::Degraded => "degraded",
            SensorStatus::Blocked => "blocked",
        }
    }
}

impl fmt::Display for SensorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Single sensor's coverage entry. One of these is produced
/// per `(arch, sensor)` pair the loader is asked to manage; for
/// the v1 host those are `process`, `file`, `network`, `dns`,
/// `syscall`, `identity` (six sensors — the `placeholder`
/// pseudo-sensor is loader-internal and never reaches the
/// JSON envelope).
#[derive(Debug, Clone)]
pub struct SensorCoverage {
    /// Sensor name as it appears in `bpf/sensors/*.bpf.c`.
    pub sensor: String,
    /// Host arch the entry was probed for.
    pub arch: String,
    /// Probe verdict — see `SensorStatus`.
    pub status: SensorStatus,
    /// The hook variant the loader actually selected (or
    /// attempted last). Examples:
    ///   * `"lsm/file_open"`     (file, primary)
    ///   * `"tracepoint/syscalls/sys_enter_openat"` (file, fallback)
    ///   * `"raw_tracepoint/sys_enter"` (syscall, only stable choice)
    ///   * `""` when the sensor was blocked before any hook
    ///     was probed.
    pub selected_hook: String,
    /// Names of hooks in the primary/fallback ladder with their
    /// probe outcome. One line per ladder rung the loader
    /// considered, regardless of selection.
    pub ladder: Vec<LadderRung>,
    /// Human-readable reasons for the current `status`.
    /// `Blocked` typically has exactly one reason (the
    /// build-pipeline failure name); `Degraded` typically has
    /// one reason per failed rung; `Capable` is empty.
    pub reasons: Vec<String>,
    /// Verifier log excerpt captured at the last `probe_and_
    /// load`. Empty string when the loader never reached
    /// `program.probe_and_load()` (e.g. empty artefact path).
    pub verifier_log_excerpt: String,
}

/// Single hook ladder rung: a `(section, outcome, reason)`
/// triple recording what the loader observed when it tried to
/// attach a particular `SEC(...)` section.
#[derive(Debug, Clone)]
pub struct LadderRung {
    /// The `SEC(...)` name the loader tried; `""` for the
    /// "no embedded artefacts" shortcut rung.
    pub section: String,
    /// True iff this rung produced a live attach.
    pub attached: bool,
    /// Free-form reason string. Empty when `attached`.
    pub reason: String,
}

/// The top-level coverage matrix. Always non-null; the
/// default-constructed value enumerates every v1 sensor at
/// status `Blocked` with the documented build-host reason.
#[derive(Debug, Clone)]
pub struct CoverageMatrix {
    /// Schema version. Bumped on backward-incompatible shape
    /// changes; currently `1`.
    pub schema_version: u32,
    /// ISO-8601 wall-clock UTC timestamp recorded at probe
    /// time. Kept as a string so the JSON serializer does not
    /// need a chrono dep.
    pub generated_at_utc: String,
    /// Loader crate version that produced this matrix.
    pub loader_version: String,
    /// Arch the matrix was probed for (`"amd64"` / `"arm64"`).
    pub arch: String,
    /// One entry per sensor in the v1 set, in deterministic
    /// order (`dns`, `file`, `identity`, `network`, `process`,
    /// `syscall` — alphabetical to keep the JSON stable).
    pub sensors: Vec<SensorCoverage>,
    /// True iff the loader observed at least one capability
    /// it could act on (i.e. `sensors[i].status == Capable`
    /// for any i).
    pub any_capable: bool,
    /// True iff the loader observed at least one degraded
    /// path.
    pub any_degraded: bool,
    /// True iff the loader observed at least one blocked
    /// sensor. Always true in the unprivileged build-host case.
    pub any_blocked: bool,
}

impl CoverageMatrix {
    /// Construct an empty matrix. The schema_version and the
    /// sorted sensor list are pre-populated; the per-sensor
    /// entries are all `Blocked` with the documented
    /// build-host reason.
    pub fn with_default_sensors() -> Self {
        let sensors = default_sensor_names()
            .iter()
            .map(|name| SensorCoverage {
                sensor: (*name).to_string(),
                arch: std::env::consts::ARCH.to_string(),
                status: SensorStatus::Blocked,
                selected_hook: String::new(),
                ladder: Vec::new(),
                reasons: vec!["BPF artifacts not embedded in this build".to_string()],
                verifier_log_excerpt: String::new(),
            })
            .collect();
        Self {
            schema_version: 1,
            generated_at_utc: String::new(),
            loader_version: env!("CARGO_PKG_VERSION").to_string(),
            arch: std::env::consts::ARCH.to_string(),
            sensors,
            any_capable: false,
            any_degraded: false,
            any_blocked: true,
        }
    }
}

/// The v1 sensor set: `process`, `file`, `network`, `dns`,
/// `syscall`, `identity`. The `placeholder` sensor is
/// loader-internal and never appears in the matrix.
pub const DEFAULT_SENSORS: &[&str] = &[
    "process", "file", "network", "dns", "syscall", "identity",
];

/// Sorted version of `DEFAULT_SENSORS`. The matrix serialiser
/// uses this order to keep the JSON stable across runs.
pub fn default_sensor_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = DEFAULT_SENSORS.iter().copied().collect();
    names.sort_unstable();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensor_status_strings_match_preflight() {
        assert_eq!(SensorStatus::Capable.as_str(), "capable");
        assert_eq!(SensorStatus::Degraded.as_str(), "degraded");
        assert_eq!(SensorStatus::Blocked.as_str(), "blocked");
        assert_eq!(SensorStatus::Degraded.to_string(), "degraded");
    }

    #[test]
    fn with_default_sensors_lists_every_v1_sensor_blocked() {
        let m = CoverageMatrix::with_default_sensors();
        assert_eq!(m.schema_version, 1);
        assert!(!m.sensors.is_empty(), "matrix must list every v1 sensor");
        assert_eq!(m.sensors.len(), DEFAULT_SENSORS.len());
        let names: Vec<String> = m.sensors.iter().map(|s| s.sensor.clone()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "matrix sensors must be sorted");
        for sensor in &m.sensors {
            assert_eq!(sensor.status, SensorStatus::Blocked);
            assert_eq!(
                sensor.reasons,
                vec!["BPF artifacts not embedded in this build".to_string()],
                "every blocked sensor must carry the documented reason"
            );
            assert!(sensor.selected_hook.is_empty());
            assert!(sensor.ladder.is_empty());
        }
        assert!(m.any_blocked);
        assert!(!m.any_capable);
        assert!(!m.any_degraded);
    }

    #[test]
    fn default_sensor_names_are_sorted() {
        assert_eq!(
            default_sensor_names(),
            vec![
                "dns", "file", "identity", "network", "process", "syscall",
            ]
        );
    }

    #[test]
    fn matrix_summary_flags_reflect_per_sensor_status() {
        let mut m = CoverageMatrix::with_default_sensors();
        m.sensors[0].status = SensorStatus::Capable;
        m.any_capable = true;
        m.sensors[1].status = SensorStatus::Degraded;
        m.any_degraded = true;
        m.any_blocked = false; // manually drop the all-blocked default
        assert!(m.any_capable);
        assert!(m.any_degraded);
        assert!(!m.any_blocked);
    }
}
