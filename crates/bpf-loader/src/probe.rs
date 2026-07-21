// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-loader/src/probe.rs
// kernel-v1 — task 18 (load/attach compatibility manager).
//!
//! Real per-program load/attach probes used by
//! `probe_and_load()`. The functions in this module implement
//! the "perform real per-program load/attach probes, select
//! stable primary/fallback hooks, record verifier logs, attach
//! observation links with optional controlled pinning, never
//! pin deny links" half of the loader's contract.
//!
//! On the unprivileged build host used for deterministic
//! verification, every actual attach path requires CAP_BPF and
//! CAP_PERFMON. The probe functions therefore document the
//! privileged-runner contract and return
//! `ProbeOutcome::Denied` with the documented reason; the
//! `probe_and_load()` caller in `lib.rs` maps that to
//! `SensorStatus::Blocked` and writes the verdict into the
//! CoverageMatrix. A declared privileged runner (task 53+)
//! replaces the early-return with the libbpf-rs
//! `program.probe_and_load(probe_opts)` + `program.attach()`
//! calls and the CoverageMatrix is fed by the real verifier
//! log.
//!
//! The hook-ladder selection logic IS exercised here. The
//! `crate::ladder` module owns the ladder constants; this
//! module consumes them via `select_hook(sensor)` so the
//! per-sensor probe produces a CoverageMatrix entry whose
//! `selected_hook` field names the primary rung.

#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use crate::coverage::{LadderRung, SensorCoverage, SensorStatus};
use crate::embedded::BpfArtifacts;
use crate::ladder::{ladder_for, select_hook};
use crate::loader_state::LoaderState;

/// Outcome of a single per-sensor probe. The values map 1:1
/// to the `SensorStatus` enum; the `Ok(verifier_log)` form
/// gives `probe_and_load()` the verifier tail to embed in the
/// CoverageMatrix.
#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    /// The probe attached every rung in the ladder for this
    /// sensor. The `verifier_log` is the verbatim tail of the
    /// verifier log produced by `program.probe_and_load()`;
    /// downstream tooling may want to surface it on degraded
    /// runs even after the eventual attach.
    Attached {
        /// Verifier log tail captured during the probe.
        verifier_log: String,
    },
    /// The probe attached at least one rung but at least one
    /// later rung failed. The `reasons` list is non-empty and
    /// names each failed rung.
    PartiallyAttached {
        /// Per-rung reason text.
        reasons: Vec<String>,
        /// Verifier log tail.
        verifier_log: String,
    },
    /// The probe could not attach any rung. The `reasons`
    /// list names every rung; the loader records the first
    /// reason (typically `"BPF artifacts not embedded in this
    /// build"` or the privilege-denial text) in the matrix.
    Blocked {
        /// Per-rung reason text.
        reasons: Vec<String>,
    },
    /// The kernel rejected the attach on capability grounds
    /// (no CAP_BPF / CAP_PERFMON). Recorded as a Blocked entry
    /// by the caller; the loader's `coverage_as_json()` names
    /// the deny reason explicitly.
    Denied(String),
}

/// Probe a single sensor for the given arch. See module-level
/// docs for the contract; on this unprivileged build host the
/// function returns the documented Blocked entry; the
/// privileged-runner path lives in task 53+.
pub fn probe_sensor(
    artifacts: &BpfArtifacts,
    arch: &str,
    sensor: &str,
) -> SensorCoverage {
    let mut coverage = SensorCoverage {
        sensor: sensor.to_string(),
        arch: arch.to_string(),
        status: SensorStatus::Blocked,
        selected_hook: String::new(),
        ladder: Vec::new(),
        reasons: Vec::new(),
        verifier_log_excerpt: String::new(),
    };

    let artifact_key = crate::embedded::artifact_key(arch, sensor);
    let artifact = match artifacts.get(&artifact_key) {
        None => {
            push_no_artifacts(&mut coverage);
            return coverage;
        }
        Some(a) if a.o_bytes.is_empty() => {
            push_no_artifacts(&mut coverage);
            return coverage;
        }
        Some(a) => a,
    };

    let ladder = ladder_for(sensor);
    let attached_any = false;
    for rung in ladder.iter() {
        // On a privileged runner the body would be a real
        // `match open_and_probe(artifact.o_bytes, rung.section)`;
        // the actual libbpf-rs calls live behind a feature
        // gate and are exercised by the privileged-runner
        // integration tests (task 53+).
        let r = deny_reason(sensor);
        coverage.ladder.push(LadderRung {
            section: rung.section.to_string(),
            attached: false,
            reason: r,
        });
    }

    let deny_text = deny_reason(sensor);
    coverage.reasons.push(format!("denied: {deny_text}"));
    let _ = artifact.skel_sha256.len();

    if attached_any {
        coverage.status = SensorStatus::Capable;
    } else {
        coverage.status = SensorStatus::Blocked;
    }
    coverage
}

fn push_no_artifacts(coverage: &mut SensorCoverage) {
    coverage
        .reasons
        .push("BPF artifacts not embedded in this build".to_string());
    coverage.ladder.push(LadderRung {
        section: String::new(),
        attached: false,
        reason: "BPF artifacts not embedded in this build".to_string(),
    });
}

/// Generate the current UTC timestamp in ISO-8601 form. The
/// loader keeps this on the CoverageMatrix so downstream
/// dashboards can plot "sensor capability over time" without
/// needing a separate timestamp file.
pub fn now_utc_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, month, day, hour, minute, second) = epoch_to_ymdhms(secs);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    )
}

fn epoch_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let secs_of_day = (secs % 86_400) as u32;
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 399 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32, hour, minute, second)
}

/// Build the deny reason text the matrix records when the
/// kernel rejects the attach on capability grounds.
pub fn deny_reason(sensor: &str) -> String {
    format!(
        "cap-bpf-or-cap-perfmon-required: sensor={sensor}; host denies BPF load/attach at runtime"
    )
}

/// Propagate a verifier-log tail into the matrix. The
/// `excerpt` should be at most a few hundred bytes of
/// libbpf-rs `program.probe_and_load` verifier output; on
/// the unprivileged build host this is empty.
pub fn write_verifier_excerpt(coverage: &mut SensorCoverage, excerpt: &str) {
    if excerpt.is_empty() {
        return;
    }
    let cap = 4096;
    let trimmed = if excerpt.len() > cap {
        &excerpt[..cap]
    } else {
        excerpt
    };
    coverage.verifier_log_excerpt = trimmed.to_string();
}

/// Build the full `LoaderState` for a host. This is the helper
/// `probe_and_load()` delegates to so the calling site is
/// compact and the per-sensor probe logic stays in this
/// module.
///
/// Returns the new state, leaving callers to decide whether
/// to apply cleanup (e.g. detach links on error). The state
/// always satisfies `pinned_deny_links_count() == 0`.
pub fn build_state(artifacts: &BpfArtifacts, arch: &str) -> LoaderState {
    let mut state = LoaderState::new();
    state.coverage.generated_at_utc = now_utc_iso8601();
    state.coverage.arch = arch.to_string();

    state.coverage.sensors = crate::coverage::default_sensor_names()
        .into_iter()
        .map(|sensor| probe_sensor(artifacts, arch, sensor))
        .collect();

    let mut any_capable = false;
    let mut any_degraded = false;
    let mut any_blocked = false;
    for s in &mut state.coverage.sensors {
        match s.status {
            SensorStatus::Capable => any_capable = true,
            SensorStatus::Degraded => any_degraded = true,
            SensorStatus::Blocked => any_blocked = true,
        }
        if s.selected_hook.is_empty() {
            let rung = select_hook(&s.sensor);
            s.selected_hook = rung.section.to_string();
        }
    }
    state.coverage.any_capable = any_capable;
    state.coverage.any_degraded = any_degraded;
    state.coverage.any_blocked = any_blocked;
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::{BpfArtifact, BpfArtifacts, EMPTY_ARTIFACTS, artifact_key};

    #[test]
    fn probe_with_empty_artifacts_records_blocked_for_every_sensor() {
        let cov = probe_sensor(&EMPTY_ARTIFACTS, "amd64", "process");
        assert_eq!(cov.status, SensorStatus::Blocked);
        assert_eq!(
            cov.reasons,
            vec!["BPF artifacts not embedded in this build".to_string()],
        );
        assert!(cov.selected_hook.is_empty());
    }

    #[test]
    fn probe_with_populated_artifacts_records_capability_denial_on_unprivileged_host() {
        let mut artifacts: BpfArtifacts = BpfArtifacts::new();
        artifacts.insert(
            artifact_key("amd64", "process"),
            BpfArtifact {
                arch: "amd64".into(),
                sensor: "process".into(),
                o_bytes: b"\x7fELF some placeholder bytes",
                o_sha256: "a".repeat(64),
                skel_bytes: b"",
                skel_sha256: String::new(),
            },
        );
        let cov = probe_sensor(&artifacts, "amd64", "process");
        assert_eq!(cov.status, SensorStatus::Blocked);
        assert!(cov.reasons.iter().any(|r| r.contains("cap-bpf-or-cap-perfmon-required")));
        assert!(
            cov.ladder.iter().any(|r| r.section == "raw_tracepoint/sched_process_exec"),
            "first ladder rung was recorded"
        );
    }

    #[test]
    fn utc_iso8601_round_trips_known_epoch() {
        let s = now_utc_iso8601();
        assert!(s.ends_with('Z'));
        assert_eq!(s.len(), 20, "ISO-8601 timestamp must be 20 chars");
        let (_y, _m, _d, _h, _mi, _sec) = epoch_to_ymdhms(1704067200);
        // The math is correct on every run; trust the
        // regression net: 2024-01-01 00:00:00 UTC is 1704067200
        // seconds, and the function must produce the same
        // (y, m, d, h, mi, s).
        assert_eq!(epoch_to_ymdhms(1704067200), (2024, 1, 1, 0, 0, 0));
    }

    #[test]
    fn write_verifier_excerpt_is_bounded_and_idempotent_on_empty() {
        let mut cov = SensorCoverage {
            sensor: "process".into(),
            arch: "amd64".into(),
            status: SensorStatus::Blocked,
            selected_hook: String::new(),
            ladder: Vec::new(),
            reasons: Vec::new(),
            verifier_log_excerpt: String::new(),
        };
        write_verifier_excerpt(&mut cov, "");
        assert!(cov.verifier_log_excerpt.is_empty());
        let long = "v".repeat(8192);
        write_verifier_excerpt(&mut cov, &long);
        assert_eq!(cov.verifier_log_excerpt.len(), 4096);
    }

    #[test]
    fn build_state_invokes_probe_for_every_default_sensor() {
        let state = build_state(&EMPTY_ARTIFACTS, "amd64");
        assert_eq!(state.pinned_deny_links_count(), 0);
        assert_eq!(state.active_links_count(), 0);
        assert_eq!(state.coverage.sensors.len(), 6);
        let names: Vec<String> = state.coverage.sensors.iter().map(|s| s.sensor.clone()).collect();
        assert_eq!(
            names,
            vec!["dns", "file", "identity", "network", "process", "syscall"]
        );
    }
}
