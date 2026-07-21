// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-loader/src/matrix_serde.rs
// kernel-v1 — task 18 (load/attach compatibility manager).
//!
//! JSON serialisation of the typed `CoverageMatrix` envelope.
//! The contract here is the canonical machine-readable form
//! that `bench/coverage-matrix.json` must match at release
//! time, and that the task-26 CLI / task-19 agent binary
//! emit on startup.

#![forbid(unsafe_code)]

use crate::coverage::CoverageMatrix;

/// Serialise a `CoverageMatrix` to JSON. The output is the
/// canonical release contract. The `sensors` field is keyed
/// by sensor name (`dns`, `file`, ...) so downstream tooling
/// can look up per-sensor entries by name without parsing an
/// array.
pub fn matrix_to_json(matrix: &CoverageMatrix) -> String {
    let mut sensors_obj = serde_json::Map::new();
    for s in &matrix.sensors {
        sensors_obj.insert(
            s.sensor.clone(),
            serde_json::json!({
                "sensor": s.sensor,
                "arch": s.arch,
                "status": s.status.as_str(),
                "selected_hook": s.selected_hook,
                "ladder": s.ladder.iter().map(|r| {
                    serde_json::json!({
                        "section": r.section,
                        "attached": r.attached,
                        "reason": r.reason,
                    })
                }).collect::<Vec<_>>(),
                "reasons": s.reasons,
                "verifier_log_excerpt": s.verifier_log_excerpt,
            }),
        );
    }
    let value = serde_json::json!({
        "schema_version": matrix.schema_version,
        "generated_at_utc": matrix.generated_at_utc,
        "loader_version": matrix.loader_version,
        "arch": matrix.arch,
        "any_capable": matrix.any_capable,
        "any_degraded": matrix.any_degraded,
        "any_blocked": matrix.any_blocked,
        "sensors": sensors_obj,
    });
    serde_json::to_string_pretty(&value)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialise-failed: {e}\"}}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::CoverageMatrix;

    #[test]
    fn empty_matrix_serialises_to_schema_one() {
        let m = CoverageMatrix::with_default_sensors();
        let s = matrix_to_json(&m);
        let v: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");
        assert_eq!(v["schema_version"], serde_json::json!(1));
        // The CoverageMatrix produced by `with_default_sensors`
        // carries a sensor for every name in the v1 set; six
        // entries expected.
        let sensors = v["sensors"]
            .as_object()
            .expect("sensors must be a JSON object");
        assert_eq!(sensors.len(), 6);
    }
}
