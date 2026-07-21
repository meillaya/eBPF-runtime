// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-loader/tests/loader.rs
// kernel-v1 — task 18 (load/attach compatibility manager).
//!
//! Host-side integration tests for the loader. The four tests
//! named below are the acceptance surface the task brief calls
//! out in `## Acceptance criteria (agent-executable)`:
//!
//!   1. `coverage_matrix_with_no_embedded_artifacts_records_
//!       blocked_for_every_sensor` — the documented graceful
//!       path produces a fully-Blocked matrix and zero
//!       attached / pinned deny links.
//!   2. `loader_state_clears_attachments_on_failure` — the
//!       cleanup path returns `attached_links` and
//!       `map_handles` to empty even when a partial-attachment
//!       state is in flight.
//!   3. `coverage_matrix_serializes_to_valid_json` — the
//!       JSON envelope is valid JSON with `schema_version == 1`.
//!   4. `no_enforcement_link_is_pinned` — the
//!       `pinned_deny_links_count() == 0` invariant is
//!       preserved across every `probe_and_load` exit path.
//!
//! Every test is host-side (no BPF required); the privileged
//! runner integration tests land under `scripts/run-privileged-
//! tests.sh` in task 53+ and exercise the real
//! `libbpf_rs::Object::open_mem_bytes` + `program.attach()`
//! paths.

use bpf_loader::{
    CoverageMatrix, LoaderState, SensorStatus, coverage_as_json, probe_and_load,
};

fn host_arch_dir() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        _ => "amd64",
    }
}

#[test]
fn coverage_matrix_with_no_embedded_artifacts_records_blocked_for_every_sensor() {
    // `probe_and_load()` on this host exercises the
    // documented graceful path: the `BPF_ARTIFACTS` table has
    // the per-arch placeholders (task 10) but no per-sensor
    // entries (task 11-17 ships those on the privileged
    // build). On the build-host the per-sensor
    // `probe_sensor()` callback records every sensor as
    // `Blocked` with the documented reason; this test names
    // that contract.
    let arch = host_arch_dir();
    let state = probe_and_load(arch).expect("probe_and_load must not Err on unprivileged host");
    let matrix: &CoverageMatrix = &state.coverage;

    assert_eq!(
        matrix.sensors.len(),
        6,
        "the matrix must list every v1 sensor (process, file, network, dns, syscall, identity)"
    );
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
    for sensor in &matrix.sensors {
        assert_eq!(
            sensor.status,
            SensorStatus::Blocked,
            "sensor {} must be Blocked",
            sensor.sensor
        );
        let expected = "BPF artifacts not embedded in this build";
        assert!(
            sensor.reasons.iter().any(|r| r == expected),
            "sensor {} must carry the documented graceful-path reason; got {:?}",
            sensor.sensor,
            sensor.reasons
        );
    }
    assert_eq!(
        state.pinned_deny_links_count(),
        0,
        "pinned deny links must always be zero by design"
    );
    assert_eq!(
        state.active_links_count(),
        0,
        "no observation links should be attached on a build host whose bpf-build cannot populate per-sensor artefacts"
    );
}

#[test]
fn loader_state_clears_attachments_on_failure() {
    // The `LoaderState::cleanup()` path is what runs after a
    // partial-failure cleanup. The test simulates a
    // partial-attachment state via direct population of
    // `attached_links` and `map_handles` (those fields are
    // intentionally `pub` so the orchestrator can record
    // attach / map-open outcomes) and asserts the
    // `pinned_deny_links_count` invariant survives.
    //
    // The integration test in this file is the canonical
    // surface that the failure-QA scenario in the plan
    // (task 18 §QA scenarios, failure column) drives. On a
    // privileged runner, the equivalent assertion is that
    // `bpftool link show` returns no changes after a forced
    // partial failure at the Nth attach.
    let mut state = LoaderState::new();
    state.attached_links.insert("process".into(), bpf_loader::BpfLinkId(42));
    state
        .map_handles
        .insert("process_events".into(), bpf_loader::MapHandle(7));
    assert_eq!(state.attached_links.len(), 1);
    assert_eq!(state.map_handles.len(), 1);

    state.cleanup();

    assert!(
        state.attached_links.is_empty(),
        "cleanup must empty attached_links"
    );
    assert!(
        state.map_handles.is_empty(),
        "cleanup must empty map_handles"
    );
    assert_eq!(
        state.pinned_deny_links_count(),
        0,
        "cleanup must not touch the pinned_deny_links invariant"
    );
    assert_eq!(state.active_links_count(), 0);

    // Reconstructing after cleanup returns to the empty,
    // scope-safe default.
    let fresh = LoaderState::new();
    assert_eq!(fresh.pinned_deny_links_count(), 0);
    assert_eq!(fresh.active_links_count(), 0);
    assert!(fresh.attached_links.is_empty());
    assert!(fresh.map_handles.is_empty());
}

#[test]
fn coverage_matrix_serializes_to_valid_json() {
    // The JSON envelope is the canonical contract that
    // `bench/coverage-matrix.json` must match at release
    // time. This test asserts the schema-version, the
    // sensor-set coverage, and the per-sensor
    // Blocked/reason fields.
    let arch = host_arch_dir();
    let state = probe_and_load(arch).expect("probe_and_load must not Err on unprivileged host");
    let _ = state;
    let raw = coverage_as_json();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap_or_else(|e| {
        panic!(
            "coverage_as_json returned invalid JSON: {e}; raw output:\n{raw}"
        )
    });

    let obj = parsed
        .as_object()
        .expect("coverage JSON must be an object at the top level");
    assert_eq!(
        obj.get("schema_version"),
        Some(&serde_json::json!(1)),
        "schema_version must be 1"
    );
    let sensors = obj
        .get("sensors")
        .and_then(|v| v.as_object())
        .expect("sensors must be a JSON object keyed by sensor name");
    for sensor in ["dns", "file", "identity", "network", "process", "syscall"] {
        assert!(
            sensors.contains_key(sensor),
            "sensor {sensor} missing from coverage JSON"
        );
    }

    // For every Blocked sensor, the documented reason must
    // appear in the JSON `reasons` array. This is the
    // contract the preflight + dashboard integration tests
    // rely on so they can filter on the reason without
    // re-deriving the matrix.
    for (_name, value) in sensors {
        let status = value
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        let reasons = value
            .get("reasons")
            .and_then(|r| r.as_array())
            .expect("reasons must be an array");
        let reason_texts: Vec<String> = reasons
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        if status == "blocked" {
            assert!(
                reason_texts
                    .iter()
                    .any(|r| r == "BPF artifacts not embedded in this build"),
                "blocked sensor must include the documented graceful-path reason; got {reason_texts:?}"
            );
        }
    }
}

#[test]
fn no_enforcement_link_is_pinned() {
    // The "never pin deny links" rule is the load's
    // load-bearing safety invariant. This test exercises it
    // on every path `probe_and_load()` exposes:
    //
    //   * the Ok path (the unprivileged-build-host graceful
    //     matrix),
    //   * the LoaderState::new() default,
    //   * the post-cleanup state after a manual partial
    //     failure simulation.
    //
    // The test would fail if a future patch weakened the
    // guard by adding a code path that pinned a deny link
    // and forgot to call `cleanup()`.
    let arch = host_arch_dir();
    let ok_state = probe_and_load(arch).expect("Ok path");
    assert_eq!(
        ok_state.pinned_deny_links_count(),
        0,
        "Ok path must not pin any deny link"
    );

    let fresh_state = LoaderState::new();
    assert_eq!(
        fresh_state.pinned_deny_links_count(),
        0,
        "fresh LoaderState has zero pinned deny links"
    );

    let mut post_fail_state = LoaderState::new();
    post_fail_state
        .attached_links
        .insert("process".into(), bpf_loader::BpfLinkId(11));
    post_fail_state
        .attached_links
        .insert("file".into(), bpf_loader::BpfLinkId(12));
    assert_eq!(post_fail_state.active_links_count(), 2);
    post_fail_state.cleanup();
    assert_eq!(
        post_fail_state.pinned_deny_links_count(),
        0,
        "post-cleanup state must continue to satisfy pinned_deny_links_count == 0"
    );
    assert_eq!(
        post_fail_state.active_links_count(),
        0,
        "post-cleanup state must release the simulated observation links"
    );
}
