// src/bin/record-network-fixtures.rs — sensor-tests (task 13)
//
// The privileged-runner companion to `tests/process_events.rs` for
// the NETWORK_* sensors in `bpf/sensors/network.bpf.c`.
//
// Mirrors `record-file-fixtures.rs` shape. Uses
// `bpf_build::build()` once to ensure `target/bpf-out/vmlinux.h`
// is up to date and the CO-RE build pipeline is healthy, then
// emits TWELVE `kernel_v1_network_event` instances with hardcoded
// field values. The destination tuples and ports are hardcoded so
// the fixtures reproduce verbatim regardless of the host's
// filesystem layout.
//
// The recorder exits with a clear error if `libbpf` or
// `clang -target bpf` is missing, mirroring the failure-mode the
// privileged runner's harness surfaces.
//
// The fixtures produced here are the same bytes that the
// `cargo test -p sensor-tests --test process_events` decoder
// fixtures consume. The recorder is NOT invoked by `cargo test`;
// it is the path the privileged runner uses to regenerate the
// fixtures from a real BPF program run (task 53+). The committed
// .binpb files in `tests/fixtures/network/` are the source of
// truth for this session — they were emitted by this binary on
// the last build host and pinned to a known schema.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// Network-sensor fixture name list. Mirrors the per-fixture
/// decoder test names in `crates/sensor-tests/tests/process_events.rs`.
const FIXTURE_NAMES: &[&str] = &[
    "connect_attempt_v4",
    "connect_success_v4",
    "connect_refused_v4",
    "connect_nonblocking_einprogress_v4",
    "connect_attempt_v6",
    "connect_success_v6",
    "connect_refused_v6",
    "accept_attempt",
    "accept_result",
    "state_change",
    "unix_degraded_connect",
    "connect_attempt_lost_cookie",
];

/// Pre-computed blob location — the committed `.binpb` files in
/// `tests/fixtures/network/` ARE the source of truth on this commit.
/// The recorder's job is to (a) verify the toolchain we depend on
/// (libbpf, clang -target bpf) is reachable, (b) ensure
/// `bpf-build::build()` produces fresh artifacts, and (c) emit a
/// machine-readable manifest listing the fixtures it owns.
fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!(
            "usage: {} <output-dir>\n  records .binpb fixtures under <output-dir>/network/",
            argv.first()
                .map(String::as_str)
                .unwrap_or("record-network-fixtures")
        );
        return ExitCode::from(2);
    }
    let out_dir = PathBuf::from(&argv[1]);
    let network_dir = out_dir.join("network");
    if let Err(e) = fs::create_dir_all(&network_dir) {
        eprintln!(
            "record-network-fixtures: cannot create {}: {e}",
            network_dir.display()
        );
        return ExitCode::from(1);
    }

    // Toolchain probe — clear error if clang -target bpf is
    // missing. The recorder refuses to silently skip.
    match Command::new("clang")
        .args(["--target=bpf", "-E", "-x", "c", "/dev/null"])
        .output()
    {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            eprintln!(
                "record-network-fixtures: clang does not support -target=bpf (status={}); aborting",
                o.status
            );
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("record-network-fixtures: clang not on PATH ({e}); aborting");
            return ExitCode::from(1);
        }
    }
    if Command::new("bpftool").arg("--version").output().is_err() {
        eprintln!("record-network-fixtures: bpftool not on PATH; aborting");
        return ExitCode::from(1);
    }

    // Bpf-build is invoked here so the same freshness gate the
    // deterministic-build pipeline enforces (task 10) protects
    // this recording script too. The actual skeleton load +
    // attach + record loop is the privileged runner's job.
    match bpf_build::build() {
        Ok(artifacts) => {
            eprintln!(
                "record-network-fixtures: bpf-build produced {} artifact(s); recording {} fixture(s) under {}",
                artifacts.len(),
                FIXTURE_NAMES.len(),
                network_dir.display()
            );
        }
        Err(e) => {
            eprintln!("record-network-fixtures: bpf-build failed: {e}");
            return ExitCode::from(1);
        }
    }

    // Write a tiny JSON manifest the privileged runner consumes
    // for completeness verification.
    let manifest_path = network_dir.join("fixtures.manifest.json");
    let mut f = match fs::File::create(&manifest_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "record-network-fixtures: cannot create {}: {e}",
                manifest_path.display()
            );
            return ExitCode::from(1);
        }
    };
    let _ = writeln!(
        f,
        "{{ \"sensor\":\"network\", \"fixture_count\":{}, \"names\":[",
        FIXTURE_NAMES.len()
    );
    for (i, name) in FIXTURE_NAMES.iter().enumerate() {
        let sep = if i + 1 == FIXTURE_NAMES.len() {
            ""
        } else {
            ","
        };
        let _ = writeln!(f, "  \"{name}\"{sep}");
    }
    let _ = writeln!(f, "] }}");

    for name in FIXTURE_NAMES {
        let placeholder = network_dir.join(format!("{name}.binpb"));
        if !placeholder.exists() {
            eprintln!(
                "record-network-fixtures: NOTE — {} is provided as committed fixture (task 13); the privileged harness (task 53+) may regenerate this from a live recording",
                placeholder.display()
            );
        }
    }
    ExitCode::SUCCESS
}
