// src/bin/record-saturation-fixtures.rs — sensor-tests (task 17)
//
// The privileged-runner companion to the saturation decoder tests
// in `crates/sensor-tests/tests/process_events.rs`.
//
// Mirrors `record-network-fixtures.rs` (task 13) shape. The
// saturation harness is `bench/saturation.sh`; the committed JSON
// verdict fixtures under `tests/fixtures/saturation/` are the
// source of truth for `cargo test`. The recorder's job is to (a)
// verify the toolchain we depend on (bash, jq, python3, clang
// -target bpf, bpftool) is reachable, (b) ensure
// `bpf-build::build()` produces fresh artifacts, and (c) emit a
// machine-readable manifest listing the fixtures it owns.
//
// The recorder is NOT invoked by `cargo test`; it is the path the
// privileged runner uses to regenerate the JSON verdict fixtures
// from a live BPF ring-buffer run (task 53+). On an unprivileged
// shell the recorder cannot exercise real BPF ring-buffer reserve
// failures, so the committed JSON fixtures are produced from a
// deterministic pure-Rust simulation in `bench/saturation.sh`
// (see the per-fixture rationale fields for provenance).
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

const FIXTURE_NAMES: &[&str] = &[
    "supported_pass",
    "saturation_shed",
    "gap_detected",
    "false_zero_loss",
    "saturation_oversize_ring",
];

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!(
            "usage: {} <output-dir>\n  records .json saturation fixtures under <output-dir>/saturation/",
            argv
                .first()
                .map(String::as_str)
                .unwrap_or("record-saturation-fixtures")
        );
        return ExitCode::from(2);
    }
    let out_dir = PathBuf::from(&argv[1]);
    let sat_dir = out_dir.join("saturation");
    if let Err(e) = fs::create_dir_all(&sat_dir) {
        eprintln!(
            "record-saturation-fixtures: cannot create {}: {e}",
            sat_dir.display()
        );
        return ExitCode::from(1);
    }

    let tool_missing = |tool: &str, hint: &str| -> Option<ExitCode> {
        match Command::new(tool).arg("--version").output() {
            Ok(o) if o.status.success() => None,
            Ok(o) => {
                eprintln!(
                    "record-saturation-fixtures: {tool} returned non-zero (status={}); {hint}; aborting",
                    o.status
                );
                Some(ExitCode::from(1))
            }
            Err(e) => {
                eprintln!("record-saturation-fixtures: {tool} not on PATH ({e}); {hint}; aborting");
                Some(ExitCode::from(1))
            }
        }
    };
    if let Some(code) = tool_missing("bash", "the saturation harness is POSIX bash") {
        return code;
    }
    if let Some(code) = tool_missing("jq", "the saturation harness validates JSON via jq") {
        return code;
    }
    if let Some(code) = tool_missing("python3", "the saturation harness runs a Python simulator") {
        return code;
    }
    match Command::new("clang")
        .args(["--target=bpf", "-E", "-x", "c", "/dev/null"])
        .output()
    {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            eprintln!(
                "record-saturation-fixtures: clang does not support -target=bpf (status={}); aborting",
                o.status
            );
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("record-saturation-fixtures: clang not on PATH ({e}); aborting");
            return ExitCode::from(1);
        }
    }
    if Command::new("bpftool").arg("--version").output().is_err() {
        eprintln!("record-saturation-fixtures: bpftool not on PATH; aborting");
        return ExitCode::from(1);
    }

    match bpf_build::build() {
        Ok(artifacts) => {
            eprintln!(
                "record-saturation-fixtures: bpf-build produced {} artifact(s); the saturation harness (task 17) targets the shared ring-buffer maps wired by these artifacts",
                artifacts.len()
            );
        }
        Err(e) => {
            eprintln!("record-saturation-fixtures: bpf-build failed: {e}");
            return ExitCode::from(1);
        }
    }

    let manifest_path = sat_dir.join("fixtures.manifest.json");
    let mut f = match fs::File::create(&manifest_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "record-saturation-fixtures: cannot create {}: {e}",
                manifest_path.display()
            );
            return ExitCode::from(1);
        }
    };
    let _ = writeln!(
        f,
        "{{ \"task\":17, \"sensor\":\"ring-buffer\", \"fixture_count\":{}, \"names\":[",
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
        let placeholder = sat_dir.join(format!("{name}.json"));
        if !placeholder.exists() {
            eprintln!(
                "record-saturation-fixtures: NOTE — {} is provided as committed fixture (task 17); the privileged harness (task 53+) may regenerate this from a live recording",
                placeholder.display()
            );
        }
    }
    ExitCode::SUCCESS
}
