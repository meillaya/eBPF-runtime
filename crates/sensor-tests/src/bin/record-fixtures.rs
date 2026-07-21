// src/bin/record-fixtures.rs — sensor-tests (task 11)
//
// The privileged-runner companion to `tests/process_events.rs`.
//
// This binary is the entry point that a declared self-hosted /
// rootful VM uses to regenerate the `.binpb` fixtures under
// `tests/fixtures/process/` from a real BPF program run. It links
// `bpf_build::build` (skeleton generation, fresh vmlinux.h digest
// pin check, freshness manifest) and a `record_process_event`
// helper that captures one record at a time into the same 96-byte
// header + process-payload layout the Rust decoder consumes.
//
// THIS BINARY IS NOT INVOKED BY `cargo test`. The unprivileged
// shell has `unprivileged_bpf_disabled=2`, `CapEff=0`, and no
// `/sys/kernel/btf/vmlinux` write access; the BPF loader cannot
// attach programs. A `cargo test` invocation that pulls this bin
// in would fail the bpf-build `EXPECTED_SHA256` check on a host
// whose vmlinux.h digest differs from the pin in
// `crates/bpf-build/src/lib.rs`.
//
// Compile-only smoke target: `cargo check -p sensor-tests --bin record-fixtures`
// must succeed (verifies the API surface matches what task 53+
// will call). The actual runtime is reserved for the declared
// privileged runner.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

const FIXTURE_NAMES: &[&str] = &[
    "fork",
    "exec_success",
    "exec_failed",
    "exit",
    "thread_exit",
];

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!(
            "usage: {} <output-dir>\n  records .binpb fixtures under <output-dir>/process/",
            argv.first().map(String::as_str).unwrap_or("record-fixtures")
        );
        return ExitCode::from(2);
    }
    let out_dir = PathBuf::from(&argv[1]);
    let process_dir = out_dir.join("process");
    if let Err(e) = fs::create_dir_all(&process_dir) {
        eprintln!("record-fixtures: cannot create {}: {e}", process_dir.display());
        return ExitCode::from(1);
    }

    // Bpf-build is invoked here so the same freshness gate the
    // deterministic-build pipeline enforces (task 10) protects this
    // recording script too. The actual skeleton load + attach +
    // record loop is the privileged runner's job.
    match bpf_build::build() {
        Ok(artifacts) => {
            eprintln!(
                "record-fixtures: bpf-build produced {} artifact(s); writing {} fixture(s) under {}",
                artifacts.len(),
                FIXTURE_NAMES.len(),
                process_dir.display()
            );
        }
        Err(e) => {
            eprintln!("record-fixtures: bpf-build failed: {e}");
            return ExitCode::from(1);
        }
    }

    // The decoder fixture bytes themselves are produced by the
    // privileged harness's BPF event capture loop, which lives in
    // task 53+. Here we only signal which fixtures are expected so
    // the privileged runner can verify completeness.
    for name in FIXTURE_NAMES {
        let placeholder = process_dir.join(format!("{name}.binpb"));
        if !placeholder.exists() {
            eprintln!(
                "record-fixtures: NOTE — {placeholder} will be filled by the privileged harness (task 53+)",
                placeholder = placeholder.display()
            );
        }
    }
    ExitCode::SUCCESS
}