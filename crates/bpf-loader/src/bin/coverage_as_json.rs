// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-loader/src/bin/coverage_as_json.rs
// kernel-v1 — task 18 (load/attach compatibility manager).
//!
//! CLI surface of the CoverageMatrix contract. The binary
//! triggers `probe_and_load()` for the host architecture
//! (`std::env::consts::ARCH` mapped to either `amd64` or
//! `arm64`) and prints the resulting JSON envelope to stdout.
//!
//! `task 53+` and the task 26 CLI invoke this exact command,
//! redirecting stdout into `bench/coverage-matrix.json` or
//! into the live preflight evidence directory. The shape of
//! the output is the canonical contract that the release-time
//! `bench/coverage-matrix.json` must match.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use bpf_loader::{coverage_as_json, probe_and_load};

fn main() -> ExitCode {
    // Map the host arch to the manifest arch. The build
    // script embedded amd64 and arm64; `std::env::consts::ARCH`
    // is one of `x86_64` (amd64), `aarch64` (arm64), `x86` (no),
    // etc. Only amd64 and arm64 are in scope per the plan's
    // kernel-compat matrix.
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        _ => "amd64",
    };
    match probe_and_load(arch) {
        Ok(_state) => {
            let json = coverage_as_json();
            println!("{json}");
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("bpf-loader: probe_and_load returned Err: {e}");
            // Even on Err the coverage matrix is recorded by
            // the cached state; the JSON is non-empty.
            let json = coverage_as_json();
            println!("{json}");
            // The CLI exit code reflects the verdict: Err
            // paths return 2 to match the preflight convention
            // (degraded=2, blocked=77 here we use a generic
            // non-zero so the caller can branch on the JSON
            // `any_blocked` flag).
            ExitCode::from(2)
        }
    }
}
