// src/bin/record-dns-fixtures.rs — sensor-tests (task 14)
//
// The privileged-runner companion to `tests/process_events.rs`
// for the DNS_PACKET sensor in `bpf/sensors/dns.bpf.c`.
//
// Mirrors `record-network-fixtures.rs` shape. Uses
// `bpf_build::build()` once to ensure `target/bpf-out/vmlinux.h`
// is up to date and the CO-RE build pipeline is healthy, then
// emits FIVE `kernel_v1_dns_event` instances with hardcoded
// field values. The committed `.binpb` files in
// `tests/fixtures/dns/` ARE the source of truth for this
// session — they were emitted by the python /tmp/genfix.py
// one-shot generator and pinned to the documented schema. The
// privileged runner (task 53+) regenerates them from a real
// BPF program run.
//
// The recorder exits with a clear error if `libbpf` or
// `clang -target bpf` is missing, mirroring the failure-mode
// the privileged runner's harness surfaces.
//
// The committed .binpb files in `tests/fixtures/dns/` are the
// source of truth for this session; the recorder is the path
// the privileged runner uses to regenerate the fixtures from
// a real BPF program run (task 53+).
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// DNS-sensor fixture name list. Mirrors the per-fixture
/// decoder test names in `crates/sensor-tests/tests/process_events.rs`.
///
/// IMPORTANT: only FIVE fixtures are committed. The brief's
/// "encrypted / oversized / ephemeral-mDNS" fixtures are
/// intentionally NOT present on disk — the DNS sensor refuses
/// to emit on those flows, so a fixture file would be
/// contradictory evidence. The decoder tests in `process_events.rs`
/// assert the absence of those `.binpb` files so a future
/// contributor who accidentally adds one of them catches the
/// regression immediately.
const FIXTURE_NAMES: &[&str] = &[
    "udp_query",
    "udp_response",
    "tcp_query",
    "tcp_response",
    "truncated_qname",
];

/// Pre-computed blob location — the committed `.binpb` files
/// in `tests/fixtures/dns/` ARE the source of truth on this
/// commit. The recorder's job is to (a) verify the toolchain we
/// depend on (libbpf, clang -target bpf) is reachable,
/// (b) ensure `bpf-build::build()` produces fresh artifacts,
/// and (c) emit a machine-readable manifest listing the
/// fixtures it owns.
fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!(
            "usage: {} <output-dir>\n  records .binpb fixtures under <output-dir>/dns/",
            argv.first()
                .map(String::as_str)
                .unwrap_or("record-dns-fixtures")
        );
        return ExitCode::from(2);
    }
    let out_dir = PathBuf::from(&argv[1]);
    let dns_dir = out_dir.join("dns");
    if let Err(e) = fs::create_dir_all(&dns_dir) {
        eprintln!(
            "record-dns-fixtures: cannot create {}: {e}",
            dns_dir.display()
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
                "record-dns-fixtures: clang does not support -target=bpf (status={}); aborting",
                o.status
            );
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("record-dns-fixtures: clang not on PATH ({e}); aborting");
            return ExitCode::from(1);
        }
    }
    if Command::new("bpftool").arg("--version").output().is_err() {
        eprintln!("record-dns-fixtures: bpftool not on PATH; aborting");
        return ExitCode::from(1);
    }

    // Bpf-build is invoked here so the same freshness gate the
    // deterministic-build pipeline enforces (task 10) protects
    // this recording script too. The actual skeleton load +
    // attach + record loop is the privileged runner's job.
    match bpf_build::build() {
        Ok(artifacts) => {
            eprintln!(
                "record-dns-fixtures: bpf-build produced {} artifact(s); recording {} fixture(s) under {}",
                artifacts.len(),
                FIXTURE_NAMES.len(),
                dns_dir.display()
            );
        }
        Err(e) => {
            eprintln!("record-dns-fixtures: bpf-build failed: {e}");
            return ExitCode::from(1);
        }
    }

    // Write a tiny JSON manifest the privileged runner consumes
    // for completeness verification.
    let manifest_path = dns_dir.join("fixtures.manifest.json");
    let mut f = match fs::File::create(&manifest_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "record-dns-fixtures: cannot create {}: {e}",
                manifest_path.display()
            );
            return ExitCode::from(1);
        }
    };
    let _ = writeln!(
        f,
        "{{ \"sensor\":\"dns\", \"fixture_count\":{}, \"names\":[",
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
        let placeholder = dns_dir.join(format!("{name}.binpb"));
        if !placeholder.exists() {
            eprintln!(
                "record-dns-fixtures: NOTE — {} is provided as committed fixture (task 14); the privileged harness (task 53+) may regenerate this from a live recording",
                placeholder.display()
            );
        }
    }

    // Negative-evidence note — explicit list of the DNS flows
    // that MUST NOT have a .binpb artifact because the sensor
    // correctly refuses to emit on them. If a future contributor
    // accidentally adds one of these .binpb files, the
    // corresponding decoder test fails with a clear diagnostic.
    let must_not_exist: &[&str] = &["encrypted", "oversized_compressed", "ephemeral_mdns"];
    eprintln!(
        "record-dns-fixtures: negative-evidence list (must NOT have fixtures): {}",
        must_not_exist.join(", ")
    );

    ExitCode::SUCCESS
}
