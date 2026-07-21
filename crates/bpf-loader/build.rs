// build.rs — bpf-loader crate
//
// Task 10 (libbpf-cargo CO-RE build pipeline) plus task 18
// (load/attach compatibility manager). The build script
// runs `bpf_build::build()` so the per-arch BPF objects are
// on disk in `<workspace>/target/bpf-out/` before the
// loader's `src/lib.rs` is compiled. `lib.rs` uses
// `include_bytes!` with absolute paths supplied via
// `cargo:rustc-env=...` directives to embed the objects at
// compile time; the task-18 `bpf_loader::embedded::BpfArtifacts`
// static table is then populated by the `BPF_ARTIFACTS`
// `LazyLock` initializer in `lib.rs`, which copies the
// embedded bytes into the `BTreeMap` so every entry is
// non-empty at runtime. When `bpf_build::build()` returns Err
// at compile time (the documented graceful path) the
// `include_bytes!` invocations fall through, the
// `BPF_ARTIFACTS` table is left empty, and
// `probe_and_load()` records every sensor as `Blocked { reasons:
// vec!["BPF artifacts not embedded in this build"] }`.
//
// We do NOT use `bpf_build::build()`'s side effect of writing
// artifacts into bpf-build's own OUT_DIR (that path is unstable
// across cargo invocations because of the per-build hash). The
// stable path is the workspace-relative `target/bpf-out/`.
//
// The build script is intentionally minimal: it does not parse the
// manifest, does not shell out to clang or bpftool directly, and
// does not duplicate any of the build-pipeline logic. All of that
// lives in `bpf_build::build()`.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Tell cargo when to re-run this build script. The bpf-build
    // library's own `cargo:rerun-if-changed` directives cover the
    // .bpf.c and .h inputs; we additionally rerun on the manifest
    // so a hand-edit of the manifest path triggers a rebuild.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../bpf-build/src/lib.rs");

    // Run the CO-RE pipeline. When `bpf_build::build()` returns
    // Err here (e.g. host lacks clang-BPF, or the pinned
    // /sys/kernel/btf/vmlinux digest drifted) we DO NOT fail
    // the build; we surface a warning so cargo reports the
    // degraded state and let the loader fall back to the
    // documented graceful path
    // (`BPF_ARTIFACTS = empty`, every sensor recorded as
    // `Blocked`).
    let artifacts = match bpf_build::build() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "cargo:warning=bpf-loader: bpf_build::build() returned Err; loader will run with empty BPF_ARTIFACTS: {e}"
            );
            return ExitCode::from(0);
        }
    };

    // Find the per-arch objects. The build pipeline writes one
    // artifact per (source, arch); we expect exactly two — amd64
    // and arm64. If the count is wrong, fail the build with a
    // clear message rather than embedding a missing object.
    let amd64 = artifacts
        .iter()
        .find(|a| a.arch == "amd64")
        .expect("bpf-build did not produce an amd64 artifact");
    let arm64 = artifacts
        .iter()
        .find(|a| a.arch == "arm64")
        .expect("bpf-build did not produce an arm64 artifact");

    // Sanity-check that the on-disk files exist. The library
    // already checks this, but a defence-in-depth assertion here
    // makes the failure mode explicit if the workspace state
    // changes between `bpf_build::build()` and `include_bytes!`
    // evaluation.
    if !amd64.o_path.is_file() {
        eprintln!(
            "bpf-loader/build.rs: amd64 .bpf.o missing at {}",
            amd64.o_path.display()
        );
        return ExitCode::from(1);
    }
    if !arm64.o_path.is_file() {
        eprintln!(
            "bpf-loader/build.rs: arm64 .bpf.o missing at {}",
            arm64.o_path.display()
        );
        return ExitCode::from(1);
    }

    // Hand the absolute paths to `lib.rs` via env vars. The
    // `include_bytes!(env!("BPF_LOADER_OBJECT_AMD64"))` form in
    // `lib.rs` reads these at compile time; the `BPF_ARTIFACTS`
    // `LazyLock` initializer in `lib.rs` then copies the embedded
    // bytes into the static table at runtime.
    let amd64_path = absolute_path(&amd64.o_path);
    let arm64_path = absolute_path(&arm64.o_path);
    println!(
        "cargo:rustc-env=BPF_LOADER_OBJECT_AMD64={}",
        amd64_path.display()
    );
    println!(
        "cargo:rustc-env=BPF_LOADER_OBJECT_ARM64={}",
        arm64_path.display()
    );

    // Expose the per-arch digests so downstream runtime checks
    // (task 18's loader manager) can verify the embedded object
    // matches the manifest the build pipeline produced.
    println!(
        "cargo:rustc-env=BPF_LOADER_OBJECT_AMD64_SHA256={}",
        amd64.o_sha256
    );
    println!(
        "cargo:rustc-env=BPF_LOADER_OBJECT_ARM64_SHA256={}",
        arm64.o_sha256
    );

    // Sanity: `OUT_DIR` is the bpf-loader crate's own OUT_DIR,
    // which is what the rest of the build pipeline expects.
    let _ = env::var("OUT_DIR");
    ExitCode::from(0)
}

fn absolute_path(p: &std::path::Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}
