// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// crates/bpf-build/src/main.rs
// kernel-v1 — task 10 (libbpf-cargo CO-RE build pipeline)
//
// CLI front-end for the bpf-build pipeline. The `devenv tasks run
// bpf:build` task invokes this binary via
// `cargo run -p bpf-build -- build --out <dir> --manifest <file>`.
//
// The CLI is a thin wrapper over `bpf_build::build_to()`. The
// public library surface (`bpf_build::build()`) is what
// `bpf-loader/build.rs` and the unit tests use; the binary exists
// so a developer can re-run the pipeline by hand without
// re-compiling a downstream crate.
//
// Exit codes:
//   0  build succeeded, manifest + artifacts written
//   1  build failed (toolchain missing, SkeletonBuilder error,
//      freshness mismatch, source/output missing, I/O error)

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        eprintln!("bpf-build — kernel-v1 deterministic CO-RE pipeline (task 10)");
        eprintln!();
        eprintln!("USAGE:");
        eprintln!("    bpf-build build [--out <dir>] [--manifest <file>]");
        eprintln!();
        eprintln!("SUBCOMMANDS:");
        eprintln!("    build          Run the CO-RE compile + skeleton pipeline");
        eprintln!();
        eprintln!("OPTIONS:");
        eprintln!("    --out <dir>        Output directory for .bpf.o and .skel.rs");
        eprintln!("                      (default: <workspace>/target/bpf-out)");
        eprintln!("    --manifest <file>  Optional path to copy the manifest to.");
        eprintln!("                      The manifest is always written to");
        eprintln!("                      <out>/bpf-build.manifest.json; this");
        eprintln!("                      flag is for an additional copy in a");
        eprintln!("                      location the caller controls.");
        return ExitCode::from(0);
    }
    if args[0] != "build" {
        eprintln!("unknown subcommand: {}", args[0]);
        return ExitCode::from(2);
    }

    let mut out_dir: Option<PathBuf> = None;
    let mut extra_manifest: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                if i + 1 >= args.len() {
                    eprintln!("--out requires a path argument");
                    return ExitCode::from(2);
                }
                out_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--manifest" => {
                if i + 1 >= args.len() {
                    eprintln!("--manifest requires a path argument");
                    return ExitCode::from(2);
                }
                extra_manifest = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let out_dir = out_dir.unwrap_or_else(bpf_build_default_out_dir);
    match bpf_build::build_to(&out_dir) {
        Ok(artifacts) => {
            println!(
                "bpf-build: ok ({} artifacts in {})",
                artifacts.len(),
                out_dir.display()
            );
            for a in &artifacts {
                println!(
                    "  arch={} source={} o_sha256={} skel_sha256={}",
                    a.arch,
                    a.source,
                    &a.o_sha256[..16],
                    &a.skel_sha256[..16],
                );
            }
            if let Some(extra) = extra_manifest {
                let src = out_dir.join("bpf-build.manifest.json");
                if let Err(e) = std::fs::copy(&src, &extra) {
                    eprintln!(
                        "bpf-build: could not copy manifest to {}: {e}",
                        extra.display()
                    );
                    return ExitCode::from(1);
                }
            }
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("bpf-build: {e}");
            ExitCode::from(1)
        }
    }
}

fn bpf_build_default_out_dir() -> PathBuf {
    // Same logic as bpf_build::default_out_dir(); duplicated here
    // so the binary can compute the default before the library's
    // build script has been linked into a `cargo run` invocation.
    // The library's own `manifest_path()` remains the canonical
    // accessor at runtime.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("target/bpf-out"))
        .unwrap_or_else(|| PathBuf::from("target/bpf-out"))
}
