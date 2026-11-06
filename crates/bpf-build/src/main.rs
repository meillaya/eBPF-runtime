// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Command line front end for the sensor build.
//!
//! The loader calls the library directly from its build script. This
//! binary exists so a developer can rebuild the objects and read the
//! manifest without touching the loader.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        usage();
        return ExitCode::from(2);
    };

    match command.as_str() {
        "build" => {
            let mut out_dir = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--out" => match args.next() {
                        Some(path) => out_dir = Some(PathBuf::from(path)),
                        None => {
                            eprintln!("bpf-build: --out needs a directory");
                            return ExitCode::from(2);
                        }
                    },
                    other => {
                        eprintln!("bpf-build: unknown argument {other}");
                        return ExitCode::from(2);
                    }
                }
            }

            let out_dir = out_dir.unwrap_or_else(bpf_build::default_out_dir);
            match bpf_build::build_to(&out_dir) {
                Ok(artifacts) => {
                    println!("built {} sensors in {}", artifacts.len(), out_dir.display());
                    for artifact in artifacts {
                        println!(
                            "  {:<9} {:<6} {}",
                            artifact.sensor,
                            artifact.arch,
                            &artifact.sha256[..12]
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("bpf-build: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        "--help" | "-h" | "help" => {
            usage();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("bpf-build: unknown command {other}");
            ExitCode::from(2)
        }
    }
}

fn usage() {
    println!("bpf-build build [--out DIR]");
    println!();
    println!("Compiles every sensor in bpf/sensors for the host architecture.");
    println!("The default output is target/bpf-out.");
}
