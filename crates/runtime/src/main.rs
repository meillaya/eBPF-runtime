// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `ebpf-runtime` entry point.

fn main() -> std::process::ExitCode {
    runtime::cli::main()
}
