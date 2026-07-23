// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CLI binary entry point with stable exit codes.
#![allow(clippy::result_large_err)]

use clap::Parser;

use cli::{run_cli, CliArgs};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = CliArgs::parse();
    run_cli(args).await.into()
}
