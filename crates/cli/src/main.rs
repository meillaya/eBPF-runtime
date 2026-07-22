// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Standalone CLI binary entry point.

use clap::Parser;

use cli::{run_cli, CliArgs, CliError};

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let args = CliArgs::parse();
    run_cli(args).await
}
