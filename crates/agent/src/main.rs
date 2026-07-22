// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Standalone agent binary entry point.

use clap::Parser;

use agent::{run_agent, AgentArgs, AgentError};

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    let args = AgentArgs::parse();
    run_agent(args).await
}
