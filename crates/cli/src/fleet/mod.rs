// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet-mode commands that talk to the control-plane API.
//!
//! All fleet commands require `--cluster` (no unscoped queries)
//! and authenticate via OIDC device flow (RFC 8628).

pub mod agents;
pub mod auth;
pub mod events;
pub mod policy;
pub mod rollout;
pub mod stream;

use clap::Subcommand;

use crate::exit_code::ExitCode;
use crate::output::OutputFormat;

/// Fleet subcommands (require authentication + cluster scope).
#[derive(Debug, Clone, Subcommand)]
pub enum FleetCommand {
    /// Authenticate via OIDC device flow (RFC 8628).
    Login,
    /// Agent inventory commands.
    Agents {
        #[command(subcommand)]
        cmd: agents::AgentsCmd,
    },
    /// Event query commands.
    Events {
        #[command(subcommand)]
        cmd: events::EventsCmd,
    },
    /// Policy management commands.
    Policy {
        #[command(subcommand)]
        cmd: policy::PolicyCmd,
    },
    /// Rollout status commands.
    Rollout {
        #[command(subcommand)]
        cmd: rollout::RolloutCmd,
    },
    /// Live event streaming.
    Stream {
        #[command(subcommand)]
        cmd: stream::StreamCmd,
    },
}

/// Fleet-level arguments shared across all fleet commands.
#[derive(Debug, Clone)]
pub struct FleetContext {
    /// Control-plane API base URL.
    pub api_base: String,
    /// Cluster scope (required for all fleet commands).
    pub cluster: String,
    /// Output format.
    pub format: OutputFormat,
    /// Bearer token (from device flow or cached).
    pub token: Option<String>,
}

/// Dispatch a fleet command. Returns the exit code.
pub async fn dispatch(cmd: &FleetCommand, ctx: &FleetContext) -> ExitCode {
    match cmd {
        FleetCommand::Login => auth::login(ctx).await,
        FleetCommand::Agents { cmd } => agents::run(cmd, ctx).await,
        FleetCommand::Events { cmd } => events::run(cmd, ctx).await,
        FleetCommand::Policy { cmd } => policy::run(cmd, ctx).await,
        FleetCommand::Rollout { cmd } => rollout::run(cmd, ctx).await,
        FleetCommand::Stream { cmd } => stream::run(cmd, ctx).await,
    }
}

/// Build the authorization header value.
pub fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

/// Build a URL with cluster scope query parameter.
pub fn scoped_url(base: &str, path: &str, cluster: &str) -> String {
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{base}{path}{sep}cluster_id={cluster}")
}
