// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet rollout status command.

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use super::{auth_header, scoped_url, FleetContext};
use crate::exit_code::ExitCode;
use crate::output::{format_output, render_table};

/// Rollout subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum RolloutCmd {
    /// Check the status of a rollout.
    Status {
        /// The rollout ID to check.
        #[arg(long)]
        id: String,
    },
}

/// A rollout status record from the control-plane API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutStatus {
    /// Rollout unique identifier.
    pub id: String,
    /// Policy being rolled out.
    pub policy_id: String,
    /// Policy version.
    pub policy_version: u32,
    /// Rollout phase (pending, in_progress, completed, failed, rolled_back).
    pub phase: String,
    /// Number of agents targeted.
    pub target_count: u32,
    /// Number of agents completed.
    pub completed_count: u32,
    /// Number of agents failed.
    pub failed_count: u32,
    /// Start timestamp (unix seconds).
    pub started_at: u64,
    /// Last update timestamp (unix seconds).
    pub updated_at: u64,
}

/// Run a rollout command.
pub async fn run(cmd: &RolloutCmd, ctx: &FleetContext) -> ExitCode {
    match cmd {
        RolloutCmd::Status { id } => rollout_status(ctx, id).await,
    }
}

async fn rollout_status(ctx: &FleetContext, id: &str) -> ExitCode {
    let path = format!("/api/v1/rollouts/{id}");
    let url = scoped_url(&ctx.api_base, &path, &ctx.cluster);

    let token = match &ctx.token {
        Some(t) => t.clone(),
        None => {
            eprintln!("Error: not authenticated. Run `cli fleet login` first.");
            return ExitCode::AuthFailure;
        }
    };

    let client = reqwest::Client::new();
    let resp = match client
        .get(&url)
        .header("Authorization", auth_header(&token))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: request failed: {e}");
            eprintln!("Suggestion: verify the control-plane is reachable");
            return ExitCode::Error;
        }
    };

    let sc = resp.status();
    if sc == reqwest::StatusCode::UNAUTHORIZED || sc == reqwest::StatusCode::FORBIDDEN {
        eprintln!("Error: authentication failed ({sc})");
        eprintln!("Suggestion: re-run `cli fleet login`");
        return ExitCode::AuthFailure;
    }
    if sc == reqwest::StatusCode::NOT_FOUND {
        eprintln!("Error: rollout '{id}' not found");
        eprintln!("Suggestion: verify the rollout ID and --cluster scope");
        return ExitCode::NotFound;
    }
    if !sc.is_success() {
        eprintln!("Error: API returned {sc}");
        return ExitCode::Error;
    }

    let body: RolloutStatus = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: parsing response: {e}");
            return ExitCode::Error;
        }
    };

    let output = format_output(&body, ctx.format, |d| {
        let rows = vec![
            vec!["ID".into(), d.id.clone()],
            vec!["Policy".into(), d.policy_id.clone()],
            vec!["Version".into(), d.policy_version.to_string()],
            vec!["Phase".into(), d.phase.clone()],
            vec![
                "Progress".into(),
                format!("{}/{}", d.completed_count, d.target_count),
            ],
            vec!["Failed".into(), d.failed_count.to_string()],
            vec!["Started".into(), d.started_at.to_string()],
            vec!["Updated".into(), d.updated_at.to_string()],
        ];
        render_table(&["FIELD", "VALUE"], &rows)
    });

    println!("{output}");
    ExitCode::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::OutputFormat;

    #[test]
    fn rollout_status_deserializes() {
        let json = r#"{
            "id": "ro-1",
            "policy_id": "pol-1",
            "policy_version": 3,
            "phase": "in_progress",
            "target_count": 100,
            "completed_count": 45,
            "failed_count": 2,
            "started_at": 1700000000,
            "updated_at": 1700001000
        }"#;
        let status: RolloutStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.phase, "in_progress");
        assert_eq!(status.target_count, 100);
        assert_eq!(status.completed_count, 45);
    }

    #[test]
    fn rollout_table_renders() {
        let body = RolloutStatus {
            id: "ro-1".into(),
            policy_id: "pol-1".into(),
            policy_version: 3,
            phase: "completed".into(),
            target_count: 50,
            completed_count: 50,
            failed_count: 0,
            started_at: 1700000000,
            updated_at: 1700002000,
        };
        let out = format_output(&body, OutputFormat::Table, |d| {
            let rows = vec![
                vec!["ID".into(), d.id.clone()],
                vec!["Phase".into(), d.phase.clone()],
                vec![
                    "Progress".into(),
                    format!("{}/{}", d.completed_count, d.target_count),
                ],
            ];
            render_table(&["FIELD", "VALUE"], &rows)
        });
        assert!(out.contains("completed"));
        assert!(out.contains("50/50"));
    }
}
