// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet agent listing command.

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use super::{auth_header, scoped_url, FleetContext};
use crate::exit_code::ExitCode;
use crate::output::{format_output, render_table};

/// Agent subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum AgentsCmd {
    /// List agents in the cluster.
    List {
        /// Filter by agent status (online, offline, degraded).
        #[arg(long)]
        status: Option<String>,
        /// Maximum number of results.
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Pagination cursor.
        #[arg(long)]
        cursor: Option<String>,
    },
}

/// An agent record from the control-plane API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    /// Agent unique identifier.
    pub id: String,
    /// Hostname of the agent node.
    pub hostname: String,
    /// Agent version.
    pub version: String,
    /// Current status.
    pub status: String,
    /// Last heartbeat timestamp (unix seconds).
    pub last_seen: u64,
}

/// Paginated agent list response.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentListResponse {
    /// The agents.
    pub agents: Vec<AgentRecord>,
    /// Next page cursor (None if last page).
    pub next_cursor: Option<String>,
    /// Total count (if available).
    pub total: Option<u64>,
}

/// Run an agents command.
pub async fn run(cmd: &AgentsCmd, ctx: &FleetContext) -> ExitCode {
    match cmd {
        AgentsCmd::List {
            status,
            limit,
            cursor,
        } => list_agents(ctx, status.as_deref(), *limit, cursor.as_deref()).await,
    }
}

async fn list_agents(
    ctx: &FleetContext,
    status: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
) -> ExitCode {
    let mut path = format!("/api/v1/agents?limit={limit}");
    if let Some(s) = status {
        path.push_str(&format!("&status={s}"));
    }
    if let Some(c) = cursor {
        path.push_str(&format!("&cursor={c}"));
    }

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

    let status_code = resp.status();
    if status_code == reqwest::StatusCode::UNAUTHORIZED
        || status_code == reqwest::StatusCode::FORBIDDEN
    {
        eprintln!("Error: authentication failed ({status_code})");
        eprintln!("Suggestion: re-run `cli fleet login`");
        return ExitCode::AuthFailure;
    }
    if status_code == reqwest::StatusCode::NOT_FOUND {
        eprintln!("Error: cluster not found");
        eprintln!("Suggestion: verify --cluster value");
        return ExitCode::NotFound;
    }
    if !status_code.is_success() {
        eprintln!("Error: API returned {status_code}");
        return ExitCode::Error;
    }

    let body: AgentListResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: parsing response: {e}");
            return ExitCode::Error;
        }
    };

    let output = format_output(&body, ctx.format, |data| {
        let rows: Vec<Vec<String>> = data
            .agents
            .iter()
            .map(|a| {
                vec![
                    a.id.clone(),
                    a.hostname.clone(),
                    a.version.clone(),
                    a.status.clone(),
                    a.last_seen.to_string(),
                ]
            })
            .collect();
        let mut table = render_table(&["ID", "HOSTNAME", "VERSION", "STATUS", "LAST_SEEN"], &rows);
        if let Some(ref cursor) = data.next_cursor {
            table.push_str(&format!("\nNext page: --cursor {cursor}\n"));
        }
        table
    });

    println!("{output}");
    ExitCode::Success
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::OutputFormat;

    #[test]
    fn agent_record_deserializes() {
        let json = r#"{
            "id": "agent-1",
            "hostname": "node-01",
            "version": "0.1.0",
            "status": "online",
            "last_seen": 1700000000
        }"#;
        let record: AgentRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.id, "agent-1");
        assert_eq!(record.status, "online");
    }

    #[test]
    fn agent_list_response_deserializes() {
        let json = r#"{
            "agents": [{"id": "a1", "hostname": "h1", "version": "1.0", "status": "online", "last_seen": 100}],
            "next_cursor": "abc",
            "total": 1
        }"#;
        let resp: AgentListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.agents.len(), 1);
        assert_eq!(resp.next_cursor, Some("abc".into()));
    }

    #[test]
    fn agent_table_renders() {
        let body = AgentListResponse {
            agents: vec![AgentRecord {
                id: "a1".into(),
                hostname: "node-01".into(),
                version: "0.1.0".into(),
                status: "online".into(),
                last_seen: 1700000000,
            }],
            next_cursor: None,
            total: Some(1),
        };
        let out = format_output(&body, OutputFormat::Table, |data| {
            let rows: Vec<Vec<String>> = data
                .agents
                .iter()
                .map(|a| {
                    vec![
                        a.id.clone(),
                        a.hostname.clone(),
                        a.version.clone(),
                        a.status.clone(),
                        a.last_seen.to_string(),
                    ]
                })
                .collect();
            render_table(&["ID", "HOSTNAME", "VERSION", "STATUS", "LAST_SEEN"], &rows)
        });
        assert!(out.contains("node-01"));
        assert!(out.contains("online"));
    }
}
