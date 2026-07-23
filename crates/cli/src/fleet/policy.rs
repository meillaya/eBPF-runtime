// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet policy management commands (list, stage, commit).

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use super::{auth_header, scoped_url, FleetContext};
use crate::exit_code::ExitCode;
use crate::output::{format_output, render_table};

/// Policy subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum PolicyCmd {
    /// List policies in the cluster.
    List {
        /// Maximum number of results.
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Pagination cursor.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Stage a new policy version.
    Stage {
        /// Path to the policy file (YAML/JSON).
        #[arg(long)]
        file: String,
    },
    /// Commit a staged policy (activate it).
    Commit {
        /// The staged policy version ID to commit.
        #[arg(long)]
        version_id: String,
    },
}

/// A policy record from the control-plane API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    /// Policy unique identifier.
    pub id: String,
    /// Policy name.
    pub name: String,
    /// Current version.
    pub version: u32,
    /// Policy status (active, staged, archived).
    pub status: String,
    /// Last updated timestamp (unix seconds).
    pub updated_at: u64,
}

/// Paginated policy list response.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyListResponse {
    /// The policies.
    pub policies: Vec<PolicyRecord>,
    /// Next page cursor.
    pub next_cursor: Option<String>,
}

/// Stage/commit mutation response.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyMutationResponse {
    /// The affected policy ID.
    pub policy_id: String,
    /// The new version number.
    pub version: u32,
    /// Result status.
    pub status: String,
}

/// Run a policy command.
pub async fn run(cmd: &PolicyCmd, ctx: &FleetContext) -> ExitCode {
    match cmd {
        PolicyCmd::List { limit, cursor } => {
            list_policies(ctx, *limit, cursor.as_deref()).await
        }
        PolicyCmd::Stage { file } => stage_policy(ctx, file).await,
        PolicyCmd::Commit { version_id } => commit_policy(ctx, version_id).await,
    }
}

async fn list_policies(ctx: &FleetContext, limit: usize, cursor: Option<&str>) -> ExitCode {
    let mut path = format!("/api/v1/policies?limit={limit}");
    if let Some(c) = cursor {
        path.push_str(&format!("&cursor={c}"));
    }
    api_get(ctx, &path, |body: PolicyListResponse| {
        format_output(&body, ctx.format, |data| {
            let rows: Vec<Vec<String>> = data
                .policies
                .iter()
                .map(|p| {
                    vec![
                        p.id.clone(),
                        p.name.clone(),
                        p.version.to_string(),
                        p.status.clone(),
                        p.updated_at.to_string(),
                    ]
                })
                .collect();
            render_table(&["ID", "NAME", "VERSION", "STATUS", "UPDATED"], &rows)
        })
    })
    .await
}

async fn stage_policy(ctx: &FleetContext, file: &str) -> ExitCode {
    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: cannot read policy file '{file}': {e}");
            eprintln!("Suggestion: verify the file path exists and is readable");
            return ExitCode::Error;
        }
    };

    let url = scoped_url(&ctx.api_base, "/api/v1/policies/stage", &ctx.cluster);
    api_post(ctx, &url, &content).await
}

async fn commit_policy(ctx: &FleetContext, version_id: &str) -> ExitCode {
    let url = scoped_url(&ctx.api_base, "/api/v1/policies/commit", &ctx.cluster);
    let body = serde_json::json!({ "version_id": version_id });
    api_post(ctx, &url, &body.to_string()).await
}

/// Generic GET helper for policy endpoints.
async fn api_get<T, F>(ctx: &FleetContext, path: &str, render: F) -> ExitCode
where
    T: serde::de::DeserializeOwned,
    F: FnOnce(T) -> String,
{
    let url = scoped_url(&ctx.api_base, path, &ctx.cluster);
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
        eprintln!("Error: resource not found");
        eprintln!("Suggestion: verify --cluster and resource ID");
        return ExitCode::NotFound;
    }
    if !sc.is_success() {
        eprintln!("Error: API returned {sc}");
        return ExitCode::Error;
    }

    match resp.json::<T>().await {
        Ok(body) => {
            println!("{}", render(body));
            ExitCode::Success
        }
        Err(e) => {
            eprintln!("Error: parsing response: {e}");
            ExitCode::Error
        }
    }
}

/// Generic POST helper for policy mutations.
async fn api_post(ctx: &FleetContext, url: &str, body: &str) -> ExitCode {
    let token = match &ctx.token {
        Some(t) => t.clone(),
        None => {
            eprintln!("Error: not authenticated. Run `cli fleet login` first.");
            return ExitCode::AuthFailure;
        }
    };

    let client = reqwest::Client::new();
    let resp = match client
        .post(url)
        .header("Authorization", auth_header(&token))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: request failed: {e}");
            return ExitCode::Error;
        }
    };

    let sc = resp.status();
    if sc == reqwest::StatusCode::UNAUTHORIZED || sc == reqwest::StatusCode::FORBIDDEN {
        eprintln!("Error: authentication failed ({sc})");
        eprintln!("Suggestion: re-run `cli fleet login`");
        return ExitCode::AuthFailure;
    }
    if !sc.is_success() {
        let text = resp.text().await.unwrap_or_default();
        eprintln!("Error: API returned {sc}: {text}");
        return ExitCode::Error;
    }

    match resp.json::<PolicyMutationResponse>().await {
        Ok(body) => {
            let out = format_output(&body, ctx.format, |d| {
                format!(
                    "Policy {} -> version {} ({})",
                    d.policy_id, d.version, d.status
                )
            });
            println!("{out}");
            ExitCode::Success
        }
        Err(e) => {
            eprintln!("Error: parsing response: {e}");
            ExitCode::Error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::OutputFormat;

    #[test]
    fn policy_record_deserializes() {
        let json = r#"{
            "id": "pol-1",
            "name": "default-deny",
            "version": 3,
            "status": "active",
            "updated_at": 1700000000
        }"#;
        let record: PolicyRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.name, "default-deny");
        assert_eq!(record.version, 3);
    }

    #[test]
    fn policy_mutation_response_deserializes() {
        let json = r#"{
            "policy_id": "pol-1",
            "version": 4,
            "status": "staged"
        }"#;
        let resp: PolicyMutationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.version, 4);
        assert_eq!(resp.status, "staged");
    }

    #[test]
    fn policy_table_renders() {
        let body = PolicyListResponse {
            policies: vec![PolicyRecord {
                id: "p1".into(),
                name: "deny-all".into(),
                version: 1,
                status: "active".into(),
                updated_at: 1700000000,
            }],
            next_cursor: None,
        };
        let out = format_output(&body, OutputFormat::Table, |data| {
            let rows: Vec<Vec<String>> = data
                .policies
                .iter()
                .map(|p| {
                    vec![
                        p.id.clone(),
                        p.name.clone(),
                        p.version.to_string(),
                        p.status.clone(),
                        p.updated_at.to_string(),
                    ]
                })
                .collect();
            render_table(&["ID", "NAME", "VERSION", "STATUS", "UPDATED"], &rows)
        });
        assert!(out.contains("deny-all"));
        assert!(out.contains("active"));
    }
}
