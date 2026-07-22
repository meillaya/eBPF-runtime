// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet event query command.

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use super::{auth_header, scoped_url, FleetContext};
use crate::exit_code::ExitCode;
use crate::output::{format_output, render_table};

/// Event subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum EventsCmd {
    /// Query historical events.
    Query {
        /// Filter by event kind (e.g. DnsPacket, ProcessExec).
        #[arg(long)]
        kind: Option<String>,
        /// Start time (unix seconds).
        #[arg(long)]
        from: Option<u64>,
        /// End time (unix seconds).
        #[arg(long)]
        to: Option<u64>,
        /// Maximum number of results.
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Pagination cursor.
        #[arg(long)]
        cursor: Option<String>,
    },
}

/// An event record from the control-plane API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    /// Event unique identifier.
    pub id: String,
    /// Event kind.
    pub kind: String,
    /// Agent that produced the event.
    pub agent_id: String,
    /// Timestamp (unix seconds).
    pub timestamp: u64,
    /// Severity level.
    pub severity: String,
    /// Brief description.
    pub summary: String,
}

/// Paginated event query response.
#[derive(Debug, Serialize, Deserialize)]
pub struct EventQueryResponse {
    /// The events.
    pub events: Vec<EventRecord>,
    /// Next page cursor.
    pub next_cursor: Option<String>,
    /// Total matching events (if available).
    pub total: Option<u64>,
}

/// Run an events command.
pub async fn run(cmd: &EventsCmd, ctx: &FleetContext) -> ExitCode {
    match cmd {
        EventsCmd::Query {
            kind,
            from,
            to,
            limit,
            cursor,
        } => query_events(ctx, kind.as_deref(), *from, *to, *limit, cursor.as_deref()).await,
    }
}

async fn query_events(
    ctx: &FleetContext,
    kind: Option<&str>,
    from: Option<u64>,
    to: Option<u64>,
    limit: usize,
    cursor: Option<&str>,
) -> ExitCode {
    let mut path = format!("/api/v1/events?limit={limit}");
    if let Some(k) = kind {
        path.push_str(&format!("&kind={k}"));
    }
    if let Some(f) = from {
        path.push_str(&format!("&from={f}"));
    }
    if let Some(t) = to {
        path.push_str(&format!("&to={t}"));
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
        eprintln!("Error: cluster or resource not found");
        eprintln!("Suggestion: verify --cluster value");
        return ExitCode::NotFound;
    }
    if !status_code.is_success() {
        eprintln!("Error: API returned {status_code}");
        return ExitCode::Error;
    }

    let body: EventQueryResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: parsing response: {e}");
            return ExitCode::Error;
        }
    };

    let output = format_output(&body, ctx.format, |data| {
        let rows: Vec<Vec<String>> = data
            .events
            .iter()
            .map(|e| {
                vec![
                    e.id.clone(),
                    e.kind.clone(),
                    e.severity.clone(),
                    e.timestamp.to_string(),
                    e.summary.clone(),
                ]
            })
            .collect();
        let mut table =
            render_table(&["ID", "KIND", "SEVERITY", "TIMESTAMP", "SUMMARY"], &rows);
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
    fn event_record_deserializes() {
        let json = r#"{
            "id": "evt-1",
            "kind": "DnsPacket",
            "agent_id": "agent-1",
            "timestamp": 1700000000,
            "severity": "info",
            "summary": "DNS query for example.com"
        }"#;
        let record: EventRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.kind, "DnsPacket");
        assert_eq!(record.severity, "info");
    }

    #[test]
    fn event_query_response_deserializes() {
        let json = r#"{
            "events": [],
            "next_cursor": null,
            "total": 0
        }"#;
        let resp: EventQueryResponse = serde_json::from_str(json).unwrap();
        assert!(resp.events.is_empty());
        assert_eq!(resp.total, Some(0));
    }

    #[test]
    fn event_table_renders() {
        let body = EventQueryResponse {
            events: vec![EventRecord {
                id: "e1".into(),
                kind: "ProcessExec".into(),
                agent_id: "a1".into(),
                timestamp: 1700000000,
                severity: "warn".into(),
                summary: "suspicious exec".into(),
            }],
            next_cursor: None,
            total: Some(1),
        };
        let out = format_output(&body, OutputFormat::Table, |data| {
            let rows: Vec<Vec<String>> = data
                .events
                .iter()
                .map(|e| {
                    vec![
                        e.id.clone(),
                        e.kind.clone(),
                        e.severity.clone(),
                        e.timestamp.to_string(),
                        e.summary.clone(),
                    ]
                })
                .collect();
            render_table(&["ID", "KIND", "SEVERITY", "TIMESTAMP", "SUMMARY"], &rows)
        });
        assert!(out.contains("ProcessExec"));
        assert!(out.contains("warn"));
    }
}
