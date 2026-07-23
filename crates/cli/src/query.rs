// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Query string builders for CLI API requests.

use super::*;

pub(crate) fn push(params: &mut Vec<String>, key: &str, value: &Option<String>) {
    if let Some(v) = value {
        params.push(format!("{key}={v}"));
    }
}

pub(crate) fn finish(params: Vec<String>) -> String {
    if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    }
}

pub(crate) fn events_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "kind", &args.kind);
    push(&mut p, "from", &args.from);
    push(&mut p, "to", &args.to);
    if let Some(acked) = args.acked {
        p.push(format!("acked={acked}"));
    }
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    push(&mut p, "cursor", &args.cursor);
    finish(p)
}

pub(crate) fn process_tree_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    if let Some(pid) = args.pid {
        p.push(format!("pid={pid}"));
    }
    if let Some(depth) = args.depth {
        p.push(format!("depth={depth}"));
    }
    finish(p)
}

pub(crate) fn sockets_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "state", &args.state);
    push(&mut p, "family", &args.family);
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    push(&mut p, "cursor", &args.cursor);
    finish(p)
}

pub(crate) fn dns_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "qname", &args.qname);
    push(&mut p, "qtype", &args.qtype);
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    push(&mut p, "cursor", &args.cursor);
    finish(p)
}

pub(crate) fn files_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "path", &args.path);
    push(&mut p, "kind", &args.kind);
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    push(&mut p, "cursor", &args.cursor);
    finish(p)
}

pub(crate) fn syscall_query(args: &CliArgs) -> String {
    let mut p = Vec::new();
    push(&mut p, "syscall", &args.syscall);
    if let Some(limit) = args.limit {
        p.push(format!("limit={limit}"));
    }
    finish(p)
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

pub(crate) async fn get_text(url: &str) -> Result<String, CliError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| CliError::QueryError(format!("request to {url} failed: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| CliError::QueryError(format!("reading body from {url} failed: {e}")))?;
    if !status.is_success() {
        return Err(CliError::QueryError(format!(
            "API rejected request ({status}): {text}"
        )));
    }
    Ok(text)
}
