// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Derived-view endpoint handlers (bounded projections over the events table).

use std::collections::BTreeMap;

use agent_core::Kind;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use serde_json::{json, Value};

use super::error::ApiError;
use super::helpers::*;
use super::ApiState;

pub(crate) fn process_tree(
    state: &ApiState,
    query: &str,
) -> Result<Response<Full<Bytes>>, ApiError> {
    let params = parse_query(query);
    let pid_filter: Option<u64> = match get_param(&params, "pid") {
        Some(p) => {
            check_filter(p)?;
            Some(
                p.parse::<u64>()
                    .map_err(|_| ApiError::query(format!("invalid pid: {p}")))?,
            )
        }
        None => None,
    };
    let depth: usize = match get_param(&params, "depth") {
        Some(d) => {
            check_filter(d)?;
            d.parse::<usize>()
                .map_err(|_| ApiError::query(format!("invalid depth: {d}")))?
        }
        None => 8,
    };
    if depth == 0 || depth > 64 {
        return Err(ApiError::oversized(format!(
            "depth {depth} out of range 1..=64"
        )));
    }
    let procs = fetch_kinds(
        state,
        &[
            Kind::ProcessFork,
            Kind::ProcessExecResult,
            Kind::ProcessExit,
        ],
    )?;
    let mut by_pid: BTreeMap<u64, Vec<&privacy::RedactedEvent>> = BTreeMap::new();
    for e in &procs {
        let pid = event_pid(e);
        if let Some(pf) = pid_filter {
            if pid != pf {
                continue;
            }
        }
        by_pid.entry(pid).or_default().push(e);
    }
    let mut processes: Vec<Value> = Vec::new();
    for (pid, evs) in by_pid.iter().take(depth) {
        let mut kind_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for e in evs {
            *kind_counts.entry(kind_name(e.kind)).or_default() += 1;
        }
        let event_ids: Vec<String> = evs.iter().map(|e| hex_id(&e.event_id)).collect();
        processes.push(json!({
            "pid": pid,
            "kinds": kind_counts,
            "event_ids": event_ids,
            "event_count": evs.len(),
        }));
    }
    let count = processes.len();
    Ok(json_response(
        StatusCode::OK,
        json!({ "processes": processes, "count": count, "depth": depth }),
    ))
}

pub(crate) fn sockets(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
    let params = parse_query(query);
    let state_f = opt_filter(&params, "state")?;
    let family_f = opt_filter(&params, "family")?;
    let limit = parse_limit(get_param(&params, "limit"))?;
    let offset = cursor_offset(get_param(&params, "cursor"))?;
    check_window(offset, limit)?;
    let nets = fetch_kinds(
        state,
        &[
            Kind::NetworkConnect,
            Kind::NetworkAccept,
            Kind::NetworkState,
        ],
    )?;
    let mut items: Vec<Value> = Vec::new();
    for e in &nets {
        let family = e
            .arguments
            .first()
            .cloned()
            .unwrap_or_else(|| "inet".to_string());
        let st = e
            .arguments
            .get(1)
            .cloned()
            .unwrap_or_else(|| "established".to_string());
        if let Some(sf) = &state_f {
            if &st != sf {
                continue;
            }
        }
        if let Some(ff) = &family_f {
            if &family != ff {
                continue;
            }
        }
        items.push(json!({
            "pid": event_pid(e),
            "kind": kind_name(e.kind),
            "family": family,
            "state": st,
            "path": e.path,
            "event_id": hex_id(&e.event_id),
        }));
    }
    paginate_json(items, offset, limit, "sockets")
}

pub(crate) fn dns(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
    let params = parse_query(query);
    let qname_f = opt_filter(&params, "qname")?;
    let qtype_f: Option<u16> = match get_param(&params, "qtype") {
        Some(t) => {
            check_filter(t)?;
            Some(
                t.parse::<u16>()
                    .map_err(|_| ApiError::query(format!("invalid qtype: {t}")))?,
            )
        }
        None => None,
    };
    let limit = parse_limit(get_param(&params, "limit"))?;
    let offset = cursor_offset(get_param(&params, "cursor"))?;
    check_window(offset, limit)?;
    let dns_events = fetch_kinds(state, &[Kind::DnsPacket])?;
    let mut items: Vec<Value> = Vec::new();
    for e in &dns_events {
        let qname = e.dns_qname.clone().unwrap_or_default();
        let qtype = e.dns_qtype.unwrap_or(0);
        if let Some(qf) = &qname_f {
            if !qname.contains(qf.as_str()) {
                continue;
            }
        }
        if let Some(qt) = qtype_f {
            if qtype != qt {
                continue;
            }
        }
        items.push(json!({
            "qname": qname,
            "qtype": qtype,
            "qclass": e.dns_qclass,
            "an_count": e.dns_an_count,
            "pid": event_pid(e),
            "event_id": hex_id(&e.event_id),
        }));
    }
    paginate_json(items, offset, limit, "dns")
}

pub(crate) fn files(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
    let params = parse_query(query);
    let path_f = opt_filter(&params, "path")?;
    let kind_f = opt_filter(&params, "kind")?;
    let limit = parse_limit(get_param(&params, "limit"))?;
    let offset = cursor_offset(get_param(&params, "cursor"))?;
    check_window(offset, limit)?;
    let file_events = fetch_kinds(
        state,
        &[
            Kind::FileOpen,
            Kind::FileCreate,
            Kind::FileUnlink,
            Kind::FileRename,
            Kind::FileTruncate,
        ],
    )?;
    let mut items: Vec<Value> = Vec::new();
    for e in &file_events {
        let path = e.path.clone().unwrap_or_default();
        let kn = kind_name(e.kind);
        if let Some(pf) = &path_f {
            if !path.contains(pf.as_str()) {
                continue;
            }
        }
        if let Some(kf) = &kind_f {
            if kn != kf.as_str() {
                continue;
            }
        }
        items.push(json!({
            "path": path,
            "kind": kn,
            "pid": event_pid(e),
            "event_id": hex_id(&e.event_id),
        }));
    }
    paginate_json(items, offset, limit, "files")
}

pub(crate) fn syscall_histograms(
    state: &ApiState,
    query: &str,
) -> Result<Response<Full<Bytes>>, ApiError> {
    let params = parse_query(query);
    let syscall_f = opt_filter(&params, "syscall")?;
    let limit = parse_limit(get_param(&params, "limit"))?;
    let sc = fetch_kinds(state, &[Kind::SyscallEnter, Kind::SyscallExit])?;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for e in &sc {
        let name = e
            .arguments
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        if let Some(sf) = &syscall_f {
            if &name != sf {
                continue;
            }
        }
        *counts.entry(name).or_default() += 1;
    }
    let total: usize = counts.values().sum();
    let mut histograms: Vec<Value> = counts
        .iter()
        .map(|(k, v)| json!({ "syscall": k, "count": v }))
        .collect();
    histograms.truncate(limit);
    let count = histograms.len();
    Ok(json_response(
        StatusCode::OK,
        json!({ "histograms": histograms, "count": count, "total": total }),
    ))
}
