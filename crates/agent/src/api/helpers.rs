// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared helper functions for the API surface.

use agent_core::Kind;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use privacy::RedactedEvent;
use serde_json::{json, Value};
use storage_local::EventQuery;

use super::error::ApiError;
use super::{ApiState, DEFAULT_PAGE_LIMIT, MAX_FILTER_BYTES, MAX_PAGE_LIMIT, MAX_PAGE_WINDOW};

/// Fetch up to [`MAX_PAGE_WINDOW`] events and keep those whose kind is in
/// `kinds`. Bounded projection used by the derived-view endpoints.
pub(crate) fn fetch_kinds(
    state: &ApiState,
    kinds: &[Kind],
) -> Result<Vec<RedactedEvent>, ApiError> {
    let q = EventQuery {
        limit: Some(MAX_PAGE_WINDOW),
        ..Default::default()
    };
    let all = state.storage.query_events(&q)?;
    Ok(all
        .into_iter()
        .filter(|e| kinds.contains(&e.kind))
        .collect())
}

/// Slice a bounded item list by cursor offset + capped limit and wrap it in a
/// paginated JSON envelope.
pub(crate) fn paginate_json(
    items: Vec<Value>,
    offset: usize,
    limit: usize,
    key: &str,
) -> Result<Response<Full<Bytes>>, ApiError> {
    let total = items.len();
    let next = if total > offset + limit {
        Some(encode_cursor(offset + limit))
    } else {
        None
    };
    let page: Vec<Value> = items.into_iter().skip(offset).take(limit).collect();
    let count = page.len();
    let mut m = serde_json::Map::new();
    m.insert(key.into(), json!(page));
    m.insert("count".into(), json!(count));
    m.insert("next_cursor".into(), json!(next));
    Ok(json_response(StatusCode::OK, Value::Object(m)))
}

pub(crate) fn event_pid(e: &RedactedEvent) -> u64 {
    e.namespaces.pid.unwrap_or(e.pid_tgid.0 >> 32)
}

pub(crate) fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::ProcessFork => "ProcessFork",
        Kind::ProcessExecResult => "ProcessExecResult",
        Kind::ProcessExit => "ProcessExit",
        Kind::FileOpen => "FileOpen",
        Kind::FileCreate => "FileCreate",
        Kind::FileUnlink => "FileUnlink",
        Kind::FileRename => "FileRename",
        Kind::FileTruncate => "FileTruncate",
        Kind::NetworkConnect => "NetworkConnect",
        Kind::NetworkAccept => "NetworkAccept",
        Kind::NetworkState => "NetworkState",
        Kind::DnsPacket => "DnsPacket",
        Kind::LsmDenyOwn => "LsmDenyOwn",
        Kind::SyscallEnter => "SyscallEnter",
        Kind::SyscallExit => "SyscallExit",
        Kind::Identity => "Identity",
    }
}

pub(crate) fn kind_to_i32(name: &str) -> Option<i32> {
    match name {
        "ProcessFork" => Some(1),
        "ProcessExecResult" => Some(2),
        "ProcessExit" => Some(3),
        "FileOpen" => Some(4),
        "FileCreate" => Some(5),
        "FileUnlink" => Some(6),
        "FileRename" => Some(7),
        "FileTruncate" => Some(8),
        "NetworkConnect" => Some(9),
        "NetworkAccept" => Some(10),
        "NetworkState" => Some(11),
        "DnsPacket" => Some(12),
        "LsmDenyOwn" => Some(15),
        "SyscallEnter" => Some(25),
        "SyscallExit" => Some(26),
        "Identity" => Some(27),
        _ => None,
    }
}

pub(crate) fn hex_id(id: &agent_core::EventId) -> String {
    let mut s = String::with_capacity(32);
    for b in id.0 {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

pub(crate) fn parse_limit(v: Option<&str>) -> Result<usize, ApiError> {
    match v {
        None => Ok(DEFAULT_PAGE_LIMIT),
        Some(s) => {
            check_filter(s)?;
            let n: usize = s
                .parse()
                .map_err(|_| ApiError::oversized(format!("invalid limit: {s}")))?;
            if n == 0 {
                return Err(ApiError::oversized("limit must be greater than zero"));
            }
            if n > MAX_PAGE_LIMIT {
                return Err(ApiError::oversized(format!(
                    "limit {n} exceeds max page limit {MAX_PAGE_LIMIT}"
                )));
            }
            Ok(n)
        }
    }
}

pub(crate) fn cursor_offset(cursor: Option<&str>) -> Result<usize, ApiError> {
    match cursor {
        Some(c) => decode_cursor(c),
        None => Ok(0),
    }
}

pub(crate) fn check_window(offset: usize, limit: usize) -> Result<(), ApiError> {
    if offset.saturating_add(limit).saturating_add(1) > MAX_PAGE_WINDOW {
        return Err(ApiError::oversized(format!(
            "cursor offset {offset} + limit {limit} exceeds max window {MAX_PAGE_WINDOW}"
        )));
    }
    Ok(())
}

pub(crate) fn check_filter(value: &str) -> Result<(), ApiError> {
    if value.len() > MAX_FILTER_BYTES {
        return Err(ApiError::oversized(format!(
            "filter value of {} bytes exceeds max {MAX_FILTER_BYTES}",
            value.len()
        )));
    }
    Ok(())
}

pub(crate) fn opt_filter(
    params: &[(String, String)],
    key: &str,
) -> Result<Option<String>, ApiError> {
    match get_param(params, key) {
        Some(v) => {
            check_filter(v)?;
            Ok(Some(v.to_string()))
        }
        None => Ok(None),
    }
}

/// Encode an offset as an opaque pagination cursor.
pub fn encode_cursor(offset: usize) -> String {
    format!("kc1:{offset:x}")
}

/// Decode an opaque pagination cursor back to an offset. Rejects malformed
/// cursors with a typed [`super::ApiErrorKind::InvalidCursorError`].
pub fn decode_cursor(cursor: &str) -> Result<usize, ApiError> {
    check_filter(cursor).map_err(|_| ApiError::invalid_cursor("cursor too large"))?;
    let rest = cursor
        .strip_prefix("kc1:")
        .ok_or_else(|| ApiError::invalid_cursor(format!("malformed cursor: {cursor}")))?;
    usize::from_str_radix(rest, 16)
        .map_err(|_| ApiError::invalid_cursor(format!("malformed cursor: {cursor}")))
}

pub(crate) fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?.to_string();
            let v = it.next().unwrap_or("").to_string();
            Some((url_decode(&k), url_decode(&v)))
        })
        .collect()
}

pub(crate) fn get_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Minimal percent-decoding (plus `+` → space) for query values.
pub(crate) fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8 as char);
                    i += 3;
                } else {
                    out.push('%');
                    i += 1;
                }
            }
            b => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

pub(crate) fn json_response(status: StatusCode, value: Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&value).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("static header names are valid")
}

pub(crate) fn text_response(
    status: StatusCode,
    content_type: &str,
    text: String,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(text.into_bytes())))
        .expect("static header names are valid")
}

pub(crate) fn error_response(
    status: StatusCode,
    kind: &str,
    message: &str,
) -> Response<Full<Bytes>> {
    json_response(
        status,
        json!({ "error": { "kind": kind, "message": message } }),
    )
}
