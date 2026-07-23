// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Event query endpoint handlers.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use privacy::RedactedEvent;
use serde_json::{json, Value};
use storage_local::EventQuery;

use super::error::ApiError;
use super::helpers::*;
use super::ApiState;

pub(crate) fn health(state: &ApiState) -> Result<Response<Full<Bytes>>, ApiError> {
    let h = state.registry.health();
    Ok(json_response(
        StatusCode::OK,
        json!({ "status": format!("{}", h.status), "reasons": h.reasons }),
    ))
}

pub(crate) fn readiness(state: &ApiState) -> Result<Response<Full<Bytes>>, ApiError> {
    let r = state.registry.readiness();
    Ok(json_response(
        StatusCode::OK,
        json!({ "status": format!("{}", r.status), "reasons": r.reasons }),
    ))
}

pub(crate) fn metrics(state: &ApiState) -> Result<Response<Full<Bytes>>, ApiError> {
    let text = state.registry.metrics();
    Ok(text_response(
        StatusCode::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        text,
    ))
}

pub(crate) fn events(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
    let params = parse_query(query);
    let (page, next) = query_event_page(state, &params)?;
    let events_json: Vec<Value> = page.iter().map(|e| e.to_json()).collect();
    let count = events_json.len();
    Ok(json_response(
        StatusCode::OK,
        json!({ "events": events_json, "count": count, "next_cursor": next }),
    ))
}

pub(crate) fn single_event(state: &ApiState, id: &str) -> Result<Response<Full<Bytes>>, ApiError> {
    check_filter(id)?;
    let q = EventQuery {
        limit: Some(super::MAX_PAGE_WINDOW),
        ..Default::default()
    };
    let all = state.storage.query_events(&q)?;
    for e in &all {
        if hex_id(&e.event_id) == id {
            return Ok(json_response(StatusCode::OK, e.to_json()));
        }
    }
    Ok(error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        &format!("no event with id {id}"),
    ))
}

pub(crate) fn export(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
    let params = parse_query(query);
    let (page, next) = query_event_page(state, &params)?;
    let mut body = String::new();
    for e in page {
        body.push_str(&serde_json::to_string(&e.to_json()).unwrap_or_default());
        body.push('\n');
    }
    let mut resp = text_response(StatusCode::OK, "application/x-ndjson", body);
    if let Some(cursor) = next {
        resp.headers_mut().insert(
            "x-next-cursor",
            cursor
                .parse()
                .unwrap_or_else(|_| " ".parse().expect("space is a valid header value")),
        );
    }
    Ok(resp)
}

/// Shared bounded event query: applies kind/from/to/acked filters at the SQL
/// layer, then opaque-cursor offset + capped limit in memory. Returns the page
/// and the next cursor (if more results exist).
pub(crate) fn query_event_page(
    state: &ApiState,
    params: &[(String, String)],
) -> Result<(Vec<RedactedEvent>, Option<String>), ApiError> {
    let mut q = EventQuery::default();
    if let Some(kind) = get_param(params, "kind") {
        check_filter(kind)?;
        let ki = kind_to_i32(kind)
            .ok_or_else(|| ApiError::query(format!("unknown event kind: {kind}")))?;
        q.event_kind = Some(ki);
    }
    if let Some(from) = get_param(params, "from") {
        check_filter(from)?;
        q.created_at_from = Some(
            from.parse::<i64>()
                .map_err(|_| ApiError::query(format!("invalid from timestamp: {from}")))?,
        );
    }
    if let Some(to) = get_param(params, "to") {
        check_filter(to)?;
        q.created_at_to = Some(
            to.parse::<i64>()
                .map_err(|_| ApiError::query(format!("invalid to timestamp: {to}")))?,
        );
    }
    if let Some(acked) = get_param(params, "acked") {
        check_filter(acked)?;
        q.acked = Some(matches!(acked, "true" | "1"));
    }
    let limit = parse_limit(get_param(params, "limit"))?;
    let offset = match get_param(params, "cursor") {
        Some(c) => decode_cursor(c)?,
        None => 0,
    };
    check_window(offset, limit)?;
    q.limit = Some(offset + limit + 1);
    let all = state.storage.query_events(&q)?;
    let next = if all.len() > offset + limit {
        Some(encode_cursor(offset + limit))
    } else {
        None
    };
    let page: Vec<RedactedEvent> = all.into_iter().skip(offset).take(limit).collect();
    Ok((page, next))
}
