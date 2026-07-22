// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Versioned local REST/WebSocket API for the standalone node service.
//!
//! Safety invariants enforced here (plan task 26):
//! - The API only READS redacted events from local storage; it never exposes
//!   loader or BPF map mutation.
//! - The no-auth dev surface only ever binds to a loopback address. A
//!   non-loopback bind (e.g. `0.0.0.0`) is rejected by a strict check.
//! - Every returned event is a [`privacy::RedactedEvent`] projection; the raw
//!   pre-redaction payload is structurally absent, so the API cannot bypass
//!   redaction.
//! - Every query is bounded: pagination via opaque cursors, a hard page-size
//!   cap, a hard pagination-window cap, and a hard per-filter byte cap. The API
//!   never returns unbounded results.
//! - A slow WebSocket consumer is shed (typed rejection) without crashing the
//!   server.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use agent_core::Kind;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use privacy::RedactedEvent;
use serde_json::{json, Value};
use storage_local::{EventQuery, LocalStorage};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use observability::MetricsRegistry;

// ---------------------------------------------------------------------------
// Bounded-query constants (mirrors of bench/schemas/storage.v1.json defaults)
// ---------------------------------------------------------------------------

/// Default page size for bounded paginated queries.
pub const DEFAULT_PAGE_LIMIT: usize = 100;
/// Hard upper bound on a single page size.
pub const MAX_PAGE_LIMIT: usize = 1000;
/// Hard upper bound on (cursor offset + limit).
pub const MAX_PAGE_WINDOW: usize = 10000;
/// Hard upper bound on the byte length of a single filter value / cursor.
pub const MAX_FILTER_BYTES: usize = 1024;
/// Bounded capacity of the live-event broadcast channel.
pub const WS_BROADCAST_CAPACITY: usize = 1024;
/// Maximum time a single WebSocket send may block before the consumer is
/// considered slow and shed.
pub const WS_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
/// Default loopback dev bind address.
pub const DEFAULT_DEV_BIND: &str = "127.0.0.1:9464";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// The kind of API error. Each variant maps to a typed HTTP rejection so the
/// server fails closed without crashing.
#[derive(Debug)]
pub enum ApiErrorKind {
    BindError(std::io::Error),
    ServeError(hyper::Error),
    StorageError(storage_local::StorageError),
    QueryError(String),
    WebSocketError(tokio_tungstenite::tungstenite::Error),
    NonLoopbackBindError(String),
    InvalidCursorError(String),
    OversizedFilterError(String),
    SlowConsumerError(String),
}

/// A typed API error.
#[derive(Debug)]
pub struct ApiError {
    pub kind: ApiErrorKind,
}

impl ApiError {
    pub fn query(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::QueryError(msg.into()),
        }
    }
    pub fn invalid_cursor(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::InvalidCursorError(msg.into()),
        }
    }
    pub fn oversized(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::OversizedFilterError(msg.into()),
        }
    }
    pub fn slow_consumer(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::SlowConsumerError(msg.into()),
        }
    }
    pub fn non_loopback(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::NonLoopbackBindError(msg.into()),
        }
    }

    /// Stable string label for the error kind (used in typed JSON rejections).
    pub fn kind_str(&self) -> &'static str {
        match self.kind {
            ApiErrorKind::BindError(_) => "bind_error",
            ApiErrorKind::ServeError(_) => "serve_error",
            ApiErrorKind::StorageError(_) => "storage_error",
            ApiErrorKind::QueryError(_) => "query_error",
            ApiErrorKind::WebSocketError(_) => "websocket_error",
            ApiErrorKind::NonLoopbackBindError(_) => "non_loopback_bind_error",
            ApiErrorKind::InvalidCursorError(_) => "invalid_cursor_error",
            ApiErrorKind::OversizedFilterError(_) => "oversized_filter_error",
            ApiErrorKind::SlowConsumerError(_) => "slow_consumer_error",
        }
    }

    /// Map the error to an HTTP status code for the typed JSON rejection.
    pub fn status(&self) -> StatusCode {
        match self.kind {
            ApiErrorKind::InvalidCursorError(_)
            | ApiErrorKind::OversizedFilterError(_)
            | ApiErrorKind::QueryError(_)
            | ApiErrorKind::WebSocketError(_) => StatusCode::BAD_REQUEST,
            ApiErrorKind::SlowConsumerError(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiErrorKind::NonLoopbackBindError(_) => StatusCode::FORBIDDEN,
            ApiErrorKind::StorageError(_)
            | ApiErrorKind::BindError(_)
            | ApiErrorKind::ServeError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Render the error as a typed JSON rejection response.
    pub fn into_response(self) -> Response<Full<Bytes>> {
        let status = self.status();
        let kind = self.kind_str();
        let message = format!("{self}");
        error_response(status, kind, &message)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ApiErrorKind::BindError(e) => write!(f, "bind error: {e}"),
            ApiErrorKind::ServeError(e) => write!(f, "serve error: {e}"),
            ApiErrorKind::StorageError(e) => write!(f, "storage error: {e}"),
            ApiErrorKind::QueryError(m) => write!(f, "query error: {m}"),
            ApiErrorKind::WebSocketError(e) => write!(f, "websocket error: {e}"),
            ApiErrorKind::NonLoopbackBindError(m) => write!(f, "non-loopback bind rejected: {m}"),
            ApiErrorKind::InvalidCursorError(m) => write!(f, "invalid cursor: {m}"),
            ApiErrorKind::OversizedFilterError(m) => write!(f, "oversized filter: {m}"),
            ApiErrorKind::SlowConsumerError(m) => write!(f, "slow consumer shed: {m}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<storage_local::StorageError> for ApiError {
    fn from(e: storage_local::StorageError) -> Self {
        Self {
            kind: ApiErrorKind::StorageError(e),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        Self {
            kind: ApiErrorKind::BindError(e),
        }
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ApiError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Self {
            kind: ApiErrorKind::WebSocketError(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// The standalone API server. Reads redacted events from local storage and
/// serves the versioned REST + WebSocket surface. Never exposes loader/map
/// mutation; never binds no-auth to non-loopback; never bypasses redaction;
/// never returns unbounded results.
pub struct ApiServer {
    pub storage: Arc<LocalStorage>,
    pub registry: Arc<MetricsRegistry>,
    pub addr: SocketAddr,
    pub broadcaster: broadcast::Sender<String>,
}

/// Per-connection shared state.
struct ApiState {
    storage: Arc<LocalStorage>,
    registry: Arc<MetricsRegistry>,
    broadcaster: broadcast::Sender<String>,
}

impl ApiServer {
    /// Construct a server with a fresh bounded broadcast channel for live
    /// events.
    pub fn new(storage: Arc<LocalStorage>, registry: Arc<MetricsRegistry>, addr: SocketAddr) -> Self {
        let (broadcaster, _) = broadcast::channel(WS_BROADCAST_CAPACITY);
        Self {
            storage,
            registry,
            addr,
            broadcaster,
        }
    }

    /// A clone of the live-event broadcast sender. The agent loop uses this to
    /// publish each redacted event as it is inserted into local storage.
    pub fn broadcaster(&self) -> broadcast::Sender<String> {
        self.broadcaster.clone()
    }

    /// Serve the API. Rejects a non-loopback bind up front (strict check), then
    /// accepts HTTP/1.1 connections (with WebSocket upgrades) until the task is
    /// dropped/aborted.
    pub async fn serve(&self) -> Result<(), ApiError> {
        if !self.addr.ip().is_loopback() {
            return Err(ApiError::non_loopback(format!(
                "refusing no-auth bind to non-loopback address {}",
                self.addr
            )));
        }
        let listener = TcpListener::bind(self.addr).await?;
        tracing::info!(addr = %self.addr, "agent API listening (loopback, no-auth dev surface)");
        let state = Arc::new(ApiState {
            storage: self.storage.clone(),
            registry: self.registry.clone(),
            broadcaster: self.broadcaster.clone(),
        });
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!(error = %e, "accept failed");
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let state = state.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    async move { Ok::<_, Infallible>(route(req, state).await) }
                });
                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, svc)
                    .with_upgrades()
                    .await
                {
                    tracing::debug!(peer = %peer, error = %e, "connection closed");
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

async fn route(req: Request<Incoming>, state: Arc<ApiState>) -> Response<Full<Bytes>> {
    // WebSocket upgrade is handled first because it consumes the request.
    if req.method() == Method::GET && req.uri().path() == "/ws" {
        return websocket(req, &state);
    }
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    if req.method() != Method::GET {
        return error_response(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "only GET is supported");
    }
    let result = match path.as_str() {
        "/api/v1/health" => health(&state),
        "/api/v1/readiness" => readiness(&state),
        "/api/v1/metrics" => metrics(&state),
        "/api/v1/events" => events(&state, &query),
        "/api/v1/process-tree" => process_tree(&state, &query),
        "/api/v1/sockets" => sockets(&state, &query),
        "/api/v1/dns" => dns(&state, &query),
        "/api/v1/files" => files(&state, &query),
        "/api/v1/syscall-histograms" => syscall_histograms(&state, &query),
        "/api/v1/export" => export(&state, &query),
        p if p.starts_with("/api/v1/events/") => single_event(&state, &p["/api/v1/events/".len()..]),
        _ => Err(ApiError::query(format!("unknown route: {path}"))),
    };
    match result {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Observability endpoints
// ---------------------------------------------------------------------------

fn health(state: &ApiState) -> Result<Response<Full<Bytes>>, ApiError> {
    let h = state.registry.health();
    Ok(json_response(
        StatusCode::OK,
        json!({ "status": format!("{}", h.status), "reasons": h.reasons }),
    ))
}

fn readiness(state: &ApiState) -> Result<Response<Full<Bytes>>, ApiError> {
    let r = state.registry.readiness();
    Ok(json_response(
        StatusCode::OK,
        json!({ "status": format!("{}", r.status), "reasons": r.reasons }),
    ))
}

fn metrics(state: &ApiState) -> Result<Response<Full<Bytes>>, ApiError> {
    let text = state.registry.metrics();
    Ok(text_response(
        StatusCode::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        text,
    ))
}

// ---------------------------------------------------------------------------
// Event query endpoints
// ---------------------------------------------------------------------------

fn events(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
    let params = parse_query(query);
    let (page, next) = query_event_page(state, &params)?;
    let events_json: Vec<Value> = page.iter().map(|e| e.to_json()).collect();
    let count = events_json.len();
    Ok(json_response(
        StatusCode::OK,
        json!({ "events": events_json, "count": count, "next_cursor": next }),
    ))
}

fn single_event(state: &ApiState, id: &str) -> Result<Response<Full<Bytes>>, ApiError> {
    check_filter(id)?;
    let mut q = EventQuery::default();
    q.limit = Some(MAX_PAGE_WINDOW);
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

fn export(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
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
            cursor.parse().unwrap_or_else(|_| " ".parse().unwrap()),
        );
    }
    Ok(resp)
}

/// Shared bounded event query: applies kind/from/to/acked filters at the SQL
/// layer, then opaque-cursor offset + capped limit in memory. Returns the page
/// and the next cursor (if more results exist).
fn query_event_page(
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

// ---------------------------------------------------------------------------
// Derived-view endpoints (bounded projections over the events table)
// ---------------------------------------------------------------------------

fn process_tree(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
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
        return Err(ApiError::oversized(format!("depth {depth} out of range 1..=64")));
    }
    let procs = fetch_kinds(
        state,
        &[Kind::ProcessFork, Kind::ProcessExecResult, Kind::ProcessExit],
    )?;
    let mut by_pid: BTreeMap<u64, Vec<&RedactedEvent>> = BTreeMap::new();
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

fn sockets(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
    let params = parse_query(query);
    let state_f = opt_filter(&params, "state")?;
    let family_f = opt_filter(&params, "family")?;
    let limit = parse_limit(get_param(&params, "limit"))?;
    let offset = cursor_offset(get_param(&params, "cursor"))?;
    check_window(offset, limit)?;
    let nets = fetch_kinds(
        state,
        &[Kind::NetworkConnect, Kind::NetworkAccept, Kind::NetworkState],
    )?;
    let mut items: Vec<Value> = Vec::new();
    for e in &nets {
        let family = e.arguments.first().cloned().unwrap_or_else(|| "inet".to_string());
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

fn dns(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
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

fn files(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
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

fn syscall_histograms(state: &ApiState, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
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

// ---------------------------------------------------------------------------
// WebSocket live events
// ---------------------------------------------------------------------------

fn is_ws_upgrade(req: &Request<Incoming>) -> bool {
    let upgrade = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = req
        .headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    upgrade && connection
}

fn websocket(req: Request<Incoming>, state: &ApiState) -> Response<Full<Bytes>> {
    let key = req
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if key.is_empty() || !is_ws_upgrade(&req) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "websocket_error",
            "missing or invalid WebSocket upgrade headers",
        );
    }
    let accept = derive_accept_key(key.as_bytes());
    let broadcaster = state.broadcaster.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                let mut ws = WebSocketStream::from_raw_socket(io, Role::Server, None).await;
                serve_ws(&mut ws, broadcaster).await;
            }
            Err(e) => tracing::debug!(error = %e, "websocket upgrade failed"),
        }
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(SEC_WEBSOCKET_ACCEPT, accept)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Forward live events to a single WebSocket consumer. A consumer that falls
/// behind the bounded broadcast channel by more than its capacity is shed with
/// a typed close frame (1013 Try Again Later) — the server keeps running.
async fn serve_ws(
    ws: &mut WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    broadcaster: broadcast::Sender<String>,
) {
    let mut rx = broadcaster.subscribe();
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(json) => {
                    // Bounded send: a consumer that does not drain its socket
                    // is shed after WS_SEND_TIMEOUT instead of stalling the
                    // server.
                    match tokio::time::timeout(WS_SEND_TIMEOUT, ws.send(Message::Text(json))).await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => break,
                        Err(_elapsed) => {
                            tracing::warn!("shedding slow websocket consumer (send timeout)");
                            let _ = ws
                                .send(Message::Close(Some(CloseFrame {
                                    code: CloseCode::Iana(1013),
                                    reason: "slow consumer shed".into(),
                                })))
                                .await;
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(lagged = n, "shedding slow websocket consumer (lagged)");
                    let _ = ws
                        .send(Message::Close(Some(CloseFrame {
                            code: CloseCode::Iana(1013),
                            reason: "slow consumer shed".into(),
                        })))
                        .await;
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = ws.next() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                Some(Ok(_)) => {} // ignore client text/ping; the stream is server-push
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fetch up to [`MAX_PAGE_WINDOW`] events and keep those whose kind is in
/// `kinds`. Bounded projection used by the derived-view endpoints.
fn fetch_kinds(state: &ApiState, kinds: &[Kind]) -> Result<Vec<RedactedEvent>, ApiError> {
    let mut q = EventQuery::default();
    q.limit = Some(MAX_PAGE_WINDOW);
    let all = state.storage.query_events(&q)?;
    Ok(all.into_iter().filter(|e| kinds.contains(&e.kind)).collect())
}

/// Slice a bounded item list by cursor offset + capped limit and wrap it in a
/// paginated JSON envelope.
fn paginate_json(
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

fn event_pid(e: &RedactedEvent) -> u64 {
    e.namespaces.pid.unwrap_or(e.pid_tgid.0 >> 32)
}

fn kind_name(kind: Kind) -> &'static str {
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

fn kind_to_i32(name: &str) -> Option<i32> {
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

fn hex_id(id: &agent_core::EventId) -> String {
    let mut s = String::with_capacity(32);
    for b in id.0 {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn parse_limit(v: Option<&str>) -> Result<usize, ApiError> {
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

fn cursor_offset(cursor: Option<&str>) -> Result<usize, ApiError> {
    match cursor {
        Some(c) => decode_cursor(c),
        None => Ok(0),
    }
}

fn check_window(offset: usize, limit: usize) -> Result<(), ApiError> {
    if offset.saturating_add(limit).saturating_add(1) > MAX_PAGE_WINDOW {
        return Err(ApiError::oversized(format!(
            "cursor offset {offset} + limit {limit} exceeds max window {MAX_PAGE_WINDOW}"
        )));
    }
    Ok(())
}

fn check_filter(value: &str) -> Result<(), ApiError> {
    if value.len() > MAX_FILTER_BYTES {
        return Err(ApiError::oversized(format!(
            "filter value of {} bytes exceeds max {MAX_FILTER_BYTES}",
            value.len()
        )));
    }
    Ok(())
}

fn opt_filter(params: &[(String, String)], key: &str) -> Result<Option<String>, ApiError> {
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
/// cursors with a typed [`ApiErrorKind::InvalidCursorError`].
pub fn decode_cursor(cursor: &str) -> Result<usize, ApiError> {
    check_filter(cursor).map_err(|_| ApiError::invalid_cursor("cursor too large"))?;
    let rest = cursor
        .strip_prefix("kc1:")
        .ok_or_else(|| ApiError::invalid_cursor(format!("malformed cursor: {cursor}")))?;
    usize::from_str_radix(rest, 16)
        .map_err(|_| ApiError::invalid_cursor(format!("malformed cursor: {cursor}")))
}

fn parse_query(q: &str) -> Vec<(String, String)> {
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

fn get_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Minimal percent-decoding (plus `+` → space) for query values.
fn url_decode(s: &str) -> String {
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

fn json_response(status: StatusCode, value: Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&value).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn text_response(status: StatusCode, content_type: &str, text: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(text.into_bytes())))
        .unwrap()
}

fn error_response(status: StatusCode, kind: &str, message: &str) -> Response<Full<Bytes>> {
    json_response(
        status,
        json!({ "error": { "kind": kind, "message": message } }),
    )
}
