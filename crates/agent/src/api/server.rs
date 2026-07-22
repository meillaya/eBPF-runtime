// SPDX-License-Identifier: Apache-2.0 OR MIT
//! API server and routing.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use observability::MetricsRegistry;
use storage_local::LocalStorage;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use super::error::ApiError;
use super::handlers;
use super::helpers::error_response;
use super::views;
use super::websocket;
use super::{ApiState, WS_BROADCAST_CAPACITY};

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

impl ApiServer {
    /// Construct a server with a fresh bounded broadcast channel for live
    /// events.
    pub fn new(
        storage: Arc<LocalStorage>,
        registry: Arc<MetricsRegistry>,
        addr: SocketAddr,
    ) -> Self {
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

async fn route(req: Request<Incoming>, state: Arc<ApiState>) -> Response<Full<Bytes>> {
    // WebSocket upgrade is handled first because it consumes the request.
    if req.method() == Method::GET && req.uri().path() == "/ws" {
        return websocket::websocket(req, &state);
    }
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    if req.method() != Method::GET {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "only GET is supported",
        );
    }
    let result = match path.as_str() {
        "/api/v1/health" => handlers::health(&state),
        "/api/v1/readiness" => handlers::readiness(&state),
        "/api/v1/metrics" => handlers::metrics(&state),
        "/api/v1/events" => handlers::events(&state, &query),
        "/api/v1/process-tree" => views::process_tree(&state, &query),
        "/api/v1/sockets" => views::sockets(&state, &query),
        "/api/v1/dns" => views::dns(&state, &query),
        "/api/v1/files" => views::files(&state, &query),
        "/api/v1/syscall-histograms" => views::syscall_histograms(&state, &query),
        "/api/v1/export" => handlers::export(&state, &query),
        p if p.starts_with("/api/v1/events/") => {
            handlers::single_event(&state, &p["/api/v1/events/".len()..])
        }
        _ => Err(ApiError::query(format!("unknown route: {path}"))),
    };
    match result {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}
