// SPDX-License-Identifier: Apache-2.0 OR MIT
//! HTTP server for `/healthz`, `/readyz`, `/metrics` endpoints.

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::{HealthState, MetricsRegistry, ObservabilityError, ObservabilityErrorKind, ReadinessState};

/// The observability HTTP server. Serves health, readiness, and metrics
/// endpoints on a given address.
pub struct ObservabilityServer {
    pub registry: Arc<MetricsRegistry>,
    pub addr: SocketAddr,
}

impl ObservabilityServer {
    /// Create a new observability server.
    pub fn new(registry: Arc<MetricsRegistry>, addr: SocketAddr) -> Self {
        Self { registry, addr }
    }

    /// Start the HTTP server. Serves:
    /// - `GET /healthz` — health status as JSON (200 if healthy, 503 otherwise)
    /// - `GET /readyz` — readiness status as JSON (200 if ready, 503 otherwise)
    /// - `GET /metrics` — Prometheus metrics as text (200)
    pub async fn serve(&self) -> Result<(), ObservabilityError> {
        let listener = TcpListener::bind(self.addr).await.map_err(|e| ObservabilityError {
            kind: ObservabilityErrorKind::BindError(e),
        })?;

        tracing::info!(addr = %self.addr, "observability server listening");

        loop {
            let (stream, _remote) = listener.accept().await.map_err(|e| ObservabilityError {
                kind: ObservabilityErrorKind::BindError(e),
            })?;

            let io = TokioIo::new(stream);
            let registry = Arc::clone(&self.registry);

            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let registry = Arc::clone(&registry);
                    async move { handle_request(req, registry) }
                });

                if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                    tracing::debug!(error = %err, "connection closed");
                }
            });
        }
    }
}

/// Route an incoming request to the appropriate handler.
fn handle_request(
    req: Request<Incoming>,
    registry: Arc<MetricsRegistry>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") => handle_healthz(&registry),
        (&Method::GET, "/readyz") => handle_readyz(&registry),
        (&Method::GET, "/metrics") => handle_metrics(&registry),
        _ => {
            let body = serde_json::json!({"error": "not found"});
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .expect("build response")
        }
    };
    Ok(response)
}

/// Handle `GET /healthz`. Returns 200 if healthy, 503 if degraded or unhealthy.
fn handle_healthz(registry: &MetricsRegistry) -> Response<Full<Bytes>> {
    let health = registry.health();
    let status_code = if health.status == HealthState::Healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = serde_json::json!({
        "status": health.status.to_string(),
        "reasons": health.reasons,
    });

    Response::builder()
        .status(status_code)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("build response")
}

/// Handle `GET /readyz`. Returns 200 if ready, 503 if not ready.
fn handle_readyz(registry: &MetricsRegistry) -> Response<Full<Bytes>> {
    let readiness = registry.readiness();
    let status_code = if readiness.status == ReadinessState::Ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = serde_json::json!({
        "status": readiness.status.to_string(),
        "reasons": readiness.reasons,
    });

    Response::builder()
        .status(status_code)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("build response")
}

/// Handle `GET /metrics`. Returns Prometheus text exposition format.
fn handle_metrics(registry: &MetricsRegistry) -> Response<Full<Bytes>> {
    let metrics = registry.metrics();

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Full::new(Bytes::from(metrics)))
        .expect("build response")
}
