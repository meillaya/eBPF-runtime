// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Loopback-only local API.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use event_model::Event;
use observability::Metrics;
use serde::Deserialize;
use serde_json::json;
use storage_local::LocalStorage;
use tokio::sync::{broadcast, watch};

/// Shared API state.
#[derive(Clone)]
pub struct ApiState {
    /// Local storage.
    pub storage: Arc<LocalStorage>,
    /// Metrics registry.
    pub metrics: Arc<Metrics>,
    /// Live event fanout.
    pub live: broadcast::Sender<Event>,
    /// Latest sensor coverage.
    pub coverage: Arc<RwLock<Option<serde_json::Value>>>,
    /// Agent id.
    pub agent_id: String,
    /// Cluster.
    pub cluster: String,
    /// Node.
    pub node: String,
    /// Process start.
    pub started: Instant,
}

/// API errors.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Storage failure.
    #[error("storage: {0}")]
    Storage(#[from] storage_local::StorageError),
    /// The bind address is not loopback.
    #[error("refusing to bind non-loopback address {0}")]
    NonLoopback(String),
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Run the API server until `shutdown` becomes true.
pub async fn serve(
    listen: &str,
    state: ApiState,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ApiError> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|_| ApiError::NonLoopback(listen.to_string()))?;
    if !addr.ip().is_loopback() {
        return Err(ApiError::NonLoopback(addr.to_string()));
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "local API listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|stop| *stop).await;
        })
        .await?;
    Ok(())
}

/// Build the router. Public for tests.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/readyz", get(ready))
        .route("/api/v1/events", get(events))
        .route("/api/v1/alerts", get(alerts))
        .route("/api/v1/outbox", get(outbox))
        .route("/api/v1/status", get(status))
        .route("/api/v1/metrics", get(metrics))
        .route("/api/v1/events/stream", get(stream))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

async fn ready(State(state): State<ApiState>) -> Response {
    let depth = state.storage.outbox_depth().unwrap_or(0);
    Json(json!({"ready": true, "outbox_depth": depth})).into_response()
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    limit: Option<usize>,
    kind: Option<String>,
}

async fn events(State(state): State<ApiState>, Query(query): Query<EventQuery>) -> Response {
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    match state.storage.query_events(limit, query.kind.as_deref()) {
        Ok(events) => Json(json!({"events": events, "next_cursor": null})).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn alerts(State(state): State<ApiState>) -> Response {
    match state.storage.query_alerts(100) {
        Ok(alerts) => Json(json!({"alerts": alerts, "next_cursor": null})).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn outbox(State(state): State<ApiState>) -> Response {
    match state.storage.outbox_depth() {
        Ok(depth) => Json(json!({"depth": depth})).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn status(State(state): State<ApiState>) -> Response {
    let coverage = state.coverage.read().ok().and_then(|value| value.clone());
    let outbox = state.storage.outbox_depth().unwrap_or(0);
    Json(json!({
        "agent_id": state.agent_id,
        "cluster": state.cluster,
        "node_name": state.node,
        "uptime_seconds": state.started.elapsed().as_secs(),
        "outbox_depth": outbox,
        "coverage": coverage,
    }))
    .into_response()
}

async fn metrics(State(state): State<ApiState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
        .into_response()
}

async fn stream(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(move |socket| stream_events(socket, state))
}

async fn stream_events(mut socket: WebSocket, state: ApiState) {
    let mut receiver = state.live.subscribe();
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tokio::select! {
            message = receiver.recv() => {
                match message {
                    Ok(event) => {
                        let text = match serde_json::to_string(&event) {
                            Ok(text) => text,
                            Err(_) => continue,
                        };
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = socket.send(Message::Text(
                            json!({"error": "lagged"}).to_string().into(),
                        )).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = heartbeat.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            message = socket.recv() => {
                match message {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalStorage::open(&dir.path().join("db"), &storage_local::StorageKey::test()).unwrap(),
        );
        let (live, _) = broadcast::channel(8);
        let state = ApiState {
            storage,
            metrics: Arc::new(Metrics::new().unwrap()),
            live,
            coverage: Arc::new(RwLock::new(None)),
            agent_id: "a".into(),
            cluster: "c".into(),
            node: "n".into(),
            started: Instant::now(),
        };
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
