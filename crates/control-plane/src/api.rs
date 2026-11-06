// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Control-plane HTTP API.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use observability::Metrics;
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::watch;
use uuid::Uuid;

/// HTTP state.
#[derive(Clone)]
pub struct HttpState {
    /// Database pool.
    pub pool: PgPool,
    /// Cluster id.
    pub cluster_id: Uuid,
    /// Metrics.
    pub metrics: Arc<Metrics>,
}

/// Serve the HTTP API until `shutdown` becomes true.
pub async fn serve(
    listen: &str,
    state: HttpState,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let addr: SocketAddr = listen.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid http listen address",
        )
    })?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "control-plane HTTP listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|stop| *stop).await;
        })
        .await?;
    Ok(())
}

/// Build the router.
pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/events", get(events))
        .route("/api/v1/agents", get(agents))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

async fn ready(State(state): State<HttpState>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => Json(json!({"ready": true})).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ready": false, "error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn metrics(State(state): State<HttpState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    limit: Option<usize>,
}

async fn events(State(state): State<HttpState>, Query(query): Query<EventQuery>) -> Response {
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    match control_db::recent_events(&state.pool, state.cluster_id, limit).await {
        Ok(events) => Json(json!({"events": events, "next_cursor": null})).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn agents(State(state): State<HttpState>) -> Response {
    match control_db::list_agents(&state.pool, state.cluster_id).await {
        Ok(agents) => Json(json!({"agents": agents, "next_cursor": null})).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}
