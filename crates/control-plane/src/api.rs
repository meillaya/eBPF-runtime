// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated control-plane HTTP API.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use auth::{AuthContext, AuthService, Role};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use observability::Metrics;
use protocol::v1::{ControlCommand, PolicySnapshot};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::{broadcast, watch};
use tower_http::services::{ServeDir, ServeFile};
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
    /// OIDC service.
    pub auth: AuthService,
    /// Policy fanout to agents.
    pub control: broadcast::Sender<ControlCommand>,
    /// Built dashboard directory.
    pub ui_dir: PathBuf,
    /// Optional ClickHouse client.
    pub clickhouse: Option<analytics_clickhouse::ClickHouse>,
    /// ClickHouse database.
    pub clickhouse_database: String,
    /// Cluster name.
    pub cluster_name: String,
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
    let index = state.ui_dir.join("index.html");
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/events", get(events))
        .route("/api/v1/alerts", get(alerts))
        .route("/api/v1/agents", get(agents))
        .route("/api/v1/policies", get(policies))
        .route("/api/v1/policies/stage", post(stage))
        .route("/api/v1/policies/commit", post(commit))
        .route("/api/v1/policies/{version}/acks", get(acks))
        .route("/api/v1/rules/validate", post(validate))
        .route("/api/v1/analytics/summary", get(analytics))
        .route("/api/v1/audit", get(audit))
        .fallback_service(ServeDir::new(&state.ui_dir).not_found_service(ServeFile::new(index)))
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

async fn authenticate(
    state: &HttpState,
    headers: &HeaderMap,
    minimum: Role,
) -> Result<AuthContext, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let context = state.auth.authenticate(token).await.map_err(|error| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": error.to_string()})),
        )
            .into_response()
    })?;
    if context.role < minimum {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "insufficient role"})),
        )
            .into_response());
    }
    Ok(context)
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    limit: Option<usize>,
}

async fn events(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, Role::Viewer).await {
        return response;
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    match control_db::recent_events(&state.pool, state.cluster_id, limit).await {
        Ok(events) => Json(json!({"events": events, "next_cursor": null})).into_response(),
        Err(error) => internal(error.to_string()),
    }
}

async fn alerts(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&state, &headers, Role::Viewer).await {
        return response;
    }
    match control_db::recent_alerts(&state.pool, state.cluster_id, 200).await {
        Ok(alerts) => Json(json!({"alerts": alerts, "next_cursor": null})).into_response(),
        Err(error) => internal(error.to_string()),
    }
}

async fn agents(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&state, &headers, Role::Viewer).await {
        return response;
    }
    match control_db::list_agents(&state.pool, state.cluster_id).await {
        Ok(agents) => Json(json!({"agents": agents, "next_cursor": null})).into_response(),
        Err(error) => internal(error.to_string()),
    }
}

async fn policies(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&state, &headers, Role::Viewer).await {
        return response;
    }
    match control_db::list_policies(&state.pool, state.cluster_id).await {
        Ok(policies) => Json(json!({"policies": policies, "next_cursor": null})).into_response(),
        Err(error) => internal(error.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct StagePolicyRequest {
    version: i64,
    content: String,
    name: Option<String>,
}

async fn stage(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<StagePolicyRequest>,
) -> Response {
    let context = match authenticate(&state, &headers, Role::PolicyAdmin).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    if request.content.len() > 1024 * 1024 {
        return bad_request("policy content is larger than 1 MiB");
    }
    if request.version <= 0 {
        return bad_request("version must be positive");
    }
    let ruleset = match rules::parse_ruleset(&request.content) {
        Ok(ruleset) => ruleset,
        Err(error) => return bad_request(error.to_string()),
    };
    let digest = match rules::canonical_digest(&ruleset) {
        Ok(digest) => digest,
        Err(error) => return internal(error.to_string()),
    };
    let name = request.name.unwrap_or_else(|| "default".to_string());
    match control_db::stage_policy(
        &state.pool,
        state.cluster_id,
        &name,
        request.version,
        &request.content,
        &digest,
        &context.sub,
    )
    .await
    {
        Ok(policy) => {
            let _ = control_db::audit(
                &state.pool,
                &context.sub,
                "policy.stage",
                &format!("{name}@{}", request.version),
                true,
                json!({"digest": digest}),
            )
            .await;
            Json(json!({"policy": policy})).into_response()
        }
        Err(error) => internal(error.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct CommitPolicyRequest {
    version: i64,
}

async fn commit(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<CommitPolicyRequest>,
) -> Response {
    let context = match authenticate(&state, &headers, Role::PolicyAdmin).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let policy = match control_db::get_policy(&state.pool, state.cluster_id, request.version).await
    {
        Ok(Some(policy)) => policy,
        Ok(None) => return not_found("policy version not found"),
        Err(error) => return internal(error.to_string()),
    };
    if let Err(error) =
        control_db::set_policy_status(&state.pool, request.version, "committed").await
    {
        return internal(error.to_string());
    }
    let command = ControlCommand {
        command: Some(protocol::v1::control_command::Command::Policy(
            PolicySnapshot {
                version: policy.version.to_string(),
                digest: policy.digest.clone(),
                yaml: policy.content.into_bytes(),
            },
        )),
    };
    let _ = state.control.send(command);
    let _ = control_db::audit(
        &state.pool,
        &context.sub,
        "policy.commit",
        &format!("{}@{}", policy.name, policy.version),
        true,
        json!({"digest": policy.digest}),
    )
    .await;
    Json(json!({"committed": true, "version": policy.version})).into_response()
}

async fn acks(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(version): Path<i64>,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, Role::Viewer).await {
        return response;
    }
    match control_db::list_policy_acks(&state.pool, version).await {
        Ok(acks) => Json(json!({"acks": acks, "next_cursor": null})).into_response(),
        Err(error) => internal(error.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct ValidateRequest {
    content: String,
}

async fn validate(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<ValidateRequest>,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, Role::Analyst).await {
        return response;
    }
    match rules::parse_ruleset(&request.content) {
        Ok(ruleset) => {
            let digest = match rules::canonical_digest(&ruleset) {
                Ok(digest) => digest,
                Err(error) => return internal(error.to_string()),
            };
            Json(json!({
                "valid": true,
                "digest": digest,
                "rules": ruleset.rules.len(),
            }))
            .into_response()
        }
        Err(error) => Json(json!({"valid": false, "error": error.to_string()})).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct AnalyticsQuery {
    hours: Option<u32>,
}

async fn analytics(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Response {
    if let Err(response) = authenticate(&state, &headers, Role::Viewer).await {
        return response;
    }
    let Some(clickhouse) = &state.clickhouse else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "analytics is not configured"})),
        )
            .into_response();
    };
    let hours = query.hours.unwrap_or(24).clamp(1, 24 * 30);
    let cluster = state.cluster_name.replace('\'', "\\'");
    let database = state.clickhouse_database.replace('`', "");
    let events_sql = format!(
        "SELECT kind, count() AS count FROM {database}.events \
         WHERE cluster = '{cluster}' AND ingested_at >= now() - INTERVAL {hours} HOUR \
         GROUP BY kind ORDER BY count DESC"
    );
    let alerts_sql = format!(
        "SELECT severity, count() AS count FROM {database}.alerts \
         WHERE cluster = '{cluster}' AND ingested_at >= now() - INTERVAL {hours} HOUR \
         GROUP BY severity ORDER BY count DESC"
    );
    match clickhouse.query_json(&events_sql).await {
        Ok(events) => match clickhouse.query_json(&alerts_sql).await {
            Ok(alerts) => {
                Json(json!({"events": events["data"], "alerts": alerts["data"]})).into_response()
            }
            Err(error) => internal(error.to_string()),
        },
        Err(error) => internal(error.to_string()),
    }
}

async fn audit(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&state, &headers, Role::Admin).await {
        return response;
    }
    match control_db::list_audit(&state.pool, 200).await {
        Ok(rows) => Json(json!({"audit": rows})).into_response(),
        Err(error) => internal(error.to_string()),
    }
}

fn internal(message: String) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": message})),
    )
        .into_response()
}

fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": message.into()})),
    )
        .into_response()
}

fn not_found(message: impl Into<String>) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": message.into()})),
    )
        .into_response()
}
