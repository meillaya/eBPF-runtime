// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet control plane.

#![forbid(unsafe_code)]

pub mod api;
pub mod config;
pub mod rollout;
pub mod service;

use std::sync::Arc;

use observability::Metrics;
use protocol::v1::agent_service_server::AgentServiceServer;
use tokio::sync::{broadcast, watch};
use tonic::transport::Server;
use uuid::Uuid;

pub use config::ControlConfig;

/// Control-plane errors.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// Configuration failure.
    #[error("config: {0}")]
    Config(#[from] config::ConfigError),
    /// Database failure.
    #[error("database: {0}")]
    Database(#[from] control_db::DbError),
    /// TLS material failure.
    #[error("tls: {0}")]
    Tls(#[from] transport::TransportError),
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// gRPC transport failure.
    #[error("grpc: {0}")]
    Grpc(#[from] tonic::transport::Error),
}

/// Run the control plane.
pub async fn serve(config: ControlConfig) -> Result<(), ControlError> {
    let pool = control_db::connect(&config.database_url, config.max_connections).await?;
    control_db::migrate(&pool).await?;
    let cluster_id = control_db::ensure_cluster(&pool, &config.cluster).await?;
    let metrics = Arc::new(Metrics::new().expect("metric names are static"));
    let (control, _) = broadcast::channel(256);
    let auth = if config.dev {
        auth::AuthService::new(
            auth::JwtVerifier::new(String::new(), String::new(), String::new()),
            Some(auth::Role::Admin),
        )
    } else {
        let verifier = if config.oidc_ca.as_os_str().is_empty() {
            auth::JwtVerifier::new(
                config.oidc_issuer.clone(),
                config.oidc_audience.clone(),
                config.oidc_jwks_url.clone(),
            )
        } else {
            let ca = std::fs::read(&config.oidc_ca).map_err(|error| {
                ControlError::Config(config::ConfigError::Read {
                    path: config.oidc_ca.clone(),
                    detail: error.to_string(),
                })
            })?;
            auth::JwtVerifier::new_with_ca(
                config.oidc_issuer.clone(),
                config.oidc_audience.clone(),
                config.oidc_jwks_url.clone(),
                &ca,
            )
            .map_err(|error| {
                ControlError::Config(config::ConfigError::Invalid(error.to_string()))
            })?
        };
        auth::AuthService::new(verifier, None)
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _rollout = tokio::spawn(rollout::run(
        pool.clone(),
        cluster_id,
        control.clone(),
        shutdown_rx.clone(),
    ));

    let service = service::AgentServiceImpl {
        pool: pool.clone(),
        cluster_id,
        dev: config.dev,
        metrics: metrics.clone(),
        control: control.clone(),
    };
    let grpc_addr: std::net::SocketAddr = config.grpc_listen.parse().map_err(|_| {
        ControlError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid grpc listen address",
        ))
    })?;

    let grpc_shutdown = shutdown_rx.clone();
    let tls = if config.dev {
        None
    } else {
        Some(
            transport::server_tls(
                config.tls_ca.clone(),
                config.tls_cert.clone(),
                config.tls_key.clone(),
            )
            .await?,
        )
    };
    let grpc = tokio::spawn(async move {
        let mut builder = Server::builder();
        if let Some(tls) = tls {
            builder = builder.tls_config(tls).map_err(ControlError::Grpc)?;
        }
        builder
            .add_service(AgentServiceServer::new(service))
            .serve_with_shutdown(grpc_addr, async move {
                let mut rx = grpc_shutdown;
                let _ = rx.wait_for(|stop| *stop).await;
            })
            .await
            .map_err(ControlError::Grpc)
    });

    let clickhouse = if config.clickhouse_url.is_empty() {
        None
    } else {
        Some(analytics_clickhouse::ClickHouse::new(
            config.clickhouse_url.clone(),
        ))
    };
    let http_state = api::HttpState {
        pool,
        cluster_id,
        metrics,
        auth,
        control,
        ui_dir: config.ui_dir.clone(),
        clickhouse,
        clickhouse_database: config.clickhouse_database.clone(),
        cluster_name: config.cluster.clone(),
    };
    let http_listen = config.http_listen.clone();
    let http_shutdown = shutdown_rx.clone();
    let http =
        tokio::spawn(async move { api::serve(&http_listen, http_state, http_shutdown).await });

    let mut signal = signal_stream();
    tokio::select! {
        _ = signal.recv() => {
            let _ = shutdown_tx.send(true);
        }
        result = grpc => {
            let _ = shutdown_tx.send(true);
            result.map_err(|_| ControlError::Io(std::io::Error::other("grpc task failed")))??;
        }
        result = http => {
            let _ = shutdown_tx.send(true);
            result.map_err(|_| ControlError::Io(std::io::Error::other("http task failed")))??;
        }
    }
    Ok(())
}

fn signal_stream() -> tokio::sync::mpsc::Receiver<()> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM");
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("SIGINT");
        tokio::select! {
            _ = sigterm.recv() => {},
            _ = sigint.recv() => {},
        }
        let _ = tx.send(()).await;
    });
    rx
}

/// Run migrations only.
pub async fn migrate(config: &ControlConfig) -> Result<(), ControlError> {
    let pool = control_db::connect(&config.database_url, 2).await?;
    control_db::migrate(&pool).await?;
    let _ = control_db::ensure_cluster(&pool, &config.cluster).await?;
    let _: Uuid = Uuid::nil();
    Ok(())
}
