// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Agent-side gRPC transport.
//!
//! The client uses mTLS with X.509 SVIDs. The control plane maps the URI SAN
//! of the client certificate to an agent. The client never sends raw kernel
//! bytes: `BatchRequest.batch_json` is the versioned `event_model::Batch`.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use event_model::Batch;
use protocol::v1::agent_service_client::AgentServiceClient;
use protocol::v1::{BatchRequest, HealthReport, RegisterRequest, RegisterResponse};
use protocol::MAX_BATCH_JSON_BYTES;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::Request;

/// Transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Control-plane gRPC endpoint, for example `https://127.0.0.1:9443`.
    pub endpoint: String,
    /// TLS server name, for example `control-plane`.
    pub domain_name: String,
    /// PEM CA bundle used to verify the control plane.
    pub ca_path: PathBuf,
    /// PEM client certificate chain.
    pub cert_path: PathBuf,
    /// PEM client private key.
    pub key_path: PathBuf,
    /// RPC timeout in seconds.
    pub timeout_secs: u64,
}

/// Transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// TLS material could not be read.
    #[error("cannot read TLS material {path}: {detail}")]
    TlsMaterial {
        /// Path.
        path: PathBuf,
        /// Detail.
        detail: String,
    },
    /// gRPC failure.
    #[error("grpc: {0}")]
    Grpc(#[from] tonic::Status),
    /// Transport failure.
    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),
    /// Invalid endpoint.
    #[error("invalid endpoint {0}")]
    Endpoint(String),
    /// Serialization failure.
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Batch is too large.
    #[error("batch JSON is {size} bytes, limit is {limit}")]
    BatchTooLarge {
        /// Actual size.
        size: usize,
        /// Limit.
        limit: usize,
    },
    /// The peer certificate has no SPIFFE URI SAN.
    #[error("peer certificate has no SPIFFE URI SAN")]
    MissingSpiffeId,
    /// The peer SPIFFE id is malformed.
    #[error("malformed SPIFFE id: {0}")]
    BadSpiffeId(String),
}

/// Agent-side client.
pub struct TransportClient {
    inner: AgentServiceClient<Channel>,
    timeout: Duration,
    agent_id: String,
    generation: String,
}

impl TransportClient {
    /// Connect with mTLS.
    pub async fn connect(
        config: &TransportConfig,
        agent_id: impl Into<String>,
        generation: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let ca = read(config.ca_path.clone()).await?;
        let cert = read(config.cert_path.clone()).await?;
        let key = read(config.key_path.clone()).await?;
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(cert, key))
            .domain_name(config.domain_name.clone());
        let endpoint = Channel::from_shared(config.endpoint.clone())
            .map_err(|_| TransportError::Endpoint(config.endpoint.clone()))?;
        let channel = endpoint
            .tls_config(tls)?
            .connect_timeout(Duration::from_secs(10))
            .connect()
            .await?;
        let inner = AgentServiceClient::new(channel)
            .max_decoding_message_size(protocol::MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(protocol::MAX_GRPC_MESSAGE_BYTES);
        Ok(Self {
            inner,
            timeout: Duration::from_secs(config.timeout_secs.max(1)),
            agent_id: agent_id.into(),
            generation: generation.into(),
        })
    }

    /// Connect without TLS. Only for a loopback dev control plane.
    pub async fn connect_insecure(
        endpoint: &str,
        agent_id: impl Into<String>,
        generation: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|_| TransportError::Endpoint(endpoint.to_string()))?
            .connect_timeout(Duration::from_secs(10))
            .connect()
            .await?;
        let inner = AgentServiceClient::new(channel)
            .max_decoding_message_size(protocol::MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(protocol::MAX_GRPC_MESSAGE_BYTES);
        Ok(Self {
            inner,
            timeout: Duration::from_secs(10),
            agent_id: agent_id.into(),
            generation: generation.into(),
        })
    }

    /// Register this agent.
    pub async fn register(
        &self,
        cluster: &str,
        node_name: &str,
        boot_id_hex: &str,
        sensors: &[String],
    ) -> Result<RegisterResponse, TransportError> {
        let request = RegisterRequest {
            agent_id: self.agent_id.clone(),
            cluster: cluster.to_string(),
            node_name: node_name.to_string(),
            agent_generation: self.generation.clone(),
            boot_id_hex: boot_id_hex.to_string(),
            protocol_major: protocol::PROTOCOL_MAJOR,
            sensors: sensors.to_vec(),
        };
        let mut client = self.inner.clone();
        let response = tokio::time::timeout(self.timeout, client.register(Request::new(request)))
            .await
            .map_err(|_| tonic::Status::deadline_exceeded("register timed out"))??;
        Ok(response.into_inner())
    }

    /// Publish one batch.
    pub async fn publish_batch(
        &self,
        batch: &Batch,
    ) -> Result<protocol::v1::BatchAck, TransportError> {
        let payload = serde_json::to_vec(batch)?;
        if payload.len() > MAX_BATCH_JSON_BYTES {
            return Err(TransportError::BatchTooLarge {
                size: payload.len(),
                limit: MAX_BATCH_JSON_BYTES,
            });
        }
        let request = BatchRequest {
            batch_id: batch.batch_id.clone(),
            agent_id: self.agent_id.clone(),
            batch_json: payload,
            idempotency_key: batch.batch_id.clone(),
        };
        let mut client = self.inner.clone();
        let response =
            tokio::time::timeout(self.timeout, client.publish_batch(Request::new(request)))
                .await
                .map_err(|_| tonic::Status::deadline_exceeded("publish timed out"))??;
        Ok(response.into_inner())
    }

    /// Watch control commands.
    pub async fn watch_control(
        &self,
    ) -> Result<tonic::Streaming<protocol::v1::ControlCommand>, TransportError> {
        let mut client = self.inner.clone();
        let request = protocol::v1::ControlRequest {
            agent_id: self.agent_id.clone(),
            agent_generation: self.generation.clone(),
        };
        let response =
            tokio::time::timeout(self.timeout, client.watch_control(Request::new(request)))
                .await
                .map_err(|_| tonic::Status::deadline_exceeded("watch timed out"))??;
        Ok(response.into_inner())
    }

    /// Report health.
    pub async fn report_health(&self, report: HealthReport) -> Result<(), TransportError> {
        let mut client = self.inner.clone();
        tokio::time::timeout(self.timeout, client.report_health(Request::new(report)))
            .await
            .map_err(|_| tonic::Status::deadline_exceeded("health timed out"))??;
        Ok(())
    }
}

async fn read(path: PathBuf) -> Result<Vec<u8>, TransportError> {
    tokio::fs::read(&path)
        .await
        .map_err(|error| TransportError::TlsMaterial {
            path,
            detail: error.to_string(),
        })
}

/// Build a tonic server TLS configuration.
pub async fn server_tls(
    ca_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<tonic::transport::ServerTlsConfig, TransportError> {
    let ca = read(ca_path).await?;
    let cert = read(cert_path).await?;
    let key = read(key_path).await?;
    Ok(tonic::transport::ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        .client_ca_root(Certificate::from_pem(ca)))
}

/// Extract the SPIFFE URI SAN from a DER certificate.
pub fn spiffe_id_from_cert(cert_der: &[u8]) -> Result<String, TransportError> {
    let (_, certificate) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|error| TransportError::BadSpiffeId(error.to_string()))?;
    for extension in certificate.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(names) =
            extension.parsed_extension()
        {
            for name in &names.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    if uri.starts_with("spiffe://") {
                        return Ok((*uri).to_string());
                    }
                }
            }
        }
    }
    Err(TransportError::MissingSpiffeId)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_certificate() {
        assert!(matches!(
            spiffe_id_from_cert(b"not a certificate"),
            Err(TransportError::BadSpiffeId(_))
        ));
    }
}
