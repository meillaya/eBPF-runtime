// SPDX-License-Identifier: Apache-2.0 OR MIT
//! gRPC ingest service.

use std::pin::Pin;
use std::sync::Arc;

use event_model::Batch;
use futures_core::Stream;
use observability::Metrics;
use protocol::v1::agent_service_server::AgentService;
use protocol::v1::{
    BatchAck, BatchRequest, ControlCommand, ControlRequest, HealthAck, HealthReport, PolicyAck,
    PolicyAckResponse, RegisterRequest, RegisterResponse,
};
use sqlx::PgPool;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::transport::server::TcpConnectInfo;
use tonic::transport::server::TlsConnectInfo;
use tonic::{Request, Response, Status};
use uuid::Uuid;

/// Peer identity extracted from the client certificate.
pub fn peer_spiffe_id<T>(request: &Request<T>) -> Option<String> {
    let info = request
        .extensions()
        .get::<TlsConnectInfo<TcpConnectInfo>>()?;
    let certs = info.peer_certs()?;
    let cert = certs.first()?;
    transport::spiffe_id_from_cert(cert.as_ref()).ok()
}

/// gRPC service implementation.
#[derive(Clone)]
pub struct AgentServiceImpl {
    /// Database pool.
    pub pool: PgPool,
    /// Cluster id.
    pub cluster_id: Uuid,
    /// Dev mode allows the request agent id and skips peer checks.
    pub dev: bool,
    /// Metrics.
    pub metrics: Arc<Metrics>,
    /// Policy and control fanout.
    pub control: broadcast::Sender<ControlCommand>,
}

#[tonic::async_trait]
impl AgentService for AgentServiceImpl {
    type WatchControlStream =
        Pin<Box<dyn Stream<Item = Result<ControlCommand, Status>> + Send + 'static>>;

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let payload = request.get_ref();
        if payload.protocol_major != protocol::PROTOCOL_MAJOR {
            return Err(Status::failed_precondition(format!(
                "protocol major {} is not supported",
                payload.protocol_major
            )));
        }
        let agent_key = match peer_spiffe_id(&request) {
            Some(id) => id,
            None if self.dev => payload.agent_id.clone(),
            None => return Err(Status::unauthenticated("client certificate missing")),
        };
        if agent_key.is_empty() {
            return Err(Status::invalid_argument("agent id is required"));
        }
        let record = control_db::register_agent(
            &self.pool,
            self.cluster_id,
            &agent_key,
            &payload.node_name,
            &payload.agent_generation,
            &payload.boot_id_hex,
            &payload.sensors,
        )
        .await
        .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(RegisterResponse {
            cluster_id: record.cluster_id.to_string(),
            accepted_generation: record.agent_generation,
            protocol_major: protocol::PROTOCOL_MAJOR,
        }))
    }

    async fn publish_batch(
        &self,
        request: Request<BatchRequest>,
    ) -> Result<Response<BatchAck>, Status> {
        let payload = request.get_ref();
        if payload.batch_json.len() > protocol::MAX_BATCH_JSON_BYTES {
            return Err(Status::resource_exhausted(format!(
                "batch JSON is {} bytes, limit is {}",
                payload.batch_json.len(),
                protocol::MAX_BATCH_JSON_BYTES
            )));
        }
        let batch: Batch = serde_json::from_slice(&payload.batch_json)
            .map_err(|error| Status::invalid_argument(format!("bad batch JSON: {error}")))?;
        let agent_key = match peer_spiffe_id(&request) {
            Some(id) => id,
            None if self.dev => payload.agent_id.clone(),
            None => return Err(Status::unauthenticated("client certificate missing")),
        };
        if batch.events.len() > 10_000 {
            return Err(Status::resource_exhausted("too many events in one batch"));
        }
        let outcome = control_db::accept_batch(&self.pool, self.cluster_id, &agent_key, &batch)
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        if !outcome.duplicate {
            self.metrics.batches_total.inc();
            self.metrics
                .ingested_events_total
                .inc_by(batch.events.len() as u64);
        }
        Ok(Response::new(BatchAck {
            batch_id: batch.batch_id,
            accepted: outcome.accepted,
            duplicate: outcome.duplicate,
            error: String::new(),
            accepted_at_unix: outcome.accepted_at_unix,
        }))
    }

    async fn watch_control(
        &self,
        request: Request<ControlRequest>,
    ) -> Result<Response<Self::WatchControlStream>, Status> {
        let payload = request.get_ref();
        let agent_key = match peer_spiffe_id(&request) {
            Some(id) => id,
            None if self.dev => payload.agent_id.clone(),
            None => return Err(Status::unauthenticated("client certificate missing")),
        };
        if agent_key.is_empty() {
            return Err(Status::invalid_argument("agent id is required"));
        }
        let receiver = self.control.subscribe();
        let stream = BroadcastStream::new(receiver).filter_map(|message| match message {
            Ok(command) => Some(Ok(command)),
            Err(_) => Some(Err(Status::unavailable("control stream lagged"))),
        });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn report_health(
        &self,
        request: Request<HealthReport>,
    ) -> Result<Response<HealthAck>, Status> {
        let payload = request.get_ref();
        let agent_key = match peer_spiffe_id(&request) {
            Some(id) => id,
            None if self.dev => payload.agent_id.clone(),
            None => return Err(Status::unauthenticated("client certificate missing")),
        };
        control_db::touch_agent(&self.pool, &agent_key)
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(HealthAck { accepted: true }))
    }

    async fn report_policy_ack(
        &self,
        request: Request<PolicyAck>,
    ) -> Result<Response<PolicyAckResponse>, Status> {
        let payload = request.get_ref();
        let agent_key = match peer_spiffe_id(&request) {
            Some(id) => id,
            None if self.dev => payload.agent_id.clone(),
            None => return Err(Status::unauthenticated("client certificate missing")),
        };
        let version: i64 = payload
            .version
            .parse()
            .map_err(|_| Status::invalid_argument("policy version must be an integer"))?;
        control_db::record_policy_ack(
            &self.pool,
            version,
            &agent_key,
            &payload.status,
            &payload.digest,
            &payload.message,
        )
        .await
        .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(PolicyAckResponse { accepted: true }))
    }
}
