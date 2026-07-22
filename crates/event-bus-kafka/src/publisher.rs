// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kafka event publisher: the control-plane entry point.
//!
//! # Central invariants
//!
//! 1. **At-least-once with declared duplicates only**: every
//!    batch is either durably accepted, declared duplicate,
//!    routed to DLQ, or remains in the outbox. No hidden loss.
//! 2. **No ACK before durability**: the durable-delivery
//!    callback fires ONLY after the mock broker confirms
//!    `acks=all` acceptance. The gRPC ACK to the agent is
//!    gated on this callback.
//! 3. **Per-agent ordering**: the partition key is derived from
//!    cluster/agent identity, so all events from one agent land
//!    on the same partition.
//! 4. **Idempotent producer**: `acks=all`, `enable.idempotence=true`,
//!    bounded in-flight (<= 5), retries on transient failure.
//! 5. **No agent credentials beyond control plane**: agents
//!    never see Kafka. The publisher runs exclusively in the
//!    control plane.
//! 6. **Schema headers on every record**: downstream consumers
//!    validate schema BEFORE deserializing; incompatible
//!    batches route to `events.dlq.v1`.
//!
//! # BLOCKER
//!
//! No live Kafka broker on this host. The publisher uses
//! `MockKafkaProducer` for all logic validation. Live
//! integration re-opens on the declared self-hosted runner.

#![forbid(unsafe_code)]

use protocol::events::Batch;
use protocol::idempotency::IdempotencyKey;

use crate::config::ProducerConfig;
use crate::dlq::DlqRouter;
use crate::error::{KafkaError, KafkaResult};
use crate::headers::{build_batch_headers, validate_schema_headers};
use crate::metrics::PublisherMetrics;
use crate::partition::{partition_for_agent, partition_key};
use crate::producer::{DurableAcceptance, MockKafkaProducer, ProducerRecord};

/// The durable-delivery callback.
///
/// Called ONLY after the broker confirms durable acceptance
/// (`acks=all`). The gRPC ACK to the agent is gated on this
/// callback. Receipt-only callbacks are structurally absent.
pub type DurableDeliveryCallback = Box<dyn FnMut(DurableAcceptance) + Send + Sync>;

/// The Kafka event publisher (control-plane only).
///
/// Publishes event batches to `events.v1` with idempotent
/// producer semantics, per-agent partition ordering, protobuf
/// schema headers, and DLQ routing for schema-rejected batches.
pub struct KafkaPublisher {
    /// Producer configuration.
    config: ProducerConfig,
    /// The mock Kafka producer.
    producer: MockKafkaProducer,
    /// The DLQ router.
    dlq: DlqRouter,
    /// Publisher metrics.
    metrics: PublisherMetrics,
    /// The durable-delivery callback (gates gRPC ACK).
    durable_callback: Option<DurableDeliveryCallback>,
    /// The supported schema major version (for downstream
    /// validation simulation).
    supported_schema_major: u32,
}

impl std::fmt::Debug for KafkaPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaPublisher")
            .field("config", &self.config)
            .field("metrics", &self.metrics)
            .field(
                "durable_callback",
                &self.durable_callback.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

impl KafkaPublisher {
    /// Create a new publisher with the given config.
    pub fn new(config: ProducerConfig) -> KafkaResult<Self> {
        config
            .validate()
            .map_err(|e| KafkaError::UnrecoverableProducerError {
                batch_id: String::new(),
                reason: format!("invalid config: {e}"),
            })?;

        let dlq_topic = config.dlq_topic.clone();
        let supported_schema_major = protocol::SCHEMA_MAJOR;

        Ok(Self {
            producer: MockKafkaProducer::new(config.clone()),
            config,
            dlq: DlqRouter::new(dlq_topic),
            metrics: PublisherMetrics::new(),
            durable_callback: None,
            supported_schema_major,
        })
    }

    /// Set the durable-delivery callback.
    ///
    /// This callback fires ONLY after durable acceptance. It is
    /// the gate for the gRPC ACK to the agent.
    pub fn set_durable_callback(&mut self, callback: DurableDeliveryCallback) {
        self.durable_callback = Some(callback);
    }

    /// The publisher metrics.
    pub fn metrics(&self) -> &PublisherMetrics {
        &self.metrics
    }

    /// The DLQ router (for inspection).
    pub fn dlq(&self) -> &DlqRouter {
        &self.dlq
    }

    /// The producer (for test access to failure modes).
    pub fn producer_mut(&mut self) -> &mut MockKafkaProducer {
        &mut self.producer
    }

    /// Publish an event batch to Kafka.
    ///
    /// # Flow
    ///
    /// 1. Derive partition key from cluster/agent identity.
    /// 2. Build schema/version headers.
    /// 3. Serialize the batch payload.
    /// 4. Produce with idempotent semantics (retry on transient
    ///    failure).
    /// 5. On durable acceptance: fire the durable-delivery
    ///    callback (gates gRPC ACK).
    /// 6. On schema rejection: route to DLQ.
    /// 7. On queue full / broker down: return error (batch
    ///    stays in outbox, no ACK).
    ///
    /// # Returns
    ///
    /// `Ok(DurableAcceptance)` on durable acceptance or
    /// declared duplicate. `Err(KafkaError)` on failure.
    pub fn publish_batch(
        &mut self,
        batch: &Batch,
        idempotency_key: &IdempotencyKey,
        cluster: &str,
        agent_path: &str,
    ) -> KafkaResult<DurableAcceptance> {
        self.metrics.record_submit();

        // Derive deterministic batch ID from idempotency key.
        let batch_id = format!("batch-{}", idempotency_key.as_str());

        // Derive partition from cluster/agent identity.
        let partition = partition_for_agent(cluster, agent_path, self.config.partition_count);
        let key = partition_key(cluster, agent_path);

        // Determine event kind from the first event (or
        // Unspecified for empty batches).
        let event_kind = batch
            .events
            .first()
            .map(|e| e.event_kind)
            .unwrap_or(protocol::events::EventKind::Unspecified);

        // Build schema/version headers.
        let headers = build_batch_headers(
            batch.schema_major,
            batch.schema_minor,
            &event_kind,
            &batch_id,
            idempotency_key.as_str(),
        );

        // Validate schema headers (simulates downstream
        // consumer validation).
        if let Err(reason) = validate_schema_headers(&headers, self.supported_schema_major) {
            // Schema rejected: route to DLQ.
            self.metrics.record_dlq();
            let payload =
                serde_json::to_vec(batch).map_err(|e| KafkaError::SerializationFailed {
                    batch_id: batch_id.clone(),
                    reason: e.to_string(),
                })?;

            self.dlq.route(
                &batch_id,
                &self.config.topic,
                partition,
                key.as_bytes().to_vec(),
                payload,
                headers,
                &reason,
            );

            return Err(KafkaError::SchemaRejected {
                batch_id,
                schema_major: batch.schema_major,
                schema_minor: batch.schema_minor,
                reason,
            });
        }

        // Serialize the batch payload.
        let payload = serde_json::to_vec(batch).map_err(|e| KafkaError::SerializationFailed {
            batch_id: batch_id.clone(),
            reason: e.to_string(),
        })?;

        // Build the producer record.
        let record = ProducerRecord {
            topic: self.config.topic.clone(),
            partition,
            key: key.as_bytes().to_vec(),
            payload,
            headers,
        };

        // Produce with idempotent retry.
        self.metrics.set_in_flight(self.producer.in_flight() + 1);
        let result = self.producer.produce_with_retry(&record, &batch_id);
        self.metrics.set_in_flight(self.producer.in_flight());

        match result {
            Ok(acceptance) => {
                if acceptance.is_duplicate {
                    self.metrics.record_duplicate();
                } else {
                    self.metrics.record_accept();
                }

                // Fire the durable-delivery callback (gates
                // gRPC ACK).
                if let Some(callback) = &mut self.durable_callback {
                    callback(acceptance.clone());
                }

                Ok(acceptance)
            }
            Err(KafkaError::QueueFull {
                in_flight,
                max_in_flight,
            }) => {
                self.metrics.record_queue_full();
                Err(KafkaError::QueueFull {
                    in_flight,
                    max_in_flight,
                })
            }
            Err(KafkaError::BrokerUnavailable { reason }) => {
                self.metrics.record_broker_unavailable();
                Err(KafkaError::BrokerUnavailable { reason })
            }
            Err(e) => {
                self.metrics.record_unrecoverable();
                Err(e)
            }
        }
    }

    /// Verify zero hidden loss.
    ///
    /// Every submitted batch must be accounted for: accepted,
    /// timed out, queue-full, DLQ, declared duplicate, or
    /// unrecoverable. In-flight batches are pending.
    pub fn verify_no_hidden_loss(&self) -> bool {
        self.metrics.verify_no_hidden_loss()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::producer::FailureMode;
    use protocol::events::{Event, EventKind};
    use std::sync::{Arc, Mutex};

    fn make_event(seq: u64) -> Event {
        Event {
            event_id: format!("00000000-0000-0000-0000-{seq:012}"),
            seq,
            ts_monotonic_ns: 0,
            sensor: "ops".into(),
            event_kind: EventKind::FileOpen,
            valids: Default::default(),
        }
    }

    fn make_batch(count: usize) -> Batch {
        Batch {
            schema_major: 1,
            schema_minor: 0,
            events: (0..count as u64).map(make_event).collect(),
            agent_generation: "gen-1".into(),
            node_name: "node-1".into(),
            boot_id_hex: "00".repeat(16),
        }
    }

    fn test_config() -> ProducerConfig {
        ProducerConfig {
            partition_count: 4,
            ..Default::default()
        }
    }

    #[test]
    fn publish_batch_happy_path() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        let batch = make_batch(5);
        let key = IdempotencyKey::from_counter(1);

        let acc = pub_
            .publish_batch(&batch, &key, "prod", "agent/prod/node-1")
            .unwrap();

        assert!(!acc.is_duplicate);
        assert_eq!(acc.topic, "events.v1");
        assert_eq!(pub_.metrics().batches_accepted, 1);
        assert!(pub_.verify_no_hidden_loss());
    }

    #[test]
    fn publish_batch_deterministic_partition() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        let batch = make_batch(1);

        let acc1 = pub_
            .publish_batch(
                &batch,
                &IdempotencyKey::from_counter(1),
                "prod",
                "agent/prod/node-1",
            )
            .unwrap();

        let acc2 = pub_
            .publish_batch(
                &batch,
                &IdempotencyKey::from_counter(2),
                "prod",
                "agent/prod/node-1",
            )
            .unwrap();

        // Same agent → same partition.
        assert_eq!(acc1.partition, acc2.partition);
    }

    #[test]
    fn publish_batch_schema_rejected_to_dlq() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        let mut batch = make_batch(1);
        batch.schema_major = 2; // Unsupported.
        let key = IdempotencyKey::from_counter(1);

        let err = pub_
            .publish_batch(&batch, &key, "prod", "agent/prod/node-1")
            .unwrap_err();

        assert!(matches!(err, KafkaError::SchemaRejected { .. }));
        assert_eq!(pub_.dlq().routed_count(), 1);
        assert_eq!(pub_.metrics().batches_dlq, 1);
        assert!(pub_.verify_no_hidden_loss());
    }

    #[test]
    fn publish_batch_queue_full_no_ack() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        pub_.producer_mut().set_failure_mode(FailureMode::QueueFull);
        let batch = make_batch(1);
        let key = IdempotencyKey::from_counter(1);

        let err = pub_
            .publish_batch(&batch, &key, "prod", "agent/prod/node-1")
            .unwrap_err();

        assert!(matches!(err, KafkaError::QueueFull { .. }));
        assert_eq!(pub_.metrics().batches_rejected_queue_full, 1);
        // No ACK sent (batch stays in outbox).
        assert_eq!(pub_.metrics().batches_accepted, 0);
    }

    #[test]
    fn publish_batch_broker_down_no_ack() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        pub_.producer_mut()
            .set_failure_mode(FailureMode::BrokerDown);
        let batch = make_batch(1);
        let key = IdempotencyKey::from_counter(1);

        let err = pub_
            .publish_batch(&batch, &key, "prod", "agent/prod/node-1")
            .unwrap_err();

        assert!(matches!(err, KafkaError::BrokerUnavailable { .. }));
        assert_eq!(pub_.metrics().broker_unavailable_events, 1);
        assert_eq!(pub_.metrics().batches_accepted, 0);
    }

    #[test]
    fn publish_batch_transient_retry_recovers() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        pub_.producer_mut()
            .set_failure_mode(FailureMode::Transient { fail_count: 2 });
        let batch = make_batch(1);
        let key = IdempotencyKey::from_counter(1);

        let acc = pub_
            .publish_batch(&batch, &key, "prod", "agent/prod/node-1")
            .unwrap();

        assert!(!acc.is_duplicate);
        assert_eq!(pub_.metrics().batches_accepted, 1);
        assert!(pub_.producer_mut().retries() >= 2);
    }

    #[test]
    fn durable_callback_fires_on_acceptance() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        let callback_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = callback_log.clone();

        pub_.set_durable_callback(Box::new(move |acc| {
            log_clone.lock().unwrap().push(format!(
                "{}:p{}:o{}",
                acc.batch_id, acc.partition, acc.offset
            ));
        }));

        let batch = make_batch(1);
        pub_.publish_batch(
            &batch,
            &IdempotencyKey::from_counter(1),
            "prod",
            "agent/prod/node-1",
        )
        .unwrap();

        let log = callback_log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert!(log[0].starts_with("batch-1:"));
    }

    #[test]
    fn durable_callback_not_fired_on_failure() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        let callback_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = callback_log.clone();

        pub_.set_durable_callback(Box::new(move |acc| {
            log_clone.lock().unwrap().push(acc.batch_id);
        }));

        pub_.producer_mut()
            .set_failure_mode(FailureMode::BrokerDown);
        let batch = make_batch(1);
        let _ = pub_.publish_batch(
            &batch,
            &IdempotencyKey::from_counter(1),
            "prod",
            "agent/prod/node-1",
        );

        let log = callback_log.lock().unwrap();
        assert!(log.is_empty(), "callback must NOT fire on failure");
    }

    #[test]
    fn ack_ordering_matches_publish_order() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        let ack_order: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let order_clone = ack_order.clone();

        pub_.set_durable_callback(Box::new(move |acc| {
            order_clone.lock().unwrap().push(acc.batch_id);
        }));

        // Publish 5 batches from the same agent (same partition).
        for i in 0..5 {
            let batch = make_batch(1);
            pub_.publish_batch(
                &batch,
                &IdempotencyKey::from_counter(i),
                "prod",
                "agent/prod/node-1",
            )
            .unwrap();
        }

        let order = ack_order.lock().unwrap();
        assert_eq!(order.len(), 5);
        // ACKs arrive in publish order (same partition).
        for i in 0..5 {
            assert_eq!(order[i], format!("batch-{i}"));
        }
    }

    #[test]
    fn zero_hidden_loss_across_mixed_outcomes() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();

        // 3 accepted.
        for i in 0..3 {
            let batch = make_batch(1);
            pub_.publish_batch(
                &batch,
                &IdempotencyKey::from_counter(i),
                "prod",
                "agent/prod/node-1",
            )
            .unwrap();
        }

        // 1 schema rejected → DLQ.
        let mut bad_batch = make_batch(1);
        bad_batch.schema_major = 99;
        let _ = pub_.publish_batch(
            &bad_batch,
            &IdempotencyKey::from_counter(100),
            "prod",
            "agent/prod/node-1",
        );

        // 1 broker down.
        pub_.producer_mut()
            .set_failure_mode(FailureMode::BrokerDown);
        let _ = pub_.publish_batch(
            &make_batch(1),
            &IdempotencyKey::from_counter(200),
            "prod",
            "agent/prod/node-1",
        );

        assert_eq!(pub_.metrics().batches_submitted, 5);
        assert_eq!(pub_.metrics().batches_accepted, 3);
        assert_eq!(pub_.metrics().batches_dlq, 1);
        assert_eq!(pub_.metrics().broker_unavailable_events, 1);
        assert!(pub_.verify_no_hidden_loss());
    }

    #[test]
    fn leader_failover_recovers_without_loss() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();

        // Publish one batch successfully.
        let batch = make_batch(1);
        let acc1 = pub_
            .publish_batch(
                &batch,
                &IdempotencyKey::from_counter(1),
                "prod",
                "agent/prod/node-1",
            )
            .unwrap();

        // Simulate leader failover on that partition.
        pub_.producer_mut().simulate_leader_failover(acc1.partition);

        // Next publish fails (leader unavailable).
        let err = pub_
            .publish_batch(
                &batch,
                &IdempotencyKey::from_counter(2),
                "prod",
                "agent/prod/node-1",
            )
            .unwrap_err();
        assert!(matches!(err, KafkaError::BrokerUnavailable { .. }));

        // Restore leader.
        pub_.producer_mut().restore_leader(acc1.partition);

        // Publish succeeds, offset continues.
        let acc3 = pub_
            .publish_batch(
                &batch,
                &IdempotencyKey::from_counter(3),
                "prod",
                "agent/prod/node-1",
            )
            .unwrap();
        assert_eq!(acc3.offset, acc1.offset + 1);
        assert!(pub_.verify_no_hidden_loss());
    }

    #[test]
    fn invalid_config_rejected() {
        let config = ProducerConfig {
            acks: "1".to_string(),
            ..Default::default()
        };
        let err = KafkaPublisher::new(config).unwrap_err();
        assert!(matches!(err, KafkaError::UnrecoverableProducerError { .. }));
    }

    #[test]
    fn empty_batch_publishes() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        let batch = make_batch(0);
        let acc = pub_
            .publish_batch(
                &batch,
                &IdempotencyKey::from_counter(1),
                "prod",
                "agent/prod/node-1",
            )
            .unwrap();
        assert!(!acc.is_duplicate);
    }

    #[test]
    fn different_agents_may_get_different_partitions() {
        let mut pub_ = KafkaPublisher::new(test_config()).unwrap();
        let batch = make_batch(1);

        let acc1 = pub_
            .publish_batch(
                &batch,
                &IdempotencyKey::from_counter(1),
                "prod",
                "agent/prod/node-1",
            )
            .unwrap();

        let acc2 = pub_
            .publish_batch(
                &batch,
                &IdempotencyKey::from_counter(2),
                "staging",
                "agent/staging/worker-99",
            )
            .unwrap();

        // Both are valid partitions.
        assert!((0..4).contains(&acc1.partition));
        assert!((0..4).contains(&acc2.partition));
    }
}
