// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Outbox delivery to the control plane.

use std::sync::Arc;
use std::time::Duration;

use observability::Metrics;
use storage_local::LocalStorage;
use transport::TransportClient;

/// Delivery task inputs.
pub struct DeliveryConfig {
    /// Local outbox.
    pub storage: Arc<LocalStorage>,
    /// Transport configuration.
    pub transport: transport::TransportConfig,
    /// Use plaintext loopback gRPC.
    pub dev: bool,
    /// Agent id.
    pub agent_id: String,
    /// Agent generation.
    pub generation: String,
    /// Cluster.
    pub cluster: String,
    /// Node.
    pub node_name: String,
    /// Sensors to report.
    pub sensors: Vec<String>,
    /// Policy updates for the sensor thread.
    pub policy_tx: tokio::sync::watch::Sender<Option<crate::PolicyUpdate>>,
    /// Metrics.
    pub metrics: Arc<Metrics>,
}

/// Deliver unacknowledged batches until shutdown.
pub async fn run(config: DeliveryConfig) {
    let DeliveryConfig {
        storage,
        transport,
        dev,
        agent_id,
        generation,
        cluster,
        node_name,
        sensors,
        policy_tx,
        metrics,
    } = config;
    let client = loop {
        let connected = if dev {
            TransportClient::connect_insecure(&transport.endpoint, &agent_id, &generation).await
        } else {
            TransportClient::connect(&transport, &agent_id, &generation).await
        };
        match connected {
            Ok(client) => break client,
            Err(error) => {
                metrics.transport_retries_total.inc();
                tracing::warn!(%error, "control plane connect failed; retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    loop {
        match client
            .register(&cluster, &node_name, &boot_id_hex(), &sensors)
            .await
        {
            Ok(_) => break,
            Err(error) => {
                metrics.transport_retries_total.inc();
                tracing::warn!(%error, "register failed; retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }

    start_control_watch(client.clone(), storage.clone(), policy_tx, metrics.clone());

    loop {
        let batches = match storage.due_batches(10) {
            Ok(batches) => batches,
            Err(error) => {
                tracing::error!(%error, "cannot read outbox");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        for outbox in batches {
            let batch: event_model::Batch = match serde_json::from_slice(&outbox.payload) {
                Ok(batch) => batch,
                Err(error) => {
                    tracing::error!(batch_id = %outbox.batch_id, %error, "corrupt outbox payload");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            match client.publish_batch(&batch).await {
                Ok(ack) if ack.accepted || ack.duplicate => {
                    if let Err(error) = storage.ack_batch(&outbox.batch_id) {
                        tracing::error!(%error, "cannot ack outbox batch");
                    } else {
                        metrics.delivered_batches_total.inc();
                        metrics
                            .delivered_events_total
                            .inc_by(batch.events.len() as u64);
                    }
                }
                Ok(ack) => {
                    metrics.transport_retries_total.inc();
                    tracing::warn!(batch_id = %outbox.batch_id, error = %ack.error, "batch rejected");
                    let delay = backoff(outbox.attempts);
                    let _ = storage.retry_batch(&outbox.batch_id, delay);
                }
                Err(error) => {
                    metrics.transport_retries_total.inc();
                    tracing::warn!(batch_id = %outbox.batch_id, %error, "publish failed");
                    let delay = backoff(outbox.attempts);
                    let _ = storage.retry_batch(&outbox.batch_id, delay);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn start_control_watch(
    client: TransportClient,
    storage: Arc<LocalStorage>,
    policy_tx: tokio::sync::watch::Sender<Option<crate::PolicyUpdate>>,
    metrics: Arc<Metrics>,
) {
    tokio::spawn(async move {
        use futures_util::StreamExt;
        loop {
            match client.watch_control().await {
                Ok(mut stream) => {
                    while let Some(command) = stream.next().await {
                        match command {
                            Ok(command) => {
                                if let Some(protocol::v1::control_command::Command::Policy(
                                    snapshot,
                                )) = command.command
                                {
                                    apply_policy(&client, &storage, &policy_tx, snapshot).await;
                                }
                            }
                            Err(error) => {
                                metrics.transport_retries_total.inc();
                                tracing::warn!(%error, "control stream error");
                                break;
                            }
                        }
                    }
                }
                Err(error) => {
                    metrics.transport_retries_total.inc();
                    tracing::warn!(%error, "control stream connect failed");
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

async fn apply_policy(
    client: &TransportClient,
    storage: &LocalStorage,
    policy_tx: &tokio::sync::watch::Sender<Option<crate::PolicyUpdate>>,
    snapshot: protocol::v1::PolicySnapshot,
) {
    let yaml = match String::from_utf8(snapshot.yaml) {
        Ok(yaml) => yaml,
        Err(_) => {
            let _ = client
                .report_policy_ack(
                    &snapshot.version,
                    &snapshot.digest,
                    "rejected",
                    "policy is not UTF-8",
                )
                .await;
            return;
        }
    };
    let ruleset = match rules::parse_ruleset(&yaml) {
        Ok(ruleset) => ruleset,
        Err(error) => {
            let _ = client
                .report_policy_ack(
                    &snapshot.version,
                    &snapshot.digest,
                    "rejected",
                    &error.to_string(),
                )
                .await;
            return;
        }
    };
    let digest = match rules::canonical_digest(&ruleset) {
        Ok(digest) => digest,
        Err(error) => {
            let _ = client
                .report_policy_ack(
                    &snapshot.version,
                    &snapshot.digest,
                    "rejected",
                    &error.to_string(),
                )
                .await;
            return;
        }
    };
    if digest != snapshot.digest {
        let _ = client
            .report_policy_ack(
                &snapshot.version,
                &snapshot.digest,
                "rejected",
                "digest mismatch",
            )
            .await;
        return;
    }
    if let Err(error) = storage.set_policy(&snapshot.version, &digest, yaml.as_bytes()) {
        let _ = client
            .report_policy_ack(&snapshot.version, &digest, "rejected", &error.to_string())
            .await;
        return;
    }
    let _ = policy_tx.send(Some(crate::PolicyUpdate {
        version: snapshot.version.clone(),
        digest: snapshot.digest.clone(),
        yaml,
    }));
    let _ = client
        .report_policy_ack(&snapshot.version, &digest, "applied", "")
        .await;
}

fn boot_id_hex() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().replace('-', ""))
        .unwrap_or_else(|_| "0".repeat(32))
}

fn backoff(attempts: u32) -> u64 {
    2u64.saturating_pow(attempts.min(6)).min(60)
}
