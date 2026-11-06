// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Node agent: attach sensors, persist events, serve the local API, and
//! fill the durable outbox.

#![forbid(unsafe_code)]

pub mod api;
pub mod batching;
pub mod config;
pub mod delivery;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bpf_loader::{RawSample, SensorStatus};
use event_model::{Alert, Event};
use observability::Metrics;
use privacy::Redactor;
use runtime::{Clock, Engine, ProcessTable};
use storage_local::{LocalStorage, StorageKey};
use tokio::sync::{broadcast, mpsc, watch};
use uuid::Uuid;

pub use config::AgentConfig;

/// A policy update pushed to the sensor thread.
#[derive(Debug, Clone)]
pub struct PolicyUpdate {
    /// Version.
    pub version: String,
    /// Digest.
    pub digest: String,
    /// YAML content.
    pub yaml: String,
}

/// Result of attempting to swap the rule engine in the sensor thread.
#[derive(Debug, Clone)]
pub struct PolicyApplyEvent {
    /// Version.
    pub version: String,
    /// Digest.
    pub digest: String,
    /// applied or rejected.
    pub status: String,
    /// Error detail for a rejection.
    pub message: String,
}

/// A decoded event and the alerts it produced.
pub struct AgentRecord {
    /// Event.
    pub event: Event,
    /// Alerts.
    pub alerts: Vec<Alert>,
}

enum AgentMessage {
    Record(Box<AgentRecord>),
    Error(String),
}

/// Agent errors.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Configuration failure.
    #[error("config: {0}")]
    Config(#[from] config::ConfigError),
    /// Storage failure.
    #[error("storage: {0}")]
    Storage(#[from] storage_local::StorageError),
    /// Key file is missing and dev mode is off.
    #[error("storage key missing at {0}")]
    KeyMissing(String),
    /// Redaction policy is invalid.
    #[error("privacy: {0}")]
    Privacy(#[from] privacy::PrivacyError),
    /// OS error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Poll thread panicked.
    #[error("sensor thread stopped unexpectedly")]
    SensorThread,
}

/// Run the agent until `shutdown` becomes true.
pub async fn run(config: AgentConfig, shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
    init_logging();
    // The external shutdown receiver is bridged to an internal one so the
    // TLS rotation watcher can request the same clean teardown path.
    let (internal_stop_tx, internal_stop_rx) = watch::channel(*shutdown.borrow());
    {
        let mut external = shutdown;
        let bridge = internal_stop_tx.clone();
        tokio::spawn(async move {
            while external.changed().await.is_ok() {
                if *external.borrow() {
                    let _ = bridge.send(true);
                    break;
                }
            }
        });
    }
    let agent_id = if config.agent_id.is_empty() {
        derive_agent_id()
    } else {
        config.agent_id.clone()
    };
    let generation = Uuid::new_v4().to_string();

    let key = match StorageKey::load(&config.key_path) {
        Ok(key) => key,
        Err(_) if config.dev => StorageKey::test(),
        Err(_) => {
            return Err(AgentError::KeyMissing(
                config.key_path.display().to_string(),
            ))
        }
    };
    let storage = Arc::new(LocalStorage::open(&config.db_path, &key)?);
    let metrics = Arc::new(Metrics::new().expect("metric names are static"));

    let stored_policy = storage.get_policy()?;
    let policy_yaml = stored_policy
        .as_ref()
        .and_then(|(_, _, content)| String::from_utf8(content.clone()).ok());
    if let Some(yaml) = &policy_yaml {
        match Engine::from_yaml(yaml) {
            Ok(engine) => tracing::info!(rules = engine.rule_count(), "loaded stored policy"),
            Err(error) => tracing::warn!(%error, "stored policy rejected; loading files"),
        }
    }
    let initial_policy = stored_policy.and_then(|(version, digest, content)| {
        String::from_utf8(content).ok().map(|yaml| PolicyUpdate {
            version,
            digest,
            yaml,
        })
    });
    let (policy_tx, policy_rx) = watch::channel(initial_policy);
    let (policy_ack_tx, policy_ack_rx) = mpsc::unbounded_channel::<PolicyApplyEvent>();

    let (live, _) = broadcast::channel(1024);
    let coverage = Arc::new(RwLock::new(None::<serde_json::Value>));
    let (coverage_tx, mut coverage_rx) = watch::channel(None::<serde_json::Value>);
    let coverage_state = coverage.clone();
    tokio::spawn(async move {
        while coverage_rx.changed().await.is_ok() {
            let value = coverage_rx.borrow().clone();
            if let Ok(mut guard) = coverage_state.write() {
                *guard = value;
            }
        }
    });

    let api_state = api::ApiState {
        storage: storage.clone(),
        metrics: metrics.clone(),
        live: live.clone(),
        coverage,
        agent_id: agent_id.clone(),
        cluster: config.cluster.clone(),
        node: config.node_name.clone(),
        started: Instant::now(),
    };

    let (api_shutdown_tx, api_shutdown_rx) = watch::channel(false);
    let api_handle = tokio::spawn({
        let listen = config.listen.clone();
        async move {
            if let Err(error) = api::serve(&listen, api_state, api_shutdown_rx).await {
                tracing::error!(%error, "local API stopped");
            }
        }
    });

    let mut tls_watch = None;
    if !config.dev {
        if let Some(transport) = config.transport.as_ref() {
            if config.tls_reload_poll_secs > 0
                && !transport.cert_path.as_os_str().is_empty()
                && !transport.key_path.as_os_str().is_empty()
            {
                tls_watch = Some(tokio::spawn(watch_tls_material(
                    transport.clone(),
                    config.tls_reload_poll_secs,
                    internal_stop_tx.clone(),
                )));
            }
        }
    }

    let mut otlp_handle = None;
    if let Some(otlp_config) = config.otlp.clone() {
        otlp_handle = Some(tokio::spawn(otlp::run(
            otlp_config,
            metrics.clone(),
            internal_stop_rx.clone(),
        )));
    }

    let mut delivery_handle = None;
    if let Some(transport) = config.transport.clone() {
        let storage = storage.clone();
        let metrics = metrics.clone();
        let agent_id = agent_id.clone();
        let generation = generation.clone();
        let sensors = config.sensors.clone();
        delivery_handle = Some(tokio::spawn(delivery::run(delivery::DeliveryConfig {
            storage,
            transport,
            dev: config.dev,
            agent_id,
            generation,
            cluster: config.cluster.clone(),
            node_name: config.node_name.clone(),
            sensors,
            policy_tx,
            policy_ack_rx,
            metrics,
        })));
    }

    let thread_stop = Arc::new(AtomicBool::new(false));
    let (sender, mut receiver) = mpsc::channel::<AgentMessage>(4096);
    let thread_config = config.clone();
    let thread_stop_poll = thread_stop.clone();
    let sensor_handle = std::thread::spawn(move || {
        poll_sensors(
            &thread_config,
            &policy_yaml,
            policy_rx,
            policy_ack_tx,
            sender,
            coverage_tx,
            thread_stop_poll,
        );
    });

    let mut shutdown_rx = internal_stop_rx.clone();
    let mut builder = batching::BatchBuilder::new(config.batch_max_events, config.batch_max_bytes);
    let mut ticker = tokio::time::interval(Duration::from_millis(config.flush_ms));
    let mut maintenance = tokio::time::interval(Duration::from_secs(60));
    let mut sensor_failed = false;

    loop {
        tokio::select! {
            message = receiver.recv() => {
                match message {
                    Some(AgentMessage::Record(record)) => {
                        let record = *record;
                        if let Err(error) = storage.insert_event(&record.event) {
                            metrics.storage_errors_total.inc();
                            tracing::error!(%error, "cannot insert event");
                        } else {
                            metrics.events_total.inc();
                        }
                        for alert in &record.alerts {
                            if let Err(error) = storage.insert_alert(alert) {
                                metrics.storage_errors_total.inc();
                                tracing::error!(%error, "cannot insert alert");
                            } else {
                                metrics.alerts_total.inc();
                            }
                        }
                        let _ = live.send(record.event.clone());
                        builder.push(record.event, record.alerts);
                        if builder.should_flush() {
                            flush(&storage, &mut builder, &agent_id, &config, &generation)?;
                        }
                    }
                    Some(AgentMessage::Error(error)) => {
                        tracing::error!(%error, "sensor loop failed");
                        sensor_failed = true;
                        break;
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                flush(&storage, &mut builder, &agent_id, &config, &generation)?;
                metrics.outbox_depth.set(storage.outbox_depth().unwrap_or(0) as i64);
                metrics.storage_bytes.set(storage.size_bytes() as i64);
            }
            _ = maintenance.tick() => {
                if let Err(error) = storage.prune(config.retention_secs) {
                    tracing::warn!(%error, "prune failed");
                }
                if let Err(error) = storage.checkpoint() {
                    tracing::warn!(%error, "checkpoint failed");
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    // Close the sensor channel before joining. The poll thread may be blocked
    // in blocking_send when the receiver is full; dropping it makes that send
    // fail and lets the thread observe the stop flag.
    drop(receiver);
    thread_stop.store(true, Ordering::SeqCst);
    sensor_handle.join().map_err(|_| AgentError::SensorThread)?;
    flush(&storage, &mut builder, &agent_id, &config, &generation)?;
    storage.checkpoint()?;
    let _ = api_shutdown_tx.send(true);
    if let Some(handle) = delivery_handle {
        handle.abort();
    }
    if let Some(handle) = otlp_handle {
        handle.abort();
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), api_handle).await;
    if let Some(handle) = tls_watch {
        handle.abort();
    }
    if sensor_failed {
        return Err(AgentError::SensorThread);
    }
    Ok(())
}

fn poll_sensors(
    config: &AgentConfig,
    policy_yaml: &Option<String>,
    mut policy_rx: watch::Receiver<Option<PolicyUpdate>>,
    policy_ack_tx: mpsc::UnboundedSender<PolicyApplyEvent>,
    sender: mpsc::Sender<AgentMessage>,
    coverage_tx: watch::Sender<Option<serde_json::Value>>,
    shutdown: Arc<AtomicBool>,
) {
    let names: Vec<&str> = config.sensors.iter().map(String::as_str).collect();
    let sensors = match bpf_loader::load(&names) {
        Ok(sensors) => sensors,
        Err(error) => {
            let _ = sender.blocking_send(AgentMessage::Error(error.to_string()));
            return;
        }
    };
    if sensors.sensors.is_empty() {
        let _ = sender.blocking_send(AgentMessage::Error(
            "no sensor attached; run ebpf-runtime check for details".to_string(),
        ));
        return;
    }
    let coverage = serde_json::to_value(&sensors.coverage).unwrap_or(serde_json::Value::Null);
    let _ = coverage_tx.send(Some(coverage));
    for sensor in &sensors.coverage.sensors {
        if sensor.status == SensorStatus::Blocked {
            tracing::warn!(sensor = %sensor.name, "sensor blocked");
        }
    }

    let mut clock = Clock::new();
    let mut table = ProcessTable::with_proc_root(&config.proc_root);
    let engine = policy_yaml
        .as_deref()
        .and_then(|yaml| Engine::from_yaml(yaml).ok())
        .or_else(|| {
            if config.rules_dir.is_dir() {
                Engine::load(&config.rules_dir).ok()
            } else {
                None
            }
        });
    let mut engine = engine.unwrap_or_else(Engine::empty);
    let redactor = match Redactor::new(&config.redaction) {
        Ok(redactor) => redactor,
        Err(error) => {
            let _ = sender.blocking_send(AgentMessage::Error(error.to_string()));
            return;
        }
    };
    let (ring, samples) = match sensors.ring_reader() {
        Ok(pair) => pair,
        Err(error) => {
            let _ = sender.blocking_send(AgentMessage::Error(error.to_string()));
            return;
        }
    };

    while !shutdown.load(Ordering::Relaxed) {
        if policy_rx.has_changed().unwrap_or(false) {
            let update = policy_rx.borrow_and_update().clone();
            if let Some(update) = update {
                update_engine(&mut engine, &update, &policy_ack_tx);
            }
        }
        if let Err(error) = ring.poll(Duration::from_millis(200)) {
            let _ = sender.blocking_send(AgentMessage::Error(error.to_string()));
            break;
        }
        for sample in samples.try_iter() {
            let Some(event) = decode_sample(&sample, &mut clock, &mut table) else {
                continue;
            };
            let rule_alerts = engine.evaluate(&event);
            let mut event = event;
            redactor.apply(&mut event);
            let alerts = rule_alerts
                .iter()
                .map(|alert| {
                    let mut alert = Alert {
                        alert_id: Uuid::new_v4().to_string(),
                        rule_id: alert.rule.clone(),
                        severity: alert.severity.clone(),
                        event_id: event.event_id.clone(),
                        fired_at: chrono::Utc::now()
                            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                        explanation: alert.description.clone(),
                        cluster: config.cluster.clone(),
                        node_name: config.node_name.clone(),
                    };
                    redactor.apply_alert(&mut alert);
                    alert
                })
                .collect();
            if sender
                .blocking_send(AgentMessage::Record(Box::new(AgentRecord {
                    event,
                    alerts,
                })))
                .is_err()
            {
                return;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified_secs: u64,
    modified_nanos: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TlsFingerprint {
    ca: Option<FileStamp>,
    cert: Option<FileStamp>,
    key: Option<FileStamp>,
}

fn file_stamp(path: &std::path::Path) -> Option<FileStamp> {
    let metadata = std::fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    let since = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(FileStamp {
        len: metadata.len(),
        modified_secs: since.as_secs(),
        modified_nanos: since.subsec_nanos(),
    })
}

fn tls_fingerprint(transport: &transport::TransportConfig) -> TlsFingerprint {
    TlsFingerprint {
        ca: file_stamp(&transport.ca_path),
        cert: file_stamp(&transport.cert_path),
        key: file_stamp(&transport.key_path),
    }
}

/// Watch certificate, key, and CA files for replacement.
///
/// A changed file requests a clean agent shutdown. systemd
/// (`Restart=always`) or Kubernetes restarts the process and the new client
/// reads the rotated material. This is the first-version rotation behavior;
/// it deliberately does not try to swap a live TLS connection.
async fn watch_tls_material(
    transport: transport::TransportConfig,
    poll_secs: u64,
    stop: watch::Sender<bool>,
) {
    let mut last = tls_fingerprint(&transport);
    let mut ticker = tokio::time::interval(Duration::from_secs(poll_secs.max(1)));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let current = tls_fingerprint(&transport);
        if current != last {
            tracing::warn!("TLS material changed; restarting agent");
            let _ = stop.send(true);
            return;
        }
        last = current;
    }
}

/// Parse and install a policy update, then report the result.
///
/// The acknowledgement is sent only after the new engine is active. The
/// control-plane rollout threshold therefore measures engine activation, not
/// just persistence of the pack.
fn update_engine(
    engine: &mut Engine,
    update: &PolicyUpdate,
    ack_tx: &mpsc::UnboundedSender<PolicyApplyEvent>,
) {
    match Engine::from_yaml(&update.yaml) {
        Ok(next) => {
            *engine = next;
            let _ = ack_tx.send(PolicyApplyEvent {
                version: update.version.clone(),
                digest: update.digest.clone(),
                status: "applied".to_string(),
                message: String::new(),
            });
            tracing::info!(version = %update.version, "policy applied");
        }
        Err(error) => {
            let _ = ack_tx.send(PolicyApplyEvent {
                version: update.version.clone(),
                digest: update.digest.clone(),
                status: "rejected".to_string(),
                message: error.to_string(),
            });
            tracing::warn!(%error, "policy rejected at apply time");
        }
    }
}

fn decode_sample(sample: &RawSample, clock: &mut Clock, table: &mut ProcessTable) -> Option<Event> {
    match event_model::decode(&sample.sensor, &sample.bytes, clock) {
        Ok(mut event) => {
            table.observe(&mut event);
            Some(event)
        }
        Err(error) => {
            tracing::debug!(%error, sensor = %sample.sensor, "decode failed");
            None
        }
    }
}

fn flush(
    storage: &LocalStorage,
    builder: &mut batching::BatchBuilder,
    agent_id: &str,
    config: &AgentConfig,
    generation: &str,
) -> Result<(), AgentError> {
    let Some(batch) = builder.take(agent_id, &config.cluster, &config.node_name, generation) else {
        return Ok(());
    };
    storage.insert_batch(&batch)?;
    Ok(())
}

fn derive_agent_id() -> String {
    let machine = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .unwrap_or_else(|_| "unknown".to_string());
    let machine = machine.trim();
    let short = machine.chars().take(12).collect::<String>();
    format!("{}-{short}", config::hostname_for_id())
}

/// Initialize logging from `RUST_LOG` and use JSON in production.
pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_agent_id_is_not_empty() {
        assert!(!derive_agent_id().is_empty());
    }

    #[test]
    fn tls_fingerprint_changes_when_material_changes() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.crt");
        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        std::fs::write(&ca_path, b"ca-one").unwrap();
        std::fs::write(&cert_path, b"cert-one").unwrap();
        std::fs::write(&key_path, b"key-one").unwrap();
        let config = transport::TransportConfig {
            endpoint: "https://127.0.0.1:9443".to_string(),
            domain_name: "control-plane".to_string(),
            ca_path,
            cert_path,
            key_path,
            timeout_secs: 5,
        };
        let first = tls_fingerprint(&config);
        assert_eq!(first, tls_fingerprint(&config));
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(&config.cert_path, b"cert-two").unwrap();
        assert_ne!(first, tls_fingerprint(&config));
    }

    #[test]
    fn update_engine_acks_after_swap_and_rejects_bad_yaml() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut engine = Engine::empty();
        let update = PolicyUpdate {
            version: "9".to_string(),
            digest: "digest".to_string(),
            yaml: "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: t\n    version: 1\n    severity: low\n    source: file\n    description: t\n    condition:\n      field: file.path\n      operator: eq\n      value: /tmp/t\n    action: alert\n".to_string(),
        };
        update_engine(&mut engine, &update, &tx);
        assert_eq!(engine.rule_count(), 1);
        let ack = rx.try_recv().expect("applied ack");
        assert_eq!(ack.status, "applied");
        assert_eq!(ack.version, "9");

        let bad = PolicyUpdate {
            version: "10".to_string(),
            digest: "digest2".to_string(),
            yaml: "not a ruleset".to_string(),
        };
        update_engine(&mut engine, &bad, &tx);
        assert_eq!(engine.rule_count(), 1);
        let ack = rx.try_recv().expect("rejected ack");
        assert_eq!(ack.status, "rejected");
    }
}
