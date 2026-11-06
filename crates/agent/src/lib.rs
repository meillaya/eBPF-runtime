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

    let policy_yaml = storage
        .get_policy()?
        .and_then(|(_, _, content)| String::from_utf8(content).ok());
    if let Some(yaml) = &policy_yaml {
        match Engine::from_yaml(yaml) {
            Ok(engine) => tracing::info!(rules = engine.rule_count(), "loaded stored policy"),
            Err(error) => tracing::warn!(%error, "stored policy rejected; loading files"),
        }
    }

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
            sender,
            coverage_tx,
            thread_stop_poll,
        );
    });

    let mut shutdown_rx = shutdown.clone();
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

    thread_stop.store(true, Ordering::SeqCst);
    sensor_handle.join().map_err(|_| AgentError::SensorThread)?;
    flush(&storage, &mut builder, &agent_id, &config, &generation)?;
    storage.checkpoint()?;
    let _ = api_shutdown_tx.send(true);
    if let Some(handle) = delivery_handle {
        handle.abort();
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), api_handle).await;
    if sensor_failed {
        return Err(AgentError::SensorThread);
    }
    Ok(())
}

fn poll_sensors(
    config: &AgentConfig,
    policy_yaml: &Option<String>,
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
}
