// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::channel::{EventPriority, PriorityBoundedChannel};
use crate::model::{ControlEvent, KillSwitchReason, KillSwitchState, NormalizedEvent};
use crate::normalize::normalize_bytes;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct AgentCoreOpts {
    pub control_capacity: usize,
    pub data_capacity: usize,
    pub allowed_sequence_gap: u64,
    pub poll_timeout: Duration,
    pub idle_timeout: Duration,
    pub drain_on_shutdown: bool,
    pub emit_delay: Duration,
}
impl Default for AgentCoreOpts {
    fn default() -> Self {
        Self {
            control_capacity: 32,
            data_capacity: 2_048,
            allowed_sequence_gap: 0,
            poll_timeout: Duration::from_millis(10),
            idle_timeout: Duration::from_secs(30),
            drain_on_shutdown: true,
            emit_delay: Duration::ZERO,
        }
    }
}
#[derive(Debug, Error)]
pub enum AgentCoreError {
    #[error("channel capacity must be non-zero")]
    ZeroCapacity,
}

pub struct AgentCore {
    pub ingestion: Mutex<Option<JoinHandle<()>>>,
    pub kafka_emit: Mutex<Option<JoinHandle<()>>>,
    pub control: PriorityBoundedChannel<ControlEvent>,
    pub data: PriorityBoundedChannel<NormalizedEvent>,
    pub cancel: CancellationToken,
    pub seq_gap_counter: Arc<AtomicU64>,
    pub drop_counter: Arc<AtomicU64>,
    pub kill_switch_state: Arc<AtomicU8>,
    error_counter: Arc<AtomicU64>,
    panic_counter: Arc<AtomicU64>,
    last_seq: Mutex<Option<u64>>,
    allowed_sequence_gap: u64,
    shutdown_started: AtomicBool,
    emitted_count: Arc<AtomicU64>,
    control_emitted_count: Arc<AtomicU64>,
}
impl AgentCore {
    pub async fn start(
        rx: libbpf_rs::RingBuffer<'static>,
        opts: AgentCoreOpts,
    ) -> Result<Self, AgentCoreError> {
        Self::build(opts, Some(rx)).await
    }
    pub async fn start_replay(opts: AgentCoreOpts) -> Result<Self, AgentCoreError> {
        Self::build(opts, None).await
    }
    async fn build(
        opts: AgentCoreOpts,
        ring: Option<libbpf_rs::RingBuffer<'static>>,
    ) -> Result<Self, AgentCoreError> {
        if opts.control_capacity == 0 || opts.data_capacity == 0 {
            return Err(AgentCoreError::ZeroCapacity);
        }
        let control = PriorityBoundedChannel::new(opts.control_capacity, opts.control_capacity);
        let data = PriorityBoundedChannel::new(opts.control_capacity, opts.data_capacity);
        let cancel = CancellationToken::new();
        let errors = Arc::new(AtomicU64::new(0));
        let ingest_cancel = cancel.clone();
        let poll_timeout = opts.poll_timeout;
        let idle_timeout = opts.idle_timeout;
        let drain = opts.drain_on_shutdown;
        let ingest_errors = Arc::clone(&errors);
        let ingestion = match ring {
            Some(rx) => tokio::task::spawn_blocking(move || {
                let mut last_event = Instant::now();
                while !ingest_cancel.is_cancelled() {
                    let count = rx.poll_raw(poll_timeout);
                    if count > 0 {
                        last_event = Instant::now();
                    } else if count < 0 {
                        ingest_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(libbpf_result = count, "ring buffer poll failed");
                    } else if drain && last_event.elapsed() >= idle_timeout {
                        ingest_cancel.cancel();
                    }
                }
            }),
            None => tokio::spawn(async move { ingest_cancel.cancelled().await }),
        };
        let emit_cancel = cancel.clone();
        let emit_control = control.clone();
        let emit_data = data.clone();
        let emitted = Arc::new(AtomicU64::new(0));
        let controls = Arc::new(AtomicU64::new(0));
        let emitted_task = Arc::clone(&emitted);
        let controls_task = Arc::clone(&controls);
        let delay = opts.emit_delay;
        let kafka_emit = tokio::spawn(async move {
            loop {
                if emit_control.try_recv().is_some() {
                    controls_task.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if emit_data.try_recv().is_some() {
                    emitted_task.fetch_add(1, Ordering::Relaxed);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    continue;
                }
                if emit_cancel.is_cancelled() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        });
        Ok(Self {
            ingestion: Mutex::new(Some(ingestion)),
            kafka_emit: Mutex::new(Some(kafka_emit)),
            control,
            data,
            cancel,
            seq_gap_counter: Arc::new(AtomicU64::new(0)),
            drop_counter: Arc::new(AtomicU64::new(0)),
            kill_switch_state: Arc::new(AtomicU8::new(0)),
            error_counter: errors,
            panic_counter: Arc::new(AtomicU64::new(0)),
            last_seq: Mutex::new(None),
            allowed_sequence_gap: opts.allowed_sequence_gap,
            shutdown_started: AtomicBool::new(false),
            emitted_count: emitted,
            control_emitted_count: controls,
        })
    }
    pub fn ingest_bytes(&self, bytes: &[u8]) -> Result<(), event_abi::DecodeError> {
        let event = normalize_bytes(bytes)?;
        let actual = event.sequence.0;
        let mut last = self.last_seq.lock();
        if let Some(previous) = *last {
            let expected = previous.saturating_add(1);
            if actual < expected || actual.saturating_sub(expected) > self.allowed_sequence_gap {
                self.seq_gap_counter.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    expected_sequence = expected,
                    actual_sequence = actual,
                    "ring sequence gap detected"
                );
            }
        }
        *last = Some(actual);
        drop(last);
        if self
            .data
            .try_send_with_priority(event, EventPriority::Data)
            .is_err()
        {
            self.drop_counter.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
    pub fn send_control(&self, event: ControlEvent) {
        if self
            .control
            .try_send_with_priority(event, EventPriority::Control)
            .is_err()
        {
            self.drop_counter.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub async fn trigger_kill_switch(&self, reason: KillSwitchReason) {
        self.kill_switch_state.store(1, Ordering::Release);
        let _ = self
            .control
            .try_send_with_priority(ControlEvent::KillSwitch(reason), EventPriority::Control);
        self.cancel.cancel();
        self.join_tasks().await;
    }
    pub async fn shutdown(&self) {
        self.shutdown_started.store(true, Ordering::Release);
        self.cancel.cancel();
        self.join_tasks().await;
    }
    async fn join_tasks(&self) {
        for slot in [&self.ingestion, &self.kafka_emit] {
            let handle = slot.lock().take();
            if let Some(handle) = handle {
                if handle.await.is_err() {
                    self.panic_counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    pub fn seq_gap_count(&self) -> u64 {
        self.seq_gap_counter.load(Ordering::Relaxed)
    }
    pub fn drop_count(&self) -> u64 {
        self.drop_counter.load(Ordering::Relaxed)
    }
    pub fn error_count(&self) -> u64 {
        self.error_counter.load(Ordering::Relaxed)
    }
    pub fn panic_count(&self) -> u64 {
        self.panic_counter.load(Ordering::Relaxed)
    }
    pub fn emitted_count(&self) -> u64 {
        self.emitted_count.load(Ordering::Relaxed)
    }
    pub fn control_emitted_count(&self) -> u64 {
        self.control_emitted_count.load(Ordering::Relaxed)
    }
    pub fn kill_switch_state(&self) -> KillSwitchState {
        match self.kill_switch_state.load(Ordering::Acquire) {
            0 => KillSwitchState::Armed,
            _ => KillSwitchState::Triggered,
        }
    }
    pub fn queue_depth(&self) -> usize {
        self.control.len().saturating_add(self.data.len())
    }
}
