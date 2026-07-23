// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Sink adapters: the only egress path for telemetry, and every sink receives
//! the **same** [`RedactedEvent`].
//!
//! # No bypass
//!
//! The [`SinkAdapter`] trait accepts only a `&RedactedEvent`. There is no
//! method that accepts a [`agent_core::NormalizedEvent`] or raw bytes; the
//! deliberate [`write_normalized_to_sinks`] entry point always returns
//! [`SinkError::BypassRejected`]. A sink therefore cannot reach past the
//! privacy boundary: the raw payload is not present on the only type a sink is
//! handed.
//!
//! # In-memory sink fixtures
//!
//! The real sinks (SQLite, Kafka, REST, WebSocket) require external services
//! that are out of scope for this host-side policy crate and absent from this
//! environment. The `sqlite`, `kafka`, `websocket`, and `reqwest` modules below
//! are therefore **in-memory fixtures / test doubles** that record exactly what
//! each sink would persist or transmit. They preserve the field shape named in
//! the plan (`SqliteSinkAdapter { db }`, `KafkaSinkAdapter { producer }`,
//! `RestSinkAdapter { client }`, `WebSocketSinkAdapter { ws }`) while letting
//! the acceptance tests assert that seeded tokens are absent from every sink's
//! recorded output. Swapping a fixture for a real driver is a later-wave task;
//! the privacy contract (same `RedactedEvent` to every sink, no raw payload)
//! is fixed here.
//!
//! The `LogSinkAdapter` deviates from the plan's literal `tracing::Subscriber`
//! field for two reasons: `tracing::Subscriber` is a trait and cannot be a bare
//! field type, and the acceptance test must inspect the exact logged bytes to
//! prove seeded tokens are absent. It records structured log lines into a
//! [`LogCapture`] and forwards them through `tracing::debug!` (redacted output
//! only).

use parking_lot::Mutex;

use crate::RedactedEvent;

// ---------------------------------------------------------------------------
// In-memory sink fixtures (test doubles for the real external sinks)
// ---------------------------------------------------------------------------

/// In-memory fixture for a SQLite connection. Records each redacted event as a
/// JSON row. Stands in for a real `sqlite::Connection`.
pub mod sqlite {
    /// In-memory stand-in for a SQLite connection: an append-only row store.
    #[derive(Debug, Default)]
    pub struct Connection {
        rows: Vec<serde_json::Value>,
    }
    impl Connection {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn insert(&mut self, row: serde_json::Value) {
            self.rows.push(row);
        }
        pub fn rows(&self) -> &[serde_json::Value] {
            &self.rows
        }
    }
}

/// In-memory fixture for a Kafka producer. Records each produced message
/// (topic + payload bytes). Stands in for a real `kafka::Producer`.
pub mod kafka {
    /// A single produced Kafka message (topic + payload).
    #[derive(Debug, Clone)]
    pub struct ProducedMessage {
        pub topic: String,
        pub payload: Vec<u8>,
    }
    /// In-memory stand-in for a Kafka producer.
    #[derive(Debug, Default)]
    pub struct Producer {
        messages: Vec<ProducedMessage>,
    }
    impl Producer {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn send(&mut self, topic: &str, payload: Vec<u8>) {
            self.messages.push(ProducedMessage {
                topic: topic.to_string(),
                payload,
            });
        }
        pub fn messages(&self) -> &[ProducedMessage] {
            &self.messages
        }
    }
}

/// In-memory fixture for a WebSocket sender. Records each sent frame's bytes.
/// Stands in for a real `websocket::Sender`.
pub mod websocket {
    /// In-memory stand-in for a WebSocket sender.
    #[derive(Debug, Default)]
    pub struct Sender {
        frames: Vec<Vec<u8>>,
    }
    impl Sender {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn send(&mut self, frame: Vec<u8>) {
            self.frames.push(frame);
        }
        pub fn frames(&self) -> &[Vec<u8>] {
            &self.frames
        }
    }
}

/// In-memory fixture for an HTTP client. Records each POST body. Stands in for
/// a real `reqwest::Client`.
pub mod reqwest {
    /// A single recorded HTTP request (url + body).
    #[derive(Debug, Clone)]
    pub struct RecordedRequest {
        pub url: String,
        pub body: Vec<u8>,
    }
    /// In-memory stand-in for a `reqwest::Client`.
    #[derive(Debug)]
    pub struct Client {
        url: String,
        requests: Vec<RecordedRequest>,
    }
    impl Client {
        pub fn new(url: impl Into<String>) -> Self {
            Self {
                url: url.into(),
                requests: Vec::new(),
            }
        }
        pub fn post(&mut self, body: Vec<u8>) {
            self.requests.push(RecordedRequest {
                url: self.url.clone(),
                body,
            });
        }
        pub fn requests(&self) -> &[RecordedRequest] {
            &self.requests
        }
    }
}

/// In-memory structured-log capture. Records each formatted redacted log line.
#[derive(Debug, Default)]
pub struct LogCapture {
    pub lines: Vec<String>,
}

impl LogCapture {
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Sink errors
// ---------------------------------------------------------------------------

/// A sink failure. [`SinkError::BypassRejected`] is returned for any attempt to
/// write a raw / pre-redaction record to a sink.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("sink failed: {0}")]
    SinkFailed(String),
    #[error("bypass rejected: {0}")]
    BypassRejected(&'static str),
}

// ---------------------------------------------------------------------------
// The canonical sink interface
// ---------------------------------------------------------------------------

/// The canonical sink interface. Every sink (SQLite, Kafka, REST, WebSocket,
/// logs) implements this and accepts **only** a [`RedactedEvent`]. There is no
/// raw-bytes write path — that is the structural no-bypass guarantee.
pub trait SinkAdapter: Send + Sync {
    /// Write a redacted event to the sink.
    fn write_redacted(&mut self, event: &RedactedEvent) -> Result<(), SinkError>;
    /// Stable sink name (for diagnostics and verification).
    fn name(&self) -> &'static str;
    /// The serialized records this sink has accepted (verification helper).
    fn recorded_bytes(&self) -> Vec<Vec<u8>>;
}

/// SQLite sink adapter. Writes each redacted event as a JSON row.
#[derive(Debug, Default)]
pub struct SqliteSinkAdapter {
    pub db: Mutex<sqlite::Connection>,
}

impl SqliteSinkAdapter {
    pub fn new() -> Self {
        Self {
            db: Mutex::new(sqlite::Connection::new()),
        }
    }
    pub fn rows(&self) -> Vec<serde_json::Value> {
        self.db.lock().rows().to_vec()
    }
}

impl SinkAdapter for SqliteSinkAdapter {
    fn write_redacted(&mut self, event: &RedactedEvent) -> Result<(), SinkError> {
        self.db.lock().insert(event.to_json());
        Ok(())
    }
    fn name(&self) -> &'static str {
        "sqlite"
    }
    fn recorded_bytes(&self) -> Vec<Vec<u8>> {
        self.db
            .lock()
            .rows()
            .iter()
            .filter_map(|row| serde_json::to_vec(row).ok())
            .collect()
    }
}

/// Kafka sink adapter. Publishes each redacted event to the `telemetry` topic.
#[derive(Debug, Default)]
pub struct KafkaSinkAdapter {
    pub producer: Mutex<kafka::Producer>,
}

/// The Kafka topic every redacted event is published to.
pub const KAFKA_TOPIC: &str = "telemetry";

impl KafkaSinkAdapter {
    pub fn new() -> Self {
        Self {
            producer: Mutex::new(kafka::Producer::new()),
        }
    }
    pub fn messages(&self) -> Vec<kafka::ProducedMessage> {
        self.producer.lock().messages().to_vec()
    }
}

impl SinkAdapter for KafkaSinkAdapter {
    fn write_redacted(&mut self, event: &RedactedEvent) -> Result<(), SinkError> {
        let bytes = event
            .to_json_bytes()
            .map_err(|e| SinkError::Serialization(e.to_string()))?;
        self.producer.lock().send(KAFKA_TOPIC, bytes);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "kafka"
    }
    fn recorded_bytes(&self) -> Vec<Vec<u8>> {
        self.producer
            .lock()
            .messages()
            .iter()
            .map(|m| m.payload.clone())
            .collect()
    }
}

/// REST sink adapter. POSTs each redacted event to the configured endpoint.
#[derive(Debug)]
pub struct RestSinkAdapter {
    pub client: reqwest::Client,
}

impl RestSinkAdapter {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(url),
        }
    }
    pub fn requests(&self) -> Vec<reqwest::RecordedRequest> {
        self.client.requests().to_vec()
    }
}

impl SinkAdapter for RestSinkAdapter {
    fn write_redacted(&mut self, event: &RedactedEvent) -> Result<(), SinkError> {
        let bytes = event
            .to_json_bytes()
            .map_err(|e| SinkError::Serialization(e.to_string()))?;
        self.client.post(bytes);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "rest"
    }
    fn recorded_bytes(&self) -> Vec<Vec<u8>> {
        self.client
            .requests()
            .iter()
            .map(|r| r.body.clone())
            .collect()
    }
}

/// WebSocket sink adapter. Sends each redacted event as a binary frame.
#[derive(Debug, Default)]
pub struct WebSocketSinkAdapter {
    pub ws: Mutex<websocket::Sender>,
}

impl WebSocketSinkAdapter {
    pub fn new() -> Self {
        Self {
            ws: Mutex::new(websocket::Sender::new()),
        }
    }
    pub fn frames(&self) -> Vec<Vec<u8>> {
        self.ws.lock().frames().to_vec()
    }
}

impl SinkAdapter for WebSocketSinkAdapter {
    fn write_redacted(&mut self, event: &RedactedEvent) -> Result<(), SinkError> {
        let bytes = event
            .to_json_bytes()
            .map_err(|e| SinkError::Serialization(e.to_string()))?;
        self.ws.lock().send(bytes);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "websocket"
    }
    fn recorded_bytes(&self) -> Vec<Vec<u8>> {
        self.ws.lock().frames().to_vec()
    }
}

/// Log sink adapter. Emits each redacted event as a structured log line and
/// records it for verification. Only redacted output is ever logged.
#[derive(Debug, Default)]
pub struct LogSinkAdapter {
    pub logger: Mutex<LogCapture>,
}

impl LogSinkAdapter {
    pub fn new() -> Self {
        Self {
            logger: Mutex::new(LogCapture::new()),
        }
    }
    pub fn lines(&self) -> Vec<String> {
        self.logger.lock().lines.clone()
    }
}

impl SinkAdapter for LogSinkAdapter {
    fn write_redacted(&mut self, event: &RedactedEvent) -> Result<(), SinkError> {
        let line = serde_json::to_string(&event.to_json())
            .map_err(|e| SinkError::Serialization(e.to_string()))?;
        // Redacted output only — the raw payload is never logged.
        tracing::debug!(redacted_event = %line, "sink=log");
        self.logger.lock().lines.push(line);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "log"
    }
    fn recorded_bytes(&self) -> Vec<Vec<u8>> {
        self.logger
            .lock()
            .lines
            .iter()
            .map(|l| l.as_bytes().to_vec())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Multi-sink fan-out
// ---------------------------------------------------------------------------

/// Fans a single [`RedactedEvent`] out to every configured sink. Every sink
/// receives the identical redacted object.
#[derive(Default)]
pub struct MultiSink {
    pub sinks: Vec<Box<dyn SinkAdapter>>,
}

impl MultiSink {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }
    pub fn add(&mut self, sink: Box<dyn SinkAdapter>) {
        self.sinks.push(sink);
    }
    /// Per-sink recorded bytes, for verification that every sink received the
    /// same redacted object and that no seeded token leaked.
    pub fn recorded(&self) -> Vec<(&'static str, Vec<Vec<u8>>)> {
        self.sinks
            .iter()
            .map(|s| (s.name(), s.recorded_bytes()))
            .collect()
    }
}

/// Write a redacted event to **all** sinks. If any sink fails the first error
/// is returned, but every other sink still receives the event (best-effort
/// fan-out with error propagation).
pub fn write_to_all_sinks(event: &RedactedEvent, sinks: &mut MultiSink) -> Result<(), SinkError> {
    let mut first_error: Option<SinkError> = None;
    for sink in sinks.sinks.iter_mut() {
        if let Err(e) = sink.write_redacted(event) {
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Deliberate raw-write entry point that **always** rejects. This exists to
/// make the no-bypass guarantee explicit and testable: the only way to reach a
/// sink is through [`crate::apply_redaction`] producing a [`RedactedEvent`].
pub fn write_normalized_to_sinks(
    _event: &agent_core::NormalizedEvent,
    _sinks: &mut MultiSink,
) -> Result<(), SinkError> {
    Err(SinkError::BypassRejected(
        "raw NormalizedEvent cannot be written to a sink; apply_redaction must produce a RedactedEvent first",
    ))
}
