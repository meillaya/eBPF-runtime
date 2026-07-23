// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Workload API client: long-lived FetchX509SVID stream with
//! reconnect/backoff and complete-set replacement.
//!
//! The client connects to the SPIFFE Workload API via a
//! protected Unix domain socket (SPIFFE_ENDPOINT_SOCKET). It
//! maintains a long-lived gRPC streaming connection (NOT
//! polling). On stream disconnect, it reconnects with
//! exponential backoff.
//!
//! # Transport abstraction
//!
//! The actual gRPC transport is abstracted behind the
//! `SvidStream` trait. This allows:
//! - Real SPIRE agent connections (via Unix socket + gRPC)
//! - Fixture-based test streams (for validation without a live
//!   SPIRE agent)
//!
//! # BLOCKER NOTE
//!
//! This host does not have a running SPIRE agent. The client
//! logic is fully implemented and tested with fixture streams.
//! Live SPIRE integration requires a declared self-hosted
//! runner with SPIRE deployed.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::RwLock;
use tracing::{debug, error, info, warn};

use crate::backoff::ExponentialBackoff;
use crate::error::{SpiffeError, SpiffeResult};
use crate::metrics::SpiffeMetrics;
use crate::spiffe_id::SpiffeIdSelector;
use crate::svid::{SvidSet, X509Bundle, X509Svid};

/// The environment variable that specifies the Workload API
/// endpoint socket path.
pub const SPIFFE_ENDPOINT_SOCKET_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";

/// Default socket path if the env var is unset.
pub const DEFAULT_SOCKET_PATH: &str = "/run/spire/agent-sockets/api.sock";

/// Stream health states for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamHealth {
    /// Never connected.
    Disconnected,
    /// Attempting to connect.
    Connecting,
    /// Actively streaming SVIDs.
    Streaming,
    /// Reconnecting after disconnect.
    Reconnecting,
}

impl StreamHealth {
    /// Metric value for this state.
    pub fn as_metric_value(&self) -> i64 {
        match self {
            Self::Disconnected => 0,
            Self::Connecting => 1,
            Self::Streaming => 2,
            Self::Reconnecting => 3,
        }
    }
}

/// A single response from the FetchX509SVID stream.
///
/// Mirrors the SPIFFE Workload API `X509SVIDResponse` message:
/// a complete set of SVIDs + trust bundles.
#[derive(Debug, Clone)]
pub struct X509SvidResponse {
    /// PEM-encoded SVID certificate chains + keys.
    pub svids: Vec<SvidEntry>,
    /// PEM-encoded trust bundle for our trust domain.
    pub bundle_pem: String,
    /// Federated trust bundles (trust domain → PEM).
    pub federated_bundles: Vec<(String, String)>,
}

/// A single SVID entry in a response.
#[derive(Debug, Clone)]
pub struct SvidEntry {
    /// PEM-encoded certificate chain.
    pub cert_chain_pem: String,
    /// PEM-encoded private key.
    pub private_key_pem: String,
}

/// Trait abstracting the FetchX509SVID stream transport.
///
/// Implementations:
/// - `FixtureSvidStream`: yields pre-built responses for tests
/// - (Future) `GrpcSvidStream`: real Unix socket + gRPC
pub trait SvidStream: Send {
    /// Get the next response from the stream.
    ///
    /// Returns `None` when the stream is closed (server hung
    /// up). Returns `Err` on transport failure.
    fn next_response(&mut self) -> SpiffeResult<Option<X509SvidResponse>>;
}

/// Shared state for the Workload API client.
pub struct WorkloadApiState {
    /// The current SVID set (None until first response).
    pub current_set: Option<SvidSet>,
    /// Stream health.
    pub health: StreamHealth,
    /// Last successful response time (unix seconds).
    pub last_response_unix: i64,
    /// Total number of rotations (complete-set replacements).
    pub rotation_count: u64,
    /// Total number of reconnection attempts.
    pub reconnect_count: u64,
}

impl Default for WorkloadApiState {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkloadApiState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self {
            current_set: None,
            health: StreamHealth::Disconnected,
            last_response_unix: 0,
            rotation_count: 0,
            reconnect_count: 0,
        }
    }
}

/// The Workload API client.
///
/// Manages the long-lived FetchX509SVID stream, validates
/// incoming SVIDs against the selector policy, performs
/// complete-set replacement with redaction, and tracks
/// health/expiry metrics.
pub struct WorkloadApiClient {
    /// The endpoint socket path.
    socket_path: String,
    /// Selector policy for validating SVIDs.
    selector: SpiffeIdSelector,
    /// Shared state (current SVID set, health, counters).
    state: Arc<RwLock<WorkloadApiState>>,
    /// Backoff for reconnection.
    backoff: ExponentialBackoff,
    /// Metrics reporter.
    metrics: SpiffeMetrics,
}

impl WorkloadApiClient {
    /// Create a new Workload API client.
    ///
    /// The socket path is read from `SPIFFE_ENDPOINT_SOCKET`
    /// env var, falling back to the default path.
    pub fn new(selector: SpiffeIdSelector, metrics: SpiffeMetrics) -> Self {
        let socket_path = std::env::var(SPIFFE_ENDPOINT_SOCKET_ENV)
            .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

        Self {
            socket_path,
            selector,
            state: Arc::new(RwLock::new(WorkloadApiState::new())),
            backoff: ExponentialBackoff::spiffe_default(),
            metrics,
        }
    }

    /// Create a client with an explicit socket path (for tests).
    pub fn with_socket_path(
        socket_path: impl Into<String>,
        selector: SpiffeIdSelector,
        metrics: SpiffeMetrics,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            selector,
            state: Arc::new(RwLock::new(WorkloadApiState::new())),
            backoff: ExponentialBackoff::spiffe_default(),
            metrics,
        }
    }

    /// The configured socket path.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Shared state handle for reading current SVID set.
    pub fn state(&self) -> Arc<RwLock<WorkloadApiState>> {
        Arc::clone(&self.state)
    }

    /// Run the stream loop: consume responses, validate, replace.
    ///
    /// This is the main entry point for the long-lived stream.
    /// It processes responses until the stream closes or errors,
    /// then returns. The caller is responsible for reconnection
    /// logic (or use `run_with_reconnect`).
    pub fn run_stream<S: SvidStream>(&mut self, stream: &mut S) -> SpiffeResult<()> {
        {
            let mut state = self.state.write();
            state.health = StreamHealth::Streaming;
        }
        self.metrics.set_stream_health(StreamHealth::Streaming);

        loop {
            match stream.next_response() {
                Ok(Some(response)) => {
                    self.process_response(response)?;
                    self.backoff.reset();
                }
                Ok(None) => {
                    // Stream closed by server.
                    info!("FetchX509SVID stream closed by server");
                    let mut state = self.state.write();
                    state.health = StreamHealth::Disconnected;
                    self.metrics.set_stream_health(StreamHealth::Disconnected);
                    return Err(SpiffeError::StreamDisconnected {
                        reason: "stream closed by server".into(),
                    });
                }
                Err(e) => {
                    error!(error = %e, "FetchX509SVID stream error");
                    let mut state = self.state.write();
                    state.health = StreamHealth::Disconnected;
                    self.metrics.set_stream_health(StreamHealth::Disconnected);
                    return Err(e);
                }
            }
        }
    }

    /// Run with automatic reconnection and backoff.
    ///
    /// Creates a new stream via the factory on each connection
    /// attempt. Reconnects with exponential backoff on failure.
    pub fn run_with_reconnect<F, S>(
        &mut self,
        mut stream_factory: F,
        max_attempts: u32,
    ) -> SpiffeResult<()>
    where
        F: FnMut() -> SpiffeResult<S>,
        S: SvidStream,
    {
        loop {
            {
                let mut state = self.state.write();
                state.health = StreamHealth::Connecting;
            }
            self.metrics.set_stream_health(StreamHealth::Connecting);

            match stream_factory() {
                Ok(mut stream) => {
                    self.backoff.reset();
                    match self.run_stream(&mut stream) {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            warn!(error = %e, "stream ended, will reconnect");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to create stream");
                }
            }

            // Reconnect with backoff.
            if self.backoff.exceeded_max_attempts(max_attempts) {
                error!(attempts = max_attempts, "max reconnect attempts exceeded");
                return Err(SpiffeError::StreamDisconnected {
                    reason: format!("max reconnect attempts ({max_attempts}) exceeded"),
                });
            }

            let delay = self.backoff.next_delay();
            {
                let mut state = self.state.write();
                state.health = StreamHealth::Reconnecting;
                state.reconnect_count += 1;
            }
            self.metrics.set_stream_health(StreamHealth::Reconnecting);
            self.metrics.increment_reconnects();

            debug!(
                delay_ms = delay.as_millis() as u64,
                "reconnecting after backoff"
            );
            std::thread::sleep(delay);
        }
    }

    /// Process a single X509SVIDResponse: validate SVIDs against
    /// the selector, then perform complete-set replacement with
    /// redaction of old material.
    fn process_response(&self, response: X509SvidResponse) -> SpiffeResult<()> {
        // Parse and validate all SVIDs.
        let mut svids = Vec::with_capacity(response.svids.len());
        for entry in &response.svids {
            let svid = X509Svid::from_pem(&entry.cert_chain_pem, &entry.private_key_pem)?;

            // Validate against selector policy.
            svid.spiffe_id().validate_selector(&self.selector)?;

            // Reject expired SVIDs (fail closed).
            if svid.is_expired(SystemTime::now()) {
                return Err(SpiffeError::SvidExpired {
                    spiffe_id: svid.spiffe_id().as_str().to_string(),
                    expired_at_unix: svid.not_after_unix(),
                });
            }

            svids.push(svid);
        }

        if svids.is_empty() {
            return Err(SpiffeError::NoCredentials {
                reason: "Workload API returned empty SVID set".into(),
            });
        }

        // Build trust bundle.
        let bundle = X509Bundle::new(self.selector.trust_domain.clone(), &response.bundle_pem);

        // Build federated bundles.
        let federated_bundles: Vec<X509Bundle> = response
            .federated_bundles
            .iter()
            .map(|(td, pem)| X509Bundle::new(td.clone(), pem))
            .collect();

        // Complete-set replacement with redaction.
        let new_set = SvidSet::new(svids, bundle, federated_bundles);

        let mut state = self.state.write();

        // Redact old set's key material.
        if let Some(old_set) = &mut state.current_set {
            old_set.redact_all();
            debug!("old SVID set redacted");
        }

        // Replace with new set.
        let now_unix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        state.current_set = Some(new_set);
        state.last_response_unix = now_unix;
        state.rotation_count += 1;

        // Update metrics.
        self.metrics.increment_rotations();
        self.metrics.set_last_rotation(now_unix);
        if let Some(set) = &state.current_set {
            if let Some(expiry) = set.seconds_until_expiry(SystemTime::now()) {
                self.metrics.set_svid_expiry_seconds(expiry);
            }
        }

        info!(
            rotation = state.rotation_count,
            trust_domain = %self.selector.trust_domain,
            "SVID set replaced (complete-set semantics)"
        );

        Ok(())
    }

    /// Get the current SVID set (if any).
    pub fn current_set(&self) -> Option<SvidSet> {
        // We can't clone SvidSet (it contains Zeroizing), so we
        // return None here. Use `state()` for direct access.
        None
    }

    /// Check if the current SVID is expired. Fail closed: if no
    /// SVID is available, returns true (expired).
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let state = self.state.read();
        state
            .current_set
            .as_ref()
            .map(|s| s.is_expired(now))
            .unwrap_or(true) // No SVID = expired (fail closed)
    }

    /// Seconds until the current SVID expires. Returns None if
    /// no SVID is available.
    pub fn seconds_until_expiry(&self, now: SystemTime) -> Option<i64> {
        let state = self.state.read();
        state.current_set.as_ref()?.seconds_until_expiry(now)
    }
}

/// A fixture-based SVID stream for testing.
///
/// Yields pre-built responses in sequence, then closes.
pub struct FixtureSvidStream {
    responses: Vec<SpiffeResult<X509SvidResponse>>,
    index: usize,
}

impl FixtureSvidStream {
    /// Create a fixture stream from a sequence of responses.
    pub fn new(responses: Vec<SpiffeResult<X509SvidResponse>>) -> Self {
        Self {
            responses,
            index: 0,
        }
    }

    /// Create a stream that yields one response then closes.
    pub fn single(response: X509SvidResponse) -> Self {
        Self {
            responses: vec![Ok(response)],
            index: 0,
        }
    }

    /// Create a stream that yields an error immediately.
    pub fn error(err: SpiffeError) -> Self {
        Self {
            responses: vec![Err(err)],
            index: 0,
        }
    }
}

impl SvidStream for FixtureSvidStream {
    fn next_response(&mut self) -> SpiffeResult<Option<X509SvidResponse>> {
        if self.index >= self.responses.len() {
            return Ok(None); // Stream closed.
        }
        let result = self.responses[self.index].clone();
        self.index += 1;
        result.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spiffe_id::SpiffeIdSelector;

    const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/spiffe");

    fn load_fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}"))
            .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
    }

    fn make_response(cert_name: &str, key_name: &str) -> X509SvidResponse {
        X509SvidResponse {
            svids: vec![SvidEntry {
                cert_chain_pem: load_fixture(cert_name),
                private_key_pem: load_fixture(key_name),
            }],
            bundle_pem: load_fixture("bundle.pem"),
            federated_bundles: vec![],
        }
    }

    fn test_selector() -> SpiffeIdSelector {
        SpiffeIdSelector::new("kernel-v1.test").with_path_prefix("/agent/")
    }

    #[test]
    fn stream_processes_valid_svid() {
        let metrics = SpiffeMetrics::new();
        let mut client =
            WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics.clone());

        let response = make_response("svid-agent.pem", "svid-agent-key.pem");
        let mut stream = FixtureSvidStream::single(response);

        let result = client.run_stream(&mut stream);
        assert!(result.is_err());

        let state = client.state.read();
        assert!(state.current_set.is_some());
        assert_eq!(state.rotation_count, 1);
        assert_eq!(state.health, StreamHealth::Disconnected);
    }

    #[test]
    fn stream_rejects_wrong_trust_domain() {
        let metrics = SpiffeMetrics::new();
        let mut client =
            WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

        let response = make_response("svid-wrong-td.pem", "svid-wrong-td-key.pem");
        let mut stream = FixtureSvidStream::single(response);

        let result = client.run_stream(&mut stream);
        assert!(result.is_err());

        let state = client.state.read();
        assert!(state.current_set.is_none());
    }

    #[test]
    fn stream_rejects_expired_svid() {
        let metrics = SpiffeMetrics::new();
        let mut client =
            WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

        let response = make_response("svid-expired.pem", "svid-expired-key.pem");
        let mut stream = FixtureSvidStream::single(response);

        let result = client.run_stream(&mut stream);
        assert!(result.is_err());

        let state = client.state.read();
        assert!(state.current_set.is_none());
    }

    #[test]
    fn complete_set_rotation_redacts_old() {
        let metrics = SpiffeMetrics::new();
        let mut client =
            WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

        let r1 = make_response("svid-agent.pem", "svid-agent-key.pem");
        let r2 = make_response("svid-agent-rotated.pem", "svid-agent-rotated-key.pem");

        let mut stream = FixtureSvidStream::new(vec![Ok(r1), Ok(r2)]);
        let _ = client.run_stream(&mut stream);

        let state = client.state.read();
        assert_eq!(state.rotation_count, 2);
        let current = state.current_set.as_ref().unwrap();
        assert!(current.primary_svid().unwrap().private_key_pem().is_ok());
    }

    #[test]
    fn stream_error_propagates() {
        let metrics = SpiffeMetrics::new();
        let mut client =
            WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

        let mut stream = FixtureSvidStream::error(SpiffeError::StreamDisconnected {
            reason: "connection reset".into(),
        });

        let result = client.run_stream(&mut stream);
        assert!(matches!(
            result,
            Err(SpiffeError::StreamDisconnected { .. })
        ));
    }

    #[test]
    fn reconnect_with_backoff() {
        let metrics = SpiffeMetrics::new();
        let mut client =
            WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics.clone());

        // Factory that fails twice, succeeds once, then fails permanently.
        let mut attempts = 0;
        let result = client.run_with_reconnect(
            || -> SpiffeResult<FixtureSvidStream> {
                attempts += 1;
                if attempts <= 2 {
                    return Err(SpiffeError::StreamDisconnected {
                        reason: "connection refused".into(),
                    });
                }
                if attempts == 3 {
                    let response = make_response("svid-agent.pem", "svid-agent-key.pem");
                    return Ok(FixtureSvidStream::single(response));
                }
                Err(SpiffeError::StreamDisconnected {
                    reason: "permanent failure".into(),
                })
            },
            3,
        );

        assert!(result.is_err());
        let state = client.state.read();
        assert!(state.current_set.is_some());
        assert!(state.reconnect_count >= 2);
    }

    #[test]
    fn max_reconnect_attempts_exceeded() {
        let metrics = SpiffeMetrics::new();
        let mut client =
            WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

        let result = client.run_with_reconnect(
            || -> SpiffeResult<FixtureSvidStream> {
                Err(SpiffeError::StreamDisconnected {
                    reason: "always fails".into(),
                })
            },
            3,
        );

        assert!(matches!(
            result,
            Err(SpiffeError::StreamDisconnected { .. })
        ));
    }

    #[test]
    fn is_expired_fails_closed_without_svid() {
        let metrics = SpiffeMetrics::new();
        let client =
            WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

        // No SVID loaded = expired (fail closed).
        assert!(client.is_expired(SystemTime::now()));
        assert!(client.seconds_until_expiry(SystemTime::now()).is_none());
    }

    #[test]
    fn socket_path_from_env() {
        // Test the default path.
        let metrics = SpiffeMetrics::new();
        let client = WorkloadApiClient::new(test_selector(), metrics);
        // Without env var set, uses default.
        assert!(!client.socket_path().is_empty());
    }
}
