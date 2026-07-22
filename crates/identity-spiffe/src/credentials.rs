// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Credential manager: builds rustls mTLS configurations from
//! the current SVID set, with hot-rebuild before expiry and
//! fail-closed semantics.
//!
//! # Trust bundle scope
//!
//! Trust bundles are used ONLY for SVID authentication
//! (verifying peer SVIDs during mTLS handshakes). They are NOT
//! used for arbitrary TLS connections.
//!
//! # Hot-rebuild
//!
//! The credential manager monitors SVID expiry and triggers a
//! rebuild before the SVID expires. If no valid SVID is
//! available, credential access fails closed (returns an error,
//! never falls back to expired/redacted material).
//!
//! # Integration with protocol crate
//!
//! The `server_tls_config()` and `client_tls_config()` methods
//! produce `rustls::ServerConfig` / `rustls::ClientConfig` that
//! can be used with any gRPC transport (tonic, hyper, etc.) for
//! mTLS channel credentials. The protocol crate's
//! `AgentIdentity` uses the SPIFFE ID from the SVID as the
//! agent's durable principal.

#![forbid(unsafe_code)]

use std::io::{BufRead, Cursor};
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::error::{SpiffeError, SpiffeResult};
use crate::workload::WorkloadApiState;

/// Fraction of SVID lifetime at which hot-rebuild is triggered.
/// At 80% of lifetime elapsed, the credential manager signals
/// that a rebuild is needed.
pub const HOT_REBUILD_THRESHOLD: f64 = 0.80;

/// Default SVID lifetime assumption for hot-rebuild scheduling
/// (1 hour, matching SPIRE's default X509 SVID TTL).
pub const DEFAULT_SVID_LIFETIME_SECS: i64 = 3600;

/// Manages mTLS credentials derived from the current SVID set.
///
/// Thread-safe: the inner state is behind a RwLock so multiple
/// gRPC channels can read credentials concurrently while the
/// Workload API client rebuilds them on rotation.
pub struct CredentialManager {
    /// Shared state from the Workload API client.
    workload_state: Arc<RwLock<WorkloadApiState>>,
    /// Cached server TLS config (rebuilt on rotation).
    server_config: RwLock<Option<Arc<ServerConfig>>>,
    /// Cached client TLS config (rebuilt on rotation).
    client_config: RwLock<Option<Arc<ClientConfig>>>,
    /// The rotation count at which configs were last built.
    last_built_rotation: RwLock<u64>,
}

impl CredentialManager {
    /// Create a credential manager bound to a Workload API
    /// client's shared state.
    pub fn new(workload_state: Arc<RwLock<WorkloadApiState>>) -> Self {
        Self {
            workload_state,
            server_config: RwLock::new(None),
            client_config: RwLock::new(None),
            last_built_rotation: RwLock::new(0),
        }
    }

    /// Whether a credential rebuild is needed (rotation happened
    /// since last build, or SVID is approaching expiry).
    pub fn needs_rebuild(&self, now: SystemTime) -> bool {
        let state = self.workload_state.read();
        let last_built = *self.last_built_rotation.read();

        // Rebuild if rotation count changed.
        if state.rotation_count != last_built {
            return true;
        }

        // Rebuild if approaching expiry.
        if let Some(set) = &state.current_set {
            if let Some(secs) = set.seconds_until_expiry(now) {
                let lifetime = DEFAULT_SVID_LIFETIME_SECS;
                let threshold = (lifetime as f64 * (1.0 - HOT_REBUILD_THRESHOLD)) as i64;
                return secs <= threshold;
            }
        }

        false
    }

    /// Rebuild TLS configurations from the current SVID set.
    ///
    /// Fails closed: if no valid SVID is available, returns an
    /// error. Never uses expired or redacted material.
    pub fn rebuild(&self, now: SystemTime) -> SpiffeResult<()> {
        let state = self.workload_state.read();

        let set = state
            .current_set
            .as_ref()
            .ok_or_else(|| SpiffeError::NoCredentials {
                reason: "no SVID set available for credential build".into(),
            })?;

        // Fail closed: reject expired SVIDs.
        if set.is_expired(now) {
            let spiffe_id = set
                .primary_svid()
                .map(|s| s.spiffe_id().as_str().to_string())
                .unwrap_or_default();
            return Err(SpiffeError::SvidExpired {
                spiffe_id,
                expired_at_unix: set.primary_svid().map(|s| s.not_after_unix()).unwrap_or(0),
            });
        }

        let svid = set
            .primary_svid()
            .ok_or_else(|| SpiffeError::NoCredentials {
                reason: "SVID set is empty".into(),
            })?;

        // Fail closed: reject redacted material.
        if svid.is_redacted() {
            return Err(SpiffeError::MaterialRedacted);
        }

        // Parse cert chain DER.
        let cert_chain_der = svid.cert_chain_der();
        let certs: Vec<CertificateDer<'static>> = cert_chain_der
            .iter()
            .map(|der| CertificateDer::from(der.clone()))
            .collect();

        // Parse private key DER.
        let key_der = svid.private_key_der()?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));

        // Build trust store from bundle.
        let trust_store = build_trust_store(set.bundle().ca_certs_pem())?;

        // Build server config (mTLS: requires client cert).
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(trust_store.clone()))
            .build()
            .map_err(|e| SpiffeError::ParseError {
                context: "client verifier".into(),
                source: e.to_string(),
            })?;

        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs.clone(), key.clone_key())
            .map_err(|e| SpiffeError::ParseError {
                context: "server TLS config".into(),
                source: e.to_string(),
            })?;

        // Build client config (mTLS: presents client cert).
        let mut root_store = RootCertStore::empty();
        for pem_cert in parse_pem_certs(set.bundle().ca_certs_pem())? {
            root_store
                .add(pem_cert)
                .map_err(|e| SpiffeError::ParseError {
                    context: "root cert store".into(),
                    source: e.to_string(),
                })?;
        }

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)
            .map_err(|e| SpiffeError::ParseError {
                context: "client TLS config".into(),
                source: e.to_string(),
            })?;

        // Store rebuilt configs.
        *self.server_config.write() = Some(Arc::new(server_config));
        *self.client_config.write() = Some(Arc::new(client_config));
        *self.last_built_rotation.write() = state.rotation_count;

        tracing::info!(
            rotation = state.rotation_count,
            "TLS credentials rebuilt from SVID"
        );

        Ok(())
    }

    /// Get the current server TLS config for mTLS.
    ///
    /// Fails closed: returns an error if no valid config is
    /// available. Never returns expired/redacted credentials.
    pub fn server_tls_config(&self, now: SystemTime) -> SpiffeResult<Arc<ServerConfig>> {
        // Rebuild if needed.
        if self.needs_rebuild(now) {
            self.rebuild(now)?;
        }

        self.server_config
            .read()
            .clone()
            .ok_or_else(|| SpiffeError::NoCredentials {
                reason: "server TLS config not yet built".into(),
            })
    }

    /// Get the current client TLS config for mTLS.
    ///
    /// Fails closed: returns an error if no valid config is
    /// available. Never returns expired/redacted credentials.
    pub fn client_tls_config(&self, now: SystemTime) -> SpiffeResult<Arc<ClientConfig>> {
        // Rebuild if needed.
        if self.needs_rebuild(now) {
            self.rebuild(now)?;
        }

        self.client_config
            .read()
            .clone()
            .ok_or_else(|| SpiffeError::NoCredentials {
                reason: "client TLS config not yet built".into(),
            })
    }

    /// Whether valid credentials are currently available.
    pub fn has_valid_credentials(&self, now: SystemTime) -> bool {
        let state = self.workload_state.read();
        state
            .current_set
            .as_ref()
            .map(|s| !s.is_expired(now))
            .unwrap_or(false)
    }
}

/// Build a `RootCertStore` from PEM-encoded CA certificates.
fn build_trust_store(ca_certs_pem: &str) -> SpiffeResult<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in parse_pem_certs(ca_certs_pem)? {
        store.add(cert).map_err(|e| SpiffeError::ParseError {
            context: "trust store".into(),
            source: e.to_string(),
        })?;
    }
    Ok(store)
}

/// Parse PEM-encoded certificates into DER.
fn parse_pem_certs(pem: &str) -> SpiffeResult<Vec<CertificateDer<'static>>> {
    let mut certs = Vec::new();
    let cursor = Cursor::new(pem.as_bytes());
    let mut reader = std::io::BufReader::new(cursor);

    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| SpiffeError::ParseError {
                context: "PEM parsing".into(),
                source: e.to_string(),
            })?;
        if n == 0 {
            break; // EOF
        }

        if line.contains("BEGIN CERTIFICATE") {
            let mut b64 = String::new();
            loop {
                let mut l = String::new();
                let n = reader
                    .read_line(&mut l)
                    .map_err(|e| SpiffeError::ParseError {
                        context: "PEM parsing".into(),
                        source: e.to_string(),
                    })?;
                if n == 0 || l.contains("END CERTIFICATE") {
                    break;
                }
                b64.push_str(l.trim());
            }

            use base64_decode;
            let der = base64_decode(&b64)?;
            certs.push(CertificateDer::from(der));
        }
    }

    if certs.is_empty() {
        return Err(SpiffeError::ParseError {
            context: "PEM certificates".into(),
            source: "no CERTIFICATE blocks found".into(),
        });
    }

    Ok(certs)
}

/// Minimal base64 decoder (no external dep needed for PEM).
fn base64_decode(input: &str) -> SpiffeResult<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input.as_bytes() {
        let val = if byte == b'=' {
            break;
        } else if let Some(pos) = TABLE.iter().position(|&c| c == byte) {
            pos as u32
        } else {
            continue; // Skip whitespace/newlines.
        };

        buf = (buf << 6) | val;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::svid::{SvidSet, X509Bundle, X509Svid};
    use crate::workload::WorkloadApiState;

    fn install_ring_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/spiffe");

    fn load_fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}"))
            .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
    }

    fn make_state_with_svid() -> Arc<RwLock<WorkloadApiState>> {
        let cert = load_fixture("svid-agent.pem");
        let key = load_fixture("svid-agent-key.pem");
        let bundle_pem = load_fixture("bundle.pem");

        let svid = X509Svid::from_pem(&cert, &key).unwrap();
        let set = SvidSet::new(
            vec![svid],
            X509Bundle::new("kernel-v1.test", &bundle_pem),
            vec![],
        );

        let mut state = WorkloadApiState::new();
        state.current_set = Some(set);
        state.rotation_count = 1;
        Arc::new(RwLock::new(state))
    }

    #[test]
    fn rebuild_produces_valid_configs() {
        install_ring_provider();
        let state = make_state_with_svid();
        let mgr = CredentialManager::new(state);

        let now = SystemTime::now();
        mgr.rebuild(now).unwrap();

        assert!(mgr.server_tls_config(now).is_ok());
        assert!(mgr.client_tls_config(now).is_ok());
        assert!(mgr.has_valid_credentials(now));
    }

    #[test]
    fn fails_closed_without_svid() {
        let state = Arc::new(RwLock::new(WorkloadApiState::new()));
        let mgr = CredentialManager::new(state);

        let now = SystemTime::now();
        let result = mgr.rebuild(now);
        assert!(matches!(result, Err(SpiffeError::NoCredentials { .. })));
        assert!(!mgr.has_valid_credentials(now));
    }

    #[test]
    fn fails_closed_on_expired_svid() {
        let cert = load_fixture("svid-expired.pem");
        let key = load_fixture("svid-expired-key.pem");
        let bundle_pem = load_fixture("bundle.pem");

        let svid = X509Svid::from_pem(&cert, &key).unwrap();
        let set = SvidSet::new(
            vec![svid],
            X509Bundle::new("kernel-v1.test", &bundle_pem),
            vec![],
        );

        let mut state = WorkloadApiState::new();
        state.current_set = Some(set);
        state.rotation_count = 1;
        let state = Arc::new(RwLock::new(state));

        let mgr = CredentialManager::new(state);
        let now = SystemTime::now();
        let result = mgr.rebuild(now);
        assert!(matches!(result, Err(SpiffeError::SvidExpired { .. })));
    }

    #[test]
    fn fails_closed_on_redacted_material() {
        let cert = load_fixture("svid-agent.pem");
        let key = load_fixture("svid-agent-key.pem");
        let bundle_pem = load_fixture("bundle.pem");

        let mut svid = X509Svid::from_pem(&cert, &key).unwrap();
        svid.redact(); // Redact before building.

        let set = SvidSet::new(
            vec![svid],
            X509Bundle::new("kernel-v1.test", &bundle_pem),
            vec![],
        );

        let mut state = WorkloadApiState::new();
        state.current_set = Some(set);
        state.rotation_count = 1;
        let state = Arc::new(RwLock::new(state));

        let mgr = CredentialManager::new(state);
        let now = SystemTime::now();
        let result = mgr.rebuild(now);
        assert!(matches!(result, Err(SpiffeError::MaterialRedacted)));
    }

    #[test]
    fn needs_rebuild_on_rotation() {
        install_ring_provider();
        let state = make_state_with_svid();
        let mgr = CredentialManager::new(state.clone());

        let now = SystemTime::now();
        mgr.rebuild(now).unwrap();

        // No rebuild needed immediately after.
        assert!(!mgr.needs_rebuild(now));

        // Simulate rotation.
        {
            let mut s = state.write();
            s.rotation_count = 2;
        }

        // Now rebuild is needed.
        assert!(mgr.needs_rebuild(now));
    }

    #[test]
    fn base64_decode_works() {
        // "SGVsbG8=" == "Hello"
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }
}
