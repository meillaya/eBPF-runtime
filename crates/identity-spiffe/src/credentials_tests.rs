// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::svid::{SvidSet, X509Bundle, X509Svid};
use crate::workload::WorkloadApiState;

/// Install the ring CryptoProvider as the process default.
/// Workspace-wide `cargo test` unifies rustls features (ring + aws-lc-rs
/// via reqwest), so no provider is auto-installed; pin ring explicitly.
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
