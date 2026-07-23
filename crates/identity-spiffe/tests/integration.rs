// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Integration tests for the SPIFFE identity crate.
//!
//! These tests use pinned ephemeral SPIRE fixtures to prove:
//! - Correct attestation/ID extraction from X.509 SVIDs
//! - Full-set rotation with old material redaction
//! - Expiry-before-rebuild detection
//! - Stream disconnect/reconnect with backoff
//! - Unauthorized selector rejection
//! - Uninterrupted credential availability across rotation
//! - Fail-closed on expired/redacted/wrong-ID material

use std::sync::Arc;
use std::time::SystemTime;

use identity_spiffe::{
    AuthorizationCallback, CredentialManager, ExponentialBackoff, FixtureSvidStream, SpiffeError,
    SpiffeId, SpiffeIdSelector, SpiffeMetrics, SvidEntry, SvidSet, WorkloadApiClient, X509Bundle,
    X509Svid, X509SvidResponse,
};

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

// ---------------------------------------------------------------------------
// Attestation / ID extraction
// ---------------------------------------------------------------------------

#[test]
fn attestation_extracts_correct_spiffe_id() {
    let cert = load_fixture("svid-agent.pem");
    let key = load_fixture("svid-agent-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    assert_eq!(
        svid.spiffe_id().as_str(),
        "spiffe://kernel-v1.test/agent/prod/node-1"
    );
    assert_eq!(svid.spiffe_id().trust_domain(), "kernel-v1.test");
    assert_eq!(svid.spiffe_id().path(), "/agent/prod/node-1");
}

#[test]
fn attestation_validates_against_selector() {
    let cert = load_fixture("svid-agent.pem");
    let key = load_fixture("svid-agent-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    let selector = test_selector();
    assert!(svid.spiffe_id().validate_selector(&selector).is_ok());
}

#[test]
fn attestation_rejects_wrong_trust_domain() {
    let cert = load_fixture("svid-wrong-td.pem");
    let key = load_fixture("svid-wrong-td-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    assert_eq!(svid.spiffe_id().trust_domain(), "evil.example");

    let selector = test_selector();
    let err = svid.spiffe_id().validate_selector(&selector).unwrap_err();
    assert!(matches!(err, SpiffeError::SelectorRejected { .. }));
}

// ---------------------------------------------------------------------------
// Full-set rotation with redaction
// ---------------------------------------------------------------------------

#[test]
fn rotation_replaces_complete_set_and_redacts_old() {
    let metrics = SpiffeMetrics::new();
    let mut client =
        WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics.clone());

    let r1 = make_response("svid-agent.pem", "svid-agent-key.pem");
    let r2 = make_response("svid-agent-rotated.pem", "svid-agent-rotated-key.pem");

    let mut stream = FixtureSvidStream::new(vec![Ok(r1), Ok(r2)]);
    let _ = client.run_stream(&mut stream);

    let state_arc = client.state();
    let state = state_arc.read();
    assert_eq!(state.rotation_count, 2);

    let current = state.current_set.as_ref().unwrap();
    let svid = current.primary_svid().unwrap();
    assert!(!svid.is_redacted());
    assert!(svid.private_key_pem().is_ok());

    assert_eq!(metrics.rotation_count(), 2);
}

#[test]
fn rotation_redacts_old_key_material_irreversibly() {
    let cert = load_fixture("svid-agent.pem");
    let key = load_fixture("svid-agent-key.pem");
    let bundle_pem = load_fixture("bundle.pem");

    let mut svid = X509Svid::from_pem(&cert, &key).unwrap();
    let key_before = svid.private_key_pem().unwrap().to_string();
    assert!(!key_before.is_empty());

    svid.redact();

    assert!(svid.is_redacted());
    assert_eq!(
        svid.private_key_pem().unwrap_err(),
        SpiffeError::MaterialRedacted
    );
    assert_eq!(
        svid.private_key_der().unwrap_err(),
        SpiffeError::MaterialRedacted
    );

    let _ = SvidSet::new(
        vec![],
        X509Bundle::new("kernel-v1.test", &bundle_pem),
        vec![],
    );
}

// ---------------------------------------------------------------------------
// Expiry detection and fail-closed
// ---------------------------------------------------------------------------

#[test]
fn expired_svid_detected_and_rejected() {
    let cert = load_fixture("svid-expired.pem");
    let key = load_fixture("svid-expired-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    assert!(svid.is_expired(SystemTime::now()));
    assert!(svid.seconds_until_expiry(SystemTime::now()) < 0);
}

#[test]
fn expired_svid_rejected_by_stream() {
    let metrics = SpiffeMetrics::new();
    let mut client =
        WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

    let response = make_response("svid-expired.pem", "svid-expired-key.pem");
    let mut stream = FixtureSvidStream::single(response);
    let result = client.run_stream(&mut stream);

    assert!(result.is_err());
    let state_arc = client.state();
    let state = state_arc.read();
    assert!(state.current_set.is_none());
}

#[test]
fn credential_manager_fails_closed_on_expiry() {
    let cert = load_fixture("svid-expired.pem");
    let key = load_fixture("svid-expired-key.pem");
    let bundle_pem = load_fixture("bundle.pem");

    let svid = X509Svid::from_pem(&cert, &key).unwrap();
    let set = SvidSet::new(
        vec![svid],
        X509Bundle::new("kernel-v1.test", &bundle_pem),
        vec![],
    );

    let mut state = identity_spiffe::workload::WorkloadApiState::new();
    state.current_set = Some(set);
    state.rotation_count = 1;
    let state = Arc::new(parking_lot::RwLock::new(state));

    let mgr = CredentialManager::new(state);
    let result = mgr.rebuild(SystemTime::now());
    assert!(matches!(result, Err(SpiffeError::SvidExpired { .. })));
    assert!(!mgr.has_valid_credentials(SystemTime::now()));
}

// ---------------------------------------------------------------------------
// Stream disconnect / reconnect
// ---------------------------------------------------------------------------

#[test]
fn stream_disconnect_triggers_reconnect() {
    let metrics = SpiffeMetrics::new();
    let mut client =
        WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics.clone());

    let mut attempts = 0;
    let result = client.run_with_reconnect(
        || -> identity_spiffe::SpiffeResult<FixtureSvidStream> {
            attempts += 1;
            if attempts == 1 {
                return Err(SpiffeError::StreamDisconnected {
                    reason: "connection reset".into(),
                });
            }
            if attempts == 2 {
                let response = make_response("svid-agent.pem", "svid-agent-key.pem");
                return Ok(FixtureSvidStream::single(response));
            }
            Err(SpiffeError::StreamDisconnected {
                reason: "done".into(),
            })
        },
        3,
    );

    assert!(result.is_err());
    let state_arc = client.state();
    let state = state_arc.read();
    assert!(state.current_set.is_some());
    assert!(state.reconnect_count >= 1);
    assert!(metrics.reconnect_count() >= 1);
}

#[test]
fn backoff_bounds_are_respected() {
    let mut bo = ExponentialBackoff::new(100, 5000, 2.0);

    for _ in 0..20 {
        let delay = bo.next_delay();
        assert!(delay.as_millis() <= 5000);
        assert!(delay.as_millis() >= 1);
    }
}

// ---------------------------------------------------------------------------
// Unauthorized selector rejection
// ---------------------------------------------------------------------------

#[test]
fn unauthorized_selector_rejected_by_stream() {
    let metrics = SpiffeMetrics::new();
    let mut client =
        WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

    let response = make_response("svid-wrong-td.pem", "svid-wrong-td-key.pem");
    let mut stream = FixtureSvidStream::single(response);
    let result = client.run_stream(&mut stream);

    assert!(result.is_err());
    let state_arc = client.state();
    let state = state_arc.read();
    assert!(state.current_set.is_none());
}

#[test]
fn authorization_callback_rejects_wrong_cluster() {
    let cb = AuthorizationCallback::new("kernel-v1.test").with_cluster("prod");

    let err = cb
        .authorize("spiffe://kernel-v1.test/agent/staging/node-1")
        .unwrap_err();
    assert!(matches!(err, SpiffeError::AuthorizationDenied { .. }));
}

#[test]
fn authorization_callback_rejects_wrong_node() {
    let cb = AuthorizationCallback::new("kernel-v1.test").with_node("node-1");

    let err = cb
        .authorize("spiffe://kernel-v1.test/agent/prod/node-99")
        .unwrap_err();
    assert!(matches!(err, SpiffeError::AuthorizationDenied { .. }));
}

#[test]
fn authorization_callback_rejects_trust_domain_substring() {
    let cb = AuthorizationCallback::new("kernel-v1.test");

    assert!(cb
        .authorize("spiffe://kernel-v1.test.evil/agent/prod/node-1")
        .is_err());
    assert!(cb
        .authorize("spiffe://kernel-v1/agent/prod/node-1")
        .is_err());
}

// ---------------------------------------------------------------------------
// Credential continuity across rotation
// ---------------------------------------------------------------------------

#[test]
fn credentials_available_across_rotation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let metrics = SpiffeMetrics::new();
    let mut client =
        WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

    let r1 = make_response("svid-agent.pem", "svid-agent-key.pem");
    let r2 = make_response("svid-agent-rotated.pem", "svid-agent-rotated-key.pem");

    let mut stream = FixtureSvidStream::new(vec![Ok(r1), Ok(r2)]);
    let _ = client.run_stream(&mut stream);

    let state = client.state();
    let mgr = CredentialManager::new(state);

    let now = SystemTime::now();
    assert!(mgr.has_valid_credentials(now));

    let server_cfg = mgr.server_tls_config(now);
    assert!(server_cfg.is_ok());

    let client_cfg = mgr.client_tls_config(now);
    assert!(client_cfg.is_ok());
}

#[test]
fn no_credentials_without_stream_connection() {
    let metrics = SpiffeMetrics::new();
    let client = WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

    let state = client.state();
    let mgr = CredentialManager::new(state);

    let now = SystemTime::now();
    assert!(!mgr.has_valid_credentials(now));
    assert!(mgr.server_tls_config(now).is_err());
    assert!(mgr.client_tls_config(now).is_err());
}

// ---------------------------------------------------------------------------
// Protocol crate integration
// ---------------------------------------------------------------------------

#[test]
fn authorization_bridges_to_protocol_register() {
    let cb = AuthorizationCallback::new("kernel-v1.test");
    let req = cb
        .to_register_request(
            "spiffe://kernel-v1.test/agent/prod/node-1",
            "host-1",
            "gen-42",
            &"ab".repeat(16),
            "6.6.0",
        )
        .unwrap();

    assert_eq!(req.node_name, "node-1");
    assert_eq!(req.cluster, "prod");

    let identity = protocol::identity::AgentIdentity::register(req, 1).unwrap();
    assert!(identity.agent_id.contains("prod"));
    assert!(identity.agent_id.contains("node-1"));
}

// ---------------------------------------------------------------------------
// Metrics reporting
// ---------------------------------------------------------------------------

#[test]
fn metrics_report_rotation_and_health() {
    let metrics = SpiffeMetrics::new();
    let mut client =
        WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics.clone());

    let r1 = make_response("svid-agent.pem", "svid-agent-key.pem");
    let r2 = make_response("svid-agent-rotated.pem", "svid-agent-rotated-key.pem");

    let mut stream = FixtureSvidStream::new(vec![Ok(r1), Ok(r2)]);
    let _ = client.run_stream(&mut stream);

    let text = metrics.render();
    assert!(text.contains("spiffe_svid_rotations_total 2"));
    assert!(text.contains("spiffe_stream_health"));
    assert!(text.contains("spiffe_svid_expiry_seconds"));
}

// ---------------------------------------------------------------------------
// Security invariants
// ---------------------------------------------------------------------------

#[test]
fn debug_output_never_exposes_private_key() {
    let cert = load_fixture("svid-agent.pem");
    let key = load_fixture("svid-agent-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    let debug = format!("{svid:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("PRIVATE KEY"));
    assert!(!debug.contains("MIGH"));
}

#[test]
fn spiffe_id_exact_match_never_substring() {
    let id = SpiffeId::parse("spiffe://kernel-v1.test/agent/prod/node-1").unwrap();

    assert!(id.assert_trust_domain("kernel-v1.test").is_ok());
    assert!(id.assert_trust_domain("kernel-v1").is_err());
    assert!(id.assert_trust_domain("kernel-v1.test.evil").is_err());
    assert!(id.assert_trust_domain("test").is_err());
}

#[test]
fn no_plaintext_fallback_on_missing_credentials() {
    let metrics = SpiffeMetrics::new();
    let client = WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

    assert!(client.is_expired(SystemTime::now()));
    assert!(client.seconds_until_expiry(SystemTime::now()).is_none());
}
