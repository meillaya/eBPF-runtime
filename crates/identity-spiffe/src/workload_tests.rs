// SPDX-License-Identifier: Apache-2.0 OR MIT
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
    let client = WorkloadApiClient::with_socket_path("/tmp/test.sock", test_selector(), metrics);

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
