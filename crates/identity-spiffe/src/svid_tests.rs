// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

// Fixture paths relative to workspace root.
const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/spiffe");

fn load_fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}"))
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

#[test]
fn parse_valid_svid_from_fixture() {
    let cert = load_fixture("svid-agent.pem");
    let key = load_fixture("svid-agent-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    assert_eq!(
        svid.spiffe_id().as_str(),
        "spiffe://kernel-v1.test/agent/prod/node-1"
    );
    assert!(!svid.is_redacted());
    assert!(svid.not_after_unix() > 0);
}

#[test]
fn redact_zeroizes_key_material() {
    let cert = load_fixture("svid-agent.pem");
    let key = load_fixture("svid-agent-key.pem");
    let mut svid = X509Svid::from_pem(&cert, &key).unwrap();

    // Key is accessible before redaction.
    assert!(svid.private_key_pem().is_ok());
    assert!(svid.private_key_der().is_ok());

    // Redact.
    svid.redact();
    assert!(svid.is_redacted());

    // Key is inaccessible after redaction.
    assert_eq!(
        svid.private_key_pem().unwrap_err(),
        SpiffeError::MaterialRedacted
    );
    assert_eq!(
        svid.private_key_der().unwrap_err(),
        SpiffeError::MaterialRedacted
    );

    // Cert chain is still accessible (public material).
    assert!(!svid.cert_chain_pem().is_empty());
}

#[test]
fn debug_never_exposes_key() {
    let cert = load_fixture("svid-agent.pem");
    let key = load_fixture("svid-agent-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    let debug = format!("{svid:?}");
    assert!(debug.contains("[REDACTED]"));
    // The actual key PEM must NOT appear in debug output.
    assert!(!debug.contains("BEGIN PRIVATE KEY"));
    assert!(!debug.contains("BEGIN EC PRIVATE KEY"));
}

#[test]
fn expired_svid_detection() {
    let cert = load_fixture("svid-expired.pem");
    let key = load_fixture("svid-expired-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    // The expired fixture has not_after in the past.
    assert!(svid.is_expired(SystemTime::now()));
    assert!(svid.seconds_until_expiry(SystemTime::now()) < 0);
}

#[test]
fn valid_svid_not_expired() {
    let cert = load_fixture("svid-agent.pem");
    let key = load_fixture("svid-agent-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    // The valid fixture has not_after far in the future.
    assert!(!svid.is_expired(SystemTime::now()));
    assert!(svid.seconds_until_expiry(SystemTime::now()) > 0);
}

#[test]
fn svid_set_complete_replace_redacts_old() {
    let cert1 = load_fixture("svid-agent.pem");
    let key1 = load_fixture("svid-agent-key.pem");
    let cert2 = load_fixture("svid-agent-rotated.pem");
    let key2 = load_fixture("svid-agent-rotated-key.pem");
    let bundle_pem = load_fixture("bundle.pem");

    let svid1 = X509Svid::from_pem(&cert1, &key1).unwrap();
    let mut old_set = SvidSet::new(
        vec![svid1],
        X509Bundle::new("kernel-v1.test", &bundle_pem),
        vec![],
    );

    // Old set is usable.
    assert!(old_set.primary_svid().unwrap().private_key_pem().is_ok());

    // Simulate complete-set replacement.
    old_set.redact_all();

    // Old set is now redacted.
    assert!(old_set.primary_svid().unwrap().is_redacted());
    assert_eq!(
        old_set
            .primary_svid()
            .unwrap()
            .private_key_pem()
            .unwrap_err(),
        SpiffeError::MaterialRedacted
    );

    // New set is independent and usable.
    let svid2 = X509Svid::from_pem(&cert2, &key2).unwrap();
    let new_set = SvidSet::new(
        vec![svid2],
        X509Bundle::new("kernel-v1.test", &bundle_pem),
        vec![],
    );
    assert!(new_set.primary_svid().unwrap().private_key_pem().is_ok());
    assert!(!new_set.primary_svid().unwrap().is_redacted());
}

#[test]
fn wrong_trust_domain_fixture() {
    let cert = load_fixture("svid-wrong-td.pem");
    let key = load_fixture("svid-wrong-td-key.pem");
    let svid = X509Svid::from_pem(&cert, &key).unwrap();

    // The wrong-td fixture has a different trust domain.
    assert_eq!(svid.spiffe_id().trust_domain(), "evil.example");
    assert!(svid
        .spiffe_id()
        .assert_trust_domain("kernel-v1.test")
        .is_err());
}
