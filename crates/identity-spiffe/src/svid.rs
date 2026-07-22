// SPDX-License-Identifier: Apache-2.0 OR MIT
//! X.509 SVID and trust bundle types with zeroize-on-drop
//! semantics and complete-set replace/redact.
//!
//! Private key material is held in `Zeroizing<Vec<u8>>` so it
//! is zeroed from memory on drop or explicit redaction. The
//! `Debug` impl NEVER exposes private key bytes.
//!
//! Complete-set semantics: when a new SVID set arrives from the
//! Workload API, it REPLACES the entire previous set. Old key
//! material is redacted (zeroized) immediately. There is no
//! partial merge.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::{Zeroize, Zeroizing};

use crate::error::{SpiffeError, SpiffeResult};
use crate::spiffe_id::SpiffeId;

/// A single X.509 SVID: certificate chain + private key +
/// SPIFFE ID + expiry.
///
/// The private key is stored in zeroizing memory. On drop or
/// explicit `redact()`, the key bytes are overwritten with
/// zeros. The `Debug` impl shows `[REDACTED]` for key material.
pub struct X509Svid {
    /// The validated SPIFFE ID for this SVID.
    spiffe_id: SpiffeId,
    /// DER-encoded certificate chain (leaf first).
    cert_chain_der: Vec<Vec<u8>>,
    /// DER-encoded PKCS#8 private key in zeroizing memory.
    private_key_der: Option<Zeroizing<Vec<u8>>>,
    /// PEM-encoded certificate chain (for rustls interop).
    cert_chain_pem: String,
    /// PEM-encoded private key in zeroizing memory.
    private_key_pem: Option<Zeroizing<String>>,
    /// Not-after timestamp (unix seconds).
    not_after_unix: i64,
    /// Whether this SVID's key material has been redacted.
    redacted: bool,
}

impl X509Svid {
    /// Create a new SVID from PEM-encoded certificate chain and
    /// private key.
    ///
    /// Extracts the SPIFFE ID from the leaf certificate's SAN
    /// URI and the not-after timestamp.
    pub fn from_pem(cert_chain_pem: &str, private_key_pem: &str) -> SpiffeResult<Self> {
        // Parse the leaf certificate to extract SPIFFE ID and expiry.
        let (spiffe_id, not_after_unix, cert_chain_der) = parse_cert_chain(cert_chain_pem)?;

        let private_key_der = pem_to_der_key(private_key_pem)?;

        Ok(Self {
            spiffe_id,
            cert_chain_der,
            private_key_der: Some(Zeroizing::new(private_key_der)),
            cert_chain_pem: cert_chain_pem.to_string(),
            private_key_pem: Some(Zeroizing::new(private_key_pem.to_string())),
            not_after_unix,
            redacted: false,
        })
    }

    /// The SPIFFE ID of this SVID.
    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// The not-after timestamp (unix seconds).
    pub fn not_after_unix(&self) -> i64 {
        self.not_after_unix
    }

    /// Whether this SVID has expired relative to `now`.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let now_unix = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(i64::MAX);
        now_unix >= self.not_after_unix
    }

    /// Seconds until expiry from `now`. Negative if expired.
    pub fn seconds_until_expiry(&self, now: SystemTime) -> i64 {
        let now_unix = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(i64::MAX);
        self.not_after_unix - now_unix
    }

    /// Whether the key material has been redacted.
    pub fn is_redacted(&self) -> bool {
        self.redacted
    }

    /// Access the PEM certificate chain. Certificates are public
    /// material and remain accessible after key redaction.
    pub fn cert_chain_pem(&self) -> &str {
        &self.cert_chain_pem
    }

    /// Access the PEM private key. Fails if redacted.
    pub fn private_key_pem(&self) -> SpiffeResult<&str> {
        if self.redacted {
            return Err(SpiffeError::MaterialRedacted);
        }
        self.private_key_pem
            .as_ref()
            .map(|k| k.as_str())
            .ok_or(SpiffeError::MaterialRedacted)
    }

    /// Access the DER certificate chain. Certificates are public
    /// material and remain accessible after key redaction.
    pub fn cert_chain_der(&self) -> &[Vec<u8>] {
        &self.cert_chain_der
    }

    /// Access the DER private key. Fails if redacted.
    pub fn private_key_der(&self) -> SpiffeResult<&[u8]> {
        if self.redacted {
            return Err(SpiffeError::MaterialRedacted);
        }
        self.private_key_der
            .as_ref()
            .map(|k| k.as_slice())
            .ok_or(SpiffeError::MaterialRedacted)
    }

    /// Redact (zeroize) the private key material. After this
    /// call, all key accessors return `Err(MaterialRedacted)`.
    /// This is irreversible.
    pub fn redact(&mut self) {
        if let Some(mut key) = self.private_key_der.take() {
            key.zeroize();
        }
        if let Some(mut pem) = self.private_key_pem.take() {
            pem.zeroize();
        }
        self.redacted = true;
    }
}

impl Drop for X509Svid {
    fn drop(&mut self) {
        self.redact();
    }
}

impl fmt::Debug for X509Svid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Svid")
            .field("spiffe_id", &self.spiffe_id.as_str())
            .field("not_after_unix", &self.not_after_unix)
            .field("redacted", &self.redacted)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// A trust bundle: the set of CA certificates for a trust
/// domain, used ONLY for SVID authentication (verifying peer
/// SVIDs during mTLS handshakes).
///
/// Trust bundles are NOT used for arbitrary TLS — they are
/// scoped exclusively to SPIFFE SVID verification.
#[derive(Debug, Clone)]
pub struct X509Bundle {
    /// The trust domain this bundle authenticates.
    trust_domain: String,
    /// PEM-encoded CA certificates.
    ca_certs_pem: String,
}

impl X509Bundle {
    /// Create a trust bundle for a trust domain.
    pub fn new(trust_domain: impl Into<String>, ca_certs_pem: &str) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            ca_certs_pem: ca_certs_pem.to_string(),
        }
    }

    /// The trust domain this bundle authenticates.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The PEM-encoded CA certificates.
    pub fn ca_certs_pem(&self) -> &str {
        &self.ca_certs_pem
    }
}

/// A complete set of SVIDs and trust bundles received from the
/// Workload API.
///
/// Complete-set semantics: this entire set REPLACES any
/// previous set. There is no partial merge. When replaced, the
/// old set's key material is redacted.
pub struct SvidSet {
    /// The SVIDs in this set (typically one primary).
    svids: Vec<X509Svid>,
    /// The trust bundle for our trust domain.
    bundle: X509Bundle,
    /// Federated trust bundles (trust domain → bundle).
    federated_bundles: Vec<X509Bundle>,
    /// When this set was received (unix seconds).
    received_at_unix: i64,
}

impl SvidSet {
    /// Create a new SVID set.
    pub fn new(
        svids: Vec<X509Svid>,
        bundle: X509Bundle,
        federated_bundles: Vec<X509Bundle>,
    ) -> Self {
        let received_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self {
            svids,
            bundle,
            federated_bundles,
            received_at_unix,
        }
    }

    /// The primary SVID (first in the set).
    pub fn primary_svid(&self) -> Option<&X509Svid> {
        self.svids.first()
    }

    /// All SVIDs in this set.
    pub fn svids(&self) -> &[X509Svid] {
        &self.svids
    }

    /// The trust bundle for our trust domain.
    pub fn bundle(&self) -> &X509Bundle {
        &self.bundle
    }

    /// Federated trust bundles.
    pub fn federated_bundles(&self) -> &[X509Bundle] {
        &self.federated_bundles
    }

    /// When this set was received (unix seconds).
    pub fn received_at_unix(&self) -> i64 {
        self.received_at_unix
    }

    /// Whether the primary SVID is expired relative to `now`.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.primary_svid()
            .map(|s| s.is_expired(now))
            .unwrap_or(true) // No SVID = expired (fail closed)
    }

    /// Seconds until the primary SVID expires. Negative if
    /// expired. Returns `None` if no SVIDs.
    pub fn seconds_until_expiry(&self, now: SystemTime) -> Option<i64> {
        self.primary_svid().map(|s| s.seconds_until_expiry(now))
    }

    /// Redact ALL key material in this set. Called when the set
    /// is replaced by a newer one.
    pub fn redact_all(&mut self) {
        for svid in &mut self.svids {
            svid.redact();
        }
    }
}

impl fmt::Debug for SvidSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SvidSet")
            .field("svid_count", &self.svids.len())
            .field("trust_domain", &self.bundle.trust_domain())
            .field("received_at_unix", &self.received_at_unix)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PEM/DER parsing helpers
// ---------------------------------------------------------------------------

/// Parse a PEM certificate chain, extracting the SPIFFE ID from
/// the leaf certificate's SAN URI and the not-after timestamp.
fn parse_cert_chain(cert_chain_pem: &str) -> SpiffeResult<(SpiffeId, i64, Vec<Vec<u8>>)> {
    use x509_parser::prelude::*;

    let mut cert_chain_der = Vec::new();
    let mut spiffe_id: Option<SpiffeId> = None;
    let mut not_after_unix: i64 = 0;

    // Parse all PEM blocks.
    let mut remaining = cert_chain_pem;
    let mut is_leaf = true;

    while let Ok((rest, pem)) = parse_x509_pem(remaining.as_bytes()) {
        remaining = std::str::from_utf8(rest).unwrap_or("");
        if pem.label != "CERTIFICATE" {
            continue;
        }

        let der = pem.contents.to_vec();

        // Parse the X.509 certificate.
        let (_, x509) = parse_x509_certificate(&der).map_err(|e| SpiffeError::ParseError {
            context: "x509 certificate".into(),
            source: e.to_string(),
        })?;

        if is_leaf {
            // Extract SPIFFE ID from SAN URI.
            spiffe_id = Some(extract_spiffe_id_from_san(&x509)?);

            // Extract not-after timestamp.
            not_after_unix = x509.validity().not_after.timestamp();
            is_leaf = false;
        }

        cert_chain_der.push(der);
    }

    if cert_chain_der.is_empty() {
        return Err(SpiffeError::ParseError {
            context: "certificate chain".into(),
            source: "no CERTIFICATE PEM blocks found".into(),
        });
    }

    let spiffe_id = spiffe_id.ok_or_else(|| SpiffeError::ParseError {
        context: "leaf certificate".into(),
        source: "no SPIFFE ID found in SAN".into(),
    })?;

    Ok((spiffe_id, not_after_unix, cert_chain_der))
}

/// Extract the SPIFFE ID from the Subject Alternative Name
/// extension's URI entry.
fn extract_spiffe_id_from_san(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> SpiffeResult<SpiffeId> {
    use x509_parser::extensions::GeneralName;

    let san = cert
        .subject_alternative_name()
        .map_err(|e| SpiffeError::ParseError {
            context: "SAN extension".into(),
            source: e.to_string(),
        })?
        .ok_or_else(|| SpiffeError::ParseError {
            context: "SAN extension".into(),
            source: "no Subject Alternative Name extension".into(),
        })?;

    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name {
            if uri.starts_with("spiffe://") {
                return SpiffeId::parse(uri);
            }
        }
    }

    Err(SpiffeError::ParseError {
        context: "SAN extension".into(),
        source: "no SPIFFE URI found in Subject Alternative Name".into(),
    })
}

/// Convert a PEM private key to DER bytes.
fn pem_to_der_key(private_key_pem: &str) -> SpiffeResult<Vec<u8>> {
    use x509_parser::prelude::parse_x509_pem;

    let (_, pem) =
        parse_x509_pem(private_key_pem.as_bytes()).map_err(|e| SpiffeError::ParseError {
            context: "private key PEM".into(),
            source: e.to_string(),
        })?;

    // Accept PRIVATE KEY (PKCS#8), EC PRIVATE KEY, RSA PRIVATE KEY.
    if pem.label == "PRIVATE KEY" || pem.label == "EC PRIVATE KEY" || pem.label == "RSA PRIVATE KEY"
    {
        Ok(pem.contents.to_vec())
    } else {
        Err(SpiffeError::ParseError {
            context: "private key PEM".into(),
            source: format!("unexpected PEM label: {}", pem.label),
        })
    }
}

#[cfg(test)]
mod tests {
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
}
