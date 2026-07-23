// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Certificate and key parsing helpers for SVIDs.

use super::*;

pub(crate) fn parse_cert_chain(
    cert_chain_pem: &str,
) -> SpiffeResult<(SpiffeId, i64, Vec<Vec<u8>>)> {
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
pub(crate) fn extract_spiffe_id_from_san(
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
pub(crate) fn pem_to_der_key(private_key_pem: &str) -> SpiffeResult<Vec<u8>> {
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
