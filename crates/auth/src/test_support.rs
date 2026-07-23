// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Test support: sign JWTs with the pinned fixture keys.
//!
//! This module is only compiled under `#[cfg(test)]`. It reads
//! the PEM private keys from `tests/fixtures/oidc/keys/` and
//! signs JWTs for validation tests.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature;

/// Sign a test JWT with the fixture private key.
///
/// `alg` must be "RS256" or "ES256". The `kid` is set in the
/// header. Claims are serialized from the provided JSON value.
pub fn sign_test_jwt(alg: &str, kid: Option<&str>, claims: &serde_json::Value) -> String {
    let header = serde_json::json!({
        "alg": alg,
        "typ": "JWT",
        "kid": kid,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let sig = match alg {
        "RS256" => sign_rs256(signing_input.as_bytes()),
        "ES256" => sign_es256(signing_input.as_bytes()),
        other => panic!("unsupported test alg: {other}"),
    };
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    format!("{signing_input}.{sig_b64}")
}

fn sign_rs256(message: &[u8]) -> Vec<u8> {
    let pem = include_str!("../../../tests/fixtures/oidc/keys/rsa-test.pem");
    let der = pem_to_der(pem);
    let key = signature::RsaKeyPair::from_pkcs8(&der).expect("fixture RSA key must parse");
    let rng = SystemRandom::new();
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut sig)
        .expect("RSA signing must succeed");
    sig
}

fn sign_es256(message: &[u8]) -> Vec<u8> {
    let pem = include_str!("../../../tests/fixtures/oidc/keys/ec-test.pem");
    let der = pem_to_der(pem);
    let key = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &der,
        &SystemRandom::new(),
    )
    .expect("fixture EC key must parse");
    let rng = SystemRandom::new();
    let sig = key.sign(&rng, message).expect("ECDSA signing must succeed");
    sig.as_ref().to_vec()
}

/// Strip PEM headers and decode base64 to DER bytes.
fn pem_to_der(pem: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(body).expect("PEM base64 must decode")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_rs256_produces_three_segments() {
        let token = sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({"sub": "test"}),
        );
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn sign_es256_produces_three_segments() {
        let token = sign_test_jwt(
            "ES256",
            Some("test-ec-key-1"),
            &serde_json::json!({"sub": "test"}),
        );
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn signed_rs256_verifies_with_fixture_jwks() {
        use crate::jwks::Jwks;
        let jwks_json = include_str!("../../../tests/fixtures/oidc/jwks.json");
        let jwks = Jwks::from_json(jwks_json).unwrap();
        let token = sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({"sub": "test", "iss": "https://dex.kernel-v1.test"}),
        );
        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let key = jwks.resolve_key(Some("test-rsa-key-1"), "RS256").unwrap();
        assert!(key.verify(signing_input.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn signed_es256_verifies_with_fixture_jwks() {
        use crate::jwks::Jwks;
        let jwks_json = include_str!("../../../tests/fixtures/oidc/jwks.json");
        let jwks = Jwks::from_json(jwks_json).unwrap();
        let token = sign_test_jwt(
            "ES256",
            Some("test-ec-key-1"),
            &serde_json::json!({"sub": "test", "iss": "https://dex.kernel-v1.test"}),
        );
        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let key = jwks.resolve_key(Some("test-ec-key-1"), "ES256").unwrap();
        assert!(key.verify(signing_input.as_bytes(), &sig).is_ok());
    }
}
