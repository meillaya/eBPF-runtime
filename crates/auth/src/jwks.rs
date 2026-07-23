// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWKS (JSON Web Key Set) parsing and key resolution.
//!
//! Supports RSA (RS256) and EC P-256 (ES256) keys. Keys are
//! resolved by `kid` and `alg`. Unknown kids are rejected.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature;
use serde::{Deserialize, Serialize};

use crate::error::{AuthError, AuthResult};

/// A JSON Web Key Set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// A single JSON Web Key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type: "RSA" or "EC".
    pub kty: String,
    /// Algorithm: "RS256" or "ES256".
    #[serde(default)]
    pub alg: Option<String>,
    /// Key ID.
    #[serde(default)]
    pub kid: Option<String>,
    /// Public key use: "sig".
    #[serde(default)]
    pub r#use: Option<String>,
    // RSA fields
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
    // EC fields
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

impl Jwks {
    /// Parse a JWKS from JSON.
    pub fn from_json(json: &str) -> AuthResult<Self> {
        serde_json::from_str(json).map_err(|e| AuthError::MalformedJwt {
            reason: format!("JWKS parse: {e}"),
        })
    }

    /// Resolve a key by kid and algorithm. Returns the
    /// `ring` verification key.
    pub fn resolve_key(&self, kid: Option<&str>, alg: &str) -> AuthResult<ResolvedKey> {
        // Reject unsupported algorithms BEFORE key lookup so
        // the error is precise.
        if alg != "RS256" && alg != "ES256" {
            return Err(AuthError::UnsupportedAlgorithm {
                alg: alg.to_string(),
            });
        }

        let candidates: Vec<&Jwk> = self
            .keys
            .iter()
            .filter(|k| {
                let kid_match = match (kid, &k.kid) {
                    (Some(want), Some(have)) => want == have,
                    (None, _) => true,
                    (Some(_), None) => false,
                };
                let alg_match = match &k.alg {
                    Some(a) => a == alg,
                    None => true,
                };
                kid_match && alg_match
            })
            .collect();

        let jwk = candidates.first().ok_or_else(|| AuthError::NoMatchingKey {
            kid: kid.map(String::from),
            alg: alg.to_string(),
        })?;

        match alg {
            "RS256" => Self::resolve_rsa(jwk),
            "ES256" => Self::resolve_ec(jwk),
            other => Err(AuthError::UnsupportedAlgorithm {
                alg: other.to_string(),
            }),
        }
    }

    fn resolve_rsa(jwk: &Jwk) -> AuthResult<ResolvedKey> {
        let n_b64 = jwk.n.as_deref().ok_or(AuthError::NoMatchingKey {
            kid: jwk.kid.clone(),
            alg: "RS256".into(),
        })?;
        let e_b64 = jwk.e.as_deref().ok_or(AuthError::NoMatchingKey {
            kid: jwk.kid.clone(),
            alg: "RS256".into(),
        })?;
        let n_bytes = URL_SAFE_NO_PAD
            .decode(n_b64)
            .map_err(|_| AuthError::NoMatchingKey {
                kid: jwk.kid.clone(),
                alg: "RS256".into(),
            })?;
        let e_bytes = URL_SAFE_NO_PAD
            .decode(e_b64)
            .map_err(|_| AuthError::NoMatchingKey {
                kid: jwk.kid.clone(),
                alg: "RS256".into(),
            })?;
        // Build DER-encoded RSA public key for ring.
        let der = encode_rsa_public_key_der(&n_bytes, &e_bytes);
        let key = signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, der);
        Ok(ResolvedKey { inner: key })
    }

    fn resolve_ec(jwk: &Jwk) -> AuthResult<ResolvedKey> {
        let x_b64 = jwk.x.as_deref().ok_or(AuthError::NoMatchingKey {
            kid: jwk.kid.clone(),
            alg: "ES256".into(),
        })?;
        let y_b64 = jwk.y.as_deref().ok_or(AuthError::NoMatchingKey {
            kid: jwk.kid.clone(),
            alg: "ES256".into(),
        })?;
        let x_bytes = URL_SAFE_NO_PAD
            .decode(x_b64)
            .map_err(|_| AuthError::NoMatchingKey {
                kid: jwk.kid.clone(),
                alg: "ES256".into(),
            })?;
        let y_bytes = URL_SAFE_NO_PAD
            .decode(y_b64)
            .map_err(|_| AuthError::NoMatchingKey {
                kid: jwk.kid.clone(),
                alg: "ES256".into(),
            })?;
        // Uncompressed EC point: 0x04 || x || y
        let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
        point.push(0x04);
        point.extend_from_slice(&x_bytes);
        point.extend_from_slice(&y_bytes);
        let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point);
        Ok(ResolvedKey { inner: key })
    }
}

/// A resolved verification key ready for signature checks.
#[derive(Debug)]
pub struct ResolvedKey {
    inner: signature::UnparsedPublicKey<Vec<u8>>,
}

impl ResolvedKey {
    /// Verify a signature over `message`.
    pub fn verify(&self, message: &[u8], sig: &[u8]) -> AuthResult<()> {
        self.inner
            .verify(message, sig)
            .map_err(|_| AuthError::SignatureInvalid)
    }
}

/// Encode an RSA public key as DER (PKCS#1 RSAPublicKey) for
/// ring consumption. Ring expects `SEQUENCE { INTEGER n,
/// INTEGER e }` — NOT the full SubjectPublicKeyInfo wrapper.
fn encode_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let n_int = der_integer(n);
    let e_int = der_integer(e);
    der_sequence(&[&n_int, &e_int])
}

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn der_sequence(contents: &[&[u8]]) -> Vec<u8> {
    let total: usize = contents.iter().map(|c| c.len()).sum();
    let mut out = vec![0x30];
    out.extend_from_slice(&der_length(total));
    for c in contents {
        out.extend_from_slice(c);
    }
    out
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x02];
    // Prepend 0x00 if high bit set (positive integer).
    let needs_pad = bytes.first().is_some_and(|b| b & 0x80 != 0);
    let len = bytes.len() + usize::from(needs_pad);
    out.extend_from_slice(&der_length(len));
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_jwks() -> Jwks {
        let json = include_str!("../../../tests/fixtures/oidc/jwks.json");
        Jwks::from_json(json).unwrap()
    }

    #[test]
    fn resolve_rsa_key_by_kid() {
        let jwks = fixture_jwks();
        let key = jwks.resolve_key(Some("test-rsa-key-1"), "RS256");
        assert!(key.is_ok());
    }

    #[test]
    fn resolve_ec_key_by_kid() {
        let jwks = fixture_jwks();
        let key = jwks.resolve_key(Some("test-ec-key-1"), "ES256");
        assert!(key.is_ok());
    }

    #[test]
    fn unknown_kid_rejected() {
        let jwks = fixture_jwks();
        let err = jwks.resolve_key(Some("nonexistent"), "RS256").unwrap_err();
        assert!(matches!(err, AuthError::NoMatchingKey { .. }));
    }

    #[test]
    fn unsupported_alg_rejected() {
        let jwks = fixture_jwks();
        let err = jwks
            .resolve_key(Some("test-rsa-key-1"), "HS256")
            .unwrap_err();
        assert!(matches!(err, AuthError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn jwks_fixture_has_two_keys() {
        let jwks = fixture_jwks();
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[1].kty, "EC");
    }
}
