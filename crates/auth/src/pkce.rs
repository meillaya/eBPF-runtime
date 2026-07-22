// SPDX-License-Identifier: Apache-2.0 OR MIT
//! PKCE (RFC 7636) code verifier and S256 challenge.
//!
//! Only the S256 method is supported. The `plain` method is
//! NEVER accepted.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::error::{AuthError, AuthResult};

/// A PKCE code verifier (43..=128 unreserved characters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceVerifier(String);

impl PkceVerifier {
    /// Generate a cryptographically random 32-byte verifier,
    /// base64url-encoded (43 characters).
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Create a verifier from a raw string, validating length.
    pub fn from_raw(raw: impl Into<String>) -> AuthResult<Self> {
        let raw = raw.into();
        if !(43..=128).contains(&raw.len()) {
            return Err(AuthError::PkceInvalidVerifierLength { len: raw.len() });
        }
        Ok(Self(raw))
    }

    /// The verifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Compute the S256 code challenge:
    /// `BASE64URL(SHA256(verifier))`.
    pub fn challenge_s256(&self) -> PkceChallenge {
        let hash = Sha256::digest(self.0.as_bytes());
        PkceChallenge(URL_SAFE_NO_PAD.encode(hash))
    }
}

/// A PKCE S256 code challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceChallenge(String);

impl PkceChallenge {
    /// Create from a raw challenge string.
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The challenge string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Verify that a verifier produces this challenge.
    pub fn verify(&self, verifier: &PkceVerifier) -> AuthResult<()> {
        let expected = verifier.challenge_s256();
        if expected.0 != self.0 {
            return Err(AuthError::PkceVerificationFailed);
        }
        Ok(())
    }
}

/// The authorization request parameters for the web flow.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: PkceChallenge,
    pub code_challenge_method: &'static str,
}

impl AuthorizationRequest {
    /// Build an authorization request with PKCE S256 and a
    /// random state + nonce.
    pub fn new(client_id: &str, redirect_uri: &str, scope: &str) -> (Self, PkceVerifier) {
        let verifier = PkceVerifier::generate();
        let challenge = verifier.challenge_s256();
        let state = random_url_safe(16);
        let nonce = random_url_safe(16);
        let req = Self {
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            state,
            nonce,
            code_challenge: challenge,
            code_challenge_method: "S256",
        };
        (req, verifier)
    }
}

/// Generate a random base64url string of `byte_len` random
/// bytes.
fn random_url_safe(byte_len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; byte_len];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_verifier_has_valid_length() {
        let v = PkceVerifier::generate();
        assert!((43..=128).contains(&v.as_str().len()));
    }

    #[test]
    fn challenge_verify_round_trip() {
        let v = PkceVerifier::generate();
        let c = v.challenge_s256();
        assert!(c.verify(&v).is_ok());
    }

    #[test]
    fn wrong_verifier_fails() {
        let v1 = PkceVerifier::generate();
        let v2 = PkceVerifier::generate();
        let c = v1.challenge_s256();
        assert_eq!(c.verify(&v2), Err(AuthError::PkceVerificationFailed));
    }

    #[test]
    fn verifier_too_short_rejected() {
        let err = PkceVerifier::from_raw("short").unwrap_err();
        assert!(matches!(
            err,
            AuthError::PkceInvalidVerifierLength { len: 5 }
        ));
    }

    #[test]
    fn verifier_too_long_rejected() {
        let long = "a".repeat(129);
        let err = PkceVerifier::from_raw(long).unwrap_err();
        assert!(matches!(
            err,
            AuthError::PkceInvalidVerifierLength { len: 129 }
        ));
    }

    #[test]
    fn s256_challenge_matches_rfc7636_example() {
        // RFC 7636 Appendix B test vector.
        let verifier =
            PkceVerifier::from_raw("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
        let challenge = verifier.challenge_s256();
        assert_eq!(
            challenge.as_str(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn authorization_request_uses_s256() {
        let (req, _verifier) = AuthorizationRequest::new("client", "https://cb", "openid");
        assert_eq!(req.code_challenge_method, "S256");
        assert!(!req.state.is_empty());
        assert!(!req.nonce.is_empty());
    }
}
