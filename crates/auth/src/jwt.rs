// SPDX-License-Identifier: Apache-2.0 OR MIT
//! JWT validation: signature (RS256/ES256 via ring), issuer,
//! audience, azp, expiry, iat, nonce.
//!
//! Unsigned, stale, or replayed tokens are NEVER accepted.

#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{AuthError, AuthResult};
use crate::jwks::Jwks;

/// Clock skew tolerance in seconds for iat validation.
pub const IAT_SKEW_SECONDS: u64 = 120;

/// Validated ID token claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    /// Audience: may be a single string or array.
    #[serde(deserialize_with = "deserialize_aud")]
    pub aud: Vec<String>,
    pub exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    /// OIDC groups claim for RBAC binding.
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

fn deserialize_aud<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Aud {
        Single(String),
        Multiple(Vec<String>),
    }
    match Aud::deserialize(deserializer)? {
        Aud::Single(s) => Ok(vec![s]),
        Aud::Multiple(v) => Ok(v),
    }
}

/// JWT header (only the fields we validate).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// Validation parameters for ID token verification.
#[derive(Debug, Clone)]
pub struct TokenValidationParams {
    /// The exact expected issuer.
    pub issuer: String,
    /// The expected audience (client_id).
    pub audience: String,
    /// The expected authorized party (client_id), if azp is
    /// present.
    pub authorized_party: Option<String>,
    /// The expected nonce (from the authorization request).
    pub nonce: Option<String>,
    /// Current time as epoch seconds (explicit for testability).
    pub now_epoch_s: u64,
}

/// Validate a JWT ID token: signature, issuer, audience, azp,
/// expiry, iat, nonce.
pub fn validate_id_token(
    token: &str,
    jwks: &Jwks,
    params: &TokenValidationParams,
) -> AuthResult<IdTokenClaims> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return Err(AuthError::MalformedJwt {
            reason: format!("expected 3 segments, got {}", segments.len()),
        });
    }

    // 1. Parse and validate header.
    let header_json = URL_SAFE_NO_PAD
        .decode(segments[0])
        .map_err(|_| AuthError::MalformedJwt {
            reason: "header base64 decode failed".into(),
        })?;
    let header: JwtHeader =
        serde_json::from_slice(&header_json).map_err(|_| AuthError::MalformedJwt {
            reason: "header JSON parse failed".into(),
        })?;

    // Reject algorithms we don't support (never "none").
    if header.alg != "RS256" && header.alg != "ES256" {
        return Err(AuthError::UnsupportedAlgorithm {
            alg: header.alg.clone(),
        });
    }

    // 2. Verify signature.
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(segments[2])
        .map_err(|_| AuthError::SignatureInvalid)?;
    let key = jwks.resolve_key(header.kid.as_deref(), &header.alg)?;
    key.verify(signing_input.as_bytes(), &sig_bytes)?;

    // 3. Parse claims.
    let claims_json = URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|_| AuthError::MalformedJwt {
            reason: "claims base64 decode failed".into(),
        })?;
    let claims: IdTokenClaims =
        serde_json::from_slice(&claims_json).map_err(|e| AuthError::JwtMissingClaim {
            claim: format!("claims parse: {e}"),
        })?;

    // 4. Validate issuer (exact match).
    if claims.iss != params.issuer {
        return Err(AuthError::JwtIssuerMismatch {
            expected: params.issuer.clone(),
            actual: claims.iss.clone(),
        });
    }

    // 5. Validate audience.
    if !claims.aud.contains(&params.audience) {
        return Err(AuthError::JwtAudienceMismatch {
            expected: params.audience.clone(),
            actual: claims.aud.clone(),
        });
    }

    // 6. Validate azp (if present in token AND expected).
    if let (Some(azp), Some(expected_azp)) = (&claims.azp, &params.authorized_party) {
        if azp != expected_azp {
            return Err(AuthError::JwtAzpMismatch {
                expected: expected_azp.clone(),
                actual: azp.clone(),
            });
        }
    }

    // 7. Validate expiry.
    if params.now_epoch_s >= claims.exp {
        return Err(AuthError::JwtExpired {
            exp: claims.exp,
            now: params.now_epoch_s,
        });
    }

    // 8. Validate iat (not too far in the future).
    if claims.iat > params.now_epoch_s + IAT_SKEW_SECONDS {
        return Err(AuthError::JwtIssuedInFuture {
            iat: claims.iat,
            now: params.now_epoch_s,
            skew_s: IAT_SKEW_SECONDS,
        });
    }

    // 9. Validate nonce (if expected).
    if let Some(expected_nonce) = &params.nonce {
        match &claims.nonce {
            Some(n) if n == expected_nonce => {}
            _ => return Err(AuthError::JwtNonceMismatch),
        }
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    fn fixture_jwks() -> Jwks {
        let json = include_str!("../../../tests/fixtures/oidc/jwks.json");
        Jwks::from_json(json).unwrap()
    }

    fn default_params(now: u64) -> TokenValidationParams {
        TokenValidationParams {
            issuer: "https://dex.kernel-v1.test".into(),
            audience: "kernel-v1-web".into(),
            authorized_party: Some("kernel-v1-web".into()),
            nonce: Some("test-nonce-123".into()),
            now_epoch_s: now,
        }
    }

    #[test]
    fn valid_rs256_token_passes() {
        let jwks = fixture_jwks();
        let now = 1_700_000_000u64;
        let token = test_support::sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({
                "iss": "https://dex.kernel-v1.test",
                "sub": "user-1",
                "aud": "kernel-v1-web",
                "azp": "kernel-v1-web",
                "exp": now + 3600,
                "iat": now,
                "nonce": "test-nonce-123",
                "groups": ["viewers"]
            }),
        );
        let claims = validate_id_token(&token, &jwks, &default_params(now)).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.groups, vec!["viewers"]);
    }

    #[test]
    fn valid_es256_token_passes() {
        let jwks = fixture_jwks();
        let now = 1_700_000_000u64;
        let token = test_support::sign_test_jwt(
            "ES256",
            Some("test-ec-key-1"),
            &serde_json::json!({
                "iss": "https://dex.kernel-v1.test",
                "sub": "user-2",
                "aud": "kernel-v1-web",
                "azp": "kernel-v1-web",
                "exp": now + 3600,
                "iat": now,
                "nonce": "test-nonce-123",
                "groups": ["analysts"]
            }),
        );
        let claims = validate_id_token(&token, &jwks, &default_params(now)).unwrap();
        assert_eq!(claims.sub, "user-2");
    }

    #[test]
    fn expired_token_rejected() {
        let jwks = fixture_jwks();
        let now = 1_700_000_000u64;
        let token = test_support::sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({
                "iss": "https://dex.kernel-v1.test",
                "sub": "user-1",
                "aud": "kernel-v1-web",
                "exp": now - 100,
                "iat": now - 3700,
                "nonce": "test-nonce-123"
            }),
        );
        let err = validate_id_token(&token, &jwks, &default_params(now)).unwrap_err();
        assert!(matches!(err, AuthError::JwtExpired { .. }));
    }

    #[test]
    fn wrong_issuer_rejected() {
        let jwks = fixture_jwks();
        let now = 1_700_000_000u64;
        let token = test_support::sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({
                "iss": "https://evil.example",
                "sub": "user-1",
                "aud": "kernel-v1-web",
                "exp": now + 3600,
                "iat": now,
                "nonce": "test-nonce-123"
            }),
        );
        let err = validate_id_token(&token, &jwks, &default_params(now)).unwrap_err();
        assert!(matches!(err, AuthError::JwtIssuerMismatch { .. }));
    }

    #[test]
    fn wrong_audience_rejected() {
        let jwks = fixture_jwks();
        let now = 1_700_000_000u64;
        let token = test_support::sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({
                "iss": "https://dex.kernel-v1.test",
                "sub": "user-1",
                "aud": "wrong-client",
                "exp": now + 3600,
                "iat": now,
                "nonce": "test-nonce-123"
            }),
        );
        let err = validate_id_token(&token, &jwks, &default_params(now)).unwrap_err();
        assert!(matches!(err, AuthError::JwtAudienceMismatch { .. }));
    }

    #[test]
    fn wrong_nonce_rejected() {
        let jwks = fixture_jwks();
        let now = 1_700_000_000u64;
        let token = test_support::sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({
                "iss": "https://dex.kernel-v1.test",
                "sub": "user-1",
                "aud": "kernel-v1-web",
                "exp": now + 3600,
                "iat": now,
                "nonce": "wrong-nonce"
            }),
        );
        let err = validate_id_token(&token, &jwks, &default_params(now)).unwrap_err();
        assert!(matches!(err, AuthError::JwtNonceMismatch));
    }

    #[test]
    fn wrong_azp_rejected() {
        let jwks = fixture_jwks();
        let now = 1_700_000_000u64;
        let token = test_support::sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({
                "iss": "https://dex.kernel-v1.test",
                "sub": "user-1",
                "aud": "kernel-v1-web",
                "azp": "evil-client",
                "exp": now + 3600,
                "iat": now,
                "nonce": "test-nonce-123"
            }),
        );
        let err = validate_id_token(&token, &jwks, &default_params(now)).unwrap_err();
        assert!(matches!(err, AuthError::JwtAzpMismatch { .. }));
    }

    #[test]
    fn iat_in_future_rejected() {
        let jwks = fixture_jwks();
        let now = 1_700_000_000u64;
        let token = test_support::sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({
                "iss": "https://dex.kernel-v1.test",
                "sub": "user-1",
                "aud": "kernel-v1-web",
                "exp": now + 7200,
                "iat": now + 600,
                "nonce": "test-nonce-123"
            }),
        );
        let err = validate_id_token(&token, &jwks, &default_params(now)).unwrap_err();
        assert!(matches!(err, AuthError::JwtIssuedInFuture { .. }));
    }

    #[test]
    fn malformed_jwt_rejected() {
        let jwks = fixture_jwks();
        let err =
            validate_id_token("not.a.valid.jwt.token", &jwks, &default_params(0)).unwrap_err();
        assert!(matches!(err, AuthError::MalformedJwt { .. }));
    }

    #[test]
    fn alg_none_rejected() {
        let jwks = fixture_jwks();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let claims = URL_SAFE_NO_PAD.encode(br#"{"iss":"x","sub":"x","aud":"x","exp":0,"iat":0}"#);
        let token = format!("{header}.{claims}.");
        let err = validate_id_token(&token, &jwks, &default_params(0)).unwrap_err();
        assert!(matches!(err, AuthError::UnsupportedAlgorithm { .. }));
    }

    #[test]
    fn tampered_signature_rejected() {
        let jwks = fixture_jwks();
        let now = 1_700_000_000u64;
        let token = test_support::sign_test_jwt(
            "RS256",
            Some("test-rsa-key-1"),
            &serde_json::json!({
                "iss": "https://dex.kernel-v1.test",
                "sub": "user-1",
                "aud": "kernel-v1-web",
                "exp": now + 3600,
                "iat": now,
                "nonce": "test-nonce-123"
            }),
        );
        // Tamper with the payload.
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.e30.{}", parts[0], parts[2]);
        let err = validate_id_token(&tampered, &jwks, &default_params(now)).unwrap_err();
        assert!(matches!(err, AuthError::SignatureInvalid));
    }
}
