// SPDX-License-Identifier: Apache-2.0 OR MIT
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
    let err = validate_id_token("not.a.valid.jwt.token", &jwks, &default_params(0)).unwrap_err();
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
