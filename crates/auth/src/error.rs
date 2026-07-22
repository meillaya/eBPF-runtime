// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed error variants for every OIDC/JWT/RBAC/session failure.

#![forbid(unsafe_code)]

/// Result alias for auth operations.
pub type AuthResult<T> = Result<T, AuthError>;

/// Every authentication, token-validation, RBAC, and session
/// failure as a typed variant. No free strings for error
/// classification.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum AuthError {
    // -- Discovery --
    /// The issuer in the discovery document does not exactly
    /// match the pinned issuer.
    #[error("issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },

    /// The discovery document is missing a required endpoint.
    #[error("discovery missing required field: {field}")]
    DiscoveryMissingField { field: String },

    // -- PKCE --
    /// The PKCE code challenge does not match the verifier.
    #[error("PKCE verification failed")]
    PkceVerificationFailed,

    /// The PKCE code verifier has an invalid length.
    #[error("PKCE verifier length {len} outside 43..=128")]
    PkceInvalidVerifierLength { len: usize },

    // -- JWT / JWKS --
    /// No key in the JWKS matches the token's kid/alg.
    #[error("no matching JWKS key for kid={kid:?} alg={alg}")]
    NoMatchingKey { kid: Option<String>, alg: String },

    /// The JWT signature is invalid.
    #[error("JWT signature verification failed")]
    SignatureInvalid,

    /// The JWT is malformed (not three dot-separated segments).
    #[error("malformed JWT: {reason}")]
    MalformedJwt { reason: String },

    /// The JWT issuer does not match the expected issuer.
    #[error("JWT issuer mismatch: expected {expected}, got {actual}")]
    JwtIssuerMismatch { expected: String, actual: String },

    /// The JWT audience does not contain the expected audience.
    #[error("JWT audience mismatch: expected {expected} in {actual:?}")]
    JwtAudienceMismatch {
        expected: String,
        actual: Vec<String>,
    },

    /// The JWT azp (authorized party) does not match.
    #[error("JWT azp mismatch: expected {expected}, got {actual}")]
    JwtAzpMismatch { expected: String, actual: String },

    /// The JWT has expired.
    #[error("JWT expired at {exp}, now is {now}")]
    JwtExpired { exp: u64, now: u64 },

    /// The JWT iat (issued-at) is in the future beyond skew.
    #[error("JWT iat {iat} is in the future (now {now}, skew {skew_s}s)")]
    JwtIssuedInFuture { iat: u64, now: u64, skew_s: u64 },

    /// The JWT nonce does not match the expected nonce.
    #[error("JWT nonce mismatch")]
    JwtNonceMismatch,

    /// The JWT is missing a required claim.
    #[error("JWT missing required claim: {claim}")]
    JwtMissingClaim { claim: String },

    /// The JWT alg is not in the supported set.
    #[error("unsupported JWT algorithm: {alg}")]
    UnsupportedAlgorithm { alg: String },

    // -- Device flow --
    /// The device code has expired.
    #[error("device code expired")]
    DeviceCodeExpired,

    /// The user denied the device authorization.
    #[error("device authorization denied by user")]
    DeviceAccessDenied,

    /// The device authorization is still pending.
    #[error("device authorization pending")]
    DeviceAuthorizationPending,

    /// The client is polling too fast.
    #[error("device polling too fast, slow down")]
    DeviceSlowDown,

    // -- Session --
    /// The session has expired.
    #[error("session expired")]
    SessionExpired,

    /// The session was explicitly revoked.
    #[error("session revoked")]
    SessionRevoked,

    /// The session was invalidated due to a group change.
    #[error("session invalidated: group membership changed")]
    SessionGroupChanged,

    /// The session ID was not found.
    #[error("session not found: {session_id}")]
    SessionNotFound { session_id: String },

    // -- RBAC --
    /// The actor's role does not permit the requested action.
    #[error("role {role} denied action {action} on {resource}")]
    RbacDenied {
        role: String,
        action: String,
        resource: String,
    },

    /// No role binding found for the actor.
    #[error("no role binding for sub={sub}")]
    NoRoleBinding { sub: String },

    // -- Middleware / bind --
    /// A no-auth bind was attempted on a non-loopback address.
    #[error("refusing no-auth bind to non-loopback address {addr}")]
    NonLoopbackBindRefused { addr: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_stable() {
        let err = AuthError::IssuerMismatch {
            expected: "https://a.test".into(),
            actual: "https://b.test".into(),
        };
        assert!(err.to_string().contains("issuer mismatch"));
    }

    #[test]
    fn error_variants_are_distinct() {
        let errors = [
            AuthError::PkceVerificationFailed,
            AuthError::SignatureInvalid,
            AuthError::DeviceCodeExpired,
            AuthError::SessionExpired,
            AuthError::SessionRevoked,
        ];
        for (i, a) in errors.iter().enumerate() {
            for (j, b) in errors.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "variants {i} and {j} must differ");
                }
            }
        }
    }
}
