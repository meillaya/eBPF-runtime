// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC bearer validation and RBAC.
//!
//! The control plane validates issuer, audience, signature, expiry, and
//! role-bearing groups. Only RS256 keys from the configured JWKS are
//! accepted. Dev mode is an explicit loopback-only role injection.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

/// Roles ordered from least to most privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Read-only.
    Viewer,
    /// Read and rule testing.
    Analyst,
    /// Policy authoring and rollout.
    PolicyAdmin,
    /// Everything, including audit.
    Admin,
}

/// A validated request identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Subject.
    pub sub: String,
    /// Effective role.
    pub role: Role,
    /// Groups from the token.
    pub groups: Vec<String>,
}

/// Claims accepted from the OIDC provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject.
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Expiry, unix seconds.
    pub exp: usize,
    /// Groups used for role mapping.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Email, optional.
    #[serde(default)]
    pub email: Option<String>,
}

/// Auth errors.
#[derive(Debug, Error)]
pub enum AuthError {
    /// No bearer token was supplied.
    #[error("missing bearer token")]
    Missing,
    /// The token could not be decoded.
    #[error("invalid token: {0}")]
    Invalid(String),
    /// The token has no recognized role.
    #[error("token has no fleet role")]
    NoRole,
    /// JWKS fetch failed.
    #[error("jwks fetch failed: {0}")]
    Jwks(String),
    /// The key id is unknown after a refresh.
    #[error("unknown signing key {0}")]
    UnknownKey(String),
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// Cached JWKS verifier.
pub struct JwtVerifier {
    issuer: String,
    audience: String,
    jwks_url: String,
    client: reqwest::Client,
    keys: RwLock<HashMap<String, Jwk>>,
    fetched_at: RwLock<Option<Instant>>,
    max_age: Duration,
}

impl JwtVerifier {
    /// Build a verifier that fetches keys on first use.
    pub fn new(issuer: String, audience: String, jwks_url: String) -> Self {
        Self {
            issuer,
            audience,
            jwks_url,
            client: reqwest::Client::new(),
            keys: RwLock::new(HashMap::new()),
            fetched_at: RwLock::new(None),
            max_age: Duration::from_secs(300),
        }
    }

    /// Build a verifier from a pinned JWKS document. Used by tests and by
    /// deployments that mount a static key set.
    pub fn from_jwks(issuer: String, audience: String, document: &str) -> Result<Self, AuthError> {
        let set: JwkSet =
            serde_json::from_str(document).map_err(|error| AuthError::Jwks(error.to_string()))?;
        let mut keys = HashMap::new();
        for key in set.keys {
            keys.insert(key.kid.clone(), key);
        }
        Ok(Self {
            issuer,
            audience,
            jwks_url: String::new(),
            client: reqwest::Client::new(),
            keys: RwLock::new(keys),
            fetched_at: RwLock::new(Some(Instant::now())),
            max_age: Duration::from_secs(300),
        })
    }

    /// Validate a bearer token.
    pub async fn verify(&self, token: &str) -> Result<AuthContext, AuthError> {
        let header = decode_header(token).map_err(|error| AuthError::Invalid(error.to_string()))?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthError::Invalid("only RS256 is accepted".to_string()));
        }
        let kid = header.kid.ok_or(AuthError::Missing)?;
        let key = self.key_for(&kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.leeway = 30;
        validation.validate_nbf = true;
        let decoding = DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(|error| AuthError::Invalid(error.to_string()))?;
        let data = decode::<Claims>(token, &decoding, &validation)
            .map_err(|error| AuthError::Invalid(error.to_string()))?;
        let role = role_from_groups(&data.claims.groups).ok_or(AuthError::NoRole)?;
        Ok(AuthContext {
            sub: data.claims.sub,
            role,
            groups: data.claims.groups,
        })
    }

    async fn key_for(&self, kid: &str) -> Result<Jwk, AuthError> {
        let stale = self
            .fetched_at
            .read()
            .await
            .map(|at| at.elapsed() > self.max_age)
            .unwrap_or(true);
        if !stale {
            if let Some(key) = self.keys.read().await.get(kid).cloned() {
                return Ok(key);
            }
            *self.fetched_at.write().await = None;
        }
        self.refresh().await?;
        self.keys
            .read()
            .await
            .get(kid)
            .cloned()
            .ok_or_else(|| AuthError::UnknownKey(kid.to_string()))
    }

    async fn refresh(&self) -> Result<(), AuthError> {
        if self.jwks_url.is_empty() {
            return Ok(());
        }
        let stale = self
            .fetched_at
            .read()
            .await
            .map(|at| at.elapsed() > self.max_age)
            .unwrap_or(true);
        if !stale {
            return Ok(());
        }
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|error| AuthError::Jwks(error.to_string()))?
            .error_for_status()
            .map_err(|error| AuthError::Jwks(error.to_string()))?;
        let set: JwkSet = response
            .json()
            .await
            .map_err(|error| AuthError::Jwks(error.to_string()))?;
        let mut keys = self.keys.write().await;
        keys.clear();
        for key in set.keys {
            if key.kty == "RSA" {
                keys.insert(key.kid.clone(), key);
            }
        }
        *self.fetched_at.write().await = Some(Instant::now());
        Ok(())
    }
}

/// Resolve a role from OIDC group names.
pub fn role_from_groups(groups: &[String]) -> Option<Role> {
    let mut role = None;
    for group in groups {
        let candidate = match group.as_str() {
            "ebpf-admins" | "fleet-admins" => Some(Role::Admin),
            "ebpf-policy-admins" | "fleet-policy-admins" => Some(Role::PolicyAdmin),
            "ebpf-analysts" | "fleet-analysts" => Some(Role::Analyst),
            "ebpf-viewers" | "fleet-viewers" => Some(Role::Viewer),
            _ => None,
        };
        if let Some(candidate) = candidate {
            role = Some(role.map_or(candidate, |current: Role| current.max(candidate)));
        }
    }
    role
}

/// Auth service with optional dev bypass.
#[derive(Clone)]
pub struct AuthService {
    verifier: Arc<JwtVerifier>,
    dev_role: Option<Role>,
}

impl AuthService {
    /// Build a service. `dev_role` must only be set for a loopback bind.
    pub fn new(verifier: JwtVerifier, dev_role: Option<Role>) -> Self {
        Self {
            verifier: Arc::new(verifier),
            dev_role,
        }
    }

    /// Authenticate a bearer token.
    pub async fn authenticate(&self, token: Option<&str>) -> Result<AuthContext, AuthError> {
        match token {
            Some(token) => self.verifier.verify(token).await,
            None => match self.dev_role {
                Some(role) => Ok(AuthContext {
                    sub: "dev".to_string(),
                    role,
                    groups: vec!["dev".to_string()],
                }),
                None => Err(AuthError::Missing),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn token(role_group: &str, aud: &str) -> String {
        let claims = Claims {
            sub: "user-1".to_string(),
            iss: "https://issuer.example".to_string(),
            aud: aud.to_string(),
            exp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize
                + 300,
            groups: vec![role_group.to_string()],
            email: None,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_string());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(include_bytes!("../tests/fixtures/test-key.pem")).unwrap(),
        )
        .unwrap()
    }

    fn verifier() -> JwtVerifier {
        JwtVerifier::from_jwks(
            "https://issuer.example".to_string(),
            "ebpf-control-plane".to_string(),
            include_str!("../tests/fixtures/jwks.json"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn accepts_a_valid_admin_token() {
        let context = verifier()
            .verify(&token("ebpf-admins", "ebpf-control-plane"))
            .await
            .unwrap();
        assert_eq!(context.role, Role::Admin);
    }

    #[tokio::test]
    async fn rejects_wrong_audience() {
        assert!(verifier()
            .verify(&token("ebpf-admins", "other-service"))
            .await
            .is_err());
    }

    #[test]
    fn highest_role_wins() {
        let groups = vec!["ebpf-viewers".to_string(), "ebpf-policy-admins".to_string()];
        assert_eq!(role_from_groups(&groups), Some(Role::PolicyAdmin));
    }
}
