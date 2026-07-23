// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC PKCE/device authentication and server-side RBAC for
//! the eBPF runtime security control plane.
//!
//! This crate provides:
//!
//! - **OIDC discovery**: exact issuer pin (no substring
//!   matching), endpoint validation.
//! - **Authorization-code + PKCE + nonce**: S256 code
//!   challenge for web clients. The `plain` method is NEVER
//!   accepted. The implicit flow is NEVER used.
//! - **RFC 8628 device flow**: polling with `slow_down`
//!   backoff and bounded expiry for CLI clients.
//! - **JWT validation**: RS256/ES256 signature verification
//!   via JWKS, issuer/audience/azp/expiry/iat/nonce checks.
//!   Unsigned and stale tokens are NEVER accepted.
//! - **Short-lived sessions**: configurable TTL, explicit
//!   revocation, group-change invalidation. No static
//!   production tokens.
//! - **RBAC**: four roles (`viewer | analyst | policy-admin |
//!   admin`), group/sub bindings (NEVER email), per-route
//!   action authorization.
//! - **Loopback-only dev bypass**: no-auth mode is refused on
//!   non-loopback addresses.
//! - **Actor-bound audit intent**: every mutation emits an
//!   audit record binding actor, action, and resource.
//!
//! # Security invariants
//!
//! - Issuer matching is EXACT (`!=`), never substring.
//! - Authorization is by group/sub, NEVER by email.
//! - Unsigned/stale/replayed tokens are NEVER accepted.
//! - Sessions are short-lived (default 15 min TTL).
//! - Dev bypass is loopback-only (127.0.0.1 / ::1).
//! - The implicit flow is NEVER used.
//! - Database RLS alone is NOT sufficient; service-layer RBAC
//!   is enforced.
//!
//! # BLOCKER NOTE
//!
//! This host does not have a running OIDC provider
//! (Dex/Keycloak). All flows are implemented and tested with
//! pinned fixtures (test JWKS, test tokens, test discovery
//! responses). Live OIDC integration requires a declared
//! self-hosted runner with an OIDC provider deployed.
//!
//! # Integration with protocol crate (task 35)
//!
//! The RBAC route actions mirror the task 6 OpenAPI action
//! annotations. Session management uses explicit `now`
//! parameters consistent with the protocol crate's deadline
//! propagation pattern.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod audit;
pub mod device;
pub mod discovery;
pub mod error;
pub mod jwks;
pub mod jwt;
pub mod middleware;
pub mod pkce;
pub mod rbac;
pub mod session;

#[cfg(test)]
pub(crate) mod test_support;

// Re-export primary types for convenience.
pub use audit::{AuditIntent, AuditSink};
pub use device::{DeviceAuthorization, DeviceFlow, DeviceFlowState, TokenPollResponse};
pub use discovery::OidcDiscovery;
pub use error::{AuthError, AuthResult};
pub use jwks::{Jwk, Jwks};
pub use jwt::{validate_id_token, IdTokenClaims, TokenValidationParams};
pub use middleware::{AuthDecision, AuthMiddleware, AuthMode};
pub use pkce::{AuthorizationRequest, PkceChallenge, PkceVerifier};
pub use rbac::{default_control_plane_policy, Action, RbacPolicy, Role, RoleBinding};
pub use session::{Session, SessionStore, DEFAULT_SESSION_TTL_S};
