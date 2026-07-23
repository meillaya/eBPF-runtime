// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Control-plane authentication middleware.
//!
//! Per-route authorization with loopback-only dev bypass.
//! A no-auth bind to a non-loopback address is REFUSED.

#![forbid(unsafe_code)]

use std::net::IpAddr;

use crate::audit::{AuditIntent, AuditSink};
use crate::error::{AuthError, AuthResult};
use crate::rbac::{Action, RbacPolicy, Role};
use crate::session::SessionStore;

/// The authentication mode for the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Full OIDC authentication required.
    Oidc,
    /// Development bypass: no auth required, but ONLY on
    /// loopback addresses (127.0.0.1 / ::1).
    DevBypass,
}

/// The result of a middleware authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// The request is authorized with the given role.
    Authorized { sub: String, role: Role },
    /// The request is authorized via dev bypass (loopback
    /// only).
    DevBypassed,
    /// The request is denied.
    Denied(AuthError),
}

/// Control-plane authentication middleware.
#[derive(Debug)]
pub struct AuthMiddleware {
    mode: AuthMode,
    rbac: RbacPolicy,
    sessions: SessionStore,
    audit: AuditSink,
}

impl AuthMiddleware {
    /// Create middleware in OIDC mode.
    pub fn oidc(rbac: RbacPolicy, sessions: SessionStore) -> Self {
        Self {
            mode: AuthMode::Oidc,
            rbac,
            sessions,
            audit: AuditSink::new(),
        }
    }

    /// Create middleware in dev-bypass mode. The bind address
    /// MUST be loopback.
    pub fn dev_bypass(
        bind_addr: IpAddr,
        rbac: RbacPolicy,
        sessions: SessionStore,
    ) -> AuthResult<Self> {
        if !bind_addr.is_loopback() {
            return Err(AuthError::NonLoopbackBindRefused {
                addr: bind_addr.to_string(),
            });
        }
        Ok(Self {
            mode: AuthMode::DevBypass,
            rbac,
            sessions,
            audit: AuditSink::new(),
        })
    }

    /// The current auth mode.
    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    /// Access the audit sink.
    pub fn audit(&self) -> &AuditSink {
        &self.audit
    }

    /// Mutable access to the session store.
    pub fn sessions_mut(&mut self) -> &mut SessionStore {
        &mut self.sessions
    }

    /// Authorize a request for a route.
    ///
    /// In OIDC mode: validates the session, resolves the role,
    /// checks the route action. In dev-bypass mode: allows all
    /// requests (loopback-only by construction).
    pub fn authorize_route(
        &mut self,
        session_id: Option<&str>,
        route: &str,
        now_epoch_s: u64,
    ) -> AuthDecision {
        match self.mode {
            AuthMode::DevBypass => AuthDecision::DevBypassed,
            AuthMode::Oidc => {
                let sid = match session_id {
                    Some(s) => s,
                    None => {
                        return AuthDecision::Denied(AuthError::SessionNotFound {
                            session_id: "<none>".into(),
                        });
                    }
                };
                let session = match self.sessions.validate(sid, now_epoch_s) {
                    Ok(s) => s.clone(),
                    Err(e) => return AuthDecision::Denied(e),
                };
                match self.rbac.authorize(&session.sub, &session.groups, route) {
                    Ok(role) => {
                        // Emit audit intent for mutations.
                        let action = self
                            .rbac
                            .authorize(&session.sub, &session.groups, route)
                            .ok();
                        if let Some(_role) = action {
                            let route_action = self.route_action(route);
                            if route_action != Action::Read {
                                self.audit.record(AuditIntent::new(
                                    &session.sub,
                                    &route_action.to_string(),
                                    route,
                                ));
                            }
                        }
                        AuthDecision::Authorized {
                            sub: session.sub.clone(),
                            role,
                        }
                    }
                    Err(e) => AuthDecision::Denied(e),
                }
            }
        }
    }

    /// Look up the action required for a route.
    fn route_action(&self, route: &str) -> Action {
        // Try the RBAC policy's route actions via a read-check
        // probe. Default to Read if unknown.
        // We access the internal route_actions through authorize
        // behavior: if a viewer can access it, it's Read.
        // For a clean lookup, we re-derive from the policy.
        self.rbac_route_action(route)
    }

    /// Internal route action lookup.
    fn rbac_route_action(&self, _route: &str) -> Action {
        // The RbacPolicy stores route_actions privately.
        // We use a convention: the middleware checks via
        // authorize(). For audit, we classify by route pattern.
        if _route.contains("stage") || _route.contains("commit") || _route.contains("rollback") {
            Action::Admin
        } else if _route.contains("config") {
            Action::SuperAdmin
        } else if _route.contains("register") {
            Action::Write
        } else {
            Action::Read
        }
    }
}

/// Validate that a bind address is loopback. Returns an error
/// for non-loopback addresses.
pub fn validate_loopback_bind(addr: IpAddr) -> AuthResult<()> {
    if addr.is_loopback() {
        Ok(())
    } else {
        Err(AuthError::NonLoopbackBindRefused {
            addr: addr.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::default_control_plane_policy;

    fn oidc_middleware() -> AuthMiddleware {
        AuthMiddleware::oidc(default_control_plane_policy(), SessionStore::new(900))
    }

    // -- Loopback bind validation --

    #[test]
    fn loopback_v4_accepted() {
        assert!(validate_loopback_bind("127.0.0.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn loopback_v6_accepted() {
        assert!(validate_loopback_bind("::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn non_loopback_v4_refused() {
        let err = validate_loopback_bind("0.0.0.0".parse().unwrap()).unwrap_err();
        assert!(matches!(err, AuthError::NonLoopbackBindRefused { .. }));
    }

    #[test]
    fn non_loopback_public_refused() {
        let err = validate_loopback_bind("10.0.0.1".parse().unwrap()).unwrap_err();
        assert!(matches!(err, AuthError::NonLoopbackBindRefused { .. }));
    }

    #[test]
    fn non_loopback_v6_refused() {
        let err = validate_loopback_bind("::".parse().unwrap()).unwrap_err();
        assert!(matches!(err, AuthError::NonLoopbackBindRefused { .. }));
    }

    // -- Dev bypass mode --

    #[test]
    fn dev_bypass_on_loopback_ok() {
        let mw = AuthMiddleware::dev_bypass(
            "127.0.0.1".parse().unwrap(),
            default_control_plane_policy(),
            SessionStore::new(900),
        );
        assert!(mw.is_ok());
        assert_eq!(mw.unwrap().mode(), AuthMode::DevBypass);
    }

    #[test]
    fn dev_bypass_on_non_loopback_refused() {
        let err = AuthMiddleware::dev_bypass(
            "0.0.0.0".parse().unwrap(),
            default_control_plane_policy(),
            SessionStore::new(900),
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::NonLoopbackBindRefused { .. }));
    }

    #[test]
    fn dev_bypass_allows_all_routes() {
        let mut mw = AuthMiddleware::dev_bypass(
            "127.0.0.1".parse().unwrap(),
            default_control_plane_policy(),
            SessionStore::new(900),
        )
        .unwrap();
        let decision = mw.authorize_route(None, "/api/v1/config", 1000);
        assert_eq!(decision, AuthDecision::DevBypassed);
    }

    // -- OIDC mode --

    #[test]
    fn oidc_mode_requires_session() {
        let mut mw = oidc_middleware();
        let decision = mw.authorize_route(None, "/api/v1/events", 1000);
        assert!(matches!(
            decision,
            AuthDecision::Denied(AuthError::SessionNotFound { .. })
        ));
    }

    #[test]
    fn oidc_mode_valid_session_authorized() {
        let mut mw = oidc_middleware();
        let session =
            mw.sessions_mut()
                .create("user-1", Role::Viewer, vec!["viewers".into()], 1000);
        let decision = mw.authorize_route(Some(&session.session_id), "/api/v1/events", 1001);
        assert!(matches!(decision, AuthDecision::Authorized { .. }));
    }

    #[test]
    fn oidc_mode_viewer_denied_write() {
        let mut mw = oidc_middleware();
        let session =
            mw.sessions_mut()
                .create("user-1", Role::Viewer, vec!["viewers".into()], 1000);
        let decision =
            mw.authorize_route(Some(&session.session_id), "/api/v1/policies/stage", 1001);
        assert!(matches!(
            decision,
            AuthDecision::Denied(AuthError::RbacDenied { .. })
        ));
    }

    #[test]
    fn oidc_mode_policy_admin_stages_policy() {
        let mut mw = oidc_middleware();
        let session = mw.sessions_mut().create(
            "admin-1",
            Role::PolicyAdmin,
            vec!["policy-admins".into()],
            1000,
        );
        let decision =
            mw.authorize_route(Some(&session.session_id), "/api/v1/policies/stage", 1001);
        assert!(matches!(decision, AuthDecision::Authorized { .. }));
    }

    #[test]
    fn oidc_mode_expired_session_denied() {
        let mut mw = oidc_middleware();
        let session =
            mw.sessions_mut()
                .create("user-1", Role::Viewer, vec!["viewers".into()], 1000);
        let decision = mw.authorize_route(Some(&session.session_id), "/api/v1/events", 2000);
        assert!(matches!(
            decision,
            AuthDecision::Denied(AuthError::SessionExpired)
        ));
    }

    #[test]
    fn oidc_mode_revoked_session_denied() {
        let mut mw = oidc_middleware();
        let session =
            mw.sessions_mut()
                .create("user-1", Role::Viewer, vec!["viewers".into()], 1000);
        mw.sessions_mut().revoke(&session.session_id).unwrap();
        let decision = mw.authorize_route(Some(&session.session_id), "/api/v1/events", 1001);
        assert!(matches!(
            decision,
            AuthDecision::Denied(AuthError::SessionRevoked)
        ));
    }

    // -- Audit intent on mutation --

    #[test]
    fn mutation_emits_audit_intent() {
        let mut mw = oidc_middleware();
        let session = mw.sessions_mut().create(
            "admin-1",
            Role::PolicyAdmin,
            vec!["policy-admins".into()],
            1000,
        );
        mw.authorize_route(Some(&session.session_id), "/api/v1/policies/stage", 1001);
        let intents = mw.audit().intents();
        assert!(!intents.is_empty());
        assert_eq!(intents[0].actor, "admin-1");
        assert!(intents[0].resource.contains("stage"));
    }

    #[test]
    fn read_does_not_emit_audit_intent() {
        let mut mw = oidc_middleware();
        let session =
            mw.sessions_mut()
                .create("user-1", Role::Viewer, vec!["viewers".into()], 1000);
        mw.authorize_route(Some(&session.session_id), "/api/v1/events", 1001);
        assert!(mw.audit().intents().is_empty());
    }
}
