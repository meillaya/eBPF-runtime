// SPDX-License-Identifier: Apache-2.0 OR MIT
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
    let session = mw
        .sessions_mut()
        .create("user-1", Role::Viewer, vec!["viewers".into()], 1000);
    let decision = mw.authorize_route(Some(&session.session_id), "/api/v1/events", 1001);
    assert!(matches!(decision, AuthDecision::Authorized { .. }));
}

#[test]
fn oidc_mode_viewer_denied_write() {
    let mut mw = oidc_middleware();
    let session = mw
        .sessions_mut()
        .create("user-1", Role::Viewer, vec!["viewers".into()], 1000);
    let decision = mw.authorize_route(Some(&session.session_id), "/api/v1/policies/stage", 1001);
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
    let decision = mw.authorize_route(Some(&session.session_id), "/api/v1/policies/stage", 1001);
    assert!(matches!(decision, AuthDecision::Authorized { .. }));
}

#[test]
fn oidc_mode_expired_session_denied() {
    let mut mw = oidc_middleware();
    let session = mw
        .sessions_mut()
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
    let session = mw
        .sessions_mut()
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
    let session = mw
        .sessions_mut()
        .create("user-1", Role::Viewer, vec!["viewers".into()], 1000);
    mw.authorize_route(Some(&session.session_id), "/api/v1/events", 1001);
    assert!(mw.audit().intents().is_empty());
}
