// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use auth::default_control_plane_policy;

fn test_rbac() -> RbacPolicy {
    default_control_plane_policy()
}

fn test_audit() -> AuditHook {
    AuditHook::new()
}

fn cluster_id() -> Uuid {
    Uuid::new_v4()
}

// -- Route lookup --

#[test]
fn lookup_exact_route() {
    let route = lookup_route("GET", "/api/v1/health").unwrap();
    assert_eq!(route.action, Action::Read);
    assert!(!route.is_mutation);
}

#[test]
fn lookup_parameterized_route() {
    let route = lookup_route("GET", "/api/v1/agents/some-uuid").unwrap();
    assert_eq!(route.path, "/api/v1/agents/{id}");
    assert_eq!(route.action, Action::Read);
}

#[test]
fn lookup_mutation_route() {
    let route = lookup_route("POST", "/api/v1/policies/stage").unwrap();
    assert_eq!(route.action, Action::Admin);
    assert!(route.is_mutation);
}

#[test]
fn lookup_unknown_route_defaults_to_read() {
    let route = lookup_route("GET", "/api/v1/unknown");
    assert!(route.is_none());
}

// -- RBAC authorization --

#[test]
fn viewer_can_read() {
    let rbac = test_rbac();
    let audit = test_audit();
    let ctx = authorize_request(
        &rbac,
        &audit,
        "u1",
        &["viewers".into()],
        "GET",
        "/api/v1/events",
        cluster_id(),
    );
    assert!(ctx.is_ok());
    assert_eq!(ctx.unwrap().role, Role::Viewer);
}

#[test]
fn viewer_cannot_mutate() {
    let rbac = test_rbac();
    let audit = test_audit();
    let result = authorize_request(
        &rbac,
        &audit,
        "u1",
        &["viewers".into()],
        "POST",
        "/api/v1/policies/stage",
        cluster_id(),
    );
    assert!(matches!(
        result.unwrap_err(),
        ControlPlaneError::AccessDenied(_) | ControlPlaneError::ViewerMutationDenied { .. }
    ));
}

#[test]
fn analyst_can_write_but_not_admin() {
    let rbac = test_rbac();
    let audit = test_audit();

    // Analyst can register agents (Write).
    let ctx = authorize_request(
        &rbac,
        &audit,
        "u1",
        &["analysts".into()],
        "POST",
        "/api/v1/agents/register",
        cluster_id(),
    );
    assert!(ctx.is_ok());

    // Analyst cannot stage policies (Admin).
    let result = authorize_request(
        &rbac,
        &audit,
        "u1",
        &["analysts".into()],
        "POST",
        "/api/v1/policies/stage",
        cluster_id(),
    );
    assert!(result.is_err());
}

#[test]
fn policy_admin_can_admin_but_not_super() {
    let rbac = test_rbac();
    let audit = test_audit();

    // Policy admin can stage policies.
    let ctx = authorize_request(
        &rbac,
        &audit,
        "u1",
        &["policy-admins".into()],
        "POST",
        "/api/v1/policies/stage",
        cluster_id(),
    );
    assert!(ctx.is_ok());

    // Policy admin cannot access config (SuperAdmin).
    let result = authorize_request(
        &rbac,
        &audit,
        "u1",
        &["policy-admins".into()],
        "PUT",
        "/api/v1/config",
        cluster_id(),
    );
    assert!(result.is_err());
}

#[test]
fn admin_can_do_everything() {
    let rbac = test_rbac();
    let audit = test_audit();

    let ctx = authorize_request(
        &rbac,
        &audit,
        "u1",
        &["admins".into()],
        "PUT",
        "/api/v1/config",
        cluster_id(),
    );
    assert!(ctx.is_ok());
    assert_eq!(ctx.unwrap().role, Role::Admin);
}

#[test]
fn no_binding_rejected() {
    let rbac = test_rbac();
    let audit = test_audit();
    let result = authorize_request(
        &rbac,
        &audit,
        "u1",
        &["unknown-group".into()],
        "GET",
        "/api/v1/events",
        cluster_id(),
    );
    assert!(matches!(
        result.unwrap_err(),
        ControlPlaneError::NoRoleBinding
    ));
}

// -- RBAC negative matrix --

#[test]
fn negative_matrix_viewer_denied_all_mutations() {
    let rbac = test_rbac();
    let audit = test_audit();
    let cid = cluster_id();

    let mutations = [
        ("POST", "/api/v1/policies/stage"),
        ("POST", "/api/v1/policies/commit"),
        ("POST", "/api/v1/policies/rollback"),
        ("POST", "/api/v1/agents/register"),
        ("PUT", "/api/v1/config"),
    ];

    for (method, path) in &mutations {
        let result = authorize_request(
            &rbac,
            &audit,
            "viewer-1",
            &["viewers".into()],
            method,
            path,
            cid,
        );
        assert!(result.is_err(), "viewer should be denied {method} {path}");
    }
}

#[test]
fn negative_matrix_analyst_denied_admin_routes() {
    let rbac = test_rbac();
    let audit = test_audit();
    let cid = cluster_id();

    let admin_routes = [
        ("POST", "/api/v1/policies/stage"),
        ("POST", "/api/v1/policies/commit"),
        ("POST", "/api/v1/policies/rollback"),
        ("PUT", "/api/v1/config"),
    ];

    for (method, path) in &admin_routes {
        let result = authorize_request(
            &rbac,
            &audit,
            "analyst-1",
            &["analysts".into()],
            method,
            path,
            cid,
        );
        assert!(result.is_err(), "analyst should be denied {method} {path}");
    }
}

#[test]
fn negative_matrix_policy_admin_denied_super_admin() {
    let rbac = test_rbac();
    let audit = test_audit();
    let cid = cluster_id();

    let result = authorize_request(
        &rbac,
        &audit,
        "pa-1",
        &["policy-admins".into()],
        "PUT",
        "/api/v1/config",
        cid,
    );
    assert!(result.is_err());
}

// -- Audit emission --

#[test]
fn mutation_emits_audit() {
    let rbac = test_rbac();
    let audit = test_audit();

    authorize_request(
        &rbac,
        &audit,
        "admin-1",
        &["admins".into()],
        "POST",
        "/api/v1/policies/stage",
        cluster_id(),
    )
    .unwrap();

    assert_eq!(audit.count(), 1);
    assert!(audit.has_actor("admin-1"));
}

#[test]
fn denied_mutation_emits_audit() {
    let rbac = test_rbac();
    let audit = test_audit();

    let _ = authorize_request(
        &rbac,
        &audit,
        "viewer-1",
        &["viewers".into()],
        "POST",
        "/api/v1/policies/stage",
        cluster_id(),
    );

    assert_eq!(audit.count(), 1);
    let intents = audit.intents();
    assert!(intents[0].action.starts_with("denied:"));
}

#[test]
fn read_does_not_emit_audit() {
    let rbac = test_rbac();
    let audit = test_audit();

    authorize_request(
        &rbac,
        &audit,
        "viewer-1",
        &["viewers".into()],
        "GET",
        "/api/v1/events",
        cluster_id(),
    )
    .unwrap();

    assert_eq!(audit.count(), 0);
}

// -- Cluster scope --

#[test]
fn cluster_scope_from_explicit() {
    let cid = Uuid::new_v4();
    let resolved = resolve_cluster_scope(Some(cid), None).unwrap();
    assert_eq!(resolved, cid);
}

#[test]
fn cluster_scope_from_default() {
    let cid = Uuid::new_v4();
    let resolved = resolve_cluster_scope(None, Some(cid)).unwrap();
    assert_eq!(resolved, cid);
}

#[test]
fn cluster_scope_missing() {
    let result = resolve_cluster_scope(None, None);
    assert!(matches!(
        result.unwrap_err(),
        ControlPlaneError::MissingClusterScope
    ));
}

#[test]
fn explicit_overrides_default() {
    let explicit = Uuid::new_v4();
    let default = Uuid::new_v4();
    let resolved = resolve_cluster_scope(Some(explicit), Some(default)).unwrap();
    assert_eq!(resolved, explicit);
}

// -- Path matching --

#[test]
fn path_pattern_matches() {
    assert!(path_matches_pattern(
        "/api/v1/agents/{id}",
        "/api/v1/agents/abc-123"
    ));
    assert!(!path_matches_pattern(
        "/api/v1/agents/{id}",
        "/api/v1/agents"
    ));
    assert!(!path_matches_pattern(
        "/api/v1/agents/{id}",
        "/api/v1/agents/abc/extra"
    ));
}
