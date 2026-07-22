// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn test_policy() -> RbacPolicy {
    default_control_plane_policy()
}

// -- Role ordering --

#[test]
fn role_ordering() {
    assert!(Role::Viewer < Role::Analyst);
    assert!(Role::Analyst < Role::PolicyAdmin);
    assert!(Role::PolicyAdmin < Role::Admin);
}

#[test]
fn role_parse_round_trip() {
    for role in [Role::Viewer, Role::Analyst, Role::PolicyAdmin, Role::Admin] {
        assert_eq!(Role::parse(role.as_str()), Some(role));
    }
    assert_eq!(Role::parse("superuser"), None);
}

// -- Action permission matrix --

#[test]
fn viewer_can_only_read() {
    assert!(Role::Viewer.permits(Action::Read));
    assert!(!Role::Viewer.permits(Action::Write));
    assert!(!Role::Viewer.permits(Action::Admin));
    assert!(!Role::Viewer.permits(Action::SuperAdmin));
}

#[test]
fn analyst_can_read_and_write() {
    assert!(Role::Analyst.permits(Action::Read));
    assert!(Role::Analyst.permits(Action::Write));
    assert!(!Role::Analyst.permits(Action::Admin));
    assert!(!Role::Analyst.permits(Action::SuperAdmin));
}

#[test]
fn policy_admin_can_read_write_admin() {
    assert!(Role::PolicyAdmin.permits(Action::Read));
    assert!(Role::PolicyAdmin.permits(Action::Write));
    assert!(Role::PolicyAdmin.permits(Action::Admin));
    assert!(!Role::PolicyAdmin.permits(Action::SuperAdmin));
}

#[test]
fn admin_can_do_everything() {
    assert!(Role::Admin.permits(Action::Read));
    assert!(Role::Admin.permits(Action::Write));
    assert!(Role::Admin.permits(Action::Admin));
    assert!(Role::Admin.permits(Action::SuperAdmin));
}

// -- Negative matrix: every role × every denied action --

#[test]
fn negative_matrix_viewer_denied_write() {
    let policy = test_policy();
    let err = policy
        .authorize("u1", &["viewers".into()], "/api/v1/policies/stage")
        .unwrap_err();
    assert!(matches!(err, AuthError::RbacDenied { .. }));
}

#[test]
fn negative_matrix_viewer_denied_admin() {
    let policy = test_policy();
    let err = policy
        .authorize("u1", &["viewers".into()], "/api/v1/policies/commit")
        .unwrap_err();
    assert!(matches!(err, AuthError::RbacDenied { .. }));
}

#[test]
fn negative_matrix_analyst_denied_admin() {
    let policy = test_policy();
    let err = policy
        .authorize("u1", &["analysts".into()], "/api/v1/policies/stage")
        .unwrap_err();
    assert!(matches!(err, AuthError::RbacDenied { .. }));
}

#[test]
fn negative_matrix_policy_admin_denied_super_admin() {
    let policy = test_policy();
    let err = policy
        .authorize("u1", &["policy-admins".into()], "/api/v1/config")
        .unwrap_err();
    assert!(matches!(err, AuthError::RbacDenied { .. }));
}

#[test]
fn negative_matrix_no_binding_rejected() {
    let policy = test_policy();
    let err = policy
        .authorize("u1", &["unknown-group".into()], "/api/v1/events")
        .unwrap_err();
    assert!(matches!(err, AuthError::NoRoleBinding { .. }));
}

// -- Positive matrix --

#[test]
fn positive_viewer_reads_events() {
    let policy = test_policy();
    let role = policy
        .authorize("u1", &["viewers".into()], "/api/v1/events")
        .unwrap();
    assert_eq!(role, Role::Viewer);
}

#[test]
fn positive_analyst_writes_agent_register() {
    let policy = test_policy();
    let role = policy
        .authorize("u1", &["analysts".into()], "/api/v1/agents/register")
        .unwrap();
    assert_eq!(role, Role::Analyst);
}

#[test]
fn positive_policy_admin_stages_policy() {
    let policy = test_policy();
    let role = policy
        .authorize("u1", &["policy-admins".into()], "/api/v1/policies/stage")
        .unwrap();
    assert_eq!(role, Role::PolicyAdmin);
}

#[test]
fn positive_admin_accesses_config() {
    let policy = test_policy();
    let role = policy
        .authorize("u1", &["admins".into()], "/api/v1/config")
        .unwrap();
    assert_eq!(role, Role::Admin);
}

// -- Sub binding --

#[test]
fn sub_binding_overrides_group() {
    let mut policy = RbacPolicy::new();
    policy.bind_group("viewers", Role::Viewer);
    policy.bind_sub("special-user", Role::Admin);
    policy.set_route_action("/api/v1/config", Action::SuperAdmin);

    let role = policy
        .resolve_role("special-user", &["viewers".into()])
        .unwrap();
    assert_eq!(role, Role::Admin);
}

#[test]
fn highest_role_wins_from_multiple_groups() {
    let policy = test_policy();
    let role = policy
        .resolve_role("u1", &["viewers".into(), "admins".into()])
        .unwrap();
    assert_eq!(role, Role::Admin);
}

// -- Email is NOT used for authorization --

#[test]
fn email_not_used_for_authorization() {
    // The RBAC policy has no email-based bindings.
    // Authorization is purely group/sub based.
    let policy = test_policy();
    // A user with an email but no group binding is denied.
    let err = policy
        .authorize("user@example.com", &[], "/api/v1/events")
        .unwrap_err();
    assert!(matches!(err, AuthError::NoRoleBinding { .. }));
}
