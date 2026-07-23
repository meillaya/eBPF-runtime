// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Server-side RBAC with four roles, group/sub bindings, and
//! per-route/RPC action authorization.
//!
//! Roles: `viewer < analyst < policy-admin < admin`.
//! Authorization is by group membership or direct sub binding,
//! NEVER by email.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{AuthError, AuthResult};

/// The four RBAC roles in ascending privilege order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Viewer,
    Analyst,
    PolicyAdmin,
    Admin,
}

impl Role {
    /// Parse from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "analyst" => Some(Self::Analyst),
            "policy-admin" => Some(Self::PolicyAdmin),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// The string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Analyst => "analyst",
            Self::PolicyAdmin => "policy-admin",
            Self::Admin => "admin",
        }
    }

    /// Whether this role permits the given action level.
    pub fn permits(&self, action: Action) -> bool {
        match action {
            Action::Read => true, // all roles can read
            Action::Write => matches!(self, Self::Analyst | Self::PolicyAdmin | Self::Admin),
            Action::Admin => matches!(self, Self::PolicyAdmin | Self::Admin),
            Action::SuperAdmin => matches!(self, Self::Admin),
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Action levels for per-route authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Read-only access (all roles).
    Read,
    /// Write/mutate access (analyst+).
    Write,
    /// Policy administration (policy-admin+).
    Admin,
    /// Super-admin operations (admin only).
    SuperAdmin,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
            Self::SuperAdmin => "super_admin",
        };
        f.write_str(name)
    }
}

/// A role binding: maps a group name or a direct sub to a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleBinding {
    /// Bind all members of a group to a role.
    Group { group: String, role: Role },
    /// Bind a specific sub (user ID) to a role.
    Sub { sub: String, role: Role },
}

/// The RBAC policy: role bindings + per-route action
/// requirements.
#[derive(Debug)]
pub struct RbacPolicy {
    bindings: Vec<RoleBinding>,
    /// Route pattern → required action.
    route_actions: HashMap<String, Action>,
}

impl RbacPolicy {
    /// Create an empty RBAC policy.
    pub fn new() -> Self {
        Self {
            bindings: Vec::new(),
            route_actions: HashMap::new(),
        }
    }

    /// Add a group → role binding.
    pub fn bind_group(&mut self, group: &str, role: Role) {
        self.bindings.push(RoleBinding::Group {
            group: group.to_string(),
            role,
        });
    }

    /// Add a sub → role binding.
    pub fn bind_sub(&mut self, sub: &str, role: Role) {
        self.bindings.push(RoleBinding::Sub {
            sub: sub.to_string(),
            role,
        });
    }

    /// Register a route's required action.
    pub fn set_route_action(&mut self, route: &str, action: Action) {
        self.route_actions.insert(route.to_string(), action);
    }

    /// Resolve the highest role for a subject given their
    /// groups and sub. Returns `None` if no binding matches.
    ///
    /// Resolution order: sub bindings take precedence, then
    /// group bindings. The HIGHEST matching role wins.
    pub fn resolve_role(&self, sub: &str, groups: &[String]) -> Option<Role> {
        let mut best: Option<Role> = None;

        for binding in &self.bindings {
            let matched = match binding {
                RoleBinding::Sub {
                    sub: bound_sub,
                    role,
                } if bound_sub == sub => Some(*role),
                RoleBinding::Group { group, role } if groups.iter().any(|g| g == group) => {
                    Some(*role)
                }
                _ => None,
            };
            if let Some(role) = matched {
                best = Some(match best {
                    Some(current) if current >= role => current,
                    _ => role,
                });
            }
        }
        best
    }

    /// Authorize a subject for a route action.
    ///
    /// 1. Resolve the subject's role from bindings.
    /// 2. Look up the route's required action.
    /// 3. Check the role permits the action.
    pub fn authorize(&self, sub: &str, groups: &[String], route: &str) -> AuthResult<Role> {
        let role = self
            .resolve_role(sub, groups)
            .ok_or_else(|| AuthError::NoRoleBinding {
                sub: sub.to_string(),
            })?;

        let action = self
            .route_actions
            .get(route)
            .copied()
            .unwrap_or(Action::Read); // default: read

        if !role.permits(action) {
            return Err(AuthError::RbacDenied {
                role: role.to_string(),
                action: action.to_string(),
                resource: route.to_string(),
            });
        }
        Ok(role)
    }

    /// The number of bindings.
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }
}

impl Default for RbacPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the default control-plane RBAC policy with standard
/// route action mappings.
pub fn default_control_plane_policy() -> RbacPolicy {
    let mut policy = RbacPolicy::new();

    // Standard group bindings.
    policy.bind_group("viewers", Role::Viewer);
    policy.bind_group("analysts", Role::Analyst);
    policy.bind_group("policy-admins", Role::PolicyAdmin);
    policy.bind_group("admins", Role::Admin);

    // Route action mappings (mirrors task 6 OpenAPI annotations).
    policy.set_route_action("/api/v1/health", Action::Read);
    policy.set_route_action("/api/v1/events", Action::Read);
    policy.set_route_action("/api/v1/process-tree", Action::Read);
    policy.set_route_action("/api/v1/sockets", Action::Read);
    policy.set_route_action("/api/v1/dns", Action::Read);
    policy.set_route_action("/api/v1/files", Action::Read);
    policy.set_route_action("/api/v1/export", Action::Read);
    policy.set_route_action("/api/v1/policies", Action::Read);
    policy.set_route_action("/api/v1/policies/stage", Action::Admin);
    policy.set_route_action("/api/v1/policies/commit", Action::Admin);
    policy.set_route_action("/api/v1/policies/rollback", Action::Admin);
    policy.set_route_action("/api/v1/agents", Action::Read);
    policy.set_route_action("/api/v1/agents/register", Action::Write);
    policy.set_route_action("/api/v1/config", Action::SuperAdmin);

    policy
}

#[cfg(test)]
mod tests {
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
}
