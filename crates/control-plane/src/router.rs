// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Route dispatch with OIDC/RBAC middleware, cluster scope
//! extraction, and viewer read-only guard.
//!
//! The router maps HTTP method + path to a route action,
//! enforces RBAC via the auth crate's [`RbacPolicy`], extracts
//! the cluster scope from the request, and guards viewer roles
//! from mutations.
//!
//! # Stateless JWT auth
//!
//! The control-plane uses stateless JWT-based auth. The
//! [`RequestContext`] carries the authenticated subject, groups,
//! resolved role, and cluster scope. No server-side session is
//! created.

#![forbid(unsafe_code)]

use auth::{Action, RbacPolicy, Role};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit::AuditHook;
use crate::error::{ControlPlaneError, Result};

/// The authenticated request context (stateless).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    /// The OIDC subject (user identity).
    pub sub: String,
    /// The groups the subject belongs to.
    pub groups: Vec<String>,
    /// The resolved RBAC role.
    pub role: Role,
    /// The cluster scope for this request.
    pub cluster_id: Uuid,
}

/// A route definition with its required action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDef {
    /// HTTP method (GET, POST, PUT, DELETE).
    pub method: &'static str,
    /// Route path pattern.
    pub path: &'static str,
    /// The required RBAC action.
    pub action: Action,
    /// Whether this route mutates state.
    pub is_mutation: bool,
}

/// The control-plane route table.
/// Mirrors the task 6 OpenAPI action annotations.
pub const ROUTE_TABLE: &[RouteDef] = &[
    // Health (unauthenticated).
    RouteDef {
        method: "GET",
        path: "/api/v1/health",
        action: Action::Read,
        is_mutation: false,
    },
    RouteDef {
        method: "GET",
        path: "/api/v1/compatibility",
        action: Action::Read,
        is_mutation: false,
    },
    // Agent inventory (read-only through API).
    RouteDef {
        method: "GET",
        path: "/api/v1/agents",
        action: Action::Read,
        is_mutation: false,
    },
    RouteDef {
        method: "GET",
        path: "/api/v1/agents/{id}",
        action: Action::Read,
        is_mutation: false,
    },
    // Historical event queries.
    RouteDef {
        method: "GET",
        path: "/api/v1/events",
        action: Action::Read,
        is_mutation: false,
    },
    RouteDef {
        method: "GET",
        path: "/api/v1/events/{id}",
        action: Action::Read,
        is_mutation: false,
    },
    // Control queries.
    RouteDef {
        method: "GET",
        path: "/api/v1/clusters/{id}",
        action: Action::Read,
        is_mutation: false,
    },
    RouteDef {
        method: "GET",
        path: "/api/v1/nodes/{id}",
        action: Action::Read,
        is_mutation: false,
    },
    RouteDef {
        method: "GET",
        path: "/api/v1/policies",
        action: Action::Read,
        is_mutation: false,
    },
    RouteDef {
        method: "GET",
        path: "/api/v1/policies/{id}",
        action: Action::Read,
        is_mutation: false,
    },
    RouteDef {
        method: "GET",
        path: "/api/v1/rollouts/{id}",
        action: Action::Read,
        is_mutation: false,
    },
    // Policy mutations (Admin only).
    RouteDef {
        method: "POST",
        path: "/api/v1/policies/stage",
        action: Action::Admin,
        is_mutation: true,
    },
    RouteDef {
        method: "POST",
        path: "/api/v1/policies/commit",
        action: Action::Admin,
        is_mutation: true,
    },
    RouteDef {
        method: "POST",
        path: "/api/v1/policies/rollback",
        action: Action::Admin,
        is_mutation: true,
    },
    // Agent registration (Write).
    RouteDef {
        method: "POST",
        path: "/api/v1/agents/register",
        action: Action::Write,
        is_mutation: true,
    },
    // Config (SuperAdmin).
    RouteDef {
        method: "GET",
        path: "/api/v1/config",
        action: Action::SuperAdmin,
        is_mutation: false,
    },
    RouteDef {
        method: "PUT",
        path: "/api/v1/config",
        action: Action::SuperAdmin,
        is_mutation: true,
    },
    // Live stream (WebSocket upgrade).
    RouteDef {
        method: "GET",
        path: "/api/v1/live",
        action: Action::Read,
        is_mutation: false,
    },
    // Static UI.
    RouteDef {
        method: "GET",
        path: "/",
        action: Action::Read,
        is_mutation: false,
    },
    RouteDef {
        method: "GET",
        path: "/static/{path}",
        action: Action::Read,
        is_mutation: false,
    },
];

/// Look up a route definition by method and path.
pub fn lookup_route(method: &str, path: &str) -> Option<&'static RouteDef> {
    ROUTE_TABLE
        .iter()
        .find(|r| r.method == method && (r.path == path || path_matches_pattern(r.path, path)))
}

/// Simple path pattern matching (supports `{param}` segments).
fn path_matches_pattern(pattern: &str, path: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();

    if pattern_parts.len() != path_parts.len() {
        return false;
    }

    pattern_parts
        .iter()
        .zip(path_parts.iter())
        .all(|(p, s)| p.starts_with('{') && p.ends_with('}') || p == s)
}

/// Authenticate and authorize a request.
///
/// 1. Resolve the role from the RBAC policy using sub + groups.
/// 2. Look up the route's required action.
/// 3. Check the role permits the action.
/// 4. Guard viewer roles from mutations.
/// 5. Emit audit intent for denied mutations.
pub fn authorize_request(
    rbac: &RbacPolicy,
    audit: &AuditHook,
    sub: &str,
    groups: &[String],
    method: &str,
    path: &str,
    cluster_id: Uuid,
) -> Result<RequestContext> {
    // Resolve role.
    let role = rbac
        .resolve_role(sub, groups)
        .ok_or(ControlPlaneError::NoRoleBinding)?;

    // Look up route action.
    let route_def = lookup_route(method, path);
    let required_action = route_def.map(|r| r.action).unwrap_or(Action::Read);
    let is_mutation = route_def.map(|r| r.is_mutation).unwrap_or(false);

    // Check role permits action.
    if !role.permits(required_action) {
        // Emit audit for denied mutations.
        if is_mutation {
            audit.record_denied(
                sub,
                &required_action.to_string(),
                path,
                &format!("role {} denied", role.as_str()),
            );
        }
        return Err(ControlPlaneError::AccessDenied(format!(
            "role {} denied action {} on {}",
            role.as_str(),
            required_action,
            path
        )));
    }

    // Viewer read-only guard: viewers cannot access mutation
    // routes even if the action check passes (defense in depth).
    if role == Role::Viewer && is_mutation {
        audit.record_denied(sub, &required_action.to_string(), path, "viewer read-only");
        return Err(ControlPlaneError::ViewerMutationDenied {
            route: path.to_string(),
        });
    }

    // Emit audit for successful mutations.
    if is_mutation {
        audit.record_mutation(sub, &required_action.to_string(), path);
    }

    Ok(RequestContext {
        sub: sub.to_string(),
        groups: groups.to_vec(),
        role,
        cluster_id,
    })
}

/// Extract and validate the cluster scope from a request.
///
/// The cluster scope is mandatory for all data queries.
/// If a default cluster is configured, it is used when no
/// explicit scope is provided.
pub fn resolve_cluster_scope(
    explicit_cluster: Option<Uuid>,
    default_cluster: Option<Uuid>,
) -> Result<Uuid> {
    explicit_cluster
        .or(default_cluster)
        .ok_or(ControlPlaneError::MissingClusterScope)
}

#[cfg(test)]
mod tests {
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
}
