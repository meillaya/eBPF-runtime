// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Typed error variants for every control-plane API failure.
//!
//! No free strings for error classification. Every failure maps
//! to a typed variant that the router translates to an HTTP
//! status code.

#![forbid(unsafe_code)]

use auth::AuthError;

/// Result alias for control-plane operations.
pub type Result<T> = std::result::Result<T, ControlPlaneError>;

/// Every control-plane API failure as a typed variant.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ControlPlaneError {
    // -- Authentication / Authorization --
    /// The request is missing a Bearer token.
    #[error("missing authorization token")]
    MissingToken,

    /// The Bearer token is malformed or invalid.
    #[error("invalid token: {reason}")]
    InvalidToken { reason: String },

    /// RBAC denied the request.
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// The actor has no role binding.
    #[error("no role binding for subject")]
    NoRoleBinding,

    /// Viewer attempted a mutation (read-only guard).
    #[error("viewer role is read-only; mutation denied on {route}")]
    ViewerMutationDenied { route: String },

    // -- Cluster scoping --
    /// The request is missing a cluster scope.
    #[error("missing cluster scope")]
    MissingClusterScope,

    /// Cross-cluster access was denied.
    #[error("cross-cluster access denied: context={context}, target={target}")]
    CrossClusterDenied { context: String, target: String },

    // -- Pagination / query bounds --
    /// The requested page size exceeds the maximum.
    #[error("page size {requested} exceeds maximum {max}")]
    PageSizeExceeded { requested: usize, max: usize },

    /// The requested time window exceeds the maximum.
    #[error("time window {requested_s}s exceeds maximum {max_s}s")]
    WindowExceeded { requested_s: u64, max_s: u64 },

    /// The cursor is invalid or expired.
    #[error("invalid cursor: {reason}")]
    InvalidCursor { reason: String },

    // -- Query errors --
    /// A PostgreSQL control query failed.
    #[error("control query failed: {0}")]
    ControlQuery(String),

    /// A ClickHouse historical query failed.
    #[error("history query failed: {0}")]
    HistoryQuery(String),

    /// The requested resource was not found.
    #[error("not found: {resource}")]
    NotFound { resource: String },

    // -- Live stream --
    /// The live subscriber buffer is full; client is shed.
    #[error("slow client shed: buffer full (cap={cap})")]
    SlowClientShed { cap: usize },

    /// The live stream cursor is outside the retained window.
    #[error("live cursor expired: requested seq {requested}, oldest retained {oldest}")]
    LiveCursorExpired { requested: u64, oldest: u64 },

    /// The cluster has no active live stream.
    #[error("no live stream for cluster {cluster}")]
    NoLiveStream { cluster: String },

    // -- Redaction --
    /// Redaction failed (fail-closed: the event is withheld).
    #[error("redaction failed: {0}")]
    RedactionFailed(String),

    // -- Static UI --
    /// The requested UI path is not found.
    #[error("ui asset not found: {path}")]
    UiNotFound { path: String },

    /// Path traversal was detected and blocked.
    #[error("path traversal blocked: {path}")]
    PathTraversal { path: String },

    // -- Internal --
    /// An unexpected internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ControlPlaneError {
    /// The HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::MissingToken | Self::InvalidToken { .. } => 401,
            Self::AccessDenied(_) | Self::NoRoleBinding | Self::ViewerMutationDenied { .. } => 403,
            Self::MissingClusterScope | Self::CrossClusterDenied { .. } => 400,
            Self::PageSizeExceeded { .. }
            | Self::WindowExceeded { .. }
            | Self::InvalidCursor { .. } => 400,
            Self::ControlQuery(_) | Self::HistoryQuery(_) => 500,
            Self::NotFound { .. } => 404,
            Self::SlowClientShed { .. } => 429,
            Self::LiveCursorExpired { .. } => 410,
            Self::NoLiveStream { .. } => 404,
            Self::RedactionFailed(_) => 500,
            Self::UiNotFound { .. } => 404,
            Self::PathTraversal { .. } => 400,
            Self::Internal(_) => 500,
        }
    }
}

impl From<AuthError> for ControlPlaneError {
    fn from(e: AuthError) -> Self {
        match &e {
            AuthError::RbacDenied {
                role,
                action,
                resource,
            } => ControlPlaneError::AccessDenied(format!(
                "role {role} denied action {action} on {resource}"
            )),
            AuthError::NoRoleBinding { .. } => ControlPlaneError::NoRoleBinding,
            _ => ControlPlaneError::AccessDenied(e.to_string()),
        }
    }
}

impl From<control_db::ControlDbError> for ControlPlaneError {
    fn from(e: control_db::ControlDbError) -> Self {
        match &e {
            control_db::ControlDbError::NotFound { table, key } => ControlPlaneError::NotFound {
                resource: format!("{table}:{key}"),
            },
            control_db::ControlDbError::RlsDenied { reason } => {
                ControlPlaneError::CrossClusterDenied {
                    context: "rls".to_string(),
                    target: reason.clone(),
                }
            }
            _ => ControlPlaneError::ControlQuery(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_are_correct() {
        assert_eq!(ControlPlaneError::MissingToken.status_code(), 401);
        assert_eq!(
            ControlPlaneError::AccessDenied("x".into()).status_code(),
            403
        );
        assert_eq!(
            ControlPlaneError::ViewerMutationDenied {
                route: "/api/v1/policies/stage".into()
            }
            .status_code(),
            403
        );
        assert_eq!(ControlPlaneError::MissingClusterScope.status_code(), 400);
        assert_eq!(
            ControlPlaneError::PageSizeExceeded {
                requested: 1000,
                max: 100
            }
            .status_code(),
            400
        );
        assert_eq!(
            ControlPlaneError::NotFound {
                resource: "agent:123".into()
            }
            .status_code(),
            404
        );
        assert_eq!(
            ControlPlaneError::SlowClientShed { cap: 64 }.status_code(),
            429
        );
        assert_eq!(
            ControlPlaneError::LiveCursorExpired {
                requested: 1,
                oldest: 100
            }
            .status_code(),
            410
        );
        assert_eq!(
            ControlPlaneError::PathTraversal {
                path: "../etc/passwd".into()
            }
            .status_code(),
            400
        );
    }

    #[test]
    fn auth_error_converts_to_access_denied() {
        let auth_err = AuthError::RbacDenied {
            role: "viewer".into(),
            action: "admin".into(),
            resource: "/api/v1/config".into(),
        };
        let cp_err: ControlPlaneError = auth_err.into();
        assert!(matches!(cp_err, ControlPlaneError::AccessDenied(_)));
        assert_eq!(cp_err.status_code(), 403);
    }

    #[test]
    fn no_role_binding_converts() {
        let auth_err = AuthError::NoRoleBinding {
            sub: "user-1".into(),
        };
        let cp_err: ControlPlaneError = auth_err.into();
        assert!(matches!(cp_err, ControlPlaneError::NoRoleBinding));
    }

    #[test]
    fn control_db_not_found_converts() {
        let db_err = control_db::ControlDbError::NotFound {
            table: "agents".into(),
            key: "abc".into(),
        };
        let cp_err: ControlPlaneError = db_err.into();
        assert!(matches!(cp_err, ControlPlaneError::NotFound { .. }));
        assert_eq!(cp_err.status_code(), 404);
    }

    #[test]
    fn control_db_rls_denied_converts() {
        let db_err = control_db::ControlDbError::RlsDenied {
            reason: "cross-cluster".into(),
        };
        let cp_err: ControlPlaneError = db_err.into();
        assert!(matches!(
            cp_err,
            ControlPlaneError::CrossClusterDenied { .. }
        ));
    }
}
