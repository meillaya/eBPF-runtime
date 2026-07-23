// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC auth repository: role bindings, sessions, revocations.
//!
//! Mirrors the auth crate's RBAC model. Sessions are short-lived
//! and revocable. Role bindings use optimistic concurrency.

#![forbid(unsafe_code)]

use uuid::Uuid;

use crate::error::{ControlDbError, Result};
use crate::models::{OidcRevocation, OidcRoleBinding, OidcSession};

/// Trait for OIDC auth operations.
#[allow(async_fn_in_trait)]
pub trait AuthRepository: Send + Sync {
    /// Create a role binding. Idempotent on (binding_type, principal, role).
    async fn create_role_binding(
        &self,
        binding_type: &str,
        principal: &str,
        role: &str,
    ) -> Result<OidcRoleBinding>;

    /// List role bindings for a principal.
    async fn get_bindings_for_principal(
        &self,
        binding_type: &str,
        principal: &str,
    ) -> Result<Vec<OidcRoleBinding>>;

    /// Delete a role binding with optimistic version check.
    async fn delete_role_binding(&self, id: Uuid, expected_version: i64) -> Result<()>;

    /// Create a session.
    async fn create_session(
        &self,
        session_id: &str,
        sub: &str,
        role: &str,
        groups_json: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<OidcSession>;

    /// Get a session by session_id.
    async fn get_session(&self, session_id: &str) -> Result<OidcSession>;

    /// Revoke a session.
    async fn revoke_session(&self, session_id: &str, reason: &str, revoked_by: &str) -> Result<()>;

    /// Revoke all sessions for a sub.
    async fn revoke_all_for_sub(&self, sub: &str, reason: &str, revoked_by: &str) -> Result<usize>;

    /// Invalidate sessions where groups have changed.
    async fn invalidate_on_group_change(&self, sub: &str, new_groups_json: &str) -> Result<usize>;

    /// List revocations for a target.
    async fn get_revocations(&self, target_type: &str, target: &str)
        -> Result<Vec<OidcRevocation>>;
}

/// SQLx-backed auth repository.
pub struct SqlxAuthRepository {
    pool: sqlx::PgPool,
}

impl SqlxAuthRepository {
    /// Create a new repository.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl AuthRepository for SqlxAuthRepository {
    async fn create_role_binding(
        &self,
        binding_type: &str,
        principal: &str,
        role: &str,
    ) -> Result<OidcRoleBinding> {
        let row = sqlx::query_as::<_, RoleBindingRow>(
            r#"
            INSERT INTO oidc_role_bindings (binding_type, principal, role)
            VALUES ($1, $2, $3)
            ON CONFLICT (binding_type, principal, role) DO UPDATE SET principal = EXCLUDED.principal
            RETURNING id, binding_type, principal, role, version, created_at, updated_at
            "#,
        )
        .bind(binding_type)
        .bind(principal)
        .bind(role)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn get_bindings_for_principal(
        &self,
        binding_type: &str,
        principal: &str,
    ) -> Result<Vec<OidcRoleBinding>> {
        let rows = sqlx::query_as::<_, RoleBindingRow>(
            r#"SELECT id, binding_type, principal, role, version, created_at, updated_at
               FROM oidc_role_bindings WHERE binding_type = $1 AND principal = $2"#,
        )
        .bind(binding_type)
        .bind(principal)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_role_binding(&self, id: Uuid, expected_version: i64) -> Result<()> {
        let result = sqlx::query("DELETE FROM oidc_role_bindings WHERE id = $1 AND version = $2")
            .bind(id)
            .bind(expected_version)
            .execute(&self.pool)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ControlDbError::VersionConflict {
                table: "oidc_role_bindings".into(),
                expected: expected_version,
                found: -1,
            });
        }
        Ok(())
    }

    async fn create_session(
        &self,
        session_id: &str,
        sub: &str,
        role: &str,
        groups_json: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<OidcSession> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"
            INSERT INTO oidc_sessions (session_id, sub, role, groups_json, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, session_id, sub, role, groups_json, created_at, expires_at, revoked, revoked_at
            "#,
        )
        .bind(session_id)
        .bind(sub)
        .bind(role)
        .bind(groups_json)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(row.into())
    }

    async fn get_session(&self, session_id: &str) -> Result<OidcSession> {
        let row = sqlx::query_as::<_, SessionRow>(
            r#"SELECT id, session_id, sub, role, groups_json, created_at, expires_at, revoked, revoked_at
               FROM oidc_sessions WHERE session_id = $1"#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?
        .ok_or_else(|| ControlDbError::NotFound {
            table: "oidc_sessions".into(),
            key: session_id.to_string(),
        })?;

        Ok(row.into())
    }

    async fn revoke_session(&self, session_id: &str, reason: &str, revoked_by: &str) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        sqlx::query(
            "UPDATE oidc_sessions SET revoked = true, revoked_at = now() WHERE session_id = $1",
        )
        .bind(session_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        sqlx::query(
            r#"INSERT INTO oidc_revocations (target_type, target, reason, revoked_by)
               VALUES ('session', $1, $2, $3)"#,
        )
        .bind(session_id)
        .bind(reason)
        .bind(revoked_by)
        .execute(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(())
    }

    async fn revoke_all_for_sub(&self, sub: &str, reason: &str, revoked_by: &str) -> Result<usize> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        let result = sqlx::query(
            "UPDATE oidc_sessions SET revoked = true, revoked_at = now() WHERE sub = $1 AND revoked = false",
        )
        .bind(sub)
        .execute(&mut *tx)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        let count = result.rows_affected() as usize;

        if count > 0 {
            sqlx::query(
                r#"INSERT INTO oidc_revocations (target_type, target, reason, revoked_by)
                   VALUES ('sub', $1, $2, $3)"#,
            )
            .bind(sub)
            .bind(reason)
            .bind(revoked_by)
            .execute(&mut *tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(count)
    }

    async fn invalidate_on_group_change(&self, sub: &str, new_groups_json: &str) -> Result<usize> {
        let result = sqlx::query(
            r#"UPDATE oidc_sessions SET revoked = true, revoked_at = now()
               WHERE sub = $1 AND revoked = false AND groups_json != $2"#,
        )
        .bind(sub)
        .bind(new_groups_json)
        .execute(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }

    async fn get_revocations(
        &self,
        target_type: &str,
        target: &str,
    ) -> Result<Vec<OidcRevocation>> {
        let rows = sqlx::query_as::<_, RevocationRow>(
            r#"SELECT id, target_type, target, reason, revoked_by, revoked_at
               FROM oidc_revocations WHERE target_type = $1 AND target = $2 ORDER BY revoked_at"#,
        )
        .bind(target_type)
        .bind(target)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ControlDbError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }
}

// -- SQLx row types --

#[derive(sqlx::FromRow)]
struct RoleBindingRow {
    id: Uuid,
    binding_type: String,
    principal: String,
    role: String,
    version: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<RoleBindingRow> for OidcRoleBinding {
    fn from(r: RoleBindingRow) -> Self {
        Self {
            id: r.id,
            binding_type: r.binding_type,
            principal: r.principal,
            role: r.role,
            version: r.version,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: Uuid,
    session_id: String,
    sub: String,
    role: String,
    groups_json: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    revoked: bool,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<SessionRow> for OidcSession {
    fn from(r: SessionRow) -> Self {
        Self {
            id: r.id,
            session_id: r.session_id,
            sub: r.sub,
            role: r.role,
            groups_json: r.groups_json,
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked: r.revoked,
            revoked_at: r.revoked_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RevocationRow {
    id: Uuid,
    target_type: String,
    target: String,
    reason: String,
    revoked_by: String,
    revoked_at: chrono::DateTime<chrono::Utc>,
}

impl From<RevocationRow> for OidcRevocation {
    fn from(r: RevocationRow) -> Self {
        Self {
            id: r.id,
            target_type: r.target_type,
            target: r.target,
            reason: r.reason,
            revoked_by: r.revoked_by,
            revoked_at: r.revoked_at,
        }
    }
}
