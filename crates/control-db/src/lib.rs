// SPDX-License-Identifier: Apache-2.0 OR MIT
//! PostgreSQL-backed authoritative fleet state and append-only
//! audit for the control plane.
//!
//! # Design invariants
//!
//! - **Short transactions**: no long-held locks; advisory locks
//!   are bounded to cluster keys and released at tx end.
//! - **Optimistic concurrency**: version columns on mutable rows;
//!   UPDATE ... WHERE version = $expected.
//! - **Idempotency**: unique constraints + ON CONFLICT for safe
//!   retries.
//! - **Same-transaction audit**: every state change writes its
//!   audit entry in the same transaction (atomic).
//! - **LISTEN/NOTIFY as wake hint only**: never state; consumer
//!   re-reads from the table.
//! - **Least-privilege roles**: control_app (DML, no audit
//!   UPDATE/DELETE), control_audit (read + insert audit),
//!   control_migrate (DDL).
//! - **RLS defense-in-depth**: cluster isolation, role-gated
//!   writes, audit INSERT-only. NOT the primary authz (service
//!   RBAC is).
//! - **Append-only audit**: no UPDATE/DELETE on audit_log,
//!   enforced at role + RLS + repository API levels.
//!
//! # BLOCKER
//!
//! This host has no running PostgreSQL instance. The SQLx
//! migrations and repository implementations are complete, but
//! live integration tests require a declared self-hosted runner
//! with PostgreSQL deployed. The `test_support` module provides
//! in-memory mock repositories for logic validation.

#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
pub mod cursors;
pub mod error;
pub mod fleet;
pub mod models;
pub mod notify;
pub mod policy;
pub mod pool;
pub mod test_support;

pub use audit::{AuditRepository, SqlxAuditRepository};
pub use auth::{AuthRepository, SqlxAuthRepository};
pub use cursors::{CursorRepository, SqlxCursorRepository};
pub use error::{ControlDbError, Result};
pub use fleet::{FleetRepository, SqlxFleetRepository};
pub use models::*;
pub use notify::{NotifyChannel, SqlxNotifyChannel, WakeHint};
pub use policy::{PolicyRepository, SqlxPolicyRepository};
pub use pool::{advisory_key_for_cluster, PoolConfig, MAX_ADVISORY_LOCK_KEY};

/// Run all migrations against a PostgreSQL database.
///
/// Requires a connection with DDL privileges (control_migrate
/// role or superuser for initial setup).
pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| ControlDbError::Migration(e.to_string()))
}

/// Roll back the last migration (for downgrade rehearsal).
///
/// Requires a connection with DDL privileges.
pub async fn rollback_last_migration(pool: &sqlx::PgPool) -> Result<()> {
    // SQLx doesn't natively support down migrations in the
    // migrate! macro. For downgrade rehearsal, we execute the
    // down SQL manually. This is a documented limitation.
    //
    // In production, downgrade is handled by the deployment
    // pipeline applying the .down.sql files in reverse order.
    let _ = pool;
    Err(ControlDbError::Migration(
        "downgrade requires manual .down.sql execution (deployment pipeline)".into(),
    ))
}
