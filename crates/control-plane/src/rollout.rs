// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Thresholded policy rollout supervisor.
//!
//! A rollout is created by the HTTP API. This worker evaluates the
//! acknowledgements that arrive after the rollout started and either promotes
//! the target or broadcasts the previous policy. The database row is the
//! source of truth, so a control-plane restart resumes pending rollouts.

use std::time::Duration;

use control_db::{PolicyVersionRecord, RolloutRecord};
use protocol::v1::{ControlCommand, PolicySnapshot};
use sqlx::PgPool;
use tokio::sync::{broadcast, watch};
use uuid::Uuid;

/// Run the rollout supervisor until shutdown.
pub async fn run(
    pool: PgPool,
    cluster_id: Uuid,
    control: broadcast::Sender<ControlCommand>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                if let Err(error) = tick(&pool, cluster_id, &control).await {
                    tracing::warn!(%error, "rollout evaluation failed");
                }
            }
        }
    }
}

async fn tick(
    pool: &PgPool,
    cluster_id: Uuid,
    control: &broadcast::Sender<ControlCommand>,
) -> Result<(), control_db::DbError> {
    for rollout in control_db::pending_rollouts(pool).await? {
        if rollout.cluster_id != cluster_id {
            continue;
        }
        let (applied, rejected) = control_db::count_rollout_acks(pool, &rollout).await?;
        let applied = applied.min(rollout.expected_agents).max(0);
        let rejected = rejected.max(0);

        if rejected > 0 {
            rollback(
                pool,
                control,
                &rollout,
                applied,
                rejected,
                "rejected by agent",
            )
            .await?;
            continue;
        }
        if ratio_met(applied, rollout.expected_agents, rollout.min_ratio) {
            promote(pool, &rollout, applied, rejected).await?;
            continue;
        }
        if chrono::Utc::now().timestamp() >= rollout.deadline_epoch {
            rollback(pool, control, &rollout, applied, rejected, "timeout").await?;
        }
    }
    Ok(())
}

/// Whether `applied / expected` reaches the requested ratio.
///
/// The caller stores a non-zero expected count, but keep the division safe so
/// a corrupt row cannot panic the supervisor.
pub fn ratio_met(applied: i32, expected: i32, min_ratio: f64) -> bool {
    expected > 0 && (applied.max(0) as f64 / expected as f64) >= min_ratio
}

async fn promote(
    pool: &PgPool,
    rollout: &RolloutRecord,
    applied: i32,
    rejected: i32,
) -> Result<(), control_db::DbError> {
    if !control_db::finish_rollout(
        pool,
        rollout.id,
        "promoted",
        applied,
        rejected,
        "threshold reached",
    )
    .await?
    {
        return Ok(());
    }
    if let Some(target) =
        control_db::get_policy_version(pool, rollout.policy_id, rollout.version).await?
    {
        control_db::set_policy_status_by_id(pool, target.id, "applied").await?;
    }
    audit(
        pool,
        rollout,
        "policy.rollout.promoted",
        true,
        serde_json::json!({
            "applied": applied,
            "expected": rollout.expected_agents,
            "rejected": rejected,
            "min_ratio": rollout.min_ratio,
        }),
    )
    .await?;
    Ok(())
}

async fn rollback(
    pool: &PgPool,
    control: &broadcast::Sender<ControlCommand>,
    rollout: &RolloutRecord,
    applied: i32,
    rejected: i32,
    reason: &str,
) -> Result<(), control_db::DbError> {
    if !control_db::finish_rollout(pool, rollout.id, "rolled_back", applied, rejected, reason)
        .await?
    {
        return Ok(());
    }

    if let Some(target) =
        control_db::get_policy_version(pool, rollout.policy_id, rollout.version).await?
    {
        control_db::set_policy_status_by_id(pool, target.id, "rolled_back").await?;
    }

    let mut previous_sent = false;
    if let Some(previous_version) = rollout.previous_version {
        if let Some(previous) =
            control_db::get_policy_version(pool, rollout.policy_id, previous_version).await?
        {
            let _ = control.send(policy_command(&previous));
            previous_sent = true;
        }
    }
    let final_reason = if previous_sent || rollout.previous_version.is_none() {
        reason.to_string()
    } else {
        format!("{reason}; previous policy version is missing")
    };
    audit(
        pool,
        rollout,
        "policy.rollout.rolled_back",
        true,
        serde_json::json!({
            "reason": final_reason,
            "applied": applied,
            "expected": rollout.expected_agents,
            "rejected": rejected,
            "min_ratio": rollout.min_ratio,
            "previous_version": rollout.previous_version,
            "previous_sent": previous_sent,
        }),
    )
    .await?;
    Ok(())
}

async fn audit(
    pool: &PgPool,
    rollout: &RolloutRecord,
    action: &str,
    success: bool,
    detail: serde_json::Value,
) -> Result<(), control_db::DbError> {
    control_db::audit(
        pool,
        &rollout.requested_by,
        action,
        &format!("{}@{}", rollout.name, rollout.version),
        success,
        detail,
    )
    .await
}

fn policy_command(policy: &PolicyVersionRecord) -> ControlCommand {
    ControlCommand {
        command: Some(protocol::v1::control_command::Command::Policy(
            PolicySnapshot {
                version: policy.version.to_string(),
                digest: policy.digest.clone(),
                yaml: policy.content.as_bytes().to_vec(),
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_boundaries() {
        assert!(ratio_met(3, 3, 1.0));
        assert!(ratio_met(19, 20, 0.95));
        assert!(!ratio_met(18, 20, 0.95));
        assert!(!ratio_met(0, 0, 0.95));
        assert!(!ratio_met(0, 3, 0.95));
    }
}
