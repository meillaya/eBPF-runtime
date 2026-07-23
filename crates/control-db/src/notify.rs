// SPDX-License-Identifier: Apache-2.0 OR MIT
//! LISTEN/NOTIFY wake-hint channel.
//!
//! NOTIFY is a WAKE HINT ONLY — it is NOT a state source.
//! The consumer MUST re-read the authoritative state from the
//! table after receiving a notification. Lost notifications are
//! safe: the consumer falls back to periodic polling.
//!
//! Pattern:
//! 1. Producer: INSERT state change → NOTIFY channel (same tx).
//! 2. Consumer: LISTEN channel → on wake → SELECT latest state.
//! 3. Consumer also polls on a timer (covers lost notifications).

#![forbid(unsafe_code)]

use crate::error::{ControlDbError, Result};

/// The notification channel name for fleet state changes.
pub const FLEET_NOTIFY_CHANNEL: &str = "control_fleet_state";

/// The notification channel name for policy rollout changes.
pub const POLICY_NOTIFY_CHANNEL: &str = "control_policy_rollout";

/// A wake hint received from LISTEN/NOTIFY.
///
/// This is NOT state. The consumer must re-read from the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeHint {
    /// The channel that produced the hint.
    pub channel: String,
    /// The payload (typically a table name or row ID hint).
    /// May be empty if the payload was lost.
    pub payload: String,
}

impl WakeHint {
    /// Whether this hint carries a payload.
    pub fn has_payload(&self) -> bool {
        !self.payload.is_empty()
    }
}

/// Trait for the notification channel. Implemented by
/// `SqlxNotifyChannel` (live PostgreSQL) and `MockNotifyChannel`
/// (test fixture).
#[allow(async_fn_in_trait)]
pub trait NotifyChannel: Send + Sync {
    /// Send a wake hint (NOTIFY). Called in the same transaction
    /// as the state change. The payload is a hint, not state.
    async fn notify(&self, channel: &str, payload: &str) -> Result<()>;

    /// Wait for the next wake hint on a channel. Returns None if
    /// the timeout expires (lost notification / no activity).
    /// The caller MUST re-read state from the table regardless.
    async fn wait_for_hint(
        &self,
        channel: &str,
        timeout: std::time::Duration,
    ) -> Result<Option<WakeHint>>;
}

/// SQLx-backed LISTEN/NOTIFY channel.
///
/// Uses a dedicated connection for LISTEN (LISTEN requires a
/// persistent connection). NOTIFY is sent via the pool.
pub struct SqlxNotifyChannel {
    pool: sqlx::PgPool,
}

impl SqlxNotifyChannel {
    /// Create a new notify channel.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Send NOTIFY within an existing transaction (same-tx as
    /// the state change).
    pub async fn notify_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        channel: &str,
        payload: &str,
    ) -> Result<()> {
        // pg_notify requires the payload to be < 8000 bytes.
        // Truncate if necessary (the payload is a hint, not state).
        let truncated = if payload.len() > 7999 {
            &payload[..7999]
        } else {
            payload
        };
        sqlx::query(&format!("SELECT pg_notify('{channel}', $1)"))
            .bind(truncated)
            .execute(&mut **tx)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;
        Ok(())
    }
}

impl NotifyChannel for SqlxNotifyChannel {
    async fn notify(&self, channel: &str, payload: &str) -> Result<()> {
        let truncated = if payload.len() > 7999 {
            &payload[..7999]
        } else {
            payload
        };
        sqlx::query(&format!("SELECT pg_notify('{channel}', $1)"))
            .bind(truncated)
            .execute(&self.pool)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;
        Ok(())
    }

    async fn wait_for_hint(
        &self,
        channel: &str,
        timeout: std::time::Duration,
    ) -> Result<Option<WakeHint>> {
        // Acquire a dedicated connection for LISTEN.
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| ControlDbError::Pool(e.to_string()))?;

        // LISTEN on the channel.
        sqlx::query(&format!("LISTEN {channel}"))
            .execute(&mut *conn)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        // Wait for notification with timeout.
        // In a real implementation, this would use sqlx's
        // connection notification stream. For now, we use a
        // timeout-based poll.
        tokio::time::sleep(timeout).await;

        // UNLISTEN to release the channel.
        sqlx::query(&format!("UNLISTEN {channel}"))
            .execute(&mut *conn)
            .await
            .map_err(|e| ControlDbError::Database(e.to_string()))?;

        // Timeout expired: no hint received (lost notification
        // or no activity). The caller falls back to polling.
        Ok(None)
    }
}

/// The recovery pattern: after a wake hint (or timeout), the
/// consumer re-reads authoritative state. This function
/// documents the pattern; actual re-read is done by the
/// consumer via the appropriate repository.
///
/// ```text
/// loop {
///     // Wait for wake hint (may be lost).
///     let hint = notify.wait_for_hint(channel, poll_interval).await?;
///
///     // ALWAYS re-read state from the table (authoritative).
///     let state = repo.get_latest_state().await?;
///
///     // Process state change.
///     process(state).await?;
/// }
/// ```
pub fn document_recovery_pattern() {
    // This function exists only to document the pattern.
    // The actual implementation is in the consumer service.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_hint_payload_detection() {
        let hint = WakeHint {
            channel: FLEET_NOTIFY_CHANNEL.to_string(),
            payload: "agents:row-123".to_string(),
        };
        assert!(hint.has_payload());

        let empty = WakeHint {
            channel: POLICY_NOTIFY_CHANNEL.to_string(),
            payload: String::new(),
        };
        assert!(!empty.has_payload());
    }

    #[test]
    fn channel_names_are_distinct() {
        assert_ne!(FLEET_NOTIFY_CHANNEL, POLICY_NOTIFY_CHANNEL);
    }

    #[test]
    fn recovery_pattern_documented() {
        // Compile-time check that the pattern function exists.
        document_recovery_pattern();
    }
}
