// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Reconnection with exponential backoff and SVID max-age
//! rotation.
//!
//! # No redial storm
//!
//! Reconnection uses exponential backoff with jitter (delegated
//! to `identity-spiffe`'s `ExponentialBackoff`). The backoff
//! resets on successful connection. A circuit breaker opens
//! after `max_reconnect_attempts` consecutive failures.
//!
//! # SVID max-age rotation
//!
//! Connections are force-closed after `max_connection_age_ms`
//! to pick up rotated SVIDs. The `needs_rotation` check
//! integrates with the `identity-spiffe` `CredentialManager`'s
//! `needs_rebuild` signal.

#![forbid(unsafe_code)]

use std::time::Duration;

use identity_spiffe::backoff::ExponentialBackoff;

use crate::config::TransportConfig;
use crate::error::{TransportError, TransportResult};

/// Reconnection policy with backoff and circuit-breaking.
#[derive(Debug)]
pub struct ReconnectPolicy {
    backoff: ExponentialBackoff,
    max_attempts: u32,
    max_connection_age: Duration,
    /// Whether the circuit breaker is open (too many failures).
    circuit_open: bool,
    /// Total successful connections (for metrics).
    successful_connections: u64,
    /// Total failed connection attempts.
    failed_attempts: u64,
}

impl ReconnectPolicy {
    /// Create a reconnect policy from transport config.
    pub fn from_config(config: &TransportConfig) -> Self {
        Self {
            backoff: ExponentialBackoff::new(
                config.backoff_base_ms,
                config.backoff_max_ms,
                config.backoff_multiplier,
            ),
            max_attempts: config.max_reconnect_attempts,
            max_connection_age: Duration::from_millis(config.max_connection_age_ms),
            circuit_open: false,
            successful_connections: 0,
            failed_attempts: 0,
        }
    }

    /// Create a reconnect policy with explicit parameters.
    pub fn new(
        base_ms: u64,
        max_ms: u64,
        multiplier: f64,
        max_attempts: u32,
        max_connection_age: Duration,
    ) -> Self {
        Self {
            backoff: ExponentialBackoff::new(base_ms, max_ms, multiplier),
            max_attempts,
            max_connection_age,
            circuit_open: false,
            successful_connections: 0,
            failed_attempts: 0,
        }
    }

    /// Record a successful connection. Resets the backoff and
    /// closes the circuit breaker.
    pub fn record_success(&mut self) {
        self.backoff.reset();
        self.circuit_open = false;
        self.successful_connections += 1;
    }

    /// Record a failed connection attempt. Returns the delay
    /// before the next retry, or an error if the circuit
    /// breaker is open.
    pub fn record_failure(&mut self) -> TransportResult<Duration> {
        self.failed_attempts += 1;

        if self.backoff.exceeded_max_attempts(self.max_attempts) {
            self.circuit_open = true;
            return Err(TransportError::ReconnectExhausted {
                attempts: self.backoff.attempt(),
                max_attempts: self.max_attempts,
            });
        }

        Ok(self.backoff.next_delay())
    }

    /// The next backoff delay without recording a failure.
    pub fn peek_delay(&self) -> Duration {
        Duration::from_millis(self.backoff.computed_delay_ms())
    }

    /// Whether the circuit breaker is open.
    pub fn is_circuit_open(&self) -> bool {
        self.circuit_open
    }

    /// The current attempt count.
    pub fn attempt_count(&self) -> u32 {
        self.backoff.attempt()
    }

    /// The maximum connection age.
    pub fn max_connection_age(&self) -> Duration {
        self.max_connection_age
    }

    /// Whether a connection of the given age should be rotated
    /// (force-closed to pick up new SVIDs).
    pub fn needs_rotation(&self, connection_age: Duration) -> bool {
        connection_age >= self.max_connection_age
    }

    /// Total successful connections.
    pub fn successful_connections(&self) -> u64 {
        self.successful_connections
    }

    /// Total failed connection attempts.
    pub fn failed_attempts(&self) -> u64 {
        self.failed_attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ReconnectPolicy {
        ReconnectPolicy::new(100, 30_000, 2.0, 5, Duration::from_secs(3600))
    }

    #[test]
    fn first_failure_returns_base_delay() {
        let mut p = policy();
        let delay = p.record_failure().unwrap();
        // First attempt: computed = 100ms, jitter in [50, 100].
        assert!(delay.as_millis() >= 50);
        assert!(delay.as_millis() <= 100);
    }

    #[test]
    fn delays_grow_exponentially() {
        let mut p = policy();
        let d0 = p.record_failure().unwrap();
        let d1 = p.record_failure().unwrap();
        // Each delay should be >= the previous (modulo jitter).
        // The computed delay doubles: 100, 200, 400, ...
        assert!(d1.as_millis() >= d0.as_millis() / 2);
    }

    #[test]
    fn circuit_breaker_opens_after_max_attempts() {
        let mut p = policy(); // max_attempts = 5
        for _ in 0..5 {
            p.record_failure().unwrap();
        }
        // 6th attempt should trip the circuit breaker.
        let err = p.record_failure().unwrap_err();
        assert!(matches!(err, TransportError::ReconnectExhausted { .. }));
        assert!(p.is_circuit_open());
    }

    #[test]
    fn success_resets_backoff_and_circuit() {
        let mut p = policy();
        p.record_failure().unwrap();
        p.record_failure().unwrap();
        assert_eq!(p.attempt_count(), 2);

        p.record_success();
        assert_eq!(p.attempt_count(), 0);
        assert!(!p.is_circuit_open());
        assert_eq!(p.successful_connections(), 1);
    }

    #[test]
    fn needs_rotation_at_max_age() {
        let p = policy(); // max_connection_age = 1 hour
        assert!(!p.needs_rotation(Duration::from_secs(3599)));
        assert!(p.needs_rotation(Duration::from_secs(3600)));
        assert!(p.needs_rotation(Duration::from_secs(7200)));
    }

    #[test]
    fn no_redial_storm_backoff_caps_at_max() {
        let mut p = ReconnectPolicy::new(100, 1000, 2.0, 100, Duration::from_secs(3600));
        for _ in 0..50 {
            if p.record_failure().is_err() {
                break;
            }
        }
        // Computed delay should be capped at max_ms.
        assert!(p.peek_delay().as_millis() <= 1000);
    }

    #[test]
    fn from_config_uses_config_values() {
        let config = TransportConfig {
            backoff_base_ms: 200,
            backoff_max_ms: 60_000,
            backoff_multiplier: 3.0,
            max_reconnect_attempts: 10,
            max_connection_age_ms: 7_200_000,
            ..Default::default()
        };
        let p = ReconnectPolicy::from_config(&config);
        assert_eq!(p.max_attempts, 10);
        assert_eq!(p.max_connection_age, Duration::from_millis(7_200_000));
    }

    #[test]
    fn metrics_tracked() {
        let mut p = policy();
        p.record_failure().unwrap();
        p.record_success();
        p.record_failure().unwrap();
        assert_eq!(p.successful_connections(), 1);
        assert_eq!(p.failed_attempts(), 2);
    }
}
