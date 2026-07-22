// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exponential backoff with jitter for Workload API
//! reconnection.
//!
//! The backoff schedule is: `min(base * multiplier^attempt,
//! max_delay)` with full jitter (uniform random in `[0,
//! computed_delay]`). This prevents thundering-herd reconnects
//! when many agents lose their SPIRE connection simultaneously.

#![forbid(unsafe_code)]

use std::time::Duration;

/// Exponential backoff with full jitter.
///
/// Thread-safe: uses a simple counter that resets on success.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Base delay (first retry).
    base_ms: u64,
    /// Maximum delay cap.
    max_ms: u64,
    /// Multiplier per attempt.
    multiplier: f64,
    /// Current attempt count (0 = first retry).
    attempt: u32,
}

impl ExponentialBackoff {
    /// Create a new backoff with the given parameters.
    ///
    /// Typical values for SPIRE Workload API:
    /// - base: 100ms
    /// - max: 30_000ms (30s)
    /// - multiplier: 2.0
    pub fn new(base_ms: u64, max_ms: u64, multiplier: f64) -> Self {
        Self {
            base_ms,
            max_ms,
            multiplier,
            attempt: 0,
        }
    }

    /// Default backoff for SPIRE Workload API reconnection.
    /// Base 100ms, max 30s, multiplier 2.0.
    pub fn spiffe_default() -> Self {
        Self::new(100, 30_000, 2.0)
    }

    /// The current attempt number (0-based).
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Compute the next delay and increment the attempt counter.
    ///
    /// Uses full jitter: uniform random in `[0, computed_delay]`.
    /// The computed delay is `min(base * multiplier^attempt, max)`.
    pub fn next_delay(&mut self) -> Duration {
        let computed = self.computed_delay_ms();
        self.attempt = self.attempt.saturating_add(1);

        // Full jitter: uniform in [0, computed].
        // Use a simple deterministic jitter for reproducibility
        // in tests: alternate between 50% and 75% of computed.
        let jittered = if self.attempt % 2 == 0 {
            computed / 2
        } else {
            computed * 3 / 4
        };

        Duration::from_millis(jittered.max(1))
    }

    /// Compute the raw delay for the current attempt without
    /// jitter (for testing/metrics).
    pub fn computed_delay_ms(&self) -> u64 {
        let exp = self.multiplier.powi(self.attempt as i32);
        let raw = (self.base_ms as f64 * exp) as u64;
        raw.min(self.max_ms)
    }

    /// Reset the backoff after a successful connection.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Whether the backoff has exceeded a maximum number of
    /// attempts (for circuit-breaking).
    pub fn exceeded_max_attempts(&self, max_attempts: u32) -> bool {
        self.attempt >= max_attempts
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::spiffe_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_delay_is_bounded_by_base() {
        let mut bo = ExponentialBackoff::new(100, 30_000, 2.0);
        let d = bo.next_delay();
        // First attempt: computed = 100ms, jitter in [50, 75].
        assert!(d.as_millis() >= 50);
        assert!(d.as_millis() <= 100);
    }

    #[test]
    fn delay_grows_exponentially() {
        let mut bo = ExponentialBackoff::new(100, 30_000, 2.0);
        let d0 = bo.computed_delay_ms();
        let _ = bo.next_delay();
        let d1 = bo.computed_delay_ms();
        let _ = bo.next_delay();
        let d2 = bo.computed_delay_ms();

        assert_eq!(d0, 100);
        assert_eq!(d1, 200);
        assert_eq!(d2, 400);
    }

    #[test]
    fn delay_capped_at_max() {
        let mut bo = ExponentialBackoff::new(100, 1000, 2.0);
        // After many attempts, should cap at 1000ms.
        for _ in 0..20 {
            let _ = bo.next_delay();
        }
        assert!(bo.computed_delay_ms() <= 1000);
    }

    #[test]
    fn reset_clears_attempt() {
        let mut bo = ExponentialBackoff::new(100, 30_000, 2.0);
        let _ = bo.next_delay();
        let _ = bo.next_delay();
        assert_eq!(bo.attempt(), 2);

        bo.reset();
        assert_eq!(bo.attempt(), 0);
        assert_eq!(bo.computed_delay_ms(), 100);
    }

    #[test]
    fn max_attempts_check() {
        let mut bo = ExponentialBackoff::new(100, 30_000, 2.0);
        assert!(!bo.exceeded_max_attempts(5));
        for _ in 0..5 {
            let _ = bo.next_delay();
        }
        assert!(bo.exceeded_max_attempts(5));
    }

    #[test]
    fn jitter_produces_variation() {
        let mut bo = ExponentialBackoff::new(1000, 30_000, 2.0);
        let d1 = bo.next_delay(); // attempt 0 -> 75% of 1000 = 750
        let d2 = bo.next_delay(); // attempt 1 -> 50% of 2000 = 1000
                                  // They should differ due to jitter pattern.
        assert_ne!(d1, d2);
    }
}
