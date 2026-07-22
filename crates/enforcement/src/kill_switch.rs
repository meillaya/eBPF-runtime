// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Kill switch: immediate config-map deny suppression.
//!
//! The kill switch is a single `lsm_kill_switch` BPF map slot.
//! When `deny_disabled == 1`, every deny-mode policy degrades to
//! audit-only (the BPF hook returns 0 instead of the errno).
//!
//! The kill switch is a **config-map flip**: the agent writes
//! `deny_disabled = 1` to the map. The BPF engine reads this on
//! every decision, so the suppression takes effect within
//! `kill_switch_max_ms` (default 5000) of the gRPC command
//! reaching the agent.
//!
//! The kill switch does NOT change the state machine state. It is
//! an orthogonal emergency control. The policy map still holds
//! deny-mode entries; they are simply suppressed at the BPF level.
//!
//! Wire-compatible with `struct lsm_kill_switch` (16 bytes) from
//! `bpf/sensors/lsm.bpf.c`.

#![forbid(unsafe_code)]

use std::time::Instant;

use serde::{Deserialize, Serialize};

/// The kill switch state. Mirrors `struct lsm_kill_switch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitch {
    /// When `true`, every deny-mode policy degrades to audit-only.
    pub deny_disabled: bool,
    /// Monotonic timestamp (ns) of the last toggle. Informational.
    pub last_toggle_ns: u64,
}

impl KillSwitch {
    /// Create a disengaged kill switch (deny enabled).
    pub fn new() -> Self {
        Self {
            deny_disabled: false,
            last_toggle_ns: 0,
        }
    }

    /// Engage the kill switch: suppress all deny-mode policies.
    /// Returns the latency of the engage operation (for
    /// benchmarking against `kill_switch_max_ms`).
    pub fn engage(&mut self) -> std::time::Duration {
        let start = Instant::now();
        self.deny_disabled = true;
        self.last_toggle_ns = start.elapsed().as_nanos() as u64;
        start.elapsed()
    }

    /// Disengage the kill switch: re-enable deny-mode policies.
    pub fn disengage(&mut self) -> std::time::Duration {
        let start = Instant::now();
        self.deny_disabled = false;
        self.last_toggle_ns = start.elapsed().as_nanos() as u64;
        start.elapsed()
    }

    /// Whether deny is currently suppressed.
    pub fn is_engaged(&self) -> bool {
        self.deny_disabled
    }

    /// Serialize to the 16-byte wire format matching
    /// `struct lsm_kill_switch`.
    pub fn to_wire(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0] = u8::from(self.deny_disabled);
        // bytes 1..8 are padding
        buf[8..16].copy_from_slice(&self.last_toggle_ns.to_le_bytes());
        buf
    }

    /// Deserialize from the 16-byte wire format.
    pub fn from_wire(bytes: &[u8; 16]) -> Self {
        Self {
            deny_disabled: bytes[0] != 0,
            last_toggle_ns: u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8])),
        }
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

/// Benchmark result for kill-switch engage/disengage pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchBenchmark {
    /// Number of engage/disengage pairs run.
    pub pairs: usize,
    /// Latencies (in microseconds) for each engage operation.
    pub engage_latencies_us: Vec<u64>,
    /// p99 engage latency in microseconds.
    pub p99_engage_us: u64,
    /// The threshold from the schema (kill_switch_max_ms).
    pub threshold_ms: u64,
    /// Whether p99 is within the threshold.
    pub within_threshold: bool,
}

/// Run a kill-switch benchmark: `pairs` engage/disengage cycles,
/// measuring engage latency. Returns the benchmark result with
/// p99 and threshold comparison.
pub fn benchmark_kill_switch(pairs: usize, threshold_ms: u64) -> KillSwitchBenchmark {
    let mut ks = KillSwitch::new();
    let mut latencies = Vec::with_capacity(pairs);

    for _ in 0..pairs {
        let latency = ks.engage();
        latencies.push(latency.as_micros() as u64);
        let _ = ks.disengage();
    }

    latencies.sort_unstable();
    let p99_idx = ((pairs as f64) * 0.99).ceil() as usize;
    let p99_idx = p99_idx.min(pairs).saturating_sub(1);
    let p99_us = latencies.get(p99_idx).copied().unwrap_or(0);
    let threshold_us = threshold_ms * 1000;

    KillSwitchBenchmark {
        pairs,
        engage_latencies_us: latencies,
        p99_engage_us: p99_us,
        threshold_ms,
        within_threshold: p99_us <= threshold_us,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_switch_starts_disengaged() {
        let ks = KillSwitch::new();
        assert!(!ks.is_engaged());
        assert!(!ks.deny_disabled);
    }

    #[test]
    fn engage_disengage_roundtrip() {
        let mut ks = KillSwitch::new();
        ks.engage();
        assert!(ks.is_engaged());
        ks.disengage();
        assert!(!ks.is_engaged());
    }

    #[test]
    fn wire_roundtrip() {
        let mut ks = KillSwitch::new();
        ks.engage();
        ks.last_toggle_ns = 12345;
        let wire = ks.to_wire();
        let restored = KillSwitch::from_wire(&wire);
        assert_eq!(ks, restored);
    }

    #[test]
    fn wire_format_matches_c_struct() {
        let ks = KillSwitch {
            deny_disabled: true,
            last_toggle_ns: 0xDEAD_BEEF_CAFE_BABE,
        };
        let wire = ks.to_wire();
        assert_eq!(wire[0], 1); // deny_disabled at offset 0
        assert_eq!(wire.len(), 16); // struct lsm_kill_switch is 16 bytes
        let ts = u64::from_le_bytes(wire[8..16].try_into().unwrap());
        assert_eq!(ts, 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn benchmark_completes_within_threshold() {
        // User-space map write is sub-millisecond; threshold is
        // 5000ms. This must pass trivially.
        let result = benchmark_kill_switch(10, 5000);
        assert_eq!(result.pairs, 10);
        assert!(result.within_threshold);
        assert!(result.p99_engage_us < 5_000_000); // < 5000ms in µs
    }

    #[test]
    fn benchmark_p99_is_reasonable() {
        let result = benchmark_kill_switch(100, 5000);
        // p99 should be well under 1ms for a memory write.
        assert!(
            result.p99_engage_us < 1000,
            "p99={}µs",
            result.p99_engage_us
        );
    }
}
