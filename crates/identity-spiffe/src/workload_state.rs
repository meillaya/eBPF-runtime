// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Workload API state tracking.

use super::{StreamHealth, SvidSet};

pub struct WorkloadApiState {
    /// The current SVID set (None until first response).
    pub current_set: Option<SvidSet>,
    /// Stream health.
    pub health: StreamHealth,
    /// Last successful response time (unix seconds).
    pub last_response_unix: i64,
    /// Total number of rotations (complete-set replacements).
    pub rotation_count: u64,
    /// Total number of reconnection attempts.
    pub reconnect_count: u64,
}

impl Default for WorkloadApiState {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkloadApiState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self {
            current_set: None,
            health: StreamHealth::Disconnected,
            last_response_unix: 0,
            rotation_count: 0,
            reconnect_count: 0,
        }
    }
}
