// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Socket table options and correlation set types.

use crate::socket_entry::SocketEntry;

pub const DEFAULT_CAPACITY: usize = 4_096;
pub const DEFAULT_TTL_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketTableOpts {
    pub capacity: usize,
    pub ttl_seconds: u64,
}

impl Default for SocketTableOpts {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrelationSet {
    pub attempts: Vec<SocketEntry>,
    pub connects: Vec<SocketEntry>,
    pub accepts: Vec<SocketEntry>,
    pub closes: Vec<SocketEntry>,
}
