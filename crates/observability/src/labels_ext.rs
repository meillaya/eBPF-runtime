// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded label enums for syscalls, attach state, enrichment, and policy.

use std::fmt;

/// Bounded enum for syscall names tracked in the latency histogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Syscall {
    Read,
    Write,
    Open,
    Openat,
    Close,
    Execve,
    Fork,
    Clone,
    Kill,
    Socket,
    Connect,
    Accept,
    Bind,
    Listen,
    Sendto,
    Recvfrom,
    Unlink,
    Rename,
    Mkdir,
    Rmdir,
}

impl Syscall {
    pub const ALL: [Syscall; 20] = [
        Syscall::Read,
        Syscall::Write,
        Syscall::Open,
        Syscall::Openat,
        Syscall::Close,
        Syscall::Execve,
        Syscall::Fork,
        Syscall::Clone,
        Syscall::Kill,
        Syscall::Socket,
        Syscall::Connect,
        Syscall::Accept,
        Syscall::Bind,
        Syscall::Listen,
        Syscall::Sendto,
        Syscall::Recvfrom,
        Syscall::Unlink,
        Syscall::Rename,
        Syscall::Mkdir,
        Syscall::Rmdir,
    ];
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Syscall::Read => "read",
            Syscall::Write => "write",
            Syscall::Open => "open",
            Syscall::Openat => "openat",
            Syscall::Close => "close",
            Syscall::Execve => "execve",
            Syscall::Fork => "fork",
            Syscall::Clone => "clone",
            Syscall::Kill => "kill",
            Syscall::Socket => "socket",
            Syscall::Connect => "connect",
            Syscall::Accept => "accept",
            Syscall::Bind => "bind",
            Syscall::Listen => "listen",
            Syscall::Sendto => "sendto",
            Syscall::Recvfrom => "recvfrom",
            Syscall::Unlink => "unlink",
            Syscall::Rename => "rename",
            Syscall::Mkdir => "mkdir",
            Syscall::Rmdir => "rmdir",
        })
    }
}

/// Bounded enum for BPF program attach state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttachState {
    Attached,
    Detached,
    Degraded,
}

impl AttachState {
    /// Numeric encoding for the Prometheus gauge: 2=attached, 1=degraded, 0=detached.
    pub fn as_metric_value(self) -> i64 {
        match self {
            AttachState::Attached => 2,
            AttachState::Degraded => 1,
            AttachState::Detached => 0,
        }
    }
}

impl fmt::Display for AttachState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AttachState::Attached => "attached",
            AttachState::Detached => "detached",
            AttachState::Degraded => "degraded",
        })
    }
}

/// Bounded enum for enrichment provider status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnrichmentState {
    Available,
    Unavailable,
    Degraded,
}

impl EnrichmentState {
    /// Numeric encoding: 2=available, 1=degraded, 0=unavailable.
    pub fn as_metric_value(self) -> i64 {
        match self {
            EnrichmentState::Available => 2,
            EnrichmentState::Degraded => 1,
            EnrichmentState::Unavailable => 0,
        }
    }
}

impl fmt::Display for EnrichmentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EnrichmentState::Available => "available",
            EnrichmentState::Unavailable => "unavailable",
            EnrichmentState::Degraded => "degraded",
        })
    }
}

/// Bounded enum for policy enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyMode {
    Audit,
    Enforce,
}

impl PolicyMode {
    /// Numeric encoding: 0=audit, 1=enforce.
    pub fn as_metric_value(self) -> i64 {
        match self {
            PolicyMode::Audit => 0,
            PolicyMode::Enforce => 1,
        }
    }
}

impl fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PolicyMode::Audit => "audit",
            PolicyMode::Enforce => "enforce",
        })
    }
}
