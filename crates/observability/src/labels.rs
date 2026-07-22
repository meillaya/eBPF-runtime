// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded label enums — the cardinality guarantee.

use std::fmt;

/// Bounded enum for event sources. Exactly six values; no unbounded strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Source {
    Process,
    File,
    Network,
    Dns,
    Syscall,
    Identity,
}

impl Source {
    /// All variants in canonical order.
    pub const ALL: [Source; 6] = [
        Source::Process,
        Source::File,
        Source::Network,
        Source::Dns,
        Source::Syscall,
        Source::Identity,
    ];
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Source::Process => "process",
            Source::File => "file",
            Source::Network => "network",
            Source::Dns => "dns",
            Source::Syscall => "syscall",
            Source::Identity => "identity",
        })
    }
}

/// Bounded enum for drop reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DropReason {
    RingFull,
    ChannelFull,
    DecodeError,
    PolicyDrop,
    EnrichmentError,
}

impl DropReason {
    pub const ALL: [DropReason; 5] = [
        DropReason::RingFull,
        DropReason::ChannelFull,
        DropReason::DecodeError,
        DropReason::PolicyDrop,
        DropReason::EnrichmentError,
    ];
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DropReason::RingFull => "ring_full",
            DropReason::ChannelFull => "channel_full",
            DropReason::DecodeError => "decode_error",
            DropReason::PolicyDrop => "policy_drop",
            DropReason::EnrichmentError => "enrichment_error",
        })
    }
}

/// Bounded enum for internal channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Channel {
    Data,
    Control,
}

impl Channel {
    pub const ALL: [Channel; 2] = [Channel::Data, Channel::Control];
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Channel::Data => "data",
            Channel::Control => "control",
        })
    }
}

/// Bounded enum for caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cache {
    ProcessGraph,
    SocketTable,
    Enrichment,
}

impl Cache {
    pub const ALL: [Cache; 3] = [Cache::ProcessGraph, Cache::SocketTable, Cache::Enrichment];
}

impl fmt::Display for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Cache::ProcessGraph => "process_graph",
            Cache::SocketTable => "socket_table",
            Cache::Enrichment => "enrichment",
        })
    }
}

/// Bounded enum for BPF programs (one per sensor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Program {
    Process,
    File,
    Network,
    Dns,
    Syscall,
    Identity,
}

impl Program {
    pub const ALL: [Program; 6] = [
        Program::Process,
        Program::File,
        Program::Network,
        Program::Dns,
        Program::Syscall,
        Program::Identity,
    ];
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Program::Process => "process",
            Program::File => "file",
            Program::Network => "network",
            Program::Dns => "dns",
            Program::Syscall => "syscall",
            Program::Identity => "identity",
        })
    }
}

/// Bounded enum for enrichment providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Provider {
    Containerd,
    Crio,
    Docker,
    Kubernetes,
}

impl Provider {
    pub const ALL: [Provider; 4] = [
        Provider::Containerd,
        Provider::Crio,
        Provider::Docker,
        Provider::Kubernetes,
    ];
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Provider::Containerd => "containerd",
            Provider::Crio => "crio",
            Provider::Docker => "docker",
            Provider::Kubernetes => "kubernetes",
        })
    }
}
