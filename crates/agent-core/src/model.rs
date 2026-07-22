// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::channel::EventPriority;
use event_abi::{DecodeError, EventKind, Header};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    ProcessFork,
    ProcessExecResult,
    ProcessExit,
    FileOpen,
    FileCreate,
    FileUnlink,
    FileRename,
    FileTruncate,
    NetworkConnect,
    NetworkAccept,
    NetworkState,
    DnsPacket,
    LsmDenyOwn,
    SyscallEnter,
    SyscallExit,
    Identity,
}
impl Kind {
    pub fn from_wire(kind: u8) -> Result<Self, DecodeError> {
        match kind {
            1 => Ok(Self::ProcessFork),
            2 => Ok(Self::ProcessExecResult),
            3 => Ok(Self::ProcessExit),
            4 => Ok(Self::FileOpen),
            5 => Ok(Self::FileCreate),
            6 => Ok(Self::FileUnlink),
            7 => Ok(Self::FileRename),
            8 => Ok(Self::FileTruncate),
            9 => Ok(Self::NetworkConnect),
            10 => Ok(Self::NetworkAccept),
            11 => Ok(Self::NetworkState),
            12 => Ok(Self::DnsPacket),
            15 => Ok(Self::LsmDenyOwn),
            25 => Ok(Self::SyscallEnter),
            26 => Ok(Self::SyscallExit),
            27 => Ok(Self::Identity),
            byte => Err(DecodeError::UnknownEventKind {
                byte,
                max: EventKind::MAX_DISCRIMINANT,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sequence(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonotonicNs(pub u64);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WallClock(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidTgid(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskStartNs(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupId(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootId(pub [u8; 16]);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventId(pub [u8; 16]);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceBundle {
    pub pid: Option<u64>,
    pub mnt: Option<u64>,
    pub net: Option<u64>,
    pub user: Option<u64>,
    pub uts: Option<u64>,
    pub ipc: Option<u64>,
    pub cgroup: Option<u64>,
    pub time: Option<u64>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    pub real_uid: Option<u32>,
    pub effective_uid: Option<u32>,
    pub saved_uid: Option<u32>,
    pub real_gid: Option<u32>,
    pub effective_gid: Option<u32>,
    pub saved_gid: Option<u32>,
    pub loginuid: Option<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerSensorPayload {
    Process { flags: u8 },
    File { flags: u8 },
    Network { flags: u8 },
    Dns { truncated: bool },
    Syscall { flags: u64 },
    Identity { flags: u32 },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvent {
    pub payload: Box<[u8]>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedEvent {
    pub header: Header,
    pub raw: RawEvent,
    pub kind: Kind,
    pub event_id: EventId,
    pub sequence: Sequence,
    pub monotonic_ns: MonotonicNs,
    pub wall_clock: WallClock,
    pub pid_tgid: PidTgid,
    pub task_start_ns: TaskStartNs,
    pub cgroup_id: CgroupId,
    pub boot_id: BootId,
    pub namespaces: NamespaceBundle,
    pub identity: Identity,
    pub payload: PerSensorPayload,
    pub priority: EventPriority,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEvent {
    KillSwitch(KillSwitchReason),
    Status,
    Rbac,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillSwitchReason(pub String);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSwitchState {
    Armed,
    Triggered,
}
