// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Socket identity, family, state, and entry record types.

pub const NAMESPACE_KIND_COUNT: usize = 8;

pub const NS_PID: usize = 0;
pub const NS_MNT: usize = 1;
pub const NS_NET: usize = 2;
pub const NS_USER: usize = 3;
pub const NS_UTS: usize = 4;
pub const NS_IPC: usize = 5;
pub const NS_TIME: usize = 6;
pub const NS_CGROUP: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketIdentity {
    pub cgroup_id: u64,
    pub namespace_tuple: [u64; NAMESPACE_KIND_COUNT],
    pub cookie: u64,
}

impl SocketIdentity {
    pub fn new(cgroup_id: u64, namespace_tuple: [u64; NAMESPACE_KIND_COUNT], cookie: u64) -> Self {
        Self {
            cgroup_id,
            namespace_tuple,
            cookie,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketFamily {
    INET,
    INET6,
    UNIX,
    OTHER,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Connecting,
    Connected,
    Accepting,
    Accepted,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEntry {
    pub identity: SocketIdentity,
    pub pid_tgid: u64,
    pub state: SocketState,
    pub family: SocketFamily,
    pub dst_ip: [u8; 16],
    pub dst_port: u16,
    pub flags: u32,
    pub connect_attempt_seq: u64,
    pub connect_result_seq: u64,
    pub accept_result_seq: u64,
    pub generation: u32,
    pub fd: i32,
    pub closed_at: Option<u64>,
}
