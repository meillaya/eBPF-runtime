// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Turn raw ring buffer records into named fields.
//!
//! The header comes from `event_abi::parse`, which validates the schema
//! version, header length, and record length. The payload readers below
//! use the byte offsets defined by the C sensors. Every reader is
//! bounds checked and returns `None` when a field is absent.

use chrono::{DateTime, SecondsFormat, Utc};
use event_abi::{DnsPacket, Header, IdentityPayload, NetworkConnectAttempt, NetworkConnectResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

/// A process, file, network, DNS, syscall, identity, or LSM event with
/// the fields the sensors actually wrote.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Event {
    /// Wall clock derived from the boot time and the record timestamp.
    pub time: String,
    /// Sensor name, for example `process`.
    pub sensor: String,
    /// Event kind in the names the rule schema uses, for example
    /// `ProcessExec`.
    pub kind: String,
    /// Wire schema major version.
    pub schema_major: u16,
    /// Wire schema minor version.
    pub schema_minor: u16,
    /// Stable event id, lower-case hex.
    pub event_id: String,
    /// Boot id, lower-case hex.
    pub boot_id: String,
    /// Per-boot monotonic sequence number.
    pub seq: u64,
    /// Fields that were dropped or masked before persistence.
    #[serde(default)]
    pub redaction: RedactionFlags,
    /// Thread id.
    pub pid: u32,
    /// Thread group id.
    pub tgid: u32,
    /// Cgroup v2 id.
    pub cgroup_id: u64,
    /// Monotonic timestamp in nanoseconds. Not serialized.
    #[serde(skip)]
    pub monotonic_ns: u64,
    /// Task start time in nanoseconds since boot, when the sensor wrote it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_start_ns: Option<u64>,
    /// Binary path for a process event, or the file path for a file event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Source path for a rename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    /// Executable of the process that caused the event, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_exec: Option<String>,
    /// Argument vector captured from an exec, when the sensor wrote one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    /// Parent process id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    /// Child process id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_pid: Option<u32>,
    /// Process exit code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// True when the event belongs to a thread that is not a thread group
    /// leader.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<bool>,
    /// Header flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u8>,
    /// Open or create flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_flags: Option<u32>,
    /// File mode bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Truncate length.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    /// Network fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkInfo>,
    /// Syscall fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall: Option<SyscallInfo>,
    /// Identity fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityInfo>,
    /// DNS fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsInfo>,
    /// LSM fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lsm: Option<LsmInfo>,
}

/// Compatibility alias for callers that still use the decoder name.
pub type DecodedEvent = Event;

/// Fields that were dropped or masked before persistence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionFlags {
    /// A path was replaced by `[REDACTED]`.
    pub path_redacted: bool,
    /// An argument was masked or truncated.
    pub argv_redacted: bool,
    /// A free-form message was masked.
    pub message_redacted: bool,
}

/// A rule match produced by the agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Alert {
    /// Stable alert id, lower-case hex.
    pub alert_id: String,
    /// Rule id from the rule pack.
    pub rule_id: String,
    /// Severity, lower case.
    pub severity: String,
    /// Event that matched.
    pub event_id: String,
    /// Wall clock at emit time.
    pub fired_at: String,
    /// Redacted explanation.
    pub explanation: String,
    /// Cluster name.
    pub cluster: String,
    /// Node name.
    pub node_name: String,
}

/// A batch of events and alerts sent from an agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Batch {
    /// Stable batch id.
    pub batch_id: String,
    /// Agent id.
    pub agent_id: String,
    /// Cluster name.
    pub cluster: String,
    /// Node name.
    pub node_name: String,
    /// Agent generation.
    pub agent_generation: String,
    /// Boot id, lower-case hex.
    pub boot_id: String,
    /// Wire schema major version.
    pub schema_major: u16,
    /// Wire schema minor version.
    pub schema_minor: u16,
    /// Wall clock at batch creation.
    pub created_at: String,
    /// Events in the batch.
    pub events: Vec<Event>,
    /// Alerts in the batch.
    pub alerts: Vec<Alert>,
}

/// Network tuple and result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Address family, 2 for IPv4 and 10 for IPv6.
    pub family: u32,
    /// Destination or peer address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Destination or peer port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Socket cookie when the sensor wrote one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie: Option<u64>,
    /// Raw errno from a connect or accept result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    /// Accepted fd.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,
    /// Previous TCP state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_state: Option<u8>,
    /// New TCP state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_state: Option<u8>,
}

/// Syscall number, name, latency, and result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyscallInfo {
    /// Syscall number.
    pub nr: u64,
    /// Syscall name for common numbers.
    pub name: String,
    /// Flags from the sensor.
    pub flags: u64,
    /// Wall time in nanoseconds.
    pub latency_ns: u64,
    /// Return value.
    pub exit: i64,
}

/// Credentials and namespace ids.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityInfo {
    /// Real uid.
    pub uid: u32,
    /// Effective uid.
    pub euid: u32,
    /// Real gid.
    pub gid: u32,
    /// Effective gid.
    pub egid: u32,
    /// cgroup v2 id.
    pub cgroup_v2: u64,
    /// Mount namespace inode.
    pub ns_mnt: u64,
    /// Network namespace inode.
    pub ns_net: u64,
    /// User namespace inode.
    pub ns_user: u64,
}

/// DNS question.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsInfo {
    /// Question name.
    pub qname: String,
    /// Question type.
    pub qtype: u16,
    /// Query or response.
    pub direction: String,
    /// UDP or TCP.
    pub protocol: String,
}

/// LSM decision record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LsmInfo {
    /// Hook family byte.
    pub hook: u8,
    /// Decision byte.
    pub decision: u8,
    /// Selector, a path prefix or raw sockaddr bytes.
    pub selector: String,
    /// Errno the hook returned.
    pub errno: i32,
}

/// Wall clock conversion for monotonic kernel timestamps.
pub struct Clock {
    boot_unix_ns: i128,
}

impl Clock {
    /// Read `/proc/uptime` once and anchor the monotonic clock.
    pub fn new() -> Self {
        let uptime_ns = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|text| {
                let seconds = text.split_whitespace().next()?.parse::<f64>().ok()?;
                Some((seconds * 1_000_000_000.0) as i128)
            })
            .unwrap_or(0);
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as i128)
            .unwrap_or(0);
        Self {
            boot_unix_ns: now_ns - uptime_ns,
        }
    }

    /// Format a monotonic timestamp as RFC 3339 with microseconds.
    pub fn format(&self, monotonic_ns: u64) -> String {
        let unix_ns = self.boot_unix_ns + i128::from(monotonic_ns);
        let seconds = (unix_ns / 1_000_000_000) as i64;
        let nanos = (unix_ns % 1_000_000_000) as u32;
        DateTime::<Utc>::from_timestamp(seconds, nanos)
            .map(|time| time.to_rfc3339_opts(SecondsFormat::Micros, true))
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode one record from `sensor`.
pub fn decode(sensor: &str, bytes: &[u8], clock: &Clock) -> Result<DecodedEvent, DecodeFailure> {
    let event = event_abi::parse(bytes).map_err(|error| DecodeFailure::Abi(error.to_string()))?;
    let header = event.header;
    let payload = event.payload;
    let kind = kind_name(header.event_kind);

    let mut decoded = Event {
        time: clock.format(header.ts_monotonic_ns),
        sensor: sensor.to_string(),
        kind: kind.to_string(),
        schema_major: header.schema_major as u16,
        schema_minor: header.schema_minor as u16,
        event_id: event_id(&header, payload),
        boot_id: hex(&header.boot_id),
        seq: header.seq,
        redaction: RedactionFlags::default(),
        pid: (header.pid_tgid & 0xffff_ffff) as u32,
        tgid: (header.pid_tgid >> 32) as u32,
        cgroup_id: header.cgroup_id,
        monotonic_ns: header.ts_monotonic_ns,
        task_start_ns: None,
        path: None,
        old_path: None,
        process_exec: None,
        argv: None,
        parent_pid: None,
        child_pid: None,
        exit_code: None,
        thread: None,
        flags: Some(header.flags),
        open_flags: None,
        mode: None,
        length: None,
        network: None,
        syscall: None,
        identity: None,
        dns: None,
        lsm: None,
    };

    if header.valids & event_abi::Valid::TaskStart as u32 != 0 {
        decoded.task_start_ns = Some(header.task_start_time_ns);
    }

    match header.event_kind {
        1 => decode_fork(&mut decoded, payload),
        2 => decode_exec(&mut decoded, payload),
        3 => decode_exit(&mut decoded, payload),
        4..=8 => decode_file(&mut decoded, header, payload),
        9..=11 => decode_network(&mut decoded, header, payload),
        12 => decode_dns(&mut decoded, payload),
        15 => decode_lsm(&mut decoded, payload),
        25 | 26 => decode_syscall(&mut decoded, payload),
        27 => decode_identity(&mut decoded, payload),
        _ => {}
    }

    Ok(decoded)
}

/// Compute a stable event id from the header and payload.
fn event_id(header: &Header, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(header.boot_id);
    hasher.update(header.seq.to_le_bytes());
    hasher.update(header.ts_monotonic_ns.to_le_bytes());
    hasher.update([header.event_kind]);
    hasher.update((header.record_len as u64).to_le_bytes());
    hasher.update(payload);
    hex(&hasher.finalize())
}

/// Lower-case hex encoding.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Failure to decode a record.
#[derive(Debug, thiserror::Error)]
pub enum DecodeFailure {
    /// The ABI parser rejected the record.
    #[error("abi: {0}")]
    Abi(String),
}

fn decode_fork(event: &mut DecodedEvent, payload: &[u8]) {
    event.parent_pid = read_u64(payload, 0).map(|value| value as u32);
    event.child_pid = read_u64(payload, 8).map(|value| value as u32);
}

fn decode_exec(event: &mut DecodedEvent, payload: &[u8]) {
    let result = read_i32(payload, 0).unwrap_or(0);
    let path = read_cstring(payload, 8, 256);
    let argv_len = read_u32(payload, 264).unwrap_or(0) as usize;
    let mut argv = Vec::new();
    if argv_len > 0 && argv_len <= 256 && payload.len() >= 268 + argv_len {
        for part in payload[268..268 + argv_len].split(|byte| *byte == 0) {
            if part.is_empty() {
                continue;
            }
            if let Ok(text) = std::str::from_utf8(part) {
                argv.push(text.to_string());
            }
        }
    }

    event.path = (!path.is_empty()).then_some(path);
    event.exit_code = (result < 0).then_some(result);
    if !argv.is_empty() {
        event.argv = Some(argv);
    }
}

fn decode_exit(event: &mut DecodedEvent, payload: &[u8]) {
    let code = read_u32(payload, 0).unwrap_or(0);
    event.exit_code = Some(code as i32);
    event.thread = Some(event.flags.map(|flags| flags & 0x20 != 0).unwrap_or(false));
}

fn decode_file(event: &mut DecodedEvent, header: Header, payload: &[u8]) {
    let kind = header.event_kind;
    match kind {
        4 => {
            event.path = nonempty(read_cstring(payload, 16, 256));
            event.open_flags = read_u32(payload, 272);
            event.mode = read_u8(payload, 276).map(u32::from);
        }
        5 => {
            event.path = nonempty(read_cstring(payload, 16, 256));
            event.mode = read_u32(payload, 272);
        }
        6 => {
            event.path = nonempty(read_cstring(payload, 16, 256));
            event.open_flags = read_u32(payload, 272);
        }
        7 => {
            event.old_path = nonempty(read_cstring(payload, 16, 256));
            event.path = nonempty(read_cstring(payload, 272, 256));
        }
        8 => {
            event.path = nonempty(read_cstring(payload, 16, 256));
            event.length = read_u64(payload, 272);
        }
        _ => {}
    }
}

fn decode_network(event: &mut DecodedEvent, header: Header, payload: &[u8]) {
    let mut info = NetworkInfo {
        family: 0,
        address: None,
        port: None,
        cookie: None,
        errno: None,
        fd: None,
        old_state: None,
        new_state: None,
    };

    match header.event_kind {
        9 => {
            if let Some(attempt) = parse_struct::<NetworkConnectAttempt>(payload) {
                info.family = attempt.family;
                info.address = ip_string(attempt.family, &attempt.dst_ip);
                info.port = Some(attempt.dst_port as u16);
            }
            if payload.len() >= 44 {
                if let Some(result) = parse_struct::<NetworkConnectResult>(payload) {
                    if result.cookie != 0 {
                        info.cookie = Some(result.cookie);
                    }
                    if result.errno_ != 0 {
                        info.errno = Some(result.errno_);
                    }
                }
            }
        }
        10 => {
            let family = read_u32(payload, 8).unwrap_or(0);
            let address = payload.get(16..32).and_then(|ip| ip_string(family, ip));
            info.family = family;
            info.address = address;
            info.port = read_u32(payload, 32).map(|port| port as u16);
            info.cookie = read_u64(payload, 0);
            info.errno = read_i32(payload, 36);
            info.fd = read_i32(payload, 40);
        }
        11 => {
            info.family = read_u32(payload, 8).unwrap_or(0);
            info.cookie = read_u64(payload, 0);
            info.old_state = read_u8(payload, 16);
            info.new_state = read_u8(payload, 17);
        }
        _ => {}
    }

    event.network = Some(info);
}

fn decode_dns(event: &mut DecodedEvent, payload: &[u8]) {
    let packet = match parse_struct::<DnsPacket>(payload) {
        Some(packet) => packet,
        None => return,
    };
    let length = usize::from(packet.qname_len).min(event_abi::DNS_QNAME_MAX);
    let qname = read_cstring(payload, 8, length);
    event.dns = Some(DnsInfo {
        qname,
        qtype: packet.qtype,
        direction: if packet.direction == 0 {
            "query".to_string()
        } else {
            "response".to_string()
        },
        protocol: if packet.protocol == 0 {
            "udp".to_string()
        } else {
            "tcp".to_string()
        },
    });
}

fn decode_syscall(event: &mut DecodedEvent, payload: &[u8]) {
    let nr = read_u64(payload, 0).unwrap_or(0);
    event.syscall = Some(SyscallInfo {
        nr,
        name: syscall_name(nr).to_string(),
        flags: read_u64(payload, 8).unwrap_or(0),
        latency_ns: read_u64(payload, 16).unwrap_or(0),
        exit: read_i64(payload, 24).unwrap_or(0),
    });
}

fn decode_identity(event: &mut DecodedEvent, payload: &[u8]) {
    let identity = match parse_struct::<IdentityPayload>(payload) {
        Some(identity) => identity,
        None => return,
    };
    event.identity = Some(IdentityInfo {
        uid: identity.real_uid,
        euid: identity.effective_uid,
        gid: identity.real_gid,
        egid: identity.effective_gid,
        cgroup_v2: identity.cgroup_v2_default_id,
        ns_mnt: identity.ns_mnt,
        ns_net: identity.ns_net,
        ns_user: identity.ns_user,
    });
}

fn decode_lsm(event: &mut DecodedEvent, payload: &[u8]) {
    let selector_len = read_u32(payload, 40).unwrap_or(0) as usize;
    let selector = read_cstring(payload, 48, selector_len.min(256));
    event.lsm = Some(LsmInfo {
        hook: read_u8(payload, 16).unwrap_or(0),
        decision: read_u8(payload, 17).unwrap_or(0),
        selector,
        errno: read_i32(payload, 32).unwrap_or(0),
    });
}

/// Event kind name used in the JSON output and in `file.kind` rule values.
pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        1 => "ProcessFork",
        2 => "ProcessExec",
        3 => "ProcessExit",
        4 => "FileOpen",
        5 => "FileCreate",
        6 => "FileUnlink",
        7 => "FileRename",
        8 => "FileTruncate",
        9 => "NetworkConnect",
        10 => "NetworkAccept",
        11 => "NetworkState",
        12 => "DnsPacket",
        15 => "LsmDecision",
        25 => "SyscallEnter",
        26 => "SyscallExit",
        27 => "Identity",
        _ => "Unknown",
    }
}

fn ip_string(family: u32, bytes: &[u8]) -> Option<String> {
    match family {
        2 if bytes.len() >= 4 => {
            Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
        }
        10 if bytes.len() >= 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[..16]);
            Some(Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

fn parse_struct<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < std::mem::size_of::<T>() {
        return None;
    }
    // SAFETY: every caller uses a packed struct made only of integer
    // fields, so every bit pattern is valid and alignment is 1.
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            value.as_mut_ptr() as *mut u8,
            std::mem::size_of::<T>(),
        );
        Some(value.assume_init())
    }
}

fn read_u8(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset).copied()
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    read_u32(bytes, offset).map(|value| value as i32)
}

fn read_i64(bytes: &[u8], offset: usize) -> Option<i64> {
    read_u64(bytes, offset).map(|value| value as i64)
}

fn read_cstring(bytes: &[u8], offset: usize, max: usize) -> String {
    let slice = match bytes.get(offset..) {
        Some(slice) => slice,
        None => return String::new(),
    };
    let end = slice.len().min(max);
    let slice = &slice[..end];
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).to_string()
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn syscall_name(nr: u64) -> &'static str {
    match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        16 => "ioctl",
        21 => "access",
        22 => "pipe",
        32 => "dup",
        33 => "dup2",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        49 => "bind",
        50 => "listen",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        72 => "fcntl",
        80 => "chdir",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        85 => "creat",
        87 => "unlink",
        90 => "chmod",
        92 => "chown",
        101 => "ptrace",
        105 => "setuid",
        106 => "setgid",
        157 => "prctl",
        231 => "exit_group",
        257 => "openat",
        262 => "newfstatat",
        263 => "unlinkat",
        264 => "renameat",
        267 => "readlinkat",
        288 => "accept4",
        292 => "dup3",
        316 => "renameat2",
        321 => "bpf",
        322 => "execveat",
        435 => "clone3",
        437 => "openat2",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 96];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&96u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&((96 + payload.len()) as u32).to_le_bytes());
        bytes[16] = kind;
        bytes[24..32].copy_from_slice(&7u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&1_000_000u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&((42u64 << 32) | 42).to_le_bytes());
        bytes[72..80].copy_from_slice(&99u64.to_le_bytes());
        bytes[84..88].copy_from_slice(&(event_abi::Valid::PidTgid as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn decodes_process_exec_path() {
        let mut payload = vec![0u8; 268];
        payload[8..17].copy_from_slice(b"/bin/true");
        let bytes = record(2, &payload);
        let event = decode("process", &bytes, &Clock::new()).expect("decode");
        assert_eq!(event.kind, "ProcessExec");
        assert_eq!(event.pid, 42);
        assert_eq!(event.tgid, 42);
        assert_eq!(event.path.as_deref(), Some("/bin/true"));
    }

    #[test]
    fn decodes_file_open_path() {
        let mut payload = vec![0u8; 552];
        payload[16..32].copy_from_slice(b"/etc/shadow\0\0\0\0\0");
        let bytes = record(4, &payload);
        let event = decode("file", &bytes, &Clock::new()).expect("decode");
        assert_eq!(event.kind, "FileOpen");
        assert_eq!(event.path.as_deref(), Some("/etc/shadow"));
    }

    #[test]
    fn decodes_rename_paths() {
        let mut payload = vec![0u8; 552];
        payload[16..21].copy_from_slice(b"/old\0");
        payload[272..277].copy_from_slice(b"/new\0");
        let bytes = record(7, &payload);
        let event = decode("file", &bytes, &Clock::new()).expect("decode");
        assert_eq!(event.old_path.as_deref(), Some("/old"));
        assert_eq!(event.path.as_deref(), Some("/new"));
    }

    #[test]
    fn decodes_network_connect_attempt() {
        let mut payload = vec![0u8; 80];
        payload[0..4].copy_from_slice(&2u32.to_le_bytes());
        payload[8..12].copy_from_slice(&[10, 0, 0, 7]);
        payload[24..28].copy_from_slice(&443u32.to_le_bytes());
        let bytes = record(9, &payload);
        let event = decode("network", &bytes, &Clock::new()).expect("decode");
        let network = event.network.expect("network");
        assert_eq!(network.address.as_deref(), Some("10.0.0.7"));
        assert_eq!(network.port, Some(443));
    }

    #[test]
    fn decodes_syscall_number_and_name() {
        let mut payload = vec![0u8; 32];
        payload[0..8].copy_from_slice(&257u64.to_le_bytes());
        payload[16..24].copy_from_slice(&1234u64.to_le_bytes());
        let bytes = record(25, &payload);
        let event = decode("syscall", &bytes, &Clock::new()).expect("decode");
        let syscall = event.syscall.expect("syscall");
        assert_eq!(syscall.nr, 257);
        assert_eq!(syscall.name, "openat");
        assert_eq!(syscall.latency_ns, 1234);
    }

    #[test]
    fn rejects_short_record() {
        assert!(decode("process", &[0u8; 8], &Clock::new()).is_err());
    }

    #[test]
    fn clock_formats_rfc3339() {
        let clock = Clock {
            boot_unix_ns: 1_700_000_000_000_000_000,
        };
        let time = clock.format(1_500_000_000);
        assert!(time.starts_with("2023-11-14T22:13:21.500000Z"), "{time}");
    }
}
