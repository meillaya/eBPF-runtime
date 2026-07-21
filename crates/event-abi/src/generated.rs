// src/generated.rs — event-abi
//
// HAND-WRITTEN MIRROR of `bpf/include/event_abi.h`. The C header is the
// single source of truth for the wire format; this file is the Rust-side
// mirror. `build.rs` records the SHA-256 of this file and the C header
// in `$OUT_DIR/event-abi.manifest.json`; `tests/manifest.rs` asserts the
// manifest matches the on-disk hashes, so any drift is caught at the
// `cargo nextest run -p event-abi` stage.
//
// This file is the deterministic fallback for hosts where bindgen/libclang
// are unavailable. The full hand-written content matches the C header
// verbatim in field order, type, and size; the Rust const_assert in
// `src/lib.rs` pins the size to exactly 96 bytes.
//
// We do NOT use bindgen here because:
//   1. bindgen requires libclang at build time, which the CI host may
//      not have. The hand-written file is portable.
//   2. The hand-written file is the deterministic source for the
//      `tests/manifest.rs` SHA-256 check. A bindgen regeneration would
//      change the SHA-256 each release; the test then becomes a
//      false-positive failure.
//   3. The C struct layout is verified by the C compiler's static_assert
//      at task 10 (build-time) plus the hand-written `const _: () = ...`
//      block in `src/lib.rs` (compile-time).
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(clippy::all)]

/// Schema major version. Bumped on a wire-incompatible change.
pub const SCHEMA_MAJOR: u32 = 1;
/// Schema minor version. Bumped on an additive, backward-compatible change.
pub const SCHEMA_MINOR: u32 = 0;
/// On-the-wire header length in bytes. MUST equal `size_of::<Header>()`.
pub const HEADER_LEN: usize = 96;
/// Bounded payload max in bytes. The parser rejects records whose
/// payload exceeds this constant.
pub const PAYLOAD_MAX: usize = 4096;

/// Every semantic event the platform can emit. The values match the C
/// `enum kernel_v1_event_kind` and the proto `EventKind` in
/// `proto/kernel/v1/events/v1/events.proto`. `repr(u8)` matches the
/// on-the-wire `uint8_t` slot at header offset 16.
///
/// TASK-12 (file sensor) EXTENSION (2026-07-21):
///   `FileTruncate = 8` was appended by task 12, shifting
///   `NetworkConnect` and every enum value above it by +1. The
///   shift was chosen over appending at value 16 because the brief
///   requires FILE_OPEN/CREATE/UNLINK/RENAME (already at 4..7 from
///   the original allocation) to remain contiguous with the
///   truncation mutation; the consumer-side `parse.rs` test was
///   updated to match the new positions, and the proto enum
///   (`proto/kernel/v1/events/v1/events.proto`) is updated as part
///   of the task-12 follow-up patch so all four layouts (C enum,
///   Rust enum, parse.rs match arms, proto enum) stay in lockstep.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    Unspecified = 0,
    ProcessFork = 1,
    ProcessExecResult = 2,
    ProcessExit = 3,
    FileOpen = 4,
    FileCreate = 5,
    FileUnlink = 6,
    FileRename = 7,
    FileTruncate = 8,
    NetworkConnect = 9,
    NetworkAccept = 10,
    NetworkState = 11,
    DnsPacket = 12,
    SyscallEnter = 13,
    SyscallExit = 14,
    LsmDenyOwn = 15,
    Identity = 16,
}

impl EventKind {
    /// Maximum accepted discriminant value. The parser rejects any
    /// `event_kind` byte above this.
    pub const MAX_DISCRIMINANT: u8 = Self::Identity as u8;
}

/// Validity bitmask. Each set bit means the corresponding identity
/// field is meaningful; a clear bit means the field is invalid. The
/// C struct only carries fields up to the 96-byte boundary; the
/// remaining valid bits (NS_USER/UTS/IPC/TIME, KFUNC_USED) are
/// forward-compat placeholders for the next minor revision.
///
/// TASK-12 (file sensor) EXTENSION (2026-07-21):
///   Added `FilePath`, `FileFlags`, `FileMode`, `FileDenySource`,
///   `FileErrno` at non-overlapping positions 0x8000..0x80000
///   (bits 15..19). See the matching block in
///   `bpf/include/event_abi.h` for the deviation rationale —
///   the brief-specified positions 0x0800..0x8000 would alias
///   `Processor`/`PayloadTrunc`/`Redacted`/`KfuncUsed` (bit 11..14).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Valid {
    BootId = 0x0001,
    CgroupId = 0x0002,
    PidTgid = 0x0004,
    NsPid = 0x0008,
    NsMnt = 0x0010,
    NsNet = 0x0020,
    NsUser = 0x0040,
    NsUts = 0x0080,
    NsIpc = 0x0100,
    NsTime = 0x0200,
    TaskStart = 0x0400,
    Processor = 0x0800,
    PayloadTrunc = 0x1000,
    Redacted = 0x2000,
    KfuncUsed = 0x4000,
    // TASK-12 additions — see header comment block in bpf/include/event_abi.h
    FilePath = 0x8000,
    FileFlags = 0x10000,
    FileMode = 0x20000,
    FileDenySource = 0x40000,
    FileErrno = 0x80000,
    // TASK-13 additions — see header comment block in
    // bpf/include/event_abi.h. The nine NET_* validity bits at
    // 0x100000..0x10000000 (bits 20..28) cover the network-sensor
    // payload fields (dst_ip, dst_port, cookie, family, peer_ip,
    // peer_port, fd, old_state, new_state).
    NetDstIp = 0x0010_0000,
    NetDstPort = 0x0020_0000,
    NetCookie = 0x0040_0000,
    NetFamily = 0x0080_0000,
    NetPeerIp = 0x0100_0000,
    NetPeerPort = 0x0200_0000,
    NetFd = 0x0400_0000,
    NetOldState = 0x0800_0000,
    NetNewState = 0x1000_0000,
}

/// Deny-source enum for FILE_OPEN events; mirrors the C
/// `enum kernel_v1_file_deny_source` (task 12).
///
/// - `None` — no observation; the default-zero value.
/// - `OwnLsm` — the BPF LSM `file_open` hook would have returned a
///   non-zero, but file.bpf.c is observation-only and never sets
///   this bit at emit time. The slot is reserved for the future
///   audit-only LSM task (per the approved plan's enforcement
///   contract).
/// - `Syscall` — the LSM hook was unavailable on the host and the
///   kprobe fallback (`__x64_sys_openat2` / `__arm64_sys_openat2`)
///   was the effective source of the recorded result.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileDenySource {
    None = 0,
    OwnLsm = 1,
    Syscall = 2,
}

/// Per-payload (file-result-namespace) flag bits. These live in the
/// FILE_* payload's `flags` byte, NOT in `kernel_v1_header.flags` —
/// each sensor reserves its own flag-byte namespace. `task 12` only
/// emits `FileResultHasErrno` (when the underlying syscall returned
/// a non-zero); `FileResultOwnLsm` is reserved for future LSM work
/// and is intentionally never set by file.bpf.c.
pub const FILE_RESULT_HAS_ERRNO: u8 = 0x01;
pub const FILE_RESULT_OWN_LSM: u8 = 0x02;

/// Per-payload (network-result-namespace) flag bits. TASK-13
/// reserves `NetResultFlagNonblocking` (O_NONBLOCK observed on the
/// file descriptor at connect-issue time) and
/// `NetResultFlagEinprogress` (connect syscall returned -EINPROGRESS).
/// Consumers MUST classify "connect succeeded" on the result event,
/// not on the EINPROGRESS flag — the flag is metadata for correlation
/// with socket-cookie state, not a success signal.
pub const NET_RESULT_FLAG_NONBLOCKING: u8 = 0x01;
pub const NET_RESULT_FLAG_EINPROGRESS: u8 = 0x02;

/// v1 producer MUST NOT set bits above bit 28.
pub const VALID_V1_ALLOWED_MASK: u32 = 0x1FFF_FFFF;

/// Network-payload layout constants. Mirror `bpf/include/event_abi.h`.
pub const NET_IPV6_LEN: usize = 16;
pub const NET_IPV4_LEN: usize = 4;
pub const NET_PAYLOAD_LEN: usize = 80;
/// Standard address families the network sensor records.
pub const AF_INET_VAL: u32 = 2;
pub const AF_INET6_VAL: u32 = 10;

/// Required bits for a v1 process event: pid_tgid + cgroup_id + boot_id + task_start.
pub const VALID_REQUIRED: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004 | 0x0000_0400;

/// flags byte bit assignments. trunc and redacted are independent.
pub const EVENT_FLAG_TRUNC: u8 = 0x01;
pub const EVENT_FLAG_REDACTED: u8 = 0x02;

/// On-the-wire header. Layout-fixed: 96 bytes, natural alignment,
/// native-endian. `#[repr(C)]` guarantees the field order matches the
/// C struct; the const_assert in `src/lib.rs` pins the size.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub schema_major: u32,
    pub schema_minor: u32,
    pub header_len: u32,
    pub record_len: u32,
    pub event_kind: u8,
    pub _pad0: [u8; 3],
    pub flags: u8,
    pub _pad1: [u8; 3],
    pub seq: u64,
    pub ts_monotonic_ns: u64,
    pub boot_id: [u8; 16],
    pub pid_tgid: u64,
    pub task_start_time_ns: u64,
    pub cgroup_id: u64,
    pub processor_id: u32,
    pub valids: u32,
    pub ns_pid: u64,
}

impl Header {
    /// Pure function: return the canonical C string name of an event
    /// kind. Matches the C `kernel_v1_event_kind_name()` exactly.
    pub fn kind_name(kind: u8) -> &'static str {
        match kind {
            0 => "UNSPECIFIED",
            1 => "PROCESS_FORK",
            2 => "PROCESS_EXEC_RESULT",
            3 => "PROCESS_EXIT",
            4 => "FILE_OPEN",
            5 => "FILE_CREATE",
            6 => "FILE_UNLINK",
            7 => "FILE_RENAME",
            8 => "FILE_TRUNCATE",
            9 => "NETWORK_CONNECT",
            10 => "NETWORK_ACCEPT",
            11 => "NETWORK_STATE",
            12 => "DNS_PACKET",
            13 => "SYSCALL_ENTER",
            14 => "SYSCALL_EXIT",
            15 => "LSM_DENY_OWN",
            16 => "IDENTITY",
            _ => "UNKNOWN_KIND",
        }
    }
}

/// TCP socket-state enum (mirrors `enum kernel_v1_tcp_state` in
/// `bpf/include/event_abi.h`). The integer values are stable
/// across C/Rust builds. `TcpNone = 0xff` is the "not a TCP socket"
/// sentry for UDP and RAW sockets where the kernel doesn't track a
/// TCP state.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum TcpState {
    Established = 1,
    SynSent = 2,
    SynRecv = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeWait = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
    NewSynRecv = 12,
    None = 0xff,
}

impl TcpState {
    /// Map a single byte from the wire to a `TcpState`. Unknown
    /// values round to `None` so the consumer never panics on a
    /// future kernel that adds a new TCP state.
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            12 => Self::NewSynRecv,
            _ => Self::None,
        }
    }
}

/// Network-payload layout (mirrors `struct kernel_v1_network_payload`
/// in `bpf/include/event_abi.h`). The structs use
/// `#[repr(C, packed)]` so the byte layout matches the C
/// `__attribute__((packed))` producer byte-for-byte. Consumers
/// dispatch on `header.event_kind` and read the relevant sub-fields.
/// `#[allow(dead_code)]` is applied because not every field is read
/// by every test.
///
/// Field access through these structs is `unsafe { core::ptr::read()
/// }` from an aligned scratch buffer — see the `process_events.rs`
/// decoder helpers. The struct shapes are the documented source of
/// truth for byte offsets; the size constants below mirror the C
/// `_Static_assert` checks.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct NetworkConnectAttempt {
    pub family: u32,
    pub _pad0: u32,
    /// 16-byte IP buffer; IPv4 stored in the leading 4 bytes,
    /// network byte order on the wire.
    pub dst_ip: [u8; NET_IPV6_LEN],
    /// Destination port in network byte order.
    pub dst_port: u32,
}

/// Mirror of `struct network_connect_result_payload`. The `errno_`
/// field carries the raw errno (zero on success; -ECONNREFUSED is
/// 111; -EINPROGRESS is 115).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct NetworkConnectResult {
    pub cookie: u64,
    pub family: u32,
    pub _pad0: u32,
    pub dst_ip: [u8; NET_IPV6_LEN],
    pub dst_port: u32,
    pub errno_: i32,
    pub flags: u8,
    pub _pad1: [u8; 3],
}

/// Mirror of `struct network_accept_attempt_payload`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct NetworkAcceptAttempt {
    pub peer_ip: [u8; NET_IPV6_LEN],
    pub peer_port: u32,
    pub _pad0: u32,
}

/// Mirror of `struct network_accept_result_payload`. The `fd`
/// field is meaningful only when >= 0; a refused accept leaves
/// `errno_` non-zero and `fd < 0`, and the sensor MUST NOT mark
/// `NetFd` valid in that case.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct NetworkAcceptResult {
    pub cookie: u64,
    pub family: u32,
    pub _pad0: u32,
    pub peer_ip: [u8; NET_IPV6_LEN],
    pub peer_port: u32,
    pub errno_: i32,
    pub fd: i32,
    pub _pad1: u32,
}

/// Mirror of `struct network_state_payload`. `old_state == new_state`
/// is reserved for the consumer to drop; the sensor emits only
/// genuine state transitions.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct NetworkState {
    pub cookie: u64,
    pub family: u32,
    pub _pad0: u32,
    pub old_state: u8,
    pub new_state: u8,
    pub _pad1: [u8; 6],
}

/// Compile-time size assertions. Mirror the C header's
/// `_Static_assert` lines. Drift between the Rust and C sizes
/// fails `cargo build`.
const _: () = {
    assert!(core::mem::size_of::<NetworkConnectAttempt>() == 28);
    assert!(core::mem::size_of::<NetworkConnectResult>() == 44);
    assert!(core::mem::size_of::<NetworkAcceptAttempt>() == 24);
    assert!(core::mem::size_of::<NetworkAcceptResult>() == 48);
    assert!(core::mem::size_of::<NetworkState>() == 24);
    assert!(NET_PAYLOAD_LEN == 80);
};
