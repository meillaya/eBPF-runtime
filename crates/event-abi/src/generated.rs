// src/generated.rs: event-abi
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
//      at build time plus the hand-written `const _: () = ...`
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
/// `enum kernel_v1_event_kind`. `repr(u8)` matches the
/// on-the-wire `uint8_t` slot at header offset 16.
///
/// File sensor extension:
///   `FileTruncate = 8` was appended later, shifting
///   `NetworkConnect` and every enum value above it by +1. The
///   shift was chosen over appending at value 16 because the format
///   requires FILE_OPEN/CREATE/UNLINK/RENAME (already at 4..7 from
///   the original allocation) to remain contiguous with the
///   truncation mutation. The C enum, the Rust enum, and the
///   `parse.rs` match arms stay in lockstep.
///
/// Identity sensor extension:
///   `Identity` re-pinned from 16 to 27 to clear the aliasing
///   collision with the prior reserved 16 slot. The committed
///   earlier `.binpb` fixtures still use the same
///   discriminants (1..12, 15, 25, 26), so the wire-format
///   compatibility is preserved. The C-side enum was updated
///   in lockstep; the SHA-256 manifest check `event-abi/build.rs`
///   enforces agreement between the two sides.
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
    LsmDenyOwn = 15,
    SyscallEnter = 25,
    SyscallExit = 26,
    Identity = 27,
}

impl EventKind {
    /// Maximum accepted discriminant value. The parser rejects any
    /// `event_kind` byte above this.
    pub const MAX_DISCRIMINANT: u8 = Self::Identity as u8;

    pub const fn is_known(byte: u8) -> bool {
        matches!(byte, 1..=12 | 15 | 25..=27)
    }
}

/// Validity bitmask. Each set bit means the corresponding identity
/// field is meaningful; a clear bit means the field is invalid. The
/// C struct only carries fields up to the 96-byte boundary; the
/// remaining valid bits (NS_USER/UTS/IPC/TIME, KFUNC_USED) are
/// forward-compat placeholders for the next minor revision.
///
/// File sensor extension:
///   Added `FilePath`, `FileFlags`, `FileMode`, `FileDenySource`,
///   `FileErrno` at non-overlapping positions 0x8000..0x80000
///   (bits 15..19). See the matching block in
///   `bpf/include/event_abi.h` for the deviation rationale.
///   The documented positions 0x0800..0x8000 would alias
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
    // File sensor additions: see header comment block in bpf/include/event_abi.h
    FilePath = 0x8000,
    FileFlags = 0x10000,
    FileMode = 0x20000,
    FileDenySource = 0x40000,
    FileErrno = 0x80000,
    // Network sensor additions: see header comment block in
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
    // DNS sensor DNS validity bits are NOT added to this enum because
    // their documented positions (0x02000000..0x40000000, bits
    // 25..30) overlap with the NET_* variants above; a Rust
    // `#[repr(u32)]` enum disallows duplicate discriminants
    // (E0081). The DNS bits exist as `pub const`s in the
    // `dns_valid` module below so consumers can do
    // `event.header.valids & dns_valid::QNAME != 0`. See the
    // deviation note in `bpf/include/event_abi.h` for the C-side
    // rationale; the consumer contract is identical because the
    // DNS_* and NETWORK_* event kinds carry different
    // `event_kind` discriminators.
}

/// Deny-source enum for FILE_OPEN events; mirrors the C
/// `enum kernel_v1_file_deny_source`.
///
/// - `None`: no observation; the default-zero value.
/// - `OwnLsm`: the BPF LSM `file_open` hook would have returned a
///   non-zero, but file.bpf.c is observation-only and never sets
///   this bit at emit time. The slot is reserved for the future
///   audit-only LSM path (per the enforcement
///   contract).
/// - `Syscall`: the LSM hook was unavailable on the host and the
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
/// FILE_* payload's `flags` byte, NOT in `kernel_v1_header.flags`.
/// each sensor reserves its own flag-byte namespace. The file sensor only
/// emits `FileResultHasErrno` (when the underlying syscall returned
/// a non-zero); `FileResultOwnLsm` is reserved for future LSM work
/// and is intentionally never set by file.bpf.c.
pub const FILE_RESULT_HAS_ERRNO: u8 = 0x01;
pub const FILE_RESULT_OWN_LSM: u8 = 0x02;

/// Per-payload (network-result-namespace) flag bits. The network sensor
/// reserves `NetResultFlagNonblocking` (O_NONBLOCK observed on the
/// file descriptor at connect-issue time) and
/// `NetResultFlagEinprogress` (connect syscall returned -EINPROGRESS).
/// Consumers MUST classify "connect succeeded" on the result event,
/// not on the EINPROGRESS flag. The flag is metadata for correlation
/// with socket-cookie state, not a success signal.
pub const NET_RESULT_FLAG_NONBLOCKING: u8 = 0x01;
pub const NET_RESULT_FLAG_EINPROGRESS: u8 = 0x02;

/// v1 producer MUST NOT set bits above bit 30.
///
/// WAS: `0x0000_7FFF` (15 bits). Widened to `0x0001_FFFF`
/// for the FILE_* bits 15..19, to `0x1FFF_FFFF` for the NET_* bits
/// 20..28, and to `0x7FFF_FFFF` for the DNS_* bits 25..30. See the
/// matching block in
/// `bpf/include/event_abi.h` for the deviation note on the bit
/// positions documented in the header.
pub const VALID_V1_ALLOWED_MASK: u32 = 0x7FFF_FFFF;

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
            15 => "LSM_DENY_OWN",
            25 => "SYSCALL_ENTER",
            26 => "SYSCALL_EXIT",
            27 => "IDENTITY",
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
/// }` from an aligned scratch buffer. See the `process_events.rs`
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

// ---------------------------------------------------------------------------
// DNS packet sensor: bounded cleartext-only capture
// ---------------------------------------------------------------------------

/// DNS validity bits as `pub const`s. The Rust `enum Valid`
/// cannot host these (the documented positions alias the
/// `Net*` variants and a Rust `#[repr(u32)]` enum rejects
/// duplicate discriminants as E0081). Consumers do
/// `event.header.valids & dns_valid::QNAME != 0` for the same
/// effect `verify_field` provides on the non-DNS bits. The
/// bit positions are the documented 0x02000000..0x40000000
/// (bits 25..30) and they alias the `NetPeerPort`, `NetFd`,
/// `NetOldState`, `NetNewState` positions by design; the
/// consumer dispatcher in `event_abi::parse` keys on
/// `event_kind` first, so the same numeric bit carries different
/// meaning for `DNS_PACKET` vs `NETWORK_*` events.
pub mod dns_valid {
    /// QNAME was decoded and fits in `DNS_QNAME_MAX`.
    pub const QNAME: u32 = 0x0200_0000;
    /// QTYPE field is valid (first question's QTYPE was decoded).
    pub const QTYPE: u32 = 0x0400_0000;
    /// DNS header flags word (16-bit) was decoded.
    pub const FLAGS: u32 = 0x0800_0000;
    /// Header counts (qdcount/ancount/nscount/arcount) were decoded.
    pub const COUNTS: u32 = 0x1000_0000;
    /// Destination IP family + bytes were decoded from the skb.
    pub const DST_IP: u32 = 0x2000_0000;
    /// `parsed_truncation_reason != NONE`: payload was clipped.
    pub const PAYLOAD_TRUNC: u32 = 0x4000_0000;
}

/// Maximum QNAME length per RFC 1035 §2.3.4 (one byte per label
/// length, plus the final 0 byte). The BPF sensor clamps
/// `qname_len` to this constant; anything longer is recorded as
/// `KERNEL_V1_DNS_TRUNC_NAME_TOO_LONG` and the
/// `DnsPayloadTrunc` validity bit is set.
pub const DNS_QNAME_MAX: usize = 253;

/// DNS packet payload length. The sensor always writes exactly
/// this many bytes; unused fields are zero, the corresponding
/// validity bit is clear.
pub const DNS_PAYLOAD_LEN: usize = 320;

/// DNS packet directional discriminator.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum DnsDirection {
    Query = 0,
    Response = 1,
}

/// DNS packet transport-protocol discriminator.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum DnsProtocol {
    Udp = 0,
    Tcp = 1,
}

/// DNS packet parsed-truncation-reason enum. Set by the sensor
/// when it clipped the qname (`NAME_TOO_LONG`), the header was
/// shorter than 12 bytes (`HEADER_TOO_SHORT`), or fell out of a
/// recoverable BPF-error path (`INTERNAL_BPF_ERROR`). On a happy
/// path the value is `None`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum DnsTruncationReason {
    None = 0,
    NameTooLong = 1,
    HeaderTooShort = 2,
    InternalBpfError = 3,
}

impl DnsDirection {
    /// Map a single byte from the wire to a `DnsDirection`. Unknown
    /// values round to `Query` because the default-zero value is
    /// the documented Query sentinel.
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Response,
            _ => Self::Query,
        }
    }
}

impl DnsProtocol {
    /// Map a single byte from the wire to a `DnsProtocol`. Unknown
    /// values round to `Udp` because the default-zero value is
    /// the documented UDP sentinel.
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Tcp,
            _ => Self::Udp,
        }
    }
}

impl DnsTruncationReason {
    /// Map a single byte from the wire to a `DnsTruncationReason`.
    /// Unknown values round to `InternalBpfError` so the consumer
    /// records an explicit truncation reason rather than silently
    /// accepting the default-zero `None`.
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::None,
            1 => Self::NameTooLong,
            2 => Self::HeaderTooShort,
            _ => Self::InternalBpfError,
        }
    }

    /// `True` iff the truncation flag (and the `DnsPayloadTrunc`
    /// validity bit) should be set. Pairs with the C
    /// `KERNEL_V1_DNS_TRUNC_*` enum at the producer side.
    pub fn is_truncation(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Mirror of `struct kernel_v1_dns_packet_payload` in
/// `bpf/include/event_abi.h`. The struct uses `#[repr(C, packed)]`
/// so the byte layout matches the C `__attribute__((packed))`
/// producer byte-for-byte. Consumers dispatch on
/// `header.event_kind` (DNS_PACKET) and read these fields; unused
/// fields in any one event are zero and the matching validity bit
/// is clear. The size is 320 bytes by `_Static_assert` in the C
/// header.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct DnsPacket {
    pub transaction_id: u16,
    pub flags: u16,
    pub qtype: u16,
    pub qname_len: u16,
    pub qname_bytes: [u8; DNS_QNAME_MAX],
    pub answer_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
    pub direction: u8,
    pub protocol: u8,
    pub family: u8,
    pub parsed_truncation_reason: u8,
    pub _pad0: [u8; 3],
    pub dst_ip: [u8; NET_IPV6_LEN],
    pub dst_port: u16,
    pub _pad1: [u8; 28],
}

pub mod syscall_valid {
    pub const NR: u64 = 0x4000_0000;
    pub const LATENCY: u64 = 0x8000_0000;
    pub const FLAGS: u64 = 0x1_0000_0000;
    pub const NOT_ALLOWED: u64 = 0x2_0000_0000;
    pub const NO_RETURN_RESULT: u64 = 0x4_0000_0000;
}

pub const SYSCALL_FLAG_IS_EXEC: u64 = 0x01;
pub const SYSCALL_FLAG_NO_RETURN: u64 = 0x02;
pub const SYSCALL_FLAG_INTERRUPTED: u64 = 0x04;
pub const SYSCALL_FLAG_RESTARTED: u64 = 0x08;
pub const SYSCALL_FLAG_FAILED: u64 = 0x10;
pub const SYSCALL_FLAG_NOT_ALLOWED: u64 = 0x20;
pub const SYSCALL_FLAG_COMPAT: u64 = 0x40;
pub const SYSCALL_NR_MAX: usize = 600;
pub const SYSCALL_BUCKETS: usize = 64;
pub const SYSCALL_PAYLOAD_LEN: usize = 32;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallEventPayload {
    pub syscall_nr: u64,
    pub flags: u64,
    pub latency_ns: u64,
    pub exit_code: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallHistogramBucket {
    pub bin_count_log2: [u64; SYSCALL_BUCKETS],
    pub sum_ns: u64,
    pub count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub interrupted_count: u64,
    pub restarted_count: u64,
    pub no_return_count: u64,
}

// ---------------------------------------------------------------------------
// Identity sensor: cgroup / namespace / credential facts
// ---------------------------------------------------------------------------

/// Identity validity bits as `pub const`s. The Rust `enum Valid`
/// cannot host these (the documented positions 0x80000000..
/// 0x4000000000000 are above the 32-bit `header.valids` field, so
/// they live in a parallel identity-side validity bitmask).
/// Consumers do `event.identity.validity & identity_valid::UID != 0`
/// for the same effect `verify_field` provides on the non-IDENTITY
/// bits. The bit positions are the documented
/// `KERNEL_V1_VALID_IDENTITY_*` constants from
/// `bpf/include/event_abi.h`. See the deviation note in
/// `bpf/include/event_abi.h` for the rationale that the identity
/// validity bits live on the payload side, not in `header.valids`.
pub mod identity_valid {
    pub const UID: u64 = 0x0000_0000_8000_0000;
    pub const GID: u64 = 0x0000_0001_0000_0000;
    pub const LOGINUID: u64 = 0x0000_0002_0000_0000;
    pub const CGROUP_V2: u64 = 0x0000_0004_0000_0000;
    pub const CGROUP_V1: u64 = 0x0000_0008_0000_0000;
    pub const NS_PID: u64 = 0x0000_0010_0000_0000;
    pub const NS_MNT: u64 = 0x0000_0020_0000_0000;
    pub const NS_NET: u64 = 0x0000_0040_0000_0000;
    pub const NS_USER: u64 = 0x0000_0080_0000_0000;
    pub const NS_UTS: u64 = 0x0000_0100_0000_0000;
    pub const NS_IPC: u64 = 0x0000_0200_0000_0000;
    pub const NS_TIME: u64 = 0x0000_0400_0000_0000;
    pub const NS_CGROUP: u64 = 0x0000_0800_0000_0000;
    pub const TASK_START: u64 = 0x0000_1000_0000_0000;
    pub const BOOT_ID: u64 = 0x0000_2000_0000_0000;
    pub const FLAGS: u64 = 0x0000_4000_0000_0000;
}

/// Identity-sensor payload layout constants. Mirror
/// `bpf/include/event_abi.h::KERNEL_V1_IDENTITY_*`.
pub const IDENTITY_PAYLOAD_LEN: usize = 96;
pub const IDENTITY_TAIL_LEN: usize = 56;
pub const IDENTITY_RECORD_LEN: usize = IDENTITY_PAYLOAD_LEN + IDENTITY_TAIL_LEN;

/// Identity-payload flag bits. Mirror
/// `KERNEL_V1_IDENTITY_FLAG_*` in `bpf/include/event_abi.h`.
pub const IDENTITY_FLAG_LOGINUID_INVALID: u32 = 0x01;
pub const IDENTITY_FLAG_CGROUP_V1_HIERARCHY: u32 = 0x02;
pub const IDENTITY_FLAG_COMPAT: u32 = 0x04;

/// Mirror of `struct kernel_v1_identity_event_payload` in
/// `bpf/include/event_abi.h`. 96-byte primary payload that the
/// identity sensor writes immediately after the 96-byte
/// `kernel_v1_header`. The byte layout is exact: the
/// `#[repr(C, packed)]` annotation guarantees the field order and
/// absence of trailing padding matches the C producer byte-for-byte.
/// Consumers dispatch on `header.event_kind == IDENTITY` and read
/// these fields; missing fields are zero, the matching
/// IDENTITY_* validity bit is clear.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityPayload {
    pub pid_tgid: u64,
    pub real_uid: u32,
    pub effective_uid: u32,
    pub saved_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub saved_gid: u32,
    pub loginuid: u32,
    pub cgroup_v2_default_id: u64,
    pub cgroup_v1_hierarchy_id: u64,
    pub flags: u32,
    pub _pad0: u32,
    pub ns_pid_for_children: u64,
    pub ns_mnt: u64,
    pub ns_net: u64,
    pub ns_user: u64,
    pub _pad1: u32,
}

/// Mirror of `struct kernel_v1_identity_event_payload_tail` in
/// `bpf/include/event_abi.h`. 56-byte overflow payload that
/// follows the primary identity payload in the same ring-buffer
/// record. The byte layout is exact: `#[repr(C, packed)]`
/// guarantees no padding. Consumers read the trailing fields
/// (16-byte boot id, four namespace inodes, task-start
/// timestamp) from this struct.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityPayloadTail {
    pub boot_id: [u8; 16],
    pub ns_uts: u64,
    pub ns_ipc: u64,
    pub ns_time: u64,
    pub ns_cgroup: u64,
    pub task_start_time_ns: u64,
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

    // DNS sensor additions: DNS payload mirrors.
    assert!(DNS_QNAME_MAX == 253);
    assert!(DNS_PAYLOAD_LEN == 320);
    assert!(core::mem::size_of::<DnsPacket>() == 320);
    assert!(core::mem::size_of::<SyscallEventPayload>() == SYSCALL_PAYLOAD_LEN);
    assert!(core::mem::size_of::<SyscallHistogramBucket>() == 568);

    // Identity sensor additions: identity payload mirrors.
    assert!(IDENTITY_PAYLOAD_LEN == 96);
    assert!(IDENTITY_TAIL_LEN == 56);
    assert!(IDENTITY_RECORD_LEN == 152);
    assert!(core::mem::size_of::<IdentityPayload>() == IDENTITY_PAYLOAD_LEN);
    assert!(core::mem::size_of::<IdentityPayloadTail>() == IDENTITY_TAIL_LEN);
};
