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

/// v1 producer MUST NOT set bits above bit 19.
pub const VALID_V1_ALLOWED_MASK: u32 = 0x000F_FFFF;

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
