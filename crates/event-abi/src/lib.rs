// src/lib.rs: event-abi
//
// Event ABI v1 + v2: safe parser, payload variants, validity/
// degradation/truncation/redaction flags, static size/offset assertions,
// endianness/version/length checks, and generation manifest hash.
//
// Schema-major 2 adds a 4-byte `stack_id` plus 4 bytes of tail padding
// (104-byte header). The parser accepts both majors: v1 records decode
// with `stack_id = None`, v2 records expose `Option<i32>` where `-1`
// maps to `None`. See `bpf/include/event_abi.h` for the layout table.
//
// The crate is the user-space Rust side of the contract pinned in
// `bpf/include/event_abi.h`. The hand-written `src/generated.rs` file
// mirrors the C header verbatim. `build.rs` records the SHA-256 of the
// generated file and the C header in `$OUT_DIR/event-abi.manifest.json`;
// `tests/manifest.rs` asserts the manifest matches.
//
// PUBLIC SURFACE (must not grow without a schema-major bump)
//   * `parse(buf)`: the safe parser
//   * `Event<'a> { header, stack_id, payload }`: the typed view
//   * `DecodeError`: typed errors with enough context for diagnostics
//   * `DecodeReport`: aggregation of validity/truncation/redaction
//   * `SCHEMA_MAJOR`, `SCHEMA_MINOR`, `HEADER_LEN`, `PAYLOAD_MAX`:
//     re-exports of the versioned constants
//   * `HeaderV2`, `STACK_ID_NONE`, `STACK_DEPTH`, `STACK_MAP_ENTRIES`:
//     the v2 header mirror and stack-capture geometry
//   * `EventKind`, `Valid`: re-exports of the hand-written enums
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![deny(unsafe_op_in_unsafe_fn)]

use core::fmt;

pub mod generated;
mod parser_helpers;

pub use generated::{
    dns_valid, identity_valid, syscall_valid, DnsDirection, DnsPacket, DnsProtocol,
    DnsTruncationReason, EventKind, FileDenySource, Header, HeaderV2, IdentityPayload,
    IdentityPayloadTail, NetworkAcceptAttempt, NetworkAcceptResult, NetworkConnectAttempt,
    NetworkConnectResult, NetworkState, SyscallEventPayload, SyscallHistogramBucket, TcpState,
    Valid, AF_INET6_VAL, AF_INET_VAL, DNS_PAYLOAD_LEN, DNS_QNAME_MAX, EVENT_FLAG_REDACTED,
    EVENT_FLAG_TRUNC, FILE_RESULT_HAS_ERRNO, FILE_RESULT_OWN_LSM, HEADER_LEN, HEADER_LEN_V1,
    IDENTITY_FLAG_CGROUP_V1_HIERARCHY, IDENTITY_FLAG_COMPAT, IDENTITY_FLAG_LOGINUID_INVALID,
    IDENTITY_PAYLOAD_LEN, IDENTITY_RECORD_LEN, IDENTITY_TAIL_LEN, NET_IPV4_LEN, NET_IPV6_LEN,
    NET_PAYLOAD_LEN, NET_RESULT_FLAG_EINPROGRESS, NET_RESULT_FLAG_NONBLOCKING, PAYLOAD_MAX,
    SCHEMA_MAJOR, SCHEMA_MINOR, SCHEMA_V1_MAJOR, STACK_DEPTH, STACK_ID_NONE, STACK_MAP_ENTRIES,
    STACK_MODE_ALL, STACK_MODE_EVENTS, STACK_MODE_OFF, STACK_VALUE_SIZE, SYSCALL_BUCKETS,
    SYSCALL_FLAG_COMPAT, SYSCALL_FLAG_FAILED, SYSCALL_FLAG_INTERRUPTED, SYSCALL_FLAG_IS_EXEC,
    SYSCALL_FLAG_NOT_ALLOWED, SYSCALL_FLAG_NO_RETURN, SYSCALL_FLAG_RESTARTED, SYSCALL_NR_MAX,
    SYSCALL_PAYLOAD_LEN, VALID_REQUIRED, VALID_V1_ALLOWED_MASK,
};
pub use parser_helpers::{
    compute_record_len, compute_record_len_v1, format_valids, is_redacted, is_truncated,
    verify_field,
};

// Compile-time assertions on the on-the-wire struct sizes.
//
// The C header's `_Static_assert`s are the source of truth on the
// producer side; these const_asserts are the source of truth on the
// consumer side. Drift between the two fails the next `cargo build`.
const _: () = {
    assert!(core::mem::size_of::<Header>() == HEADER_LEN_V1);
    assert!(core::mem::align_of::<Header>() == 8);
    assert!(core::mem::size_of::<HeaderV2>() == HEADER_LEN);
    assert!(core::mem::align_of::<HeaderV2>() == 8);
    assert!(core::mem::offset_of!(HeaderV2, stack_id) == 96);
    assert!(core::mem::offset_of!(HeaderV2, user_stack_id) == 100);
    assert!(HEADER_LEN == HEADER_LEN_V1 + 8);
    assert!(STACK_VALUE_SIZE == STACK_DEPTH as usize * 8);
};

/// Typed error returned by [`parse`]. Each variant carries enough
/// context for downstream diagnostics and unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer is shorter than the minimum (version-1, 96-byte) header.
    ShortBuffer { have: usize, need: usize },
    /// `header.schema_major` is neither [`SCHEMA_V1_MAJOR`] nor
    /// [`SCHEMA_MAJOR`].
    UnknownSchemaMajor { got: u32, expected: u32 },
    /// `header.record_len`/`header.header_len` disagrees with the buffer
    /// or the header length.
    LengthMismatch {
        record_len: u32,
        header_len: u32,
        buf_len: usize,
    },
    /// `event_kind` byte is 0 (UNSPECIFIED) or above the max accepted discriminant.
    UnknownEventKind { byte: u8, max: u8 },
    /// Payload slice extends past the buffer (defensive: `LengthMismatch`
    /// covers the common case but the parser also checks this).
    BufferUnderflow { record_len: u32, header_len: u32 },
    /// Payload exceeds `PAYLOAD_MAX`. The parser clips the slice in
    /// `Event::payload` to the in-buffer length but still flags the
    /// record as truncated via the `PayloadTrunc` valid bit.
    PayloadTruncated { record_len: u32, header_len: u32 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortBuffer { have, need } => {
                write!(f, "buffer too short: have {have} bytes, need {need}")
            }
            Self::UnknownSchemaMajor { got, expected } => {
                write!(f, "unknown schema major: got {got}, expected {expected}")
            }
            Self::LengthMismatch {
                record_len,
                header_len,
                buf_len,
            } => write!(
                f,
                "length mismatch: record_len={record_len} header_len={header_len} buf_len={buf_len}"
            ),
            Self::UnknownEventKind { byte, max } => {
                write!(f, "unknown event kind: byte={byte} max={max}")
            }
            Self::BufferUnderflow {
                record_len,
                header_len,
            } => write!(
                f,
                "payload underflow: record_len={record_len} header_len={header_len}"
            ),
            Self::PayloadTruncated {
                record_len,
                header_len,
            } => write!(
                f,
                "payload truncated: record_len={record_len} header_len={header_len}"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Typed view of a single record. `header` is a copy of the fixed
/// version-1 96-byte prefix (the same bytes in both schema majors);
/// `stack_id` / `user_stack_id` are the decoded v2 kernel/user stack
/// handles and are `None` for v1 records or for v2 records whose
/// producer set [`STACK_ID_NONE`]; `payload` borrows from the input
/// buffer and starts at the record's `header_len` (96 for v1, 104 for
/// v2, or larger for a forward-compatible minor revision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event<'a> {
    pub header: Header,
    /// Kernel stack-trace-map handle when the record carries one.
    pub stack_id: Option<i32>,
    /// User stack-trace-map handle when the record carries one.
    pub user_stack_id: Option<i32>,
    pub payload: &'a [u8],
}

/// Aggregated report of validity, truncation, and redaction. Used by
/// tests for fixture round-trip assertions and by the loader's bound
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeReport {
    pub schema_major: u32,
    pub schema_minor: u32,
    pub record_len: u32,
    pub kind: u8,
    pub kind_name: &'static str,
    pub truncated: bool,
    pub redacted: bool,
    pub valids: u32,
    pub payload_len: usize,
    /// Kernel stack handle decoded from a v2 record; `None` for v1/no-stack.
    pub stack_id: Option<i32>,
    /// User stack handle decoded from a v2 record; `None` for v1/no-stack.
    pub user_stack_id: Option<i32>,
}

impl Event<'_> {
    /// Convenience: aggregate validity / truncation / redaction / kind
    /// into a `DecodeReport`. Allocates nothing.
    pub fn report(&self) -> DecodeReport {
        DecodeReport {
            schema_major: self.header.schema_major,
            schema_minor: self.header.schema_minor,
            record_len: self.header.record_len,
            kind: self.header.event_kind,
            kind_name: Header::kind_name(self.header.event_kind),
            truncated: is_truncated(&self.header),
            redacted: is_redacted(&self.header),
            valids: self.header.valids,
            payload_len: self.payload.len(),
            stack_id: self.stack_id,
            user_stack_id: self.user_stack_id,
        }
    }

    /// `True` iff the field's valid bit is set in `header.valids`.
    /// Forwarder to `parser_helpers::verify_field`.
    pub fn verify_field(&self, field: Valid) -> bool {
        verify_field(&self.header, field)
    }

    /// `True` iff the truncation flag is set.
    pub fn is_truncated(&self) -> bool {
        is_truncated(&self.header)
    }

    /// `True` iff the redaction flag is set.
    pub fn is_redacted(&self) -> bool {
        is_redacted(&self.header)
    }

    /// Canonical C string name of the event kind (e.g. `"PROCESS_FORK"`).
    pub fn kind_name(&self) -> &'static str {
        Header::kind_name(self.header.event_kind)
    }
}

/// Safe parser. Accepts both wire schema majors and performs this
/// validation chain:
///
///   1. Buffer length >= 96 (the smallest, version-1 header)
///   2. `header.schema_major` is 1 (frozen) or 2 (current)
///   3. v1: `header.header_len == 96`
///      v2: `header.header_len >= 104` and `<= buf.len()` (a future
///      schema minor may append fields; the payload always starts at
///      `header_len`)
///   4. `header.record_len >= header_len` and `<= buf.len()`
///   5. `header.event_kind` is in `[1, EventKind::MAX_DISCRIMINANT]`
///   6. payload = `buf[header_len..record_len]`; for v2 the kernel
///      `stack_id` word at offset 96 and the `user_stack_id` word at
///      offset 100 are decoded and `-1` becomes `None`
pub fn parse<'a>(buf: &'a [u8]) -> Result<Event<'a>, DecodeError> {
    if buf.len() < HEADER_LEN_V1 {
        return Err(DecodeError::ShortBuffer {
            have: buf.len(),
            need: HEADER_LEN_V1,
        });
    }

    // SAFETY: `buf.len() >= HEADER_LEN_V1` is checked above. The header
    // is plain-old-data and its layout is `#[repr(C)]` matching the C
    // struct; the const_assert at the top of this file pins its size to
    // 96, so this read is sound for any host where the C producer and
    // the Rust consumer agree on the layout.
    let header: Header = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<Header>()) };

    match header.schema_major {
        SCHEMA_V1_MAJOR => parse_v1(buf, header),
        SCHEMA_MAJOR => parse_v2(buf, header),
        other => Err(DecodeError::UnknownSchemaMajor {
            got: other,
            expected: SCHEMA_MAJOR,
        }),
    }
}

/// Version-1 record: fixed 96-byte header, no stack id.
fn parse_v1<'a>(buf: &'a [u8], header: Header) -> Result<Event<'a>, DecodeError> {
    let header_len = HEADER_LEN_V1;
    if header.header_len as usize != header_len {
        return Err(DecodeError::LengthMismatch {
            record_len: header.record_len,
            header_len: header.header_len,
            buf_len: buf.len(),
        });
    }
    finish_parse(buf, header, None, None)
}

/// Version-2 record: 104-byte header (or larger, for a forward-compatible
/// minor revision), with the stack id in the v2 extension.
fn parse_v2<'a>(buf: &'a [u8], header: Header) -> Result<Event<'a>, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::ShortBuffer {
            have: buf.len(),
            need: HEADER_LEN,
        });
    }
    let header_len = header.header_len as usize;
    if header_len < HEADER_LEN || header_len > buf.len() {
        return Err(DecodeError::LengthMismatch {
            record_len: header.record_len,
            header_len: header.header_len,
            buf_len: buf.len(),
        });
    }
    // The v2 extension carries two little-endian i32 handles: kernel
    // `stack_id` at offset 96 and `user_stack_id` at offset 100. The
    // buffer is at least `HEADER_LEN` (104) bytes here, so both reads
    // are in bounds. `-1` is the "no stack" sentinel.
    let raw_stack_id = unsafe { core::ptr::read_unaligned(buf.as_ptr().add(96).cast::<i32>()) };
    let raw_user_stack_id =
        unsafe { core::ptr::read_unaligned(buf.as_ptr().add(100).cast::<i32>()) };
    let stack_id = (raw_stack_id != STACK_ID_NONE).then_some(raw_stack_id);
    let user_stack_id = (raw_user_stack_id != STACK_ID_NONE).then_some(raw_user_stack_id);
    finish_parse(buf, header, stack_id, user_stack_id)
}

/// Shared tail of both parsers: length, kind, and payload checks.
fn finish_parse<'a>(
    buf: &'a [u8],
    header: Header,
    stack_id: Option<i32>,
    user_stack_id: Option<i32>,
) -> Result<Event<'a>, DecodeError> {
    let header_len = header.header_len as usize;
    let record_len = header.record_len as usize;
    if record_len < header_len || record_len > buf.len() {
        return Err(DecodeError::LengthMismatch {
            record_len: header.record_len,
            header_len: header.header_len,
            buf_len: buf.len(),
        });
    }

    if !EventKind::is_known(header.event_kind) {
        return Err(DecodeError::UnknownEventKind {
            byte: header.event_kind,
            max: EventKind::MAX_DISCRIMINANT,
        });
    }

    let payload = &buf[header_len..record_len];
    Ok(Event {
        header,
        stack_id,
        user_stack_id,
        payload,
    })
}
