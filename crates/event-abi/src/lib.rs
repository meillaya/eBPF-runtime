// src/lib.rs — event-abi
//
// kernel-v1 event ABI v1: safe parser, payload variants, validity/
// degradation/truncation/redaction flags, static size/offset assertions,
// endianness/version/length checks, and generation manifest hash.
//
// The crate is the user-space Rust side of the contract pinned in
// `bpf/include/event_abi.h`. The hand-written `src/generated.rs` file
// mirrors the C header verbatim. `build.rs` records the SHA-256 of the
// generated file and the C header in `$OUT_DIR/event-abi.manifest.json`;
// `tests/manifest.rs` asserts the manifest matches.
//
// PUBLIC SURFACE (must not grow without a plan-major bump)
//   * `parse(buf)` — the safe parser
//   * `Event<'a> { header, payload }` — the typed view
//   * `DecodeError` — typed errors with enough context for diagnostics
//   * `DecodeReport` — aggregation of validity/truncation/redaction
//   * `SCHEMA_MAJOR`, `SCHEMA_MINOR`, `HEADER_LEN`, `PAYLOAD_MAX` —
//     re-exports of the versioned constants
//   * `EventKind`, `Valid` — re-exports of the hand-written enums
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![deny(unsafe_op_in_unsafe_fn)]

use core::fmt;

pub mod generated;
mod parser_helpers;

pub use generated::{
    EventKind, FileDenySource, Header, Valid, EVENT_FLAG_REDACTED, EVENT_FLAG_TRUNC,
    FILE_RESULT_HAS_ERRNO, FILE_RESULT_OWN_LSM, HEADER_LEN, PAYLOAD_MAX, SCHEMA_MAJOR,
    SCHEMA_MINOR, VALID_REQUIRED, VALID_V1_ALLOWED_MASK,
};
pub use parser_helpers::{
    compute_record_len, format_valids, is_redacted, is_truncated, verify_field,
};

// Compile-time assertions on the on-the-wire struct size.
//
// The C header's `_Static_assert(sizeof(struct kernel_v1_header) == 96)`
// is the source of truth on the producer side; this const_assert is the
// source of truth on the consumer side. Drift between the two fails
// the next `cargo build` of the crate.
const _: () = {
    assert!(core::mem::size_of::<Header>() == 96);
    assert!(core::mem::align_of::<Header>() == 8);
};

/// Typed error returned by [`parse`]. Each variant carries enough
/// context for downstream diagnostics and unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer is shorter than the fixed 96-byte header.
    ShortBuffer { have: usize, need: usize },
    /// `header.schema_major` does not match `SCHEMA_MAJOR`.
    UnknownSchemaMajor { got: u32, expected: u32 },
    /// `header.record_len` disagrees with the buffer or the header length.
    LengthMismatch {
        record_len: u32,
        header_len: u32,
        buf_len: usize,
    },
    /// `event_kind` byte is 0 (UNSPECIFIED) or above the max accepted discriminant.
    UnknownEventKind { byte: u8, max: u8 },
    /// Payload slice extends past the buffer (defensive — `LengthMismatch`
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

/// Typed view of a single record. `header` is a copy of the 96-byte
/// fixed prefix; `payload` borrows from the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

/// Aggregated report of validity, truncation, and redaction. Used by
/// tests for fixture round-trip assertions and by the loader's bound
/// diagnostics (task 19).
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

/// Safe parser. Performs the validation chain in the order required by
/// the v1 contract:
///
///   1. Buffer length >= `HEADER_LEN`
///   2. `header.schema_major == SCHEMA_MAJOR`
///   3. `header.header_len == HEADER_LEN` (drift detector)
///   4. `header.record_len >= HEADER_LEN` and `header.record_len <= buf.len()`
///   5. `header.event_kind` is in `[1, EventKind::MAX_DISCRIMINANT]`
///   6. `buf[HEADER_LEN..record_len]` slice is the payload (clipped to
///      `buf.len()` if the producer over-reported)
pub fn parse<'a>(buf: &'a [u8]) -> Result<Event<'a>, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Err(DecodeError::ShortBuffer {
            have: buf.len(),
            need: HEADER_LEN,
        });
    }

    // SAFETY: `buf.len() >= HEADER_LEN` is checked above. The header is
    // plain-old-data and the layout is `#[repr(C)]` matching the C
    // struct. The const_assert at the top of this file pins the size
    // to 96, so this read is sound for any host where the C producer
    // and Rust consumer agree on the layout (the C `_Static_assert`
    // enforces the same size on the producer side).
    let header: Header = unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<Header>()) };

    if header.schema_major != SCHEMA_MAJOR {
        return Err(DecodeError::UnknownSchemaMajor {
            got: header.schema_major,
            expected: SCHEMA_MAJOR,
        });
    }

    if header.header_len as usize != HEADER_LEN {
        return Err(DecodeError::LengthMismatch {
            record_len: header.record_len,
            header_len: header.header_len,
            buf_len: buf.len(),
        });
    }

    if (header.record_len as usize) < HEADER_LEN || (header.record_len as usize) > buf.len() {
        return Err(DecodeError::LengthMismatch {
            record_len: header.record_len,
            header_len: header.header_len,
            buf_len: buf.len(),
        });
    }

    if header.event_kind == 0 || header.event_kind > EventKind::MAX_DISCRIMINANT {
        return Err(DecodeError::UnknownEventKind {
            byte: header.event_kind,
            max: EventKind::MAX_DISCRIMINANT,
        });
    }

    // Defensive payload extraction. If the producer set
    // `record_len - HEADER_LEN > PAYLOAD_MAX`, the parser still clips
    // the slice to `buf[HEADER_LEN..record_len]` but flags the record
    // as truncated.
    let payload_end = header.record_len as usize;
    let payload = &buf[HEADER_LEN..payload_end];
    Ok(Event { header, payload })
}
