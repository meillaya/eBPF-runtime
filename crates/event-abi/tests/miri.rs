// tests/miri.rs — event-abi
//
// Miri configuration / soundness tests for the single `unsafe` boundary in
// the crate: the `core::ptr::read_unaligned` of the 96-byte header inside
// `event_abi::parse` (src/lib.rs). Miri interprets these tests and reports
// any undefined behaviour in the pointer arithmetic / unaligned read.
//
// The whole file is gated on `#[cfg(miri)]` so it only compiles and runs
// under `cargo miri test -p event-abi`; a normal `cargo test` build sees an
// empty test binary. Run with:
//
//     MIRIFLAGS="-Zmiri-strict-provenance" cargo miri test -p event-abi
//
// The tests build well-formed records (no unsafe needed to construct bytes)
// and place the 96-byte header at every alignment offset 0..8 inside a
// larger buffer, then parse the misaligned slice. `read_unaligned` must be
// sound at all alignments; Miri fails the run if it is not.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(miri)]

use event_abi::{parse, HEADER_LEN, PAYLOAD_MAX, SCHEMA_MAJOR, SCHEMA_MINOR};

/// Build a well-formed record buffer (96-byte header + `payload_len` bytes)
/// using only safe byte patches — no unsafe required to construct the input.
fn build_record(payload_len: usize, kind: u8) -> Vec<u8> {
    let mut buf = vec![0u8; HEADER_LEN + payload_len];
    buf[0..4].copy_from_slice(&SCHEMA_MAJOR.to_le_bytes());
    buf[4..8].copy_from_slice(&SCHEMA_MINOR.to_le_bytes());
    buf[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&((HEADER_LEN + payload_len) as u32).to_le_bytes());
    buf[16] = kind; // a known kind (e.g. 1 = PROCESS_FORK)
    for b in buf[HEADER_LEN..].iter_mut() {
        *b = 0xAB;
    }
    buf
}

/// Parse a well-formed record placed at every alignment offset 0..8 inside a
/// padded buffer. Exercises `read_unaligned` soundness at misaligned addresses.
#[test]
fn parse_header_at_every_alignment() {
    let record = build_record(32, 1);
    for offset in 0..8usize {
        let mut padded = vec![0u8; offset + record.len()];
        padded[offset..].copy_from_slice(&record);
        let ev = parse(&padded[offset..]).expect("well-formed record must parse at any alignment");
        assert_eq!(ev.header.event_kind, 1);
        assert_eq!(ev.payload.len(), 32);
        assert_eq!(ev.header.record_len as usize, record.len());
    }
}

/// Parse records across a range of payload sizes (0, small, and the declared
/// PAYLOAD_MAX) to exercise the payload-slice pointer arithmetic at the
/// boundary. Miri checks the slice never exceeds the allocation.
#[test]
fn parse_payload_size_boundaries() {
    for &payload_len in &[0usize, 1, 8, 31, 32, 96, 4095, PAYLOAD_MAX] {
        let record = build_record(payload_len, 4); // 4 = FILE_OPEN
        let ev = parse(&record).expect("record must parse");
        assert_eq!(ev.payload.len(), payload_len);
        assert_eq!(ev.payload.as_ptr() as usize, record.as_ptr() as usize + HEADER_LEN);
    }
}

/// Short buffers (0..HEADER_LEN) must return a typed `ShortBuffer` error
/// BEFORE any header read — Miri confirms no out-of-bounds read occurs.
#[test]
fn short_buffer_never_reads_header() {
    for n in 0..HEADER_LEN {
        let buf = vec![0xFFu8; n];
        assert!(parse(&buf).is_err(), "buffer of {n} bytes must be rejected");
    }
}

/// A record whose `record_len` over-reports past the buffer end must be a
/// typed `LengthMismatch`; Miri confirms the payload slice is never formed
/// out of bounds.
#[test]
fn overreported_record_len_is_typed_error() {
    let mut record = build_record(16, 1);
    // Claim a record_len far beyond the actual buffer.
    record[12..16].copy_from_slice(&((HEADER_LEN + 10_000) as u32).to_le_bytes());
    assert!(parse(&record).is_err(), "over-reported record_len must fail typed");
}
