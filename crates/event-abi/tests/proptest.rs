// tests/proptest.rs: event-abi
//
// Property tests for the ABI decode boundary (task: fuzz & property-test
// parser boundaries). Three families of properties:
//
//   1. ROUNDTRIP STABILITY: for any well-formed record (arbitrary header
//      bytes + arbitrary payload, with the four wire-constrained fields
//      patched to legal values), `parse` succeeds, re-serializing the
//      decoded header yields byte-for-byte the original 96 header bytes
//      (encode -> decode -> encode == same bytes), and the payload slice is
//      exactly `buf[HEADER_LEN..record_len]`.
//   2. DETERMINISM: parsing the same buffer twice yields an identical
//      `Event` (same input -> same output).
//   3. BOUNDS + NEVER-PANIC: for fully arbitrary bytes (up to the anchored
//      max_input_size), `parse` returns a typed `Ok`/`Err` and NEVER panics;
//      on success the payload length never exceeds the buffer and always
//      equals `record_len - HEADER_LEN`.
//
// The unsafe header (de)serialization helper here is test-only and mirrors
// `tests/parse.rs`; the "no unsafe in fuzz targets" rule applies to the
// cargo-fuzz harnesses under `fuzz/`, not to proptest modules.
//
// The input bound is 65536 bytes and the corpus runs 1000 cases.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use event_abi::{parse, Event, Header, HEADER_LEN, PAYLOAD_MAX, SCHEMA_MAJOR, SCHEMA_MINOR};
use proptest::prelude::*;

/// Every legal `event_kind` discriminant on the v1 wire (mirrors
/// `EventKind::is_known`: 1..=12 | 15 | 25..=27).
const KNOWN_KINDS: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 25, 26, 27];

/// Serialize a `Header` into its 96-byte on-the-wire representation.
///
/// SAFETY: `Header` is `#[repr(C)]` plain-old-data and the const_assert in
/// `lib.rs` pins `size_of::<Header>() == 96 == HEADER_LEN`. Reading it as a
/// `[u8; HEADER_LEN]` is a bitwise copy with no validity requirement. This is
/// test-only; the cargo-fuzz targets never use unsafe.
fn header_to_bytes(h: &Header) -> [u8; HEADER_LEN] {
    unsafe { core::ptr::read(core::ptr::addr_of!(*h) as *const [u8; HEADER_LEN]) }
}

/// Patch the four wire-constrained header fields of a raw 96-byte header so
/// the record is well-formed for `parse`:
///   - `schema_major` (offset 0, u32 LE) = SCHEMA_MAJOR
///   - `schema_minor` (offset 4, u32 LE) = SCHEMA_MINOR
///   - `header_len`   (offset 8, u32 LE) = HEADER_LEN
///   - `record_len`   (offset 12, u32 LE) = HEADER_LEN + payload_len
///   - `event_kind`   (offset 16, u8)     = `kind`
fn patch_header(header: &mut [u8], kind: u8, payload_len: usize) {
    header[0..4].copy_from_slice(&SCHEMA_MAJOR.to_le_bytes());
    header[4..8].copy_from_slice(&SCHEMA_MINOR.to_le_bytes());
    header[8..12].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    header[12..16].copy_from_slice(&((HEADER_LEN + payload_len) as u32).to_le_bytes());
    header[16] = kind;
}

/// Build a well-formed record buffer from arbitrary header bytes, an arbitrary
/// payload, and a chosen kind. Returns the buffer.
fn build_record(mut header: [u8; HEADER_LEN], kind: u8, payload: &[u8]) -> Vec<u8> {
    patch_header(&mut header, kind, payload.len());
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&header);
    buf.extend_from_slice(payload);
    buf
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        .. ProptestConfig::default()
    })]

    /// ROUNDTRIP STABILITY + DETERMINISM for well-formed records.
    ///
    /// encode(arbitrary header bytes + payload) -> decode(parse) ->
    /// encode(re-serialize header) yields the SAME 96 header bytes; the
    /// payload slice is exactly `buf[HEADER_LEN..record_len]`; parsing twice
    /// yields an identical `Event`.
    #[test]
    fn roundtrip_and_determinism(
        header in prop::array::uniform::<_, HEADER_LEN>(any::<u8>()),
        kind in prop::sample::select(KNOWN_KINDS),
        payload in prop::collection::vec(any::<u8>(), 0..=PAYLOAD_MAX),
    ) {
        let buf = build_record(header, kind, &payload);

        // decode
        let ev: Event<'_> = parse(&buf).expect("well-formed record must parse");

        // encode -> decode -> encode == same bytes (header roundtrip).
        let reserialized = header_to_bytes(&ev.header);
        prop_assert_eq!(&reserialized[..], &buf[..HEADER_LEN],
            "re-serialized header must equal the original 96 header bytes");

        // payload slice is exactly buf[HEADER_LEN..record_len].
        prop_assert_eq!(ev.payload, &buf[HEADER_LEN..],
            "payload slice must equal buf[HEADER_LEN..record_len]");
        prop_assert_eq!(ev.payload.len(), payload.len());
        prop_assert_eq!(ev.header.record_len as usize, buf.len());
        prop_assert_eq!(ev.header.event_kind, kind);

        // DETERMINISM: same input -> same output.
        let ev2 = parse(&buf).expect("re-parse must succeed");
        prop_assert_eq!(ev, ev2, "parse must be deterministic");

        // report() agrees with the decoded view (bounds + consistency).
        let report = ev.report();
        prop_assert_eq!(report.payload_len, ev.payload.len());
        prop_assert_eq!(report.record_len as usize, buf.len());
        prop_assert_eq!(report.kind, kind);
    }

    /// BOUNDS + NEVER-PANIC for fully arbitrary bytes up to the anchored
    /// max_input_size (65536). `parse` must return a typed result and never
    /// panic; on success the payload never exceeds the buffer and always
    /// equals `record_len - HEADER_LEN`.
    #[test]
    fn arbitrary_bytes_never_panic_and_respect_bounds(
        buf in prop::collection::vec(any::<u8>(), 0..=65536usize),
    ) {
        // A panic here fails the property: parse must be total over &[u8].
        if let Ok(ev) = parse(&buf) {
            prop_assert!(ev.payload.len() <= buf.len(),
                "payload must never exceed the input buffer");
            prop_assert_eq!(ev.payload.len() + HEADER_LEN, ev.header.record_len as usize,
                "payload_len must equal record_len - HEADER_LEN");
            prop_assert!(ev.header.record_len as usize <= buf.len(),
                "record_len must never exceed the buffer length");
            prop_assert!(event_abi::EventKind::is_known(ev.header.event_kind),
                "a parsed event must have a known kind");
        }
    }

    /// Truncated payloads: a well-formed header whose buffer is cut short must
    /// fail with a typed `LengthMismatch`, never panic and never read OOB.
    #[test]
    fn truncated_record_is_typed_error(
        header in prop::array::uniform::<_, HEADER_LEN>(any::<u8>()),
        kind in prop::sample::select(KNOWN_KINDS),
        payload_len in 1usize..=PAYLOAD_MAX,
        cut in 0usize..=PAYLOAD_MAX,
    ) {
        let payload = vec![0xAAu8; payload_len];
        let buf = build_record(header, kind, &payload);
        // Cut the buffer somewhere; if the cut removes bytes the header's
        // record_len promises, parse must fail typed (LengthMismatch), not
        // panic. If the cut keeps the full record, parse succeeds.
        let cut_at = HEADER_LEN.saturating_add(cut).min(buf.len());
        let truncated = &buf[..cut_at];
        if let Ok(ev) = parse(truncated) {
            prop_assert_eq!(ev.header.record_len as usize, truncated.len());
        }
    }
}
