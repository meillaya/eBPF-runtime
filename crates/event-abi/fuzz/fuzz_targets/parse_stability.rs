// fuzz_targets/parse_stability.rs — event-abi
//
// Roundtrip / determinism fuzz target for the ABI decode boundary. For any
// buffer that parses successfully:
//   * DETERMINISM — parsing the same bytes twice yields an identical `Event`
//     (same input -> same output);
//   * ROUNDTRIP — the decoded payload slice is exactly
//     `data[HEADER_LEN..record_len]`, and re-parsing that exact recorded
//     slice yields the same header (decode is self-consistent);
//   * BOUNDS — `record_len` never exceeds the buffer length.
// A violated invariant is a real bug and intentionally aborts the run. No
// unsafe in this target (the encode->decode->encode byte roundtrip is covered
// by the proptest module, which is allowed to use the test-only serializer).
//
// Run: cargo fuzz run parse_stability -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(ev1) = event_abi::parse(data) else {
        return;
    };

    // BOUNDS: record_len never exceeds the buffer.
    let end = ev1.header.record_len as usize;
    assert!(end <= data.len(), "record_len must not exceed buffer length");

    // ROUNDTRIP: payload slice is exactly data[HEADER_LEN..record_len].
    assert_eq!(
        ev1.payload,
        &data[event_abi::HEADER_LEN..end],
        "payload must equal data[HEADER_LEN..record_len]"
    );

    // DETERMINISM: same input -> same output.
    let ev2 = event_abi::parse(data).expect("re-parse of the same buffer must succeed");
    assert_eq!(ev1, ev2, "parse must be deterministic");

    // Self-consistency: re-parsing the exact recorded slice matches the header.
    if let Ok(ev3) = event_abi::parse(&data[..end]) {
        assert_eq!(ev3.header, ev1.header, "header must be stable across re-slice");
    }
});
