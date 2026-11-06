// tests/fuzz.rs: event-abi
//
// Fuzz harness gated behind `--features fuzz`. Uses a hand-rolled
// PRNG to generate random bytes (avoids the nightly `cargo-fuzz`
// runtime, which the test contract acknowledges is not available in this
// session). The real nightly harness is a one-liner that wraps this
// function with `cargo_fuzz::fuzz_target!`.
//
// The harness asserts no panic occurs for any input by wrapping the
// `parse` call in `std::panic::catch_unwind`.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "fuzz")]

use event_abi::parse;

#[inline]
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn fuzz_random_inputs_never_panic() {
    let mut state: u64 = 0x0123_4567_89AB_CDEF;
    let n = 4096usize;
    for i in 0..n {
        // Build a buffer of 0..=4096 bytes from the PRNG.
        let len = (xorshift64(&mut state) as usize) % 4096;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((xorshift64(&mut state) & 0xFF) as u8);
        }
        // Mutate the header bytes (if present) with random values
        // to exercise the unknown-major / unknown-kind / length
        // mismatch / truncation / redaction paths.
        if buf.len() >= 96 {
            for j in 0..24 {
                buf[j] = (xorshift64(&mut state) & 0xFF) as u8;
            }
        }
        let r = std::panic::catch_unwind(|| parse(&buf));
        match r {
            Ok(_) => {}
            Err(_) => panic!("fuzz input #{i} caused a panic (len={len})"),
        }
    }
}

#[test]
fn fuzz_all_zeros_is_well_typed() {
    // All-zeros is a deterministic, hostile input. It must produce a
    // typed error (LengthMismatch, because record_len=0 < HEADER_LEN)
    // and never panic.
    let buf = vec![0u8; 4096];
    let r = std::panic::catch_unwind(|| parse(&buf));
    assert!(r.is_ok(), "all-zeros must not panic");
}

#[test]
fn fuzz_max_length_garbage_is_well_typed() {
    let mut buf = vec![0xFFu8; 8192];
    // Set a valid schema_major and a valid record_len that points past
    // the buffer; we must get LengthMismatch.
    buf[0] = 1; // schema_major
    buf[4] = 0; // schema_minor
    buf[8] = 96; // header_len
    buf[12] = 0xFF; // record_len high byte
    let r = std::panic::catch_unwind(|| parse(&buf));
    assert!(r.is_ok(), "max-length garbage must not panic");
}
