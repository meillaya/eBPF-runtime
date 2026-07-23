// src/bin/fuzz_roundtrip.rs — event-abi
//
// Reads random bytes from stdin and feeds them to `event_abi::parse`.
// The harness asserts no panic occurs for any input by wrapping the
// call in `std::panic::catch_unwind`. Exits 0 if every input was
// handled (Ok or Err); non-zero only on a panic.
//
// This is the deterministic seed-loop wrapper required by the task
// spec's "fuzz-roundtrip run 100x with /dev/urandom" QA. The
// real `cargo-fuzz` harness lives at `tests/fuzz.rs` (gated behind
// `--features fuzz`) for nightly-toolchain runs.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{self, Read};

fn main() {
    let mut buf = Vec::with_capacity(64 * 1024);
    if let Err(e) = io::stdin().read_to_end(&mut buf) {
        eprintln!("fuzz-roundtrip: read_to_end failed: {e}");
        std::process::exit(2);
    }

    // If the input is empty, emit a single empty-buffer call so the
    // harness still exercises the parser (the empty case returns
    // `ShortBuffer`).
    if buf.is_empty() {
        let r = std::panic::catch_unwind(|| event_abi::parse(&[]));
        match r {
            Ok(Ok(_)) => unreachable!("empty buffer must not parse"),
            Ok(Err(_)) => {}
            Err(_) => {
                eprintln!("fuzz-roundtrip: PANIC on empty input");
                std::process::exit(1);
            }
        }
        println!("fuzz-roundtrip: empty input handled (ShortBuffer)");
        return;
    }

    let n = 100usize;
    let mut ok = 0usize;
    let mut err_typed = 0usize;
    let mut chunks = buf.chunks(4096);
    for i in 0..n {
        let slice = chunks
            .next()
            .unwrap_or_else(|| chunks.next().unwrap_or(&[]));
        let r = std::panic::catch_unwind(|| event_abi::parse(slice));
        match r {
            Ok(Ok(_ev)) => ok += 1,
            Ok(Err(_e)) => err_typed += 1,
            Err(_) => {
                eprintln!("fuzz-roundtrip: PANIC on input #{i}");
                std::process::exit(1);
            }
        }
    }

    println!("fuzz-roundtrip: {n} iterations: ok={ok} typed_err={err_typed} panic=0");
}
