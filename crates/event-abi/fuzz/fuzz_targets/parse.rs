// fuzz_targets/parse.rs: event-abi
//
// Primary ABI-decode fuzz target. Feeds arbitrary bytes (malformed headers,
// truncated payloads, unknown versions, arbitrary endianness) straight into
// the safe parser. `event_abi::parse` must be TOTAL over `&[u8]`: it returns
// a typed `Ok(Event)` or a typed `DecodeError` and NEVER panics. A panic
// here is a fuzzer-found bug. No unsafe in this target.
//
// Run: cargo fuzz run parse -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser must accept any byte slice and produce a typed result.
    let _ = event_abi::parse(data);
});
