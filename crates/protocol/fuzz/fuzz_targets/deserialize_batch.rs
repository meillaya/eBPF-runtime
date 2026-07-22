// fuzz_targets/deserialize_batch.rs — protocol
//
// Primary protocol-deserialization fuzz target. Feeds arbitrary bytes (unknown
// fields, oversized messages, truncated JSON, hostile UTF-8) into the `Batch`
// deserializer (the serde JSON mirror of `Batch` in events.proto). The
// deserializer must be TOTAL: a typed `Ok(Batch)` or a typed `serde_json`
// error, NEVER a panic. A panic here is a fuzzer-found bug. No unsafe.
//
// Run: cargo fuzz run deserialize_batch -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use libfuzzer_sys::fuzz_target;
use protocol::events::Batch;

fuzz_target!(|data: &[u8]| {
    // Must produce a typed result for any input, never panic.
    let _ = serde_json::from_slice::<Batch>(data);
});
