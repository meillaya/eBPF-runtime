// fuzz_targets/deserialize_event.rs — protocol
//
// Event + enum deserialization fuzz target. Exercises two surfaces with
// arbitrary bytes:
//   * `serde_json::from_slice::<Event>` — unknown fields, truncated JSON,
//     oversized payloads, hostile UTF-8;
//   * `EventKind::from_proto_name` — arbitrary (lossy) strings through the
//     proto-enum-name parser, which must return `Option` and never panic.
// Both must be total. No unsafe.
//
// Run: cargo fuzz run deserialize_event -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use libfuzzer_sys::fuzz_target;
use protocol::events::{Event, EventKind};

fuzz_target!(|data: &[u8]| {
    // Typed result for any byte input, never a panic.
    let _ = serde_json::from_slice::<Event>(data);

    // The proto-enum-name parser must be total over arbitrary strings.
    let name = String::from_utf8_lossy(data);
    let _ = EventKind::from_proto_name(&name);
});
