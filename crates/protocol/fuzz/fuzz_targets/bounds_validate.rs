// fuzz_targets/bounds_validate.rs — protocol
//
// Message-bounds fuzz target. For arbitrary bytes that decode to a `Batch`,
// runs `MessageBounds::default().validate_batch` (oversized-batch and
// oversized-message checks) and re-validates each event's serialized size;
// also feeds an arbitrary `usize` (derived from the input) through
// `validate_message_size`. Every path must return a typed `ProtocolResult`
// and NEVER panic, regardless of how large or malformed the decoded batch is.
// No unsafe.
//
// Run: cargo fuzz run bounds_validate -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use libfuzzer_sys::fuzz_target;
use protocol::bounds::MessageBounds;
use protocol::events::Batch;

fuzz_target!(|data: &[u8]| {
    let bounds = MessageBounds::default();

    // Arbitrary size through the single-message bound check (never panics).
    let size = data
        .chunks(8)
        .next()
        .map(|c| {
            let mut buf = [0u8; 8];
            buf[..c.len()].copy_from_slice(c);
            usize::try_from(u64::from_le_bytes(buf)).unwrap_or(usize::MAX)
        })
        .unwrap_or(0);
    let _ = bounds.validate_message_size(size);

    // A decoded batch must validate (or reject typed) without panicking.
    if let Ok(batch) = serde_json::from_slice::<Batch>(data) {
        let _ = bounds.validate_batch(&batch);
        for event in &batch.events {
            if let Ok(serialized) = serde_json::to_vec(event) {
                let _ = bounds.validate_message_size(serialized.len());
            }
        }
    }
});
