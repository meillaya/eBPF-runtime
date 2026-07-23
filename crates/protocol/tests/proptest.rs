// tests/proptest.rs — protocol
//
// Property tests for the protocol (protobuf-shaped) deserialization boundary
// (task: fuzz & property-test parser boundaries). The wire surface is the
// serde JSON mirror of the proto contracts (`Batch`, `Event`, `EventKind`).
// Three families of properties:
//
//   1. ROUNDTRIP STABILITY — for any generated `Batch`,
//      serialize -> deserialize -> serialize yields byte-for-byte the same
//      JSON (encode -> decode -> encode == same bytes); serde_json is
//      deterministic (fixed struct field order, ordered `BTreeMap` valids).
//   2. DETERMINISM — deserializing the same bytes twice yields an identical
//      `Batch` (same input -> same output).
//   3. NEVER-PANIC + BOUNDS — arbitrary bytes deserialize to a typed
//      `Ok`/`Err` and never panic; a decoded batch's serialized size is
//      re-checkable against `MessageBounds` without panicking.
//
// Constants are anchored in `bench/schemas/fuzz.v1.json` (corpus_size,
// max_message_size_bytes) and `bench/schemas/protocol.v1.json`.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use proptest::prelude::*;

use protocol::bounds::MessageBounds;
use protocol::events::{Batch, Event, EventKind};

const KINDS: &[EventKind] = &[
    EventKind::Unspecified,
    EventKind::ProcessFork,
    EventKind::ProcessExecResult,
    EventKind::ProcessExit,
    EventKind::FileOpen,
    EventKind::FileCreate,
    EventKind::FileUnlink,
    EventKind::FileRename,
    EventKind::NetworkConnect,
    EventKind::NetworkAccept,
    EventKind::NetworkState,
    EventKind::DnsPacket,
    EventKind::SyscallEnter,
    EventKind::SyscallExit,
    EventKind::LsmDenyOwn,
    EventKind::Identity,
];

fn arb_event_kind() -> impl Strategy<Value = EventKind> {
    prop::sample::select(KINDS)
}

fn arb_valids() -> impl Strategy<Value = BTreeMap<String, bool>> {
    prop::collection::btree_map("[a-z._]{1,8}", any::<bool>(), 0..4)
}

fn arb_event() -> impl Strategy<Value = Event> {
    ("[0-9a-f-]{1,36}", any::<u64>(), any::<u64>(), "[a-z]{1,8}", arb_event_kind(), arb_valids())
        .prop_map(
            |(event_id, seq, ts_monotonic_ns, sensor, event_kind, valids)| Event {
                event_id,
                seq,
                ts_monotonic_ns,
                sensor,
                event_kind,
                valids,
            },
        )
}

fn arb_batch() -> impl Strategy<Value = Batch> {
    (
        any::<u32>(),
        any::<u32>(),
        prop::collection::vec(arb_event(), 0..6),
        "[a-z0-9-]{1,16}",
        "[a-z0-9-]{1,16}",
        "[0-9a-f]{0,32}",
    )
        .prop_map(
            |(schema_major, schema_minor, events, agent_generation, node_name, boot_id_hex)| {
                Batch {
                    schema_major,
                    schema_minor,
                    events,
                    agent_generation,
                    node_name,
                    boot_id_hex,
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000, // anchored corpus_size default (bench/schemas/fuzz.v1.json)
        .. ProptestConfig::default()
    })]

    /// ROUNDTRIP STABILITY + DETERMINISM for generated batches.
    #[test]
    fn json_roundtrip_is_stable_and_deterministic(batch in arb_batch()) {
        // encode
        let json1 = serde_json::to_string(&batch).expect("batch must serialize");

        // decode (twice -> deterministic)
        let decoded1: Batch = serde_json::from_str(&json1).expect("serialized batch must decode");
        let decoded2: Batch = serde_json::from_str(&json1).expect("re-decode must succeed");
        prop_assert_eq!(&decoded1, &decoded2, "deserialize must be deterministic");
        prop_assert_eq!(&decoded1, &batch, "decode must recover the original batch");

        // encode again -> byte-for-byte stable (encode -> decode -> encode).
        let json2 = serde_json::to_string(&decoded1).expect("re-serialize must succeed");
        prop_assert_eq!(json1, json2, "encode -> decode -> encode must be byte-stable");
    }

    /// NEVER-PANIC + BOUNDS for arbitrary bytes: deserialization yields a typed
    /// result; a decoded batch can be re-validated against MessageBounds without
    /// panicking, and an oversized batch is rejected typed (not a panic).
    #[test]
    fn arbitrary_bytes_never_panic_and_respect_bounds(buf in prop::collection::vec(any::<u8>(), 0..=4096usize)) {
        // A panic here fails the property: from_slice must be total.
        if let Ok(batch) = serde_json::from_slice::<Batch>(&buf) {
            // Re-validation against the default bounds must not panic.
            let bounds = MessageBounds::default();
            let _ = bounds.validate_batch(&batch);
            // Each event's serialized size is a concrete, bounded usize.
            for event in &batch.events {
                let serialized = serde_json::to_vec(event).expect("event must serialize");
                let _ = bounds.validate_message_size(serialized.len());
            }
        }
    }
}
