# protocol fuzz targets

cargo-fuzz (libFuzzer) harnesses for the protocol (protobuf-shaped)
deserialization boundary — the serde JSON mirror of the proto contracts
(`Batch`, `Event`, `EventKind`) plus `MessageBounds` validation. Targets
accept arbitrary bytes and assert deserialization is total: a typed
`Ok`/`Err`, never a panic.

## Targets

| Target              | Boundary exercised                                                                  |
|---------------------|-------------------------------------------------------------------------------------|
| `deserialize_batch` | Raw `Batch` deserialization: unknown fields, oversized messages, truncated JSON, hostile UTF-8. |
| `deserialize_event` | `Event` deserialization + `EventKind::from_proto_name` over arbitrary strings.        |
| `bounds_validate`   | `MessageBounds` oversized-batch / oversized-message checks on decoded batches and arbitrary sizes. |

## Run

```bash
cargo fuzz run deserialize_batch -- -max_len=65536
cargo fuzz run deserialize_event -- -max_len=65536
cargo fuzz run bounds_validate -- -max_len=65536
```

`-max_len=65536` and the 1 MiB message bound are anchored by
`bench/schemas/fuzz.v1.json` (`max_input_size`, `max_message_size_bytes`) and
`bench/schemas/protocol.v1.json`. cargo-fuzz requires a nightly toolchain.

The JSON roundtrip-stability, determinism, and bounds properties live in
`../tests/proptest.rs` (run via `cargo test -p protocol`). See top-level
`FUZZING.md`.
