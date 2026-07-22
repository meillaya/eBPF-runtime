# Fuzzing & property testing

This document describes how to run the fuzz targets, property tests, and Miri
soundness checks that defend the parser / decoder boundaries:

| Crate            | Boundary                                              | Fuzz targets | Property tests |
|------------------|-------------------------------------------------------|--------------|----------------|
| `event-abi`      | ABI decode (`parse`, the `read_unaligned` header read) | 3 | roundtrip / determinism / bounds (`tests/proptest.rs`) |
| `rules`          | YAML parse, bounded regex, condition nesting           | 3 | predicate + parse determinism, serialize/parse roundtrip (`proptest/`) |
| `protocol`       | protobuf-shaped (serde JSON) deserialization + bounds  | 3 | JSON roundtrip / determinism / bounds (`tests/proptest.rs`) |
| `storage-local`  | SQLCipher open (corrupt DB, truncated WAL, wrong key)  | 3 | — |

All numeric bounds are anchored in **`bench/schemas/fuzz.v1.json`**
(`max_input_size` 65536, `max_nesting_depth` 16, `max_regex_chars` 256,
`corpus_size` 1000, plus `max_record_len` and `max_message_size_bytes`). The
harnesses reference these defaults; they are not hardcoded at call sites.

## Property tests (proptest)

Property tests are integrated into the normal test suite — no extra tooling:

```bash
cargo test --workspace                 # runs every proptest module
cargo test -p event-abi --test proptest
cargo test -p rules     --test proptest
cargo test -p protocol  --test proptest
```

Each `proptest!` block runs the anchored `corpus_size` (1000) cases and
verifies roundtrip stability (encode → decode → encode == same bytes),
determinism (same input → same output), and bounds (output never exceeds the
declared max).

## Fuzz targets (cargo-fuzz / libFuzzer)

Each crate has a self-contained `fuzz/` harness crate (its own workspace, so
`cargo test --workspace` and the root `Cargo.lock` are never affected).

```bash
# one-time setup
cargo install cargo-fuzz
rustup toolchain install nightly   # cargo-fuzz requires nightly

# event-abi — ABI decode
cargo fuzz run parse           -- -max_len=65536   # in crates/event-abi/fuzz
cargo fuzz run parse_stability -- -max_len=65536
cargo fuzz run decode_report   -- -max_len=65536

# rules — YAML / regex / nesting
cargo fuzz run parse_yaml      -- -max_len=65536   # in crates/rules/fuzz
cargo fuzz run regex_boundary  -- -max_len=65536
cargo fuzz run deep_nesting    -- -max_len=65536

# protocol — protobuf-shaped deserialization + bounds
cargo fuzz run deserialize_batch -- -max_len=65536 # in crates/protocol/fuzz
cargo fuzz run deserialize_event -- -max_len=65536
cargo fuzz run bounds_validate   -- -max_len=65536

# storage-local — SQLCipher encrypted persistence
cargo fuzz run open_corrupt_db -- -max_len=65536   # in crates/storage-local/fuzz
cargo fuzz run wrong_key       -- -max_len=65536
cargo fuzz run truncated_wal   -- -max_len=65536
```

Run each `cargo fuzz run` from inside the corresponding `crates/<crate>/fuzz/`
directory (or pass `--fuzz-dir crates/<crate>/fuzz`). `-max_len=65536` is the
anchored `max_input_size`. Every target accepts arbitrary bytes, never panics
on valid behaviour, and returns typed errors; a panic or abort is a
fuzzer-found bug. No target uses `unsafe`, requires an external service, or can
infinite-loop (structured inputs are bounded).

## Miri (unsafe-boundary soundness)

`event-abi` contains the single `unsafe` boundary (`read_unaligned` of the
96-byte header in `parse`). Miri-interpreted tests live in
`crates/event-abi/tests/miri.rs`, gated on `#[cfg(miri)]` so they only build
under Miri:

```bash
rustup component add miri
MIRIFLAGS="-Zmiri-strict-provenance" cargo miri test -p event-abi
```

These exercise the header read at every alignment offset (0..8) and across
payload-size boundaries (0 .. `PAYLOAD_MAX`), confirming the pointer
arithmetic is sound and short buffers never read out of bounds.
