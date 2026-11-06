# event-abi fuzz targets

cargo-fuzz harnesses for the record parser. Every target feeds arbitrary
bytes to `event_abi::parse` and requires a typed `Ok` or `Err`. A panic is
a bug.

## Targets

| Target | What it exercises |
|---|---|
| `parse` | Malformed headers, truncated payloads, unknown schema versions. |
| `parse_stability` | Record length bounds, payload slicing, and repeated parse stability. |
| `decode_report` | `report()`, truncation and redaction flags, `kind_name`, and `verify_field`. |

## Run

cargo-fuzz needs a nightly toolchain.

```bash
cd crates/event-abi/fuzz
cargo +nightly fuzz run parse -- -max_len=65536
cargo +nightly fuzz run parse_stability -- -max_len=65536
cargo +nightly fuzz run decode_report -- -max_len=65536
```

The property tests for the same parser live in `../tests/proptest.rs`.
The Miri test for the unaligned header read lives in `../tests/miri.rs`.
