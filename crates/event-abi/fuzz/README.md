# event-abi fuzz targets

cargo-fuzz (libFuzzer) harnesses for the ABI decode boundary
(`event_abi::parse` — the single `unsafe` `read_unaligned` of the 96-byte
header plus the validation chain). Targets accept arbitrary bytes and assert
the parser is total: a typed `Ok`/`Err`, never a panic.

## Targets

| Target            | Boundary exercised                                                                 |
|-------------------|------------------------------------------------------------------------------------|
| `parse`           | Raw decode of arbitrary bytes: malformed headers, truncated payloads, unknown versions/endianness. |
| `parse_stability` | Roundtrip + determinism: `record_len` bounds, payload slice == `data[HEADER_LEN..record_len]`, re-parse stability. |
| `decode_report`   | Full decode surface: `report()`, truncation/redaction flags, `kind_name`, `verify_field` across validity bits. |

## Run

```bash
# from the repo root (cargo-fuzz uses the crate dir automatically)
cargo fuzz run parse -- -max_len=65536
cargo fuzz run parse_stability -- -max_len=65536
cargo fuzz run decode_report -- -max_len=65536
```

`-max_len=65536` is anchored by `bench/schemas/fuzz.v1.json` (`max_input_size`).
cargo-fuzz requires a nightly toolchain (`rustup run nightly cargo fuzz ...`).

The encode→decode→encode byte roundtrip and Miri soundness checks for the
`read_unaligned` boundary live in `../tests/proptest.rs` and `../tests/miri.rs`
(run the latter with `cargo miri test -p event-abi`). See top-level `FUZZING.md`.
