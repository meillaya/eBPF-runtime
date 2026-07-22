# rules fuzz targets

cargo-fuzz (libFuzzer) harnesses for the rule parser / predicate boundary
(`rules::parse_ruleset` — YAML parse, JSON-Schema structural validation,
bounded-regex validation, condition nesting). Targets accept arbitrary bytes
and assert the parser is total: a typed `Ok`/`Err`, never a panic or hang.

## Targets

| Target           | Boundary exercised                                                                  |
|------------------|-------------------------------------------------------------------------------------|
| `parse_yaml`     | Raw parse of arbitrary bytes (lossy UTF-8): YAML injection, malformed docs, garbage. |
| `regex_boundary` | Catastrophic regex: arbitrary pattern embedded in a `regex` condition; size/complexity bounds must reject typed, never hang. |
| `deep_nesting`   | Deep AND-nesting (bounded depth from input byte); depths over the budget must reject typed, never stack-overflow. |

## Run

```bash
cargo fuzz run parse_yaml -- -max_len=65536
cargo fuzz run regex_boundary -- -max_len=65536
cargo fuzz run deep_nesting -- -max_len=65536
```

`-max_len=65536` is anchored by `bench/schemas/fuzz.v1.json` (`max_input_size`);
the nesting budget (16) and regex char bound (256) are anchored there and in
`bench/schemas/rule-budget.v1.json`. cargo-fuzz requires a nightly toolchain.

The predicate-evaluation determinism, parse determinism, and serialize/parse
roundtrip properties live in `../proptest/` (run via `cargo test -p rules`).
See top-level `FUZZING.md`.
