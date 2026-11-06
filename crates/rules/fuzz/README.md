# rules fuzz targets

cargo-fuzz harnesses for the rule parser and predicate boundary. Every
target feeds arbitrary bytes to `rules::parse_ruleset` or the evaluator and
requires a typed `Ok` or `Err`. A panic or a hang is a bug.

## Targets

| Target | What it exercises |
|---|---|
| `parse_yaml` | Arbitrary bytes as YAML: malformed documents, duplicate keys, garbage. |
| `regex_boundary` | A regex pattern inside a condition. The size and complexity checks must reject bad patterns. |
| `deep_nesting` | Nested conditions at the input depth. Depths over the budget must reject. |

## Run

cargo-fuzz needs a nightly toolchain.

```bash
cd crates/rules/fuzz
cargo +nightly fuzz run parse_yaml -- -max_len=65536
cargo +nightly fuzz run regex_boundary -- -max_len=65536
cargo +nightly fuzz run deep_nesting -- -max_len=65536
```

The parse and predicate property tests live in `../proptest/` and run with
`cargo test -p rules`.
