# storage-local fuzz targets

cargo-fuzz (libFuzzer) harnesses for the SQLCipher encrypted-persistence
boundary (`LocalStorage::open` — key verification, WAL recovery, integrity
checks). Targets write arbitrary bytes to temp database / WAL files and assert
the storage layer is total: a typed `Ok`/`StorageError`, never a panic. Each
iteration uses an auto-cleaned temp dir; **no external services** are required.

## Targets

| Target           | Boundary exercised                                                                  |
|------------------|-------------------------------------------------------------------------------------|
| `open_corrupt_db`| Open against arbitrary (corrupt / non-DB / truncated) file bytes with the test key.  |
| `wrong_key`      | Re-open a valid test-key DB with an arbitrary 32-byte key; wrong keys must reject typed (SQLCipher HMAC). |
| `truncated_wal`  | Open against a corrupt DB plus a truncated/garbage `<db>-wal` sidecar; safe recovery or typed error. |

## Run

```bash
cargo fuzz run open_corrupt_db -- -max_len=65536
cargo fuzz run wrong_key -- -max_len=65536
cargo fuzz run truncated_wal -- -max_len=65536
```

`-max_len=65536` is anchored by `bench/schemas/fuzz.v1.json` (`max_input_size`).
cargo-fuzz requires a nightly toolchain. These targets build the bundled
SQLCipher via `rusqlite`'s `bundled-sqlcipher` feature (inherited from the
`storage-local` crate). See top-level `FUZZING.md`.
