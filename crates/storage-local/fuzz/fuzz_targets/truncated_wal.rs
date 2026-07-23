// fuzz_targets/truncated_wal.rs — storage-local
//
// Truncated/corrupt WAL fuzz target for the SQLCipher boundary. Writes
// arbitrary bytes to both a database file and its `<db>-wal` write-ahead-log
// sidecar, then attempts `LocalStorage::open` with the test key. A truncated
// or garbage WAL alongside a corrupt DB must yield a typed `StorageError` or a
// safe recovery — NEVER a panic and NEVER an out-of-bounds read. If the open
// succeeds, migrations + integrity check must be panic-free. Bounded: a single
// open per iteration, auto-cleaned temp dir, no external services. No unsafe.
//
// Run: cargo fuzz run truncated_wal -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use storage_local::{test_key, LocalStorage};

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let db_path = dir.path().join("wal.db");
    let wal_path = dir.path().join("wal.db-wal");

    // Split the input between the DB file and its WAL sidecar so both the
    // corrupt-DB and truncated-WAL paths are exercised together.
    let mid = data.len() / 2;
    let (db_bytes, wal_bytes) = data.split_at(mid);

    if let Ok(mut f) = std::fs::File::create(&db_path) {
        let _ = f.write_all(db_bytes);
    }
    if let Ok(mut f) = std::fs::File::create(&wal_path) {
        let _ = f.write_all(wal_bytes);
    }

    // Open against corrupt DB + truncated/garbage WAL: typed result, no panic.
    if let Ok(storage) = LocalStorage::open(&db_path, &test_key()) {
        let _ = storage.run_migrations();
        let _ = storage.integrity_check();
        let _ = storage.checkpoint();
    }
});
