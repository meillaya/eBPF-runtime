// fuzz_targets/open_corrupt_db.rs — storage-local
//
// Corrupt-database fuzz target for the SQLCipher boundary. Writes arbitrary
// bytes to a temp file and attempts `LocalStorage::open` with the test key.
// A corrupt / non-database / truncated file must yield a typed `StorageError`
// (e.g. NOTADB / key-mismatch from SQLCipher's HMAC check), NEVER a panic. If
// the open somehow succeeds, migrations + integrity check must also be
// panic-free. Each iteration uses an auto-cleaned temp dir (no external
// services) and performs a single bounded open. No unsafe.
//
// Run: cargo fuzz run open_corrupt_db -- -max_len=65536
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
    let db_path = dir.path().join("corrupt.db");
    let mut file = match std::fs::File::create(&db_path) {
        Ok(f) => f,
        Err(_) => return,
    };
    if file.write_all(data).is_err() {
        return;
    }
    drop(file);

    // Open against arbitrary (likely corrupt) bytes: typed result, no panic.
    if let Ok(storage) = LocalStorage::open(&db_path, &test_key()) {
        // If a corrupt file is accepted, migrations + integrity must not panic.
        let _ = storage.run_migrations();
        let _ = storage.integrity_check();
        let _ = storage.db_size_bytes();
    }
});
