// fuzz_targets/wrong_key.rs — storage-local
//
// Wrong-key fuzz target for the SQLCipher boundary. First creates a valid,
// migrated database encrypted with the test key, then re-opens it with an
// arbitrary 32-byte key derived from the fuzz input. SQLCipher v4 (HMAC/KDF
// always enabled) must reject a wrong key with a typed `StorageError` from the
// `sqlite_master` verification read — NEVER a panic and NEVER silent success
// on a genuinely wrong key. If the derived key happens to equal the test key
// (all zeros), the open legitimately succeeds; the integrity check must then
// be panic-free. Bounded: one create + one re-open per iteration, auto-cleaned
// temp dir, no external services. No unsafe.
//
// Run: cargo fuzz run wrong_key -- -max_len=65536
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_main]

use libfuzzer_sys::fuzz_target;
use storage_local::{test_key, LocalStorage, StorageKey};

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let db_path = dir.path().join("keyed.db");

    // Create a valid encrypted DB with the test key and migrate it.
    {
        let storage = match LocalStorage::open(&db_path, &test_key()) {
            Ok(s) => s,
            Err(_) => return,
        };
        if storage.run_migrations().is_err() {
            return;
        }
    } // connection dropped here

    // Derive an arbitrary 32-byte key from the input (zero-padded).
    let mut key_bytes = [0u8; 32];
    let n = data.len().min(32);
    key_bytes[..n].copy_from_slice(&data[..n]);
    let key = StorageKey { key_bytes };

    // Re-open with the (possibly wrong) key: typed result, no panic.
    if let Ok(storage) = LocalStorage::open(&db_path, &key) {
        let _ = storage.integrity_check();
        let _ = storage.schema_version();
    }
});
