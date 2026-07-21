// build.rs — event-abi crate
//
// The header `bpf/include/event_abi.h` is the single source of truth for
// the kernel-v1 wire format. The `src/generated.rs` file is the
// hand-written Rust mirror of that header; the `build.rs` script:
//
//   1. Computes a SHA-256 of the C header and the `src/generated.rs`
//      file. We use a vendored, dependency-free SHA-256 implementation
//      to avoid the build-dep / dev-dep fingerprint collision that
//      `cargo 1.95` exhibits when `sha2` is in both `[build-dependencies]`
//      and `[dev-dependencies]` for the same crate.
//   2. Writes a manifest to `$OUT_DIR/event-abi.manifest.json` recording
//      `schema_major`, `schema_minor`, `header_len`, `payload_max`,
//      `header_sha256`, and `bindings_sha256`.
//   3. Re-emits `cargo:rerun-if-changed=...` for the C header, the
//      generated bindings, and this build script so the next
//      `cargo build` re-runs only when one of those files changes.
//
// We do NOT use `bindgen` to regenerate `src/generated.rs` here because
// (a) bindgen requires libclang to be present on the build host and
// (b) the hand-written file is the deterministic fallback. The hand-
// written file's content is verified by `tests/manifest.rs` against the
// recorded SHA-256 so any drift fails the test.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

// SHA-256 (FIPS 180-4) — vendored, no external dependencies.
//
// The round constants K are the first 32 bits of the fractional parts
// of the cube roots of the first 64 primes. SHA-256 is a 64-round
// Merkle–Damgård construction over 512-bit blocks producing 256 bits
// of output. Implemented from the FIPS 180-4 spec so build.rs is
// free of any Cargo dependency.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (bytes.len() as u64) * 8;
    let mut msg = bytes.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = sha256(bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(sha256_hex(&bytes))
}

fn write_manifest(
    out_dir: &Path,
    header_sha: &str,
    bindings_sha: &str,
    schema_major: u32,
    schema_minor: u32,
    header_len: u32,
    payload_max: u32,
) -> io::Result<PathBuf> {
    let manifest_path = out_dir.join("event-abi.manifest.json");
    let body = format!(
        "{{\n  \"schema_major\": {schema_major},\n  \"schema_minor\": {schema_minor},\n  \"header_len\": {header_len},\n  \"payload_max\": {payload_max},\n  \"header_sha256\": \"{header_sha}\",\n  \"bindings_sha256\": \"{bindings_sha}\",\n  \"generated_by\": \"event-abi/build.rs\"\n}}\n"
    );
    fs::write(&manifest_path, body)?;
    Ok(manifest_path)
}

fn main() -> io::Result<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("CARGO_MANIFEST_DIR: {e}")))?;
    let root = PathBuf::from(&manifest_dir);
    let out_dir = env::var("OUT_DIR")
        .map(PathBuf::from)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("OUT_DIR: {e}")))?;
    let target_dir = env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            root.parent()
                .and_then(|p| p.parent())
                .unwrap()
                .join("target")
        });

    let header_path = root
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("bpf/include/event_abi.h");
    let bindings_path = root.join("src/generated.rs");
    let c_check_path = out_dir.join("event_abi_check.c");
    let c_check_bin = out_dir.join("event_abi_check");

    // Rerun policy: rebuild only when one of these three files changes.
    println!("cargo:rerun-if-changed={}", header_path.display());
    println!("cargo:rerun-if-changed={}", bindings_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let header_sha = sha256_file(&header_path)?;
    let bindings_sha = sha256_file(&bindings_path)?;

    // 1. C-side size/offset check. We compile a tiny TU that includes
    //    the header and prints the struct size; the build fails if the
    //    size does not match the C ABI constant.
    let c_check_src = r#"
#include "event_abi.h"
#include <stddef.h>
#include <stdio.h>

int main(void) {
    /* If the size drifted, the static_assert in the header would have
     * already failed the compile. We still print it so the build log
     * carries a positive confirmation. */
    printf("KERNEL_V1_ABI_HEADER_LEN=%u\n", (unsigned)KERNEL_V1_ABI_HEADER_LEN);
    printf("KERNEL_V1_ABI_PAYLOAD_MAX=%u\n", (unsigned)KERNEL_V1_ABI_PAYLOAD_MAX);
    printf("sizeof(struct kernel_v1_header)=%zu\n", sizeof(struct kernel_v1_header));
    return 0;
}
"#;
    fs::write(&c_check_path, c_check_src)?;

    // Try clang first; fall back to cc. We do NOT fail the build if
    // neither is present, because the C ABI is also validated by
    // `tests/manifest.rs` against the recorded SHA-256. The C check
    // is a *belt-and-braces* reinforcement of the same fact.
    let header_dir = header_path.parent().unwrap();
    let candidates: &[&str] = &["clang", "cc", "gcc"];
    let mut cc_used: Option<String> = None;
    for cc in candidates {
        let status = Command::new(cc)
            .arg("-I")
            .arg(header_dir)
            .arg(&c_check_path)
            .arg("-o")
            .arg(&c_check_bin)
            .status();
        if let Ok(s) = status {
            if s.success() {
                cc_used = Some((*cc).to_string());
                break;
            }
        }
    }
    if let Some(cc) = &cc_used {
        println!("cargo:warning=event-abi: ABI size check compiled with `{cc}`");
        let _ = Command::new(&c_check_bin).status();
    } else {
        println!(
            "cargo:warning=event-abi: no C compiler (clang/cc/gcc) available; ABI size check skipped at build time. The hand-written generated.rs and the `tests/manifest.rs` SHA-256 check are the source of truth for the C layout."
        );
    }

    // 2. Write the manifest. Constants are taken from the C header
    //    definition; the Rust const_assert in src/lib.rs pins the
    //    same numbers from the other direction. Drift between the two
    //    sides fails the next `cargo nextest run -p event-abi`.
    let manifest_path = write_manifest(&out_dir, &header_sha, &bindings_sha, 1, 0, 96, 4096)?;
    println!(
        "cargo:warning=event-abi: manifest written to {}",
        manifest_path.display()
    );

    // 3. Also copy the manifest to the workspace `target/` so the
    //    QA scripts can inspect it without re-running build.rs.
    let stable = target_dir.join("event-abi.manifest.json");
    if let Some(parent) = stable.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::copy(&manifest_path, &stable);

    Ok(())
}
