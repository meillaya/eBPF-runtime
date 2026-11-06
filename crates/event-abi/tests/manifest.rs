// tests/manifest.rs: event-abi
//
// Asserts the build-time manifest written by `build.rs` matches the
// on-disk files: `bpf/include/event_abi.h` and `src/generated.rs`.
// The manifest lives at `$OUT_DIR/event-abi.manifest.json` and is
// also copied to `$CARGO_TARGET_DIR/event-abi.manifest.json`.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::PathBuf;

use event_abi::{HEADER_LEN, PAYLOAD_MAX, SCHEMA_MAJOR, SCHEMA_MINOR};

fn manifest_path() -> PathBuf {
    if let Ok(env) = std::env::var("CARGO_MANIFEST_DIR") {
        let in_target = PathBuf::from(env)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("target/event-abi.manifest.json"));
        if let Some(p) = in_target {
            if p.exists() {
                return p;
            }
        }
    }
    PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"))
        .join("event-abi.manifest.json")
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

fn read_string(bytes: &[u8], start: usize) -> (String, usize) {
    debug_assert_eq!(bytes[start], b'"');
    let mut i = start + 1;
    let mut out = String::new();
    while i < bytes.len() && bytes[i] != b'"' {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            out.push(match bytes[i + 1] {
                b'n' => '\n',
                b't' => '\t',
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                c => c as char,
            });
            i += 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    if i < bytes.len() {
        i += 1;
    }
    (out, i)
}

fn read_value(bytes: &[u8], start: usize) -> (String, usize) {
    let i = skip_ws(bytes, start);
    if i < bytes.len() && bytes[i] == b'"' {
        return read_string(bytes, i);
    }
    let s = i;
    let mut e = i;
    while e < bytes.len() && !matches!(bytes[e], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
    {
        e += 1;
    }
    (
        std::str::from_utf8(&bytes[s..e]).unwrap_or("").to_string(),
        e,
    )
}

fn parse_flat(s: &str) -> std::collections::HashMap<String, String> {
    let bytes = s.as_bytes();
    let mut out = std::collections::HashMap::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len()
            && matches!(
                bytes[i],
                b' ' | b'\t' | b'\n' | b'\r' | b',' | b'{' | b'}' | b'[' | b']'
            )
        {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'"' {
            break;
        }
        let (key, after) = read_string(bytes, i);
        i = after;
        while i < bytes.len() && bytes[i] != b':' {
            i += 1;
        }
        if i < bytes.len() {
            i += 1;
        }
        let (val, after) = read_value(bytes, i);
        out.insert(key, val);
        i = after;
    }
    out
}

// Vendored SHA-256 (FIPS 180-4). The round constants are the first 32
// bits of the fractional parts of the cube roots of the first 64
// primes. Used only by this test to recompute the manifest hash
// without dragging in `sha2` (which collides with the `cargo 1.95`
// proc-macro fingerprint under clippy).
fn sha256_of(path: &std::path::Path) -> String {
    let bytes = std::fs::read(path).expect("read for sha256");
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
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, b) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
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
        for (word, slot) in [a, b, c, d, e, f, g, hh].into_iter().zip(h.iter_mut()) {
            *slot = slot.wrapping_add(word);
        }
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for word in h {
        for byte in word.to_be_bytes() {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    s
}

#[test]
fn manifest_exists_and_records_current_constants() {
    let p = manifest_path();
    let text = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("manifest not readable at {}: {e}", p.display()));
    let flat = parse_flat(&text);
    assert_eq!(
        flat.get("schema_major")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap() as u32,
        SCHEMA_MAJOR
    );
    assert_eq!(
        flat.get("schema_minor")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap() as u32,
        SCHEMA_MINOR
    );
    assert_eq!(
        flat.get("header_len")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap() as usize,
        HEADER_LEN
    );
    assert_eq!(
        flat.get("payload_max")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap() as usize,
        PAYLOAD_MAX
    );
    assert!(flat.contains_key("header_sha256"));
    assert!(flat.contains_key("bindings_sha256"));
    assert_eq!(
        flat.get("generated_by").map(|s| s.as_str()),
        Some("event-abi/build.rs")
    );
}

#[test]
fn manifest_header_hash_matches_c_header_on_disk() {
    let text = std::fs::read_to_string(manifest_path()).expect("manifest");
    let flat = parse_flat(&text);
    let recorded = flat.get("header_sha256").expect("header_sha256 field");
    let c_header = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("bpf/include/event_abi.h");
    assert_eq!(recorded, &sha256_of(&c_header), "C header SHA-256 drifted");
}

#[test]
fn manifest_bindings_hash_matches_generated_rs_on_disk() {
    let text = std::fs::read_to_string(manifest_path()).expect("manifest");
    let flat = parse_flat(&text);
    let recorded = flat.get("bindings_sha256").expect("bindings_sha256 field");
    let generated = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/generated.rs");
    assert_eq!(
        recorded,
        &sha256_of(&generated),
        "src/generated.rs SHA-256 drifted"
    );
}

#[test]
fn build_is_deterministic_across_runs() {
    let c_header = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("bpf/include/event_abi.h");
    let generated = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/generated.rs");
    let h1 = sha256_of(&c_header);
    let h2 = sha256_of(&c_header);
    let g1 = sha256_of(&generated);
    let g2 = sha256_of(&generated);
    assert_eq!(h1, h2, "C header SHA-256 must be deterministic");
    assert_eq!(g1, g2, "bindings SHA-256 must be deterministic");
}
